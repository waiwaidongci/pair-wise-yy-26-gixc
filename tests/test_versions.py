import hashlib
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from database import ConflictError, DomainError, VulnerabilityDB, content_fingerprint


def sha256(text):
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


class EvidenceVersionTest(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.db = VulnerabilityDB(self.path)
        self.reporter = self.db.add_user("报告人", "reporter", "研究所")
        self.coord = self.db.add_user("协调员", "coordinator", "响应中心")
        self.maint = self.db.add_user("维护者", "maintainer", "项目组")
        self.outsider = self.db.add_user("旁观者", "reporter", "外部")
        self.product = self.db.add_product("网关", "项目组")
        self.report = self.db.create_report("鉴权绕过", self.product, self.reporter,
                                            "特制请求可绕过鉴权", "2026-10-30", ["3.2.0"])
        self.db.add_member(self.report, self.maint, "maintainer", self.coord)
        self.evidence = self.db.add_evidence(self.report, "请求样例", "原始取证内容",
                                             "private", self.reporter)

    def tearDown(self):
        self.db.close()
        os.unlink(self.path)

    def _publish(self):
        self.db.set_status(self.report, "triaged", self.coord)
        self.db.set_status(self.report, "fixing", self.coord)
        self.db.set_fix_plan(self.report, self.maint, "增加鉴权前置校验", "2026-10-20")
        self.db.set_status(self.report, "resolved", self.coord)
        self.db.create_advisory_draft(self.report, "受影响版本 3.2.0。请升级到 3.2.1。", self.coord)
        self.db.publish_report(self.report, self.coord, "2026-10-30")

    def test_first_upload_creates_version_one_with_fingerprint(self):
        versions = self.db.get_evidence_versions(self.report, self.evidence, self.coord)
        self.assertEqual(1, len(versions))
        self.assertEqual(1, versions[0]["version"])
        self.assertEqual("原始取证内容", versions[0]["content"])
        self.assertEqual(sha256("原始取证内容"), versions[0]["fingerprint"])
        self.assertEqual(self.reporter, versions[0]["created_by"])
        self.assertTrue(versions[0]["created_at"])
        self.assertTrue(versions[0]["is_current"])
        self.assertEqual("首次提交", versions[0]["reason"])

    def test_each_edit_appends_version_and_keeps_old_queryable(self):
        r2 = self.db.add_evidence_version(self.report, self.evidence, "协调员补充说明 v2",
                                          "补充时间线", self.coord, expected_version=1)
        self.assertEqual(2, r2["version"])
        self.assertEqual(sha256("协调员补充说明 v2"), r2["fingerprint"])
        r3 = self.db.add_evidence_version(self.report, self.evidence, "维护者补充日志 v3",
                                          "附上崩溃日志", self.maint, expected_version=2)
        self.assertEqual(3, r3["version"])

        versions = self.db.get_evidence_versions(self.report, self.evidence, self.maint)
        self.assertEqual([1, 2, 3], [v["version"] for v in versions])
        self.assertEqual(["首次提交", "补充时间线", "附上崩溃日志"], [v["reason"] for v in versions])
        self.assertEqual([self.reporter, self.coord, self.maint], [v["created_by"] for v in versions])
        # 最初交来的取证内容仍可查，且指纹未被改动
        self.assertEqual("原始取证内容", versions[0]["content"])
        self.assertEqual(sha256("原始取证内容"), versions[0]["fingerprint"])
        self.assertTrue(versions[-1]["is_current"])
        self.assertFalse(versions[0]["is_current"])

        detail = self.db.get_report_for_user(self.report, self.coord)["evidence"][0]
        self.assertEqual(3, detail["current_version"])
        self.assertEqual("维护者补充日志 v3", detail["content"])
        self.assertIsNone(detail["published_content"])

    def test_stale_base_version_raises_conflict_and_no_duplicate_version_numbers(self):
        self.db.add_evidence_version(self.report, self.evidence, "v2 内容", "原因2", self.coord, 1)
        with self.assertRaises(ConflictError):
            # 后到的一方仍基于 v1 提交
            self.db.add_evidence_version(self.report, self.evidence, "并发内容", "并发修改", self.maint, 1)
        versions = self.db.get_evidence_versions(self.report, self.evidence, self.coord)
        self.assertEqual([1, 2], [v["version"] for v in versions])
        with self.assertRaisesRegex(DomainError, "修改原因"):
            self.db.add_evidence_version(self.report, self.evidence, "无原因内容", "  ", self.coord, 2)
        with self.assertRaisesRegex(DomainError, "无权"):
            self.db.add_evidence_version(self.report, self.evidence, "外部内容", "外部修改", self.outsider, 2)

    def test_published_report_only_appends_and_advisory_returns_to_pending(self):
        self._publish()
        advisory = self.db.get_advisory(self.report, self.outsider)
        self.assertEqual("published", advisory["status"])
        self.assertEqual(1, advisory["materials"][0]["published_version"])

        self.db.add_evidence_version(self.report, self.evidence, "公开后补充的勘误",
                                     "公告勘误", self.coord, expected_version=1)

        # 公告回到待确认；外部用户在确认前仍只能看到旧的公开内容
        advisory = self.db.get_advisory(self.report, self.outsider)
        self.assertEqual("pending", advisory["status"])
        self.assertEqual(1, advisory["materials"][0]["published_version"])
        self.assertEqual("原始取证内容", advisory["materials"][0]["content"])
        self.assertEqual(1, advisory["pending_versions"])

        detail = self.db.get_report_for_user(self.report, self.coord)["evidence"][0]
        self.assertEqual(2, detail["current_version"])
        self.assertEqual("公开后补充的勘误", detail["content"])
        self.assertEqual("原始取证内容", detail["published_content"])
        self.assertEqual(sha256("原始取证内容"), detail["published_fingerprint"])
        self.assertTrue(any(v["is_published"] for v in detail["versions"] if v["version"] == 1))

        # 协调员重新确认后，公开内容更新为最新版本
        result = self.db.confirm_published_advisory(self.report, self.coord)
        self.assertEqual([{"evidence_id": self.evidence, "name": "请求样例", "version": 2}],
                         result["snapshot"])
        advisory = self.db.get_advisory(self.report, self.outsider)
        self.assertEqual("published", advisory["status"])
        self.assertEqual(2, advisory["materials"][0]["published_version"])
        self.assertEqual("公开后补充的勘误", advisory["materials"][0]["content"])
        with self.assertRaisesRegex(DomainError, "待确认"):
            self.db.confirm_published_advisory(self.report, self.coord)

    def test_maintainer_cannot_confirm(self):
        self._publish()
        self.db.add_evidence_version(self.report, self.evidence, "v2", "原因", self.coord, 1)
        with self.assertRaisesRegex(DomainError, "只有协调员"):
            self.db.confirm_published_advisory(self.report, self.maint)


class ConcurrentEditHttpTest(unittest.TestCase):
    """Two people editing the same material at once: exactly one wins, loser gets 409."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.environ["VULN_DB"] = self.db_path
        os.environ["PORT"] = "8114"
        sys.modules.pop("app", None)
        import app
        self.app = app
        self.db = app.Handler.db
        self.reporter = self.db.add_user("报告人A", "reporter", "研究所")
        self.coord = self.db.add_user("协调员A", "coordinator", "响应中心")
        self.ed2 = self.db.add_user("维护者B", "maintainer", "项目组二组")
        product = self.db.add_product("网关X", "项目组")
        self.report = self.db.create_report("并发问题", product, self.reporter,
                                            "两个人同时改", "2026-12-30", ["1.0"])
        self.db.add_member(self.report, self.ed2, "maintainer", self.coord)
        self.evidence = self.db.add_evidence(self.report, "PoC", "原始 PoC", "private", self.reporter)
        self.server = app.ThreadingHTTPServer(("127.0.0.1", 8114), app.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.db.close()
        os.unlink(self.db_path)

    def _post(self, path, payload):
        req = urllib.request.Request(
            "http://127.0.0.1:8114" + path,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_concurrent_edits_only_one_accepted_and_loser_gets_409(self):
        path = f"/api/reports/{self.report}/evidence/{self.evidence}/versions"
        results = {}

        def edit(uid, label):
            results[label] = self._post(path, {
                "content": f"{label} 修改后的内容",
                "reason": f"{label} 同时修改",
                "user_id": uid,
                "expected_version": 1,
            })

        t1 = threading.Thread(target=edit, args=(self.coord, "coord"))
        t2 = threading.Thread(target=edit, args=(self.ed2, "reporter2"))
        t1.start(); t2.start(); t1.join(); t2.join()

        statuses = sorted([results["coord"][0], results["reporter2"][0]])
        self.assertEqual([201, 409], statuses, results)

        # 后到一方基于最新 v2 重试，成功产生 v3；不存在重复版本号
        loser = self.coord if results["coord"][0] == 409 else self.ed2
        status, body = self._post(path, {
            "content": "基于 v2 的再修改", "reason": "冲突后重试",
            "user_id": loser, "expected_version": 2,
        })
        self.assertEqual(201, status, body)
        self.assertEqual(3, body["version"])
        versions = self.db.get_evidence_versions(self.report, self.evidence, self.coord)
        self.assertEqual([1, 2, 3], [v["version"] for v in versions])
        self.assertEqual(len({v["fingerprint"] for v in versions}), 3)


if __name__ == "__main__":
    unittest.main()
