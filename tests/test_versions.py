import hashlib
import os
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from database import ConflictError, DomainError, VulnerabilityDB


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class EvidenceVersionTest(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db"); os.close(fd)
        self.db = VulnerabilityDB(self.path)
        self.reporter = self.db.add_user("报告人", "reporter", "研究所")
        self.coord = self.db.add_user("协调员", "coordinator", "响应中心")
        self.maint = self.db.add_user("维护者", "maintainer", "项目组")
        self.outsider = self.db.add_user("旁观者", "reporter", "外部")
        self.product = self.db.add_product("网关", "项目组")
        self.report = self.db.create_report("鉴权绕过", self.product, self.reporter,
                                            "特制请求可绕过鉴权", "2026-01-01", ["3.2.0"])
        self.db.add_member(self.report, self.maint, "maintainer", self.coord)

    def tearDown(self):
        self.db.close(); os.unlink(self.path)

    def _publish(self, content="受影响版本 3.2.0，请尽快升级到修复版本。"):
        self.db.set_status(self.report, "triaged", self.coord)
        self.db.set_status(self.report, "fixing", self.coord)
        self.db.set_fix_plan(self.report, self.maint, "增加鉴权前置校验", "2026-01-10")
        self.db.set_status(self.report, "resolved", self.coord)
        self.db.create_advisory_draft(self.report, content, self.coord)
        self.db.publish_report(self.report, self.coord, "2026-01-01")

    def test_first_upload_creates_v1_with_fingerprint_and_metadata(self):
        eid = self.db.add_evidence(self.report, "PoC", "原始抓包", "private", self.reporter)
        detail = self.db.evidence_versions(eid, self.reporter)
        self.assertEqual(1, detail["current_version"])
        self.assertEqual(1, len(detail["versions"]))
        v1 = detail["versions"][0]
        self.assertEqual(1, v1["version"])
        self.assertEqual(sha("原始抓包"), v1["fingerprint"])
        self.assertEqual("初始提交", v1["change_reason"])
        self.assertEqual(self.reporter, v1["uploaded_by"])
        self.assertEqual("报告人", v1["uploader_name"])
        self.assertTrue(v1["created_at"])

    def test_each_change_appends_keeps_old_versions_and_bumps(self):
        eid = self.db.add_evidence(self.report, "PoC", "v1内容", "private", self.reporter)
        v2 = self.db.add_evidence_version(eid, "v2内容", self.coord, 1, "协调员补充说明")
        v3 = self.db.add_evidence_version(eid, "v3内容", self.reporter, 2, "报告人更新")
        self.assertEqual((2, sha("v2内容")), (v2["version"], v2["fingerprint"]))
        detail = self.db.evidence_versions(eid, self.coord)
        self.assertEqual(3, detail["current_version"])
        self.assertEqual([1, 2, 3], [v["version"] for v in detail["versions"]])
        self.assertEqual(["初始提交", "协调员补充说明", "报告人更新"],
                         [v["change_reason"] for v in detail["versions"]])
        self.assertEqual(["v1内容", "v2内容", "v3内容"], [v["content"] for v in detail["versions"]])
        self.assertEqual([sha("v1内容"), sha("v2内容"), sha("v3内容")],
                         [v["fingerprint"] for v in detail["versions"]])
        payload = self.db.get_report_for_user(self.report, self.coord)
        mat = [e for e in payload["evidence"] if e["id"] == eid][0]
        self.assertEqual("v3内容", mat["content"])
        self.assertEqual(3, mat["current_version"])

    def test_stale_baseline_returns_conflict_and_version_number_never_duplicates(self):
        eid = self.db.add_evidence(self.report, "PoC", "v1内容", "private", self.reporter)
        self.db.add_evidence_version(eid, "v2内容", self.coord, 1, "先到的修改")
        with self.assertRaises(ConflictError):
            self.db.add_evidence_version(eid, "迟到的修改", self.reporter, 1, "基线过期")
        # 冲突后后到者基于新版本重试可以成功，版本号继续递增不重复
        v3 = self.db.add_evidence_version(eid, "重试的修改", self.reporter, 2, "基于v2重试")
        self.assertEqual(3, v3["version"])
        numbers = [v["version"] for v in self.db.evidence_versions(eid, self.coord)["versions"]]
        self.assertEqual([1, 2, 3], numbers)

    def test_requires_reason_and_rejects_identical_content(self):
        eid = self.db.add_evidence(self.report, "PoC", "v1内容", "private", self.reporter)
        with self.assertRaisesRegex(DomainError, "原因不能为空"):
            self.db.add_evidence_version(eid, "v2内容", self.reporter, 1, "   ")
        with self.assertRaisesRegex(DomainError, "完全相同"):
            self.db.add_evidence_version(eid, "v1内容", self.reporter, 1, "没有变化")
        with self.assertRaisesRegex(DomainError, "expected_version"):
            self.db.add_evidence_version(eid, "v2内容", self.reporter, 0, "非法基线")

    def test_concurrent_edits_only_one_wins(self):
        other = VulnerabilityDB(self.path)
        try:
            eid = self.db.add_evidence(self.report, "PoC", "v1内容", "private", self.reporter)
            barrier = threading.Barrier(2)
            results = []

            def worker(db, actor, text):
                barrier.wait()
                try:
                    results.append(("ok", db.add_evidence_version(eid, text, actor, 1, text)))
                except ConflictError:
                    results.append(("conflict", None))

            t1 = threading.Thread(target=worker, args=(self.db, self.coord, "协调员的并发修改"))
            t2 = threading.Thread(target=worker, args=(other, self.reporter, "报告人的并发修改"))
            t1.start(); t2.start(); t1.join(); t2.join()
            self.assertEqual(["conflict", "ok"], sorted(r[0] for r in results))
            numbers = [v["version"] for v in self.db.evidence_versions(eid, self.coord)["versions"]]
            self.assertEqual([1, 2], numbers)
        finally:
            other.close()

    def test_published_report_append_flags_advisory_pending_but_keeps_public_text(self):
        eid = self.db.add_evidence(self.report, "PoC", "公开时内容", "private", self.reporter)
        self._publish("初始公开公告，至少十个字")
        public = self.db.get_advisory(self.report, self.outsider)
        self.assertEqual("published", public["status"])
        self.assertEqual(1, public["materials"][0]["published_version"])
        self.assertFalse(public["materials"][0]["changed_since_publish"])

        self.db.add_evidence_version(eid, "公开后的新材料", self.reporter, 1, "补充披露后证据")
        waiting = self.db.get_advisory(self.report, self.outsider)
        self.assertEqual("pending", waiting["status"])
        # 当前公开内容保持为确认前的旧正文
        self.assertEqual("初始公开公告，至少十个字", waiting["content"])
        self.assertEqual("初始公开公告，至少十个字", waiting["published_content"])
        # 外部看不到材料正文，只能看到指纹/版本/原因
        self.assertNotIn("公开后的新材料", str(waiting))
        material = waiting["materials"][0]
        self.assertTrue(material["changed_since_publish"])
        self.assertEqual(2, material["current_version"])
        self.assertEqual(1, material["published_version"])
        self.assertEqual(sha("公开后的新材料"), material["current_fingerprint"])
        self.assertEqual(sha("公开时内容"), material["published_fingerprint"])
        reasons = [v["change_reason"] for v in material["versions"]]
        self.assertEqual(["初始提交", "补充披露后证据"], reasons)
        # 内部人可以看到待确认的新正文草稿
        insider = self.db.get_advisory(self.report, self.coord)
        self.assertIn("draft_content", insider)

    def test_confirm_advisory_update_republishes_snapshot(self):
        eid = self.db.add_evidence(self.report, "PoC", "公开时内容", "private", self.reporter)
        self._publish("初始公开公告，至少十个字")
        self.db.add_evidence_version(eid, "公开后的新材料", self.reporter, 1, "补充披露后证据")
        self.db.create_advisory_draft(self.report, "更新后的公告正文，至少十个字", self.coord)
        result = self.db.confirm_advisory_update(self.report, self.coord)
        self.assertEqual("published", result["status"])
        public = self.db.get_advisory(self.report, self.outsider)
        self.assertEqual("published", public["status"])
        self.assertEqual("更新后的公告正文，至少十个字", public["content"])
        self.assertEqual(2, public["materials"][0]["published_version"])
        self.assertEqual(sha("公开后的新材料"), public["materials"][0]["published_fingerprint"])
        self.assertFalse(public["materials"][0]["changed_since_publish"])

    def test_only_coordinator_confirms_and_draft_edits_stay_draft(self):
        self._publish()
        self.db.add_evidence(self.report, "新材料", "追加内容", "private", self.reporter)
        with self.assertRaisesRegex(DomainError, "协调员"):
            self.db.confirm_advisory_update(self.report, self.maint)
        with self.assertRaisesRegex(DomainError, "协调员"):
            self.db.confirm_advisory_update(self.report, self.reporter)
        # 未公开报告的草稿编辑不进入 pending
        fd2, path2 = tempfile.mkstemp(suffix=".db"); os.close(fd2)
        db2 = VulnerabilityDB(path2)
        try:
            rep2 = db2.add_user("另一报告人", "reporter", "研究所")
            coord2 = db2.add_user("另一协调员", "coordinator", "响应中心")
            prod2 = db2.add_product("另一产品", "项目组")
            r2 = db2.create_report("草稿期", prod2, rep2, "另一个报告摘要", "2026-12-31", ["1.0"])
            db2.set_status(r2, "triaged", coord2)
            db2.set_status(r2, "fixing", coord2)
            db2.create_advisory_draft(r2, "第一版草稿，至少十个字", coord2)
            db2.create_advisory_draft(r2, "第二版草稿，至少十个字", coord2)
            self.assertEqual("draft", db2.get_advisory(r2, coord2)["status"])
        finally:
            db2.close(); os.unlink(path2)

    def test_coordinator_only_material_hidden_from_maintainer_versions(self):
        eid = self.db.add_evidence(self.report, "密件", "机密内容", "coordinator", self.coord)
        with self.assertRaisesRegex(DomainError, "协调员专用"):
            self.db.evidence_versions(eid, self.maint)
        with self.assertRaisesRegex(DomainError, "协调员专用"):
            self.db.add_evidence_version(eid, "维护者偷改", self.maint, 1, "越权")
        detail = self.db.get_report_for_user(self.report, self.reporter)
        self.assertTrue(any(e["id"] == eid for e in detail["evidence"]))


class LegacySchemaMigrationTest(unittest.TestCase):
    def test_old_database_is_backfilled(self):
        fd, path = tempfile.mkstemp(suffix=".db"); os.close(fd)
        conn = sqlite3.connect(path)
        conn.executescript(
            """
            CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT UNIQUE,role TEXT,organization TEXT DEFAULT '');
            CREATE TABLE products(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT UNIQUE,owner TEXT DEFAULT '');
            CREATE TABLE reports(id INTEGER PRIMARY KEY AUTOINCREMENT,public_id TEXT UNIQUE,title TEXT,product_id INT,
              reporter_id INT,summary TEXT,status TEXT DEFAULT 'new',confidential_until TEXT,public_at TEXT,
              created_at TEXT,updated_at TEXT);
            CREATE TABLE affected_versions(id INTEGER PRIMARY KEY,report_id INT,version_key TEXT,details TEXT DEFAULT '',UNIQUE(report_id,version_key));
            CREATE TABLE report_members(report_id INT,user_id INT,member_role TEXT,added_by INT,PRIMARY KEY(report_id,user_id));
            CREATE TABLE evidence(id INTEGER PRIMARY KEY AUTOINCREMENT,report_id INT,name TEXT,content TEXT,
              classification TEXT,uploaded_by INT,created_at TEXT,UNIQUE(report_id,name));
            CREATE TABLE fix_plans(id INTEGER PRIMARY KEY,report_id INT UNIQUE,maintainer_id INT,plan TEXT,target_date TEXT,status TEXT DEFAULT 'proposed',created_at TEXT);
            CREATE TABLE status_history(id INTEGER PRIMARY KEY,report_id INT,old_status TEXT,new_status TEXT,changed_by INT,note TEXT DEFAULT '',created_at TEXT);
            CREATE TABLE extensions(id INTEGER PRIMARY KEY,report_id INT,old_deadline TEXT,new_deadline TEXT,reason TEXT,coordinator_id INT,created_at TEXT);
            CREATE TABLE notifications(id INTEGER PRIMARY KEY,report_id INT,user_id INT,kind TEXT,message TEXT,created_at TEXT);
            CREATE TABLE advisory_drafts(id INTEGER PRIMARY KEY,report_id INT UNIQUE,content TEXT,
              status TEXT DEFAULT 'draft' CHECK(status IN ('draft','published')),created_by INT,created_at TEXT,published_at TEXT);
            INSERT INTO users VALUES(1,'旧报告人','reporter',''),(2,'旧协调','coordinator','');
            INSERT INTO products VALUES(1,'旧产品','');
            INSERT INTO reports VALUES(1,'VULN-2026-0001','旧标题',1,1,'摘要','published','2026-01-01','2026-01-01','t','t');
            INSERT INTO evidence VALUES(1,1,'旧材料','旧内容指纹','private',1,'t');
            INSERT INTO advisory_drafts VALUES(1,1,'已公开的旧公告','published',2,'t','t');
            """
        )
        conn.commit(); conn.close()
        db = VulnerabilityDB(path)
        try:
            ev = db.evidence_versions(1, 1)
            self.assertEqual(1, ev["current_version"])
            self.assertEqual(sha("旧内容指纹"), ev["versions"][0]["fingerprint"])
            self.assertEqual("初始提交", ev["versions"][0]["change_reason"])
            adv = db.get_advisory(1, 2)
            self.assertEqual("published", adv["status"])
            self.assertEqual("已公开的旧公告", adv["published_content"])
            db.add_evidence_version(1, "迁移后新内容", 2, 1, "旧库升级后追加")
            self.assertEqual("pending", db.get_advisory(1, 2)["status"])
        finally:
            db.close(); os.unlink(path)


if __name__ == "__main__":
    unittest.main()
