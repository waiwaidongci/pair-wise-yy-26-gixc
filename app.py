from __future__ import annotations
import json, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from database import DomainError, VulnerabilityDB

BASE=Path(__file__).resolve().parent
DB_PATH=os.environ.get("VULN_DB",str(BASE/"vulnerability.db"))

class Handler(BaseHTTPRequestHandler):
    db=VulnerabilityDB(DB_PATH)
    def log_message(self,fmt,*args): return
    def _json(self,status,payload):
        data=json.dumps(payload,ensure_ascii=False).encode()
        self.send_response(status); self.send_header("Content-Type","application/json; charset=utf-8"); self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)
    def _body(self):
        length=int(self.headers.get("Content-Length",0))
        try: value=json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError as exc: raise DomainError("请求体必须是合法 JSON") from exc
        if not isinstance(value,dict): raise DomainError("请求体必须是对象")
        return value
    def do_GET(self):
        parsed=urlparse(self.path); parts=[p for p in parsed.path.split("/") if p]
        try:
            if parsed.path in ("/","/index.html"):
                data=(BASE/"static"/"index.html").read_bytes(); self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8"); self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data); return
            if parsed.path=="/api/state": return self._json(200,self.db.snapshot())
            if len(parts)==3 and parts[:2]==["api","reports"]:
                uid=int(parse_qs(parsed.query).get("user_id",[0])[0]); return self._json(200,self.db.get_report_for_user(int(parts[2]),uid))
            if len(parts)==4 and parts[:2]==["api","reports"] and parts[3]=="notifications":
                return self._json(200,{"notifications":self.db.notifications_for(int(parts[2]))})
            if len(parts)==4 and parts[:2]==["api","reports"] and parts[3]=="advisory":
                uid=int(parse_qs(parsed.query).get("user_id",[0])[0]); return self._json(200,self.db.get_advisory(int(parts[2]),uid))
            if parsed.path=="/api/duplicates":
                q=parse_qs(parsed.query); return self._json(200,{"duplicates":self.db.find_duplicate_reports(int(q.get("product_id",[0])[0]),q.get("version",[""])[0])})
            self._json(404,{"ok":False,"error":"接口不存在"})
        except (DomainError,ValueError) as exc: self._json(400,{"ok":False,"error":str(exc)})
    def do_POST(self):
        parts=[p for p in urlparse(self.path).path.split("/") if p]; path="/"+"/".join(parts)
        try:
            b=self._body()
            if path=="/api/users": return self._json(201,{"ok":True,"id":self.db.add_user(str(b.get("name","")),str(b.get("role","reporter")),str(b.get("organization","")))})
            if path=="/api/products": return self._json(201,{"ok":True,"id":self.db.add_product(str(b.get("name","")),str(b.get("owner","")))})
            if path=="/api/reports": return self._json(201,{"ok":True,"id":self.db.create_report(str(b.get("title","")),int(b.get("product_id",0)),int(b.get("reporter_id",0)),str(b.get("summary","")),str(b.get("confidential_until","")),list(b.get("versions",[])),str(b.get("version_details","")),bool(b.get("allow_duplicate",False)))})
            if path=="/api/members": self.db.add_member(int(b.get("report_id",0)),int(b.get("user_id",0)),str(b.get("member_role","maintainer")),int(b.get("added_by",0))); return self._json(201,{"ok":True})
            if path=="/api/evidence": return self._json(201,{"ok":True,"id":self.db.add_evidence(int(b.get("report_id",0)),str(b.get("name","")),str(b.get("content","")),str(b.get("classification","private")),int(b.get("uploaded_by",0)))})
            if path=="/api/fixes": return self._json(201,{"ok":True,"id":self.db.set_fix_plan(int(b.get("report_id",0)),int(b.get("maintainer_id",0)),str(b.get("plan","")),b.get("target_date"))})
            if path=="/api/extensions": return self._json(201,{"ok":True,"id":self.db.extend_embargo(int(b.get("report_id",0)),str(b.get("new_deadline","")),str(b.get("reason","")),int(b.get("coordinator_id",0)))})
            if path=="/api/advisories": return self._json(201,{"ok":True,"id":self.db.create_advisory_draft(int(b.get("report_id",0)),str(b.get("content","")),int(b.get("user_id",0)))})
            if len(parts)==4 and parts[:2]==["api","reports"] and parts[3]=="status": self.db.set_status(int(parts[2]),str(b.get("status","")),int(b.get("user_id",0)),str(b.get("note",""))); return self._json(200,{"ok":True})
            if len(parts)==4 and parts[:2]==["api","reports"] and parts[3]=="publish": self.db.publish_report(int(parts[2]),int(b.get("coordinator_id",0)),b.get("as_of")); return self._json(200,{"ok":True})
            self._json(404,{"ok":False,"error":"接口不存在"})
        except (DomainError,ValueError) as exc: self._json(400,{"ok":False,"error":str(exc)})

def main():
    VulnerabilityDB(DB_PATH).seed_demo(); port=int(os.environ.get("PORT","8113")); print(f"Vulnerability disclosure service: http://127.0.0.1:{port}"); ThreadingHTTPServer(("0.0.0.0",port),Handler).serve_forever()
if __name__=="__main__": main()
