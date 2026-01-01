from fastapi import FastAPI
from pydantic import BaseModel
from uuid import uuid4
from .tasks import ping
from .db import SessionLocal
from .models import Scan
from .tasks import run_semgrep_smoke
from .tasks import run_semgrep_and_store 
from .models import Finding #추가

app = FastAPI(title="FuzzLab API Demo")

class ScanRequest(BaseModel):
    # 지금은 업로드 없이 스모크만: scan_id를 생성만 해도 되고
    # 요청에서 받아도 되는데, 일단 받는 형태로 만들어둘게.
    scan_id: str | None = None

@app.post("/scan")
def create_scan(body: ScanRequest):
    scan_id = body.scan_id or str(uuid4())
    db = SessionLocal()
    try:
        db.add(Scan(scan_id=scan_id, status="queued"))
        db.commit()
    finally:
        db.close()

    async_result = ping.delay(scan_id)
    return {"scan_id": scan_id, "task_id": async_result.id, "status": "queued"}

@app.post("/scan/semgrep-smoke")
def semgrep_smoke():
    target_dir = "/home/sonotri/FuzzLab/workspace/testscan/src"
    async_result = run_semgrep_smoke.delay(target_dir)
    return {"task_id": async_result.id, "target_dir": target_dir}

@app.post("/scan/semgrep")
def start_semgrep_scan():
    scan_id = str(uuid4())
    repo_root = "/home/sonotri/FuzzLab/workspace/testscan/src"

    db = SessionLocal()
    try:
        db.add(Scan(scan_id=scan_id, status="queued", workspace_path=repo_root))
        db.commit()
    finally:
        db.close()

    run_semgrep_and_store.delay(scan_id, repo_root)
    return {"scan_id": scan_id, "status": "queued"}

#추가
@app.get("/scan/{scan_id}/report")
def get_report(scan_id: str):
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            return {"error": "scan not found"}

        findings = (
            db.query(Finding)
            .filter(Finding.scan_id == scan_id)
            .order_by(Finding.id.asc())
            .all()
        )

        return {
            "scan": {
                "scan_id": scan.scan_id,
                "status": scan.status,
                "workspace_path": scan.workspace_path,
                "error_message": scan.error_message,
                "created_at": scan.created_at,
                "updated_at": scan.updated_at,
            },
            "findings": [
                {
                    "id": f.id,
                    "tool": f.tool,
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "message": f.message,
                    "path": f.path,
                    "start_line": f.start_line,
                    "end_line": f.end_line,
                    "normalized": f.normalized_json,
                }
                for f in findings
            ],
        }
    finally:
        db.close()