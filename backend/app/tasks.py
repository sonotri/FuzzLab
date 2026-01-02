import time
from .celery_app import celery_app 
from .db import SessionLocal
from .models import Scan
from datetime import datetime, timezone

import json
import subprocess
from pathlib import Path
from .celery_app import celery_app

from .models import Finding
from .normalize_semgrep import normalize_semgrep_result

def set_status(scan_id: str, status: str, error_message: str | None = None):
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            return
        scan.status = status
        scan.error_message = error_message
        scan.updated_at = datetime.now(timezone.utc)
        db.commit()
    finally:
        db.close()

@celery_app.task
def ping(scan_id: str) -> dict:
    set_status(scan_id, "running")
    try:
        print(f"[worker] task start scan_id={scan_id}")
        time.sleep(1)
        print(f"[worker] task done scan_id={scan_id}")
        set_status(scan_id, "done")
        return {"작업이 완료되었습니다 -> scan_id": scan_id, "status": "ok"}
    except Exception as e:
        set_status(scan_id, "failed", str(e))
        raise

@celery_app.task 
def run_semgrep_smoke(target_dir: str) -> dict:
     target = Path(target_dir) 
     if not target.exists(): 
         raise RuntimeError(f"Target dir does not exist: {target_dir}") 
     
     # semgrep 기본 룰셋 
     cmd = ["semgrep", "--config", "p/default", "--json", str(target)] 
     proc = subprocess.run(cmd, capture_output=True, text=True) 
     
     if proc.returncode not in (0, 1): 
          # 0=매치 없음, 1=매치 있음 
          raise RuntimeError(f"semgrep failed rc={proc.returncode} stderr={proc.stderr}") 
     
     data = json.loads(proc.stdout) 
     return {"target": target_dir, "results": len(data.get("results", []))}


@celery_app.task
def run_semgrep_and_store(scan_id: str) -> dict:
    set_status(scan_id, "running")

    # repo_root는 DB에서 가져옴
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if not scan or not scan.workspace_path:
            raise RuntimeError("workspace_path missing for scan")
        root = Path(scan.workspace_path)
    finally:
        db.close()

    cmd = ["semgrep", "--config", "p/default", "--json", "."]
    proc = subprocess.run(
        cmd,
        cwd=str(root),
        capture_output=True,
        text=True,
    )

    if proc.returncode not in (0, 1):
        set_status(scan_id, "failed", proc.stderr)
        raise RuntimeError(proc.stderr)

    data = json.loads(proc.stdout)
    results = data.get("results", [])

    db = SessionLocal()
    try:
        for r in results:
            normalized = normalize_semgrep_result(r, root)
            loc = normalized.get("location") or {}

            db.add(Finding(
                scan_id=scan_id,
                tool="semgrep",
                rule_id=(normalized.get("rule") or {}).get("id"),
                severity=normalized.get("severity"),
                message=(normalized.get("rule") or {}).get("name"),
                path=loc.get("path"),      # 상대경로
                start_line=loc.get("start_line"),
                end_line=loc.get("end_line"),
                raw_json=r,
                normalized_json=normalized,
            ))
        db.commit()
    finally:
        db.close()

    set_status(scan_id, "done")
    return {"scan_id": scan_id, "findings": len(results)}
