import time
import json
import subprocess
from pathlib import Path
from datetime import datetime, timezone

from .celery_app import celery_app
from .db import SessionLocal
from .models import Scan, Finding, LLMAnswer
from .normalize_semgrep import normalize_semgrep_result
from .ollama_client import call_ollama
from .llm_service import build_llm_input, make_prompt


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

    cmd = ["semgrep", "--config", "p/default", "--json", str(target)]
    proc = subprocess.run(cmd, capture_output=True, text=True)

    if proc.returncode not in (0, 1):
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

            db.add(
                Finding(
                    scan_id=scan_id,
                    tool="semgrep",
                    rule_id=(normalized.get("rule") or {}).get("id"),
                    severity=normalized.get("severity"),
                    message=(normalized.get("rule") or {}).get("name"),
                    path=loc.get("path"),  # 상대경로
                    start_line=loc.get("start_line"),
                    end_line=loc.get("end_line"),
                    raw_json=r,
                    normalized_json=normalized,
                )
            )
        db.commit()
    finally:
        db.close()

    set_status(scan_id, "done")
    return {"scan_id": scan_id, "findings": len(results)}


@celery_app.task
def generate_llm_answer_for_group(scan_id: str, group_id: str, model: str = "llama3.1:8b") -> dict:
    """
    1) scan_id + group_id로 llm-input 생성
    2) prompt 생성
    3) Ollama 호출 (JSON 고정)
    4) llm_answers 테이블에 upsert 저장

    안정화(중요):
    - placeholder row가 이미 만들어져 있다고 가정하고(status=queued)
      task 시작 시 running으로 바꾼다.
    """
    db = SessionLocal()
    prompt = ""
    try:
        # ✅ Step 6: 작업 시작 표시 (queued -> running)
        row = (
            db.query(LLMAnswer)
            .filter(LLMAnswer.scan_id == scan_id, LLMAnswer.group_id == group_id)
            .first()
        )
        if row:
            row.status = "running"
            db.commit()

        # 순환 import 방지: group_findings만 지연 import
        from .main import group_findings

        llm_input = build_llm_input(db, scan_id, group_id, group_findings)
        prompt = make_prompt(llm_input)

        resp = call_ollama(model=model, prompt=prompt)

        # upsert (scan_id, group_id 유니크)
        row = (
            db.query(LLMAnswer)
            .filter(LLMAnswer.scan_id == scan_id, LLMAnswer.group_id == group_id)
            .first()
        )
        if not row:
            # placeholder가 없더라도 안전하게 생성
            row = LLMAnswer(
                scan_id=scan_id,
                group_id=group_id,
                model=model,
                prompt=prompt,
                status="running",
            )
            db.add(row)
        else:
            row.model = model
            row.prompt = prompt

        if isinstance(resp, dict):
            row.response_json = resp
            row.response_text = None
            row.status = "done"
        else:
            row.response_json = None
            row.response_text = resp
            row.status = "failed_parse"

        db.commit()
        return {"scan_id": scan_id, "group_id": group_id, "status": row.status}

    except Exception as e:
        # 실패도 DB에 남기기
        row = (
            db.query(LLMAnswer)
            .filter(LLMAnswer.scan_id == scan_id, LLMAnswer.group_id == group_id)
            .first()
        )
        if not row:
            row = LLMAnswer(
                scan_id=scan_id,
                group_id=group_id,
                model=model,
                prompt=prompt,
            )
            db.add(row)

        row.response_json = None
        row.response_text = str(e)
        row.status = "failed_call"
        db.commit()
        raise

    finally:
        db.close()
