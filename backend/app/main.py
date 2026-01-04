from fastapi import FastAPI
from pydantic import BaseModel
from uuid import uuid4
from .tasks import ping
from .db import SessionLocal
from .models import Scan
from .tasks import run_semgrep_smoke
from .tasks import run_semgrep_and_store 
from .models import Finding 
from fastapi import UploadFile, File, Form
from pathlib import Path
import zipfile
import shutil
import math
from fastapi import HTTPException
from .models import LLMAnswer
from .tasks import generate_llm_answer_for_group
from pydantic import BaseModel
from .models import LLMAnswer

SEVERITY_MAP = {
    None: 0,
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

app = FastAPI(title="FuzzLab API Demo")

class ScanRequest(BaseModel):
    scan_id: str | None = None

@app.post("/scan")
def create_scan(
    file: UploadFile = File(...),
    project_name: str | None = Form(None),
):
    scan_id = str(uuid4())

    # workspace/<scan_id>/src
    base = Path("workspace") / scan_id
    repo_root = base / "src"
    base.mkdir(parents=True, exist_ok=True)
    repo_root.mkdir(parents=True, exist_ok=True)

    # zip 저장
    zip_path = base / "upload.zip"
    with zip_path.open("wb") as f:
        shutil.copyfileobj(file.file, f)

    # unzip(zip-slip 방지)
    try:
        with zipfile.ZipFile(zip_path, "r") as z:
            safe_extract_zip(z, repo_root)
    except Exception as e:
        shutil.rmtree(base, ignore_errors=True)
        raise RuntimeError(f"zip extract failed: {e}")

    # DB에 scan 저장
    db = SessionLocal()
    try:
        db.add(Scan(
            scan_id=scan_id,
            status="queued",
            workspace_path=str(repo_root),
        ))
        db.commit()
    finally:
        db.close()

    # semgrep 실행 (scan_id만 넘김)
    run_semgrep_and_store.delay(scan_id)

    return {
        "scan_id": scan_id,
        "status": "queued",
        "workspace_path": str(repo_root),
    }


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
        db.add(Scan(
            scan_id=scan_id,
            status="queued",
            workspace_path=repo_root,  # 여기서만 설정하도록
        ))
        db.commit()
    finally:
        db.close()

    # scan_id만 전달하도록
    run_semgrep_and_store.delay(scan_id)
    return {"scan_id": scan_id, "status": "queued"}


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

        grouped = group_findings(findings)

        return {
            "scan": {
                "scan_id": scan.scan_id,
                "status": scan.status,
                "workspace_path": scan.workspace_path,
                "error_message": scan.error_message,
                "created_at": scan.created_at,
                "updated_at": scan.updated_at,
            },
            "grouped_findings": grouped,   # 새로 추가
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


#zpi-slip 방지용
def safe_extract_zip(zipf: zipfile.ZipFile, dest: Path):
    dest = dest.resolve()
    for member in zipf.infolist():
        target = (dest / member.filename).resolve()
        if not str(target).startswith(str(dest)):
            raise ValueError(f"zip slip detected: {member.filename}")
    zipf.extractall(dest)

# grouping 함수 추가
def group_findings(findings: list[Finding]) -> list[dict]:
    groups = {}

    for f in findings:
        key = (f.path, f.start_line, f.end_line)

        if key not in groups:
            groups[key] = {
                "group_id": f"{f.path}:{f.start_line}-{f.end_line}",
                "location": {
                    "path": f.path,
                    "start_line": f.start_line,
                    "end_line": f.end_line,
                },
                "rules": [],
                "evidence": None,
                "max_severity": 0,
            }

        group = groups[key]

        # rule 정보 누적
        sev_text = f.severity
        sev_score = SEVERITY_MAP.get(sev_text, 0)

        group["rules"].append({
            "rule_id": f.rule_id,
            "message": f.message,
            "severity": sev_text,
        })

        group["max_severity"] = max(group["max_severity"], sev_score)

        # evidence는 하나만 있으면O(동일 위치)
        if group["evidence"] is None:
            group["evidence"] = (
                f.normalized_json or {}
            ).get("evidence")

    # 그룹 → 리스트 변환 + score 계산
    grouped = []
    for g in groups.values():
        rule_count = len(g["rules"])
        score = g["max_severity"] + math.log2(rule_count + 1)

        grouped.append({
            "group_id": g["group_id"],
            "location": g["location"],
            "rules": g["rules"],
            "final_severity": g["max_severity"],
            "score": round(score, 2),
            "evidence": g["evidence"],
        })

    # 점수 높은 순 정렬
    grouped.sort(key=lambda x: x["score"], reverse=True)
    return grouped

@app.get("/scan/{scan_id}/groups/{group_id}/llm-input")
def get_llm_input(scan_id: str, group_id: str):
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="scan not found")

        findings = (
            db.query(Finding)
            .filter(Finding.scan_id == scan_id)
            .order_by(Finding.id.asc())
            .all()
        )

        grouped = group_findings(findings)
        group = next((g for g in grouped if g["group_id"] == group_id), None)
        if not group:
            raise HTTPException(status_code=404, detail="group not found")

        # LLM용으로 필요한 필드만 깔끔하게 정리
        return {
            "scan": {
                "scan_id": scan.scan_id,
                "workspace_path": scan.workspace_path,  # (참고) 코드 위치
                "status": scan.status,
                "created_at": scan.created_at,
            },
            "group": {
                "group_id": group["group_id"],
                "location": group["location"],
                "final_severity": group["final_severity"],
                "score": group["score"],
                "rules": group["rules"],
                "evidence": group["evidence"],  # context_lines 포함
            },
            "contract": {
                "group_id_format": "{path}:{start_line}-{end_line}",
                "expected_output_fields": [
                    "summary",
                    "risk_level",
                    "reasoning",
                    "impact",
                    "recommendation",
                    "safe_example",
                ],
            },
        }
    finally:
        db.close()


@app.post("/scan/{scan_id}/groups/{group_id}/llm-answer")
def request_llm_answer(scan_id: str, group_id: str, model: str = "llama3.1:8b"):
    db = SessionLocal()
    try:
        # scan 존재 확인
        scan = db.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="scan not found")

        # semgrep 끝나기 전이면 막기(레이스 방지)
        if scan.status != "done":
            raise HTTPException(status_code=409, detail=f"scan not ready: status={scan.status}")

        # placeholder upsert
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
                prompt="",
                status="queued",
            )
            db.add(row)
        else:
            row.model = model
            row.status = "queued"

        db.commit()
    finally:
        db.close()

    async_result = generate_llm_answer_for_group.delay(scan_id, group_id, model)

    return {
        "task_id": async_result.id,
        "status": "queued",
        "scan_id": scan_id,
        "group_id": group_id,
        "model": model,
    }


@app.get("/scan/{scan_id}/groups/{group_id}/llm-answer")
def get_llm_answer(scan_id: str, group_id: str):
    db = SessionLocal()
    try:
        row = (
            db.query(LLMAnswer)
            .filter(LLMAnswer.scan_id == scan_id, LLMAnswer.group_id == group_id)
            .order_by(LLMAnswer.id.desc())
            .first()
        )
        if not row:
            raise HTTPException(status_code=404, detail="llm answer not found")

        return {
            "id": row.id,
            "scan_id": row.scan_id,
            "group_id": row.group_id,
            "model": row.model,
            "status": row.status,
            "response_json": row.response_json,
            "response_text": row.response_text,
            "created_at": row.created_at,
        }
    finally:
        db.close()

class ManualLLMAnswerRequest(BaseModel):
    model: str
    response_json: dict


@app.post("/scan/{scan_id}/groups/{group_id}/llm-answer/manual")
def save_manual_llm_answer(scan_id: str, group_id: str, req: ManualLLMAnswerRequest):
    db = SessionLocal()
    try:
        # scan 존재 확인
        scan = db.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="scan not found")

        # upsert
        row = (
            db.query(LLMAnswer)
            .filter(LLMAnswer.scan_id == scan_id, LLMAnswer.group_id == group_id)
            .first()
        )
        if not row:
            row = LLMAnswer(
                scan_id=scan_id,
                group_id=group_id,
                model=req.model,
                prompt="(manual from open-webui)",
                status="done",
                response_json=req.response_json,
                response_text=None,
            )
            db.add(row)
        else:
            row.model = req.model
            row.prompt = "(manual from open-webui)"
            row.status = "done"
            row.response_json = req.response_json
            row.response_text = None

        db.commit()

        return {"scan_id": scan_id, "group_id": group_id, "status": "done", "source": "manual"}
    finally:
        db.close()


