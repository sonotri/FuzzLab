import json
from fastapi import HTTPException
from .models import Scan, Finding

# LLM에 전달할 입력(JSON) 생성
# group_findings_func를 인자로 받아 순환 import 방지
def build_llm_input(db, scan_id: str, group_id: str, group_findings_func) -> dict:

    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")

    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan_id)
        .order_by(Finding.id.asc())
        .all()
    )

    grouped = group_findings_func(findings)
    group = next((g for g in grouped if g["group_id"] == group_id), None)

    if not group:
        raise HTTPException(status_code=404, detail="group not found")

    return {
        "scan": {
            "scan_id": scan.scan_id,
            "workspace_path": scan.workspace_path,
            "status": scan.status,
            "created_at": scan.created_at,
        },
        "group": {
            "group_id": group["group_id"],
            "location": group["location"],
            "final_severity": group["final_severity"],
            "score": group["score"],
            "rules": group["rules"],
            "evidence": group["evidence"],
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

# Ollama에 전달할 프롬프트
def make_prompt(llm_input: dict) -> str:
    return (
        "You are a security analyst.\n"
        "Return ONLY a valid JSON object.\n"
        "Do NOT include markdown, code fences, or extra text.\n"
        "Use ONLY the provided evidence. If evidence is insufficient, state that in reasoning.\n\n"
        "Required JSON fields:\n"
        "- summary (string)\n"
        "- risk_level (one of: low, medium, high, critical)\n"
        "- reasoning (string)\n"
        "- impact (string)\n"
        "- recommendation (string)\n"
        "- safe_example (string)\n\n"
        "INPUT JSON:\n"
        f"{json.dumps(llm_input, ensure_ascii=False, default=str)}\n"
    )
