import os
import json
import requests
from typing import Any, Dict, Optional, Union

# 기본 스키마 (JSON 고정용)
DEFAULT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "risk_level": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
        "reasoning": {"type": "string"},
        "impact": {"type": "string"},
        "recommendation": {"type": "string"},
        "safe_example": {"type": "string"},
    },
    "required": ["summary", "risk_level", "reasoning", "impact", "recommendation", "safe_example"],
    "additionalProperties": False,
}

# Ollama /api/generate 호출
def call_ollama(
    model: str,
    prompt: str,
    base_url: Optional[str] = None,
    schema: Optional[Dict[str, Any]] = DEFAULT_SCHEMA,
    timeout_sec: int = 180,
) -> Union[Dict[str, Any], str]:
    """
    반환:
      - JSON 파싱 성공: dict
      - JSON 파싱 실패: raw string (DB에 response_text로 저장)
    """
    base_url = base_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        # 핵심: 구조화 출력(가능하면 schema)
        "format": schema or "json",
        # 안정성: 낮은 temperature
        "options": {"temperature": 0.1},
    }

    r = requests.post(f"{base_url}/api/generate", json=payload, timeout=timeout_sec)
    r.raise_for_status()

    text = r.json().get("response", "")

    try:
        return json.loads(text)
    except Exception:
        return text
