from __future__ import annotations
from pathlib import Path

def read_snippet(file_path: Path, start_line: int | None, end_line: int | None, context: int = 3) -> str | None:
    if start_line is None or end_line is None:
        return None
    if not file_path.exists():
        return None

    lines = file_path.read_text(errors="ignore").splitlines()
    # semgrep line은 1-based
    s = max(1, start_line - context)
    e = min(len(lines), end_line + context)

    snippet_lines = []
    for ln in range(s, e + 1):
        snippet_lines.append(f"{ln}: {lines[ln-1]}")
    return "\n".join(snippet_lines)

def normalize_semgrep_result(result: dict, repo_root: Path) -> dict:
    # 설계한 Finding JSON 중 핵심 필드만 최소로 채운 버전(나중에 스키마 확장하면서 더 채우면 댐)
    path = result.get("path")
    start = (result.get("start") or {}).get("line")
    end = (result.get("end") or {}).get("line")

    extra = result.get("extra") or {}
    meta = extra.get("metadata") or {}

    cwe_list = meta.get("cwe") or []
    # cwe가 문자열/리스트 등 섞일 수 있어 수정
    if isinstance(cwe_list, str):
        cwe_list = [cwe_list]

    # snippet/context는 파일에서 읽어 채움
    snippet = None
    if path and start and end:
        snippet = read_snippet(repo_root / path, start, end, context=3)

    normalized = {
        "tool": "semgrep",
        "rule": {
            "id": result.get("check_id"),
            "name": extra.get("message"),
        },
        "severity": extra.get("severity"),
        "location": {
            "path": path,
            "start_line": start,
            "end_line": end,
        },
        "references": {
            "cwe": cwe_list,
        },
        "evidence": {
            "snippet": snippet,
        },
    }
    return normalized
