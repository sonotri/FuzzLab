from __future__ import annotations
from pathlib import Path

def safe_join_repo(repo_root: Path, rel_path: str) -> Path:
    root = repo_root.resolve()
    candidate = (root / rel_path).resolve()
    try:
        candidate.relative_to(root)
    except Exception:
        raise ValueError(f"path traversal blocked: {rel_path}")
    return candidate


def to_repo_relpath(semgrep_path: str, repo_root: Path) -> str:
    root = repo_root.resolve()
    p = Path(semgrep_path)

    if p.is_absolute():
        try:
            return p.resolve().relative_to(root).as_posix()
        except Exception:
            return p.as_posix()

    try:
        abs_p = (root / p).resolve()
        return abs_p.relative_to(root).as_posix()
    except Exception:
        return p.as_posix().lstrip("./")


def read_context_lines(
    file_path: Path,
    start_line: int | None,
    end_line: int | None,
    before: int = 3,
    after: int = 3,
) -> list[dict] | None:
    """
    returns:
      [{"line": 12, "text": "...", "is_match": True/False}, ...]
    """
    if start_line is None or end_line is None:
        return None
    if not file_path.exists():
        return None

    lines = file_path.read_text(errors="ignore").splitlines()
    s = max(1, start_line - before)
    e = min(len(lines), end_line + after)

    out = []
    for ln in range(s, e + 1):
        text = lines[ln - 1]
        out.append({
            "line": ln,
            "text": text,
            "is_match": (start_line <= ln <= end_line),
        })
    return out


def context_lines_to_snippet(context_lines: list[dict]) -> str:
    # 기존처럼 "line: text" 형태 문자열도 함께 제공
    return "\n".join([f'{x["line"]}: {x["text"]}' for x in context_lines])


def normalize_semgrep_result(result: dict, repo_root: Path) -> dict:
    raw_path = result.get("path")
    start = (result.get("start") or {}).get("line")
    end = (result.get("end") or {}).get("line")

    extra = result.get("extra") or {}
    meta = extra.get("metadata") or {}

    cwe_list = meta.get("cwe") or []
    if isinstance(cwe_list, str):
        cwe_list = [cwe_list]

    rel_path = None
    if raw_path:
        rel_path = to_repo_relpath(str(raw_path), repo_root)

    before = 3
    after = 3

    evidence_status = "none"
    evidence_reason = None
    context_lines = None
    snippet = None

    if not rel_path:
        evidence_status = "missing_path"
        evidence_reason = "semgrep result has no path"
    elif start is None or end is None:
        evidence_status = "missing_location"
        evidence_reason = "start/end line missing"
    else:
        try:
            abs_path = safe_join_repo(repo_root, rel_path)
            context_lines = read_context_lines(abs_path, start, end, before=before, after=after)

            if not context_lines:
                evidence_status = "unavailable"
                evidence_reason = "file missing or line range invalid"
            else:
                snippet = context_lines_to_snippet(context_lines)
                evidence_status = "ok"

        except ValueError as ve:
            evidence_status = "blocked"
            evidence_reason = str(ve)
        except Exception as e:
            evidence_status = "error"
            evidence_reason = f"{type(e).__name__}: {e}"

    normalized = {
        "tool": "semgrep",
        "rule": {
            "id": result.get("check_id"),
            "name": extra.get("message"),
        },
        "severity": result.get("severity"),
        "location": {
            "path": rel_path,
            "start_line": start,
            "end_line": end,
        },
        "references": {"cwe": cwe_list},

        # 프론트/LLM 친화 구조
        "evidence": {
            "status": evidence_status,
            "reason": evidence_reason,
            "match": {"start_line": start, "end_line": end},
            "context": {"before": before, "after": after},
            "context_lines": context_lines,  # ← 배열
            "snippet": snippet,              # ← 문자열(기존 호환)
        },

        "metadata": {
            "semgrep": {"raw_path": raw_path}
        },
    }
    return normalized


