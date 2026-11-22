from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import threading

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_AUDIT_PATH = BASE_DIR / "audit.jsonl"

_LOCK = threading.Lock()

def _sanitize_text(value: object) -> str:
    if value is None:
        text = ""
    else:
        text = str(value)

    cleaned = []

    for char in text:
        code = ord(char)
        if code >= 32 and code != 127:
            cleaned.append(char)
        else:
            cleaned.append(f"\\u{code:04x}")
    return "".join(cleaned)

def write_audit(*, user: str | None, op: str, path: str | None, allowed: bool, reason: str, model: str | None = None, session: str | None = None, audit_path = DEFAULT_AUDIT_PATH) -> None:
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user": _sanitize_text(user),
        "op": _sanitize_text(op),
        "path": _sanitize_text(path),
        "allowed": bool(allowed),
        "reason": _sanitize_text(reason),
        "model": _sanitize_text(model),
        "session": _sanitize_text(session) 
    }

    line = json.dumps(record, ensure_ascii=False) + "\n"
    with _LOCK:
        audit_path = Path(audit_path)
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        with audit_path.open("a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()