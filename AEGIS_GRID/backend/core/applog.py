"""
Application Log
Rolling, file-backed log of scan events and errors, kept small on purpose
(last N entries) so it can be cheaply included as chatbot context for
error-correction / log-analysis conversations.
"""
import json
import time
from pathlib import Path

STATE_DIR = Path("state")
LOG_FILE = STATE_DIR / "app_log.json"
MAX_ENTRIES = 200


def _load() -> list:
    if not LOG_FILE.exists():
        return []
    try:
        return json.loads(LOG_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return []


def _save(entries: list) -> None:
    STATE_DIR.mkdir(exist_ok=True)
    LOG_FILE.write_text(json.dumps(entries[-MAX_ENTRIES:], indent=2))


def log_event(category: str, message: str, level: str = "info") -> None:
    """category: e.g. 'scan', 'quota', 'server', 'ai'. level: info|warning|error."""
    entries = _load()
    entries.append(
        {
            "timestamp": time.time(),
            "category": category,
            "level": level,
            "message": message[:500],  # never let a runaway message (or a key) bloat/leak into logs
        }
    )
    _save(entries)


def recent(n: int = 30, level: str | None = None) -> list:
    entries = _load()
    if level:
        entries = [e for e in entries if e["level"] == level]
    return entries[-n:]


def tail_as_text(n: int = 30) -> str:
    lines = [f"[{e['level'].upper()}] {e['category']}: {e['message']}" for e in recent(n)]
    return "\n".join(lines) if lines else "(no recent log entries)"
