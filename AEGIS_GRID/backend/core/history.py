"""
Scan History
Persists every scan result (headers, nmap, ip reputation, ssl, dns, sandbox,
full assessment) so they can be browsed and exported later from the Reports
tab, instead of disappearing the moment you run another scan.
"""
import json
import time
import uuid
from pathlib import Path

STATE_DIR = Path("state")
HISTORY_FILE = STATE_DIR / "history.json"
MAX_ENTRIES = 300


def _load() -> list:
    if not HISTORY_FILE.exists():
        return []
    try:
        return json.loads(HISTORY_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return []


def _save(entries: list) -> None:
    STATE_DIR.mkdir(exist_ok=True)
    HISTORY_FILE.write_text(json.dumps(entries[-MAX_ENTRIES:], indent=2))


def save_entry(scan_type: str, target: str, data: dict, command: str = None) -> dict:
    entries = _load()
    entry = {
        "id": uuid.uuid4().hex[:12],
        "timestamp": time.time(),
        "type": scan_type,
        "target": target,
        "command": command,
        "data": data,
    }
    entries.append(entry)
    _save(entries)
    return entry


def list_entries() -> list:
    """Summary only (no full payload) — used for the Reports list view."""
    entries = _load()
    return [
        {"id": e["id"], "timestamp": e["timestamp"], "type": e["type"], "target": e["target"], "command": e.get("command")}
        for e in reversed(entries)
    ]


def get_entry(entry_id: str):
    for e in _load():
        if e["id"] == entry_id:
            return e
    return None


def delete_entry(entry_id: str) -> bool:
    entries = _load()
    filtered = [e for e in entries if e["id"] != entry_id]
    if len(filtered) == len(entries):
        return False
    _save(filtered)
    return True


def clear_all() -> None:
    _save([])
