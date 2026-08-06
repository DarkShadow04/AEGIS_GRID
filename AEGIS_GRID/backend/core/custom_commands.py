"""
Custom Nmap Commands
Lets the user save their own frequently-used flag combinations into the
Command Library, alongside the built-in Basic/Aggressive/Vuln presets.
Saved commands are still validated through the same allowlist as any other
custom command when actually run — saving one here doesn't bypass that.
"""
import json
import uuid
from pathlib import Path

STATE_DIR = Path("state")
FILE = STATE_DIR / "custom_nmap_commands.json"


def _load() -> list:
    if not FILE.exists():
        return []
    try:
        return json.loads(FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return []


def _save(entries: list) -> None:
    STATE_DIR.mkdir(exist_ok=True)
    FILE.write_text(json.dumps(entries, indent=2))


def list_commands() -> list:
    return _load()


def add_command(label: str, cmd: str) -> dict:
    entries = _load()
    entry = {"id": uuid.uuid4().hex[:10], "label": label, "cmd": cmd}
    entries.append(entry)
    _save(entries)
    return entry


def delete_command(entry_id: str) -> bool:
    entries = _load()
    filtered = [e for e in entries if e["id"] != entry_id]
    if len(filtered) == len(entries):
        return False
    _save(filtered)
    return True
