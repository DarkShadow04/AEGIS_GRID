"""
Runtime Config
User-adjustable operational settings — request timeouts for every AI
provider and scan tool, plus access-log behavior — that used to be
hardcoded constants scattered across modules (the 120s Ollama timeout
that was cutting off legitimate local generations was one of these).
Exposed in the dashboard's "Access & Limits" tab so they can be tuned
from the UI instead of editing source, and take effect immediately —
every value is read live from disk on each call, nothing is cached at
import time or requires a restart.

Persisted to config/runtime_config.json — same gitignored directory as
secrets.json, though nothing stored here is sensitive.
"""
import json
import threading
from pathlib import Path

CONFIG_DIR = Path("config")
CONFIG_FILE = CONFIG_DIR / "runtime_config.json"
_LOCK = threading.Lock()

# key -> metadata. "default" is what applies until the user overrides it.
# Numeric settings are bounded (min/max) so a typo can't set a 2-second or
# a 5-hour timeout by accident; bool settings use "type": "bool".
SETTINGS = {
    "timeout_anthropic": {"default": 120, "min": 10, "max": 1800, "unit": "s", "group": "AI providers", "label": "Anthropic (Claude)"},
    "timeout_openai": {"default": 30, "min": 5, "max": 600, "unit": "s", "group": "AI providers", "label": "OpenAI"},
    "timeout_gemini": {"default": 30, "min": 5, "max": 600, "unit": "s", "group": "AI providers", "label": "Gemini"},
    "timeout_groq": {"default": 30, "min": 5, "max": 600, "unit": "s", "group": "AI providers", "label": "Groq"},
    "timeout_openrouter": {"default": 30, "min": 5, "max": 600, "unit": "s", "group": "AI providers", "label": "OpenRouter"},
    "timeout_anyapi": {"default": 30, "min": 5, "max": 600, "unit": "s", "group": "AI providers", "label": "AnyAPI"},
    "timeout_ollama": {
        "default": 600, "min": 30, "max": 3600, "unit": "s", "group": "AI providers", "label": "Ollama (Local)",
        "note": "Local CPU-only inference is the slowest path — raise this first if you're seeing local timeouts.",
    },
    "timeout_nmap": {
        "default": 1800, "min": 60, "max": 7200, "unit": "s", "group": "Scan tools", "label": "Nmap (preset/custom, synchronous)",
        "note": "Doesn't apply to async Nmap jobs (Security Sessions → Live Terminal), which have no fixed timeout by design.",
    },
    "timeout_headers": {"default": 10, "min": 3, "max": 120, "unit": "s", "group": "Scan tools", "label": "Header scan"},
    "timeout_ssl": {"default": 10, "min": 3, "max": 120, "unit": "s", "group": "Scan tools", "label": "SSL/TLS certificate check"},
    "timeout_nel": {"default": 10, "min": 3, "max": 120, "unit": "s", "group": "Scan tools", "label": "NEL header check"},
    "access_log_enabled": {
        "default": True, "type": "bool", "group": "Server", "label": "Log visitor sessions",
        "note": "Records IP, approximate location, device/browser, and actions for anyone hitting this server — including everyone using a shared tunnel link.",
    },
    "access_log_max_entries": {"default": 1000, "min": 50, "max": 20000, "unit": "entries", "group": "Server", "label": "Access log retention"},
}


def _load() -> dict:
    if not CONFIG_FILE.exists():
        return {}
    try:
        return json.loads(CONFIG_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _save(data: dict) -> None:
    CONFIG_DIR.mkdir(exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(data, indent=2))


def get(key: str):
    """Read a single setting's current value (override if set, else default)."""
    if key not in SETTINGS:
        raise KeyError(f"Unknown runtime config key: {key}")
    return _load().get(key, SETTINGS[key]["default"])


def get_all() -> dict:
    """Full metadata + current value for every setting, grouped for the UI."""
    stored = _load()
    return {key: {**meta, "value": stored.get(key, meta["default"])} for key, meta in SETTINGS.items()}


def set_value(key: str, value) -> dict:
    if key not in SETTINGS:
        return {"error": f"Unknown setting: {key}"}
    meta = SETTINGS[key]
    if meta.get("type") == "bool":
        value = bool(value)
    else:
        try:
            value = int(value)
        except (TypeError, ValueError):
            return {"error": "Value must be a whole number."}
        lo, hi = meta.get("min"), meta.get("max")
        if lo is not None and value < lo:
            return {"error": f"Minimum is {lo}{meta.get('unit', '')}."}
        if hi is not None and value > hi:
            return {"error": f"Maximum is {hi}{meta.get('unit', '')}."}
    with _LOCK:
        stored = _load()
        stored[key] = value
        _save(stored)
    return {"key": key, "value": value}


def reset_value(key: str) -> dict:
    if key not in SETTINGS:
        return {"error": f"Unknown setting: {key}"}
    with _LOCK:
        stored = _load()
        stored.pop(key, None)
        _save(stored)
    return {"key": key, "value": SETTINGS[key]["default"]}
