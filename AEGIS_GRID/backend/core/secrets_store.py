"""
Local Secrets Store
Lets the user enter API keys once through the dashboard; they're persisted
to a local, gitignored file so they don't have to be re-entered every run.

Security rules this module enforces:
  - Keys are NEVER hardcoded in source (that's the exact bug found in the
    old AbuseLPDB / Dark_Console repos — this exists to prevent a repeat).
  - The file this writes to (config/secrets.json) is gitignored by default
    — see .gitignore in the project root.
  - Keys are never logged, never included in exceptions, and never
    returned in full by the API — only a masked preview and a
    configured/not-configured boolean.
  - File permissions are locked to owner-read/write only (chmod 600) on
    POSIX systems.
"""
import json
import os
import stat
from pathlib import Path

CONFIG_DIR = Path("config")
SECRETS_FILE = CONFIG_DIR / "secrets.json"

KNOWN_KEYS = [
    "anthropic_api_key",
    "abuseipdb_api_key",
    "virustotal_api_key",
    "gemini_api_key",
    "openai_api_key",
    "groq_api_key",
    "openrouter_api_key",
    "ollama_base_url",
    "anyapi_api_key",
    "shodan_api_key",
    "smtp_host",
    "smtp_port",
    "smtp_user",
    "smtp_password",
    "smtp_from",
]


def _load() -> dict:
    if not SECRETS_FILE.exists():
        return {}
    try:
        return json.loads(SECRETS_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _save(data: dict) -> None:
    CONFIG_DIR.mkdir(exist_ok=True)
    SECRETS_FILE.write_text(json.dumps(data, indent=2))
    try:
        os.chmod(SECRETS_FILE, stat.S_IRUSR | stat.S_IWUSR)  # 600: owner rw only
    except OSError:
        pass  # best-effort on platforms that don't support chmod (e.g. Windows)


def set_key(name: str, value: str) -> None:
    if name not in KNOWN_KEYS:
        raise ValueError(f"Unknown key name: {name}")
    data = _load()
    if value:
        data[name] = value
    else:
        data.pop(name, None)
    _save(data)


def get_key(name: str) -> str | None:
    """Returns the real key value for internal use only (e.g. calling the
    upstream API). Never send this value back out over the API."""
    if name not in KNOWN_KEYS:
        return None
    # Local store takes priority, falls back to an env var of the same name
    # (uppercased) for anyone who still prefers that route.
    stored = _load().get(name)
    if stored:
        return stored
    return os.environ.get(name.upper())


def mask(value: str) -> str:
    """Fixed-length preview regardless of key length — a long key (some are
    150+ chars) previously produced a single unbroken run of asterisks that
    doesn't wrap, stretching the whole settings card and breaking the grid
    layout. Capped here; CSS also has a word-break fallback as defense in depth."""
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * 8 + value[-4:]


def status() -> dict:
    """Safe-to-expose summary: which keys are configured, masked previews only."""
    data = _load()
    result = {}
    for name in KNOWN_KEYS:
        value = data.get(name) or os.environ.get(name.upper())
        result[name] = {
            "configured": bool(value),
            "preview": mask(value) if value else None,
            "source": "stored" if data.get(name) else ("env" if value else None),
        }
    return result
