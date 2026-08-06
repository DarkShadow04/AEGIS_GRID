"""
Quota Tracker
Generic sliding-window rate/quota tracker used in front of every external
API call in AEGIS GRID. Every module checks quota_tracker.check() BEFORE
making a call (so we never burn quota on a call we already know will fail
or isn't worth spending), then calls quota_tracker.record() AFTER a real
response comes back.

Limits below are hardcoded to the free/standard tiers reported by the user
on 2026-07-11. These will drift if the providers change their tiers or the
account is upgraded — update LIMITS accordingly.
"""
import json
import time
from pathlib import Path

STATE_DIR = Path("state")
QUOTA_FILE = STATE_DIR / "quota_log.json"

_WINDOW_SECONDS = {
    "minute": 60,
    "hour": 3600,
    "day": 86400,
    "month": 30 * 86400,
}

# service -> endpoint -> {period: limit}
LIMITS = {
    "abuseipdb": {
        "blacklist": {"day": 5},
        "bulk-report": {"day": 5},
        "bulk-check": {"day": 5},
        "check": {"day": 1000},
        "check-block": {"day": 100},
        "clear-address": {"day": 5},
        "report": {"day": 1000},
        "reports": {"day": 100},
    },
    "virustotal": {
        "lookup": {"minute": 4, "day": 500, "month": 15500},
    },
    "gemini": {
        # Free tier, "Antigravity Agents" category as reported.
        "generate": {"minute": 60, "day": 100},
    },
    "openai": {
        "gpt-5.5": {"minute": 3, "day": 50},
        "gpt-5.5-pro": {"minute": 3, "day": 50},
        "gpt-image": {"minute": 10, "day": 50},
    },
    "groq": {
        "llama-3.3-70b-versatile": {"minute": 30, "day": 1000},
        "llama-3.1-8b-instant": {"minute": 30, "day": 14400},
    },
    "openrouter": {
        # Conservative (<10 lifetime credits purchased) tier. Bump "day" to
        # 1000 here if you've purchased 10+ credits on your account.
        "free_model": {"minute": 20, "day": 50},
    },
    "anyapi": {
        # Free tier is 100,000 tokens/day; requests tracked as a proxy since
        # per-call token counts vary by prompt/response size.
        "chat": {"day": 200},
    },
    "shodan": {
        # Membership tier, as reported: 100 query credits/month, 100 scan
        # credits/month. Tracked as 1 call = 1 credit (a conservative floor
        # — faceted/paginated searches can cost more per Shodan's own
        # accounting; GET /api-info via account_info() has the real number).
        "search": {"month": 100},
        "scan": {"month": 100},
    },
}


def _load() -> dict:
    if not QUOTA_FILE.exists():
        return {}
    try:
        return json.loads(QUOTA_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _save(data: dict) -> None:
    STATE_DIR.mkdir(exist_ok=True)
    QUOTA_FILE.write_text(json.dumps(data, indent=2))


def _key(service: str, endpoint: str) -> str:
    return f"{service}:{endpoint}"


def _prune(timestamps: list, now: float) -> list:
    max_window = max(_WINDOW_SECONDS.values())
    return [t for t in timestamps if now - t <= max_window]


def usage_for(service: str, endpoint: str) -> dict:
    """Returns current usage vs limit for every period defined for this endpoint."""
    limits = LIMITS.get(service, {}).get(endpoint)
    if not limits:
        return {"error": f"No limit config for {service}/{endpoint}"}

    data = _load()
    timestamps = data.get(_key(service, endpoint), [])
    now = time.time()

    result = {}
    for period, limit in limits.items():
        window = _WINDOW_SECONDS[period]
        used = sum(1 for t in timestamps if now - t <= window)
        result[period] = {
            "used": used,
            "limit": limit,
            "remaining": max(0, limit - used),
            "pct": round(100 * used / limit, 1) if limit else 0,
        }
    return result


def check(service: str, endpoint: str) -> dict:
    """Call before making the real API request. Returns {allowed, blocked_by, usage}."""
    usage = usage_for(service, endpoint)
    if "error" in usage:
        # No configured limit for this endpoint — allow by default, nothing to enforce.
        return {"allowed": True, "blocked_by": None, "usage": {}}

    for period, stats in usage.items():
        if stats["remaining"] <= 0:
            return {"allowed": False, "blocked_by": period, "usage": usage}
    return {"allowed": True, "blocked_by": None, "usage": usage}


def record(service: str, endpoint: str) -> None:
    """Call after a real API response comes back (success or failure — it still cost quota)."""
    data = _load()
    key = _key(service, endpoint)
    now = time.time()
    timestamps = _prune(data.get(key, []), now)
    timestamps.append(now)
    data[key] = timestamps
    _save(data)


def full_summary() -> dict:
    """All services/endpoints, for the dashboard's Quota tab."""
    summary = {}
    for service, endpoints in LIMITS.items():
        summary[service] = {ep: usage_for(service, ep) for ep in endpoints}
    return summary
