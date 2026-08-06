"""
Access / Session Log
Tracks who hits this server and what they do — for when you tunnel AEGIS
GRID and share the link (Settings → Backend Connection & Remote Access,
or the Server & Tunnel workspace tunnel). Every request gets attributed
to a session (a cookie set on first contact, main.py's access_log_middleware
handles that part), with IP, best-effort location, device/browser, and a
human-readable action label.

The toggle and retention are controlled from Access & Limits → Server, via
core/runtime_config.py. The enabled/disabled decision itself is made in
main.py's middleware *before* the request is handled, not in here — see
that middleware's comment for why (so toggling logging off is still
captured as the last entry before it stops, instead of silently vanishing).

Caveat, stated plainly rather than implied: the IP recorded is whatever
the request arrives with once it reaches this process. Most tunnel
providers (ngrok, Cloudflare Tunnel, etc.) forward the real visitor IP via
X-Forwarded-For or X-Real-IP, and this reads those first — but if you're
behind a tunnel type that doesn't set either header, every visitor will
show as the tunnel's own forwarding address instead of their real IP.
There's no way to detect that mismatch from inside this process alone;
verify it once against a device you know the real IP of before relying on
this for anything more than a rough sense of activity.
"""
import json
import threading
import time
import uuid
from pathlib import Path

from core import runtime_config, geoip, ua_parser

STATE_DIR = Path("state")
LOG_FILE = STATE_DIR / "access_log.json"

# record() runs via asyncio.to_thread from the request middleware, so
# concurrent requests (two friends hitting the tunnel at once) can call it
# on different threads at the same time. Without a lock, two threads doing
# read-modify-write on the same JSON file race and silently drop whichever
# write loses — confirmed this actually happens under concurrent load
# during testing, not just a theoretical risk. One lock around the whole
# read+append+write per call is cheap enough at this traffic scale.
_LOCK = threading.Lock()

# Longest/most specific prefixes first so e.g. /api/scan/nmap/job doesn't
# get swallowed by a hypothetical shorter /api/scan prefix.
ACTION_LABELS = [
    ("/api/scan/nmap/job", "Started/polled an async Nmap job"),
    ("/api/scan/nmap/custom", "Ran a custom Nmap command"),
    ("/api/scan/nmap/validate", "Validated a custom Nmap command"),
    ("/api/scan/nmap", "Ran an Nmap scan"),
    ("/api/scan/headers", "Ran a header scan"),
    ("/api/scan/nel", "Ran a NEL check"),
    ("/api/scan/ssl", "Ran an SSL/TLS check"),
    ("/api/scan/dns", "Ran a DNS recon lookup"),
    ("/api/scan/ip-reputation", "Ran an IP reputation check"),
    ("/api/assess/full", "Ran a full assessment"),
    ("/api/chat", "Sent a chatbot message"),
    ("/api/reports/email", "Emailed a report"),
    ("/api/shodan/host", "Ran a Shodan host lookup"),
    ("/api/shodan/search", "Ran a Shodan search"),
    ("/api/shodan/scan", "Requested a Shodan scan"),
    ("/api/shodan/dns", "Ran a Shodan DNS resolve"),
    ("/api/shodan/account", "Checked Shodan credits"),
    ("/api/settings/keys", "Touched an API key in Settings"),
    ("/api/settings/runtime-config", "Changed a Limits & Timeouts setting"),
    ("/api/settings/nmap-commands", "Touched the custom Nmap command library"),
    ("/api/tunnel", "Touched tunnel/remote-access controls"),
    ("/api/server", "Touched workspace server controls"),
    ("/api/reports", "Viewed Reports"),
    ("/api/history", "Viewed scan history"),
    ("/api/quota", "Viewed quota state"),
    ("/api/telemetry", "Polled system telemetry"),
    ("/api/health", "Checked tool health"),
    ("/", "Loaded the dashboard"),
]


def _label_for(path: str) -> str:
    if path == "/":
        return "Loaded the dashboard"
    for prefix, label in ACTION_LABELS:
        if prefix == "/":
            continue
        if path == prefix or path.startswith(prefix.rstrip("/") + "/"):
            return label
    return path


def _load() -> list:
    if not LOG_FILE.exists():
        return []
    try:
        return json.loads(LOG_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return []


def _save(entries: list) -> None:
    STATE_DIR.mkdir(exist_ok=True)
    max_entries = runtime_config.get("access_log_max_entries")
    LOG_FILE.write_text(json.dumps(entries[-max_entries:], indent=2))


def new_session_id() -> str:
    return uuid.uuid4().hex[:16]


def record(session_id: str, ip: str, user_agent: str, method: str, path: str, action_override: str | None = None) -> None:
    if path.startswith("/api/access-log"):
        return  # don't let the admin's own polling of this log fill up this log

    ua = ua_parser.parse(user_agent)
    entry = {
        "timestamp": time.time(),
        "session_id": session_id,
        "ip": ip or "unknown",
        "location": geoip.lookup(ip),
        "browser": ua["browser"],
        "os": ua["os"],
        "device": ua["device"],
        "method": method,
        "path": path,
        "action": action_override or _label_for(path),
    }
    with _LOCK:
        entries = _load()
        entries.append(entry)
        _save(entries)


def recent(limit: int = 200) -> list:
    entries = _load()
    return list(reversed(entries[-limit:]))


def summary() -> dict:
    entries = _load()
    sessions: dict[str, dict] = {}
    for e in entries:
        s = sessions.setdefault(
            e["session_id"],
            {
                "ip": e["ip"],
                "location": e["location"],
                "browser": e["browser"],
                "os": e["os"],
                "device": e["device"],
                "first_seen": e["timestamp"],
                "last_seen": e["timestamp"],
                "actions": 0,
            },
        )
        s["last_seen"] = max(s["last_seen"], e["timestamp"])
        s["first_seen"] = min(s["first_seen"], e["timestamp"])
        s["actions"] += 1
    return {"total_events": len(entries), "unique_sessions": len(sessions), "sessions": sessions}


def clear() -> None:
    with _LOCK:
        _save([])
