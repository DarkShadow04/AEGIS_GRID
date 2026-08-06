"""
Server / Tunnel Manager
Ported from the original CLI tool's core/server.py. Manages a local HTTP server for a
workspace directory plus an optional cloudflared tunnel for public exposure.

Tunnel URL extraction: cloudflared's startup output contains multiple lines
that can mention "trycloudflare.com" — including generic banner/docs text —
not just the actual assigned subdomain. Naively grabbing the first line that
contains that substring can grab the wrong one. This reads output on a
background thread and matches a strict regex for a real https URL instead.
"""
import json
import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path

from core import system_info

STATE_DIR = Path("state")
STATE_FILE = STATE_DIR / "server.json"

TUNNEL_URL_RE = re.compile(r"https://[a-zA-Z0-9\-]+\.trycloudflare\.com")


def _load() -> dict:
    STATE_DIR.mkdir(exist_ok=True)
    if not STATE_FILE.exists():
        return {}
    try:
        return json.loads(STATE_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _save(data: dict) -> None:
    STATE_DIR.mkdir(exist_ok=True)
    STATE_FILE.write_text(json.dumps(data, indent=2))


def _is_running(pid) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except (OSError, TypeError):
        return False


def status() -> dict:
    data = _load()
    pid = data.get("pid")
    running = _is_running(pid)
    port = data.get("port") if running else None
    local_ip = system_info.get_local_ip()

    return {
        "running": running,
        "pid": pid if running else None,
        "port": port,
        "workspace": data.get("workspace") if running else None,
        "local_url": f"http://{local_ip}:{port}" if running and local_ip else (f"http://localhost:{port}" if running else None),
        "started_at": data.get("started_at") if running else None,
        "tunnel_pid": data.get("tunnel_pid") if _is_running(data.get("tunnel_pid")) else None,
        "public_url": data.get("public_url") if _is_running(data.get("tunnel_pid")) else None,
    }


def start_server(workspace: str, port: int = 8080) -> dict:
    workspace_path = Path(workspace).expanduser().resolve()
    if not workspace_path.is_dir():
        return {"error": f"Workspace path does not exist: {workspace_path}"}

    current = status()
    if current["running"]:
        return {"error": f"Server already running on port {current['port']} (pid {current['pid']})"}

    proc = subprocess.Popen(
        ["python3", "-m", "http.server", str(port)],
        cwd=str(workspace_path),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.5)

    if proc.poll() is not None:
        return {"error": f"Server process exited immediately (port {port} may already be in use)."}

    data = _load()
    data.update({"pid": proc.pid, "port": port, "workspace": str(workspace_path), "started_at": time.time()})
    _save(data)
    return status()


def stop_server() -> dict:
    data = _load()
    pid = data.get("pid")
    if pid and _is_running(pid):
        os.kill(pid, 15)
    data["pid"] = None
    _save(data)
    return status()


def start_tunnel() -> dict:
    if not shutil.which("cloudflared"):
        return {"error": "cloudflared is not installed. Install it to expose a public URL."}

    data = _load()
    port = data.get("port")
    if not port or not _is_running(data.get("pid")):
        return {"error": "Local server is not running. Start it before creating a tunnel."}

    proc = subprocess.Popen(
        ["cloudflared", "tunnel", "--url", f"http://localhost:{port}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    output_buffer = []
    found_url = {"value": None}

    def reader():
        for line in proc.stdout:
            output_buffer.append(line)
            match = TUNNEL_URL_RE.search(line)
            if match and found_url["value"] is None:
                found_url["value"] = match.group(0)

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    thread.join(timeout=20)

    public_url = found_url["value"]
    data["tunnel_pid"] = proc.pid
    data["public_url"] = public_url
    _save(data)

    if not public_url:
        return {
            "error": "Tunnel started but no valid trycloudflare.com URL was detected within 20s.",
            "raw_output_tail": "".join(output_buffer[-10:]),
        }
    return status()


def stop_tunnel() -> dict:
    data = _load()
    pid = data.get("tunnel_pid")
    if pid and _is_running(pid):
        os.kill(pid, 15)
    data["tunnel_pid"] = None
    data["public_url"] = None
    _save(data)
    return status()


# ---------------------------------------------------------------------------
# Self-tunnel — exposes THIS backend (dashboard + API, same origin) for
# remote access, as opposed to start_tunnel() above which exposes a
# separate static workspace directory. This is the one that actually makes
# "use AEGIS GRID from another device" work, since the dashboard is served
# by this same process (see main.py's static mount).
# ---------------------------------------------------------------------------
def self_tunnel_status() -> dict:
    data = _load()
    running = _is_running(data.get("self_tunnel_pid"))
    return {
        "running": running,
        "pid": data.get("self_tunnel_pid") if running else None,
        "public_url": data.get("self_tunnel_public_url") if running else None,
        "port": data.get("self_tunnel_port") if running else None,
    }


def start_self_tunnel(port: int) -> dict:
    if not shutil.which("cloudflared"):
        return {"error": "cloudflared is not installed. Install it from https://github.com/cloudflare/cloudflared/releases to enable remote access."}

    current = self_tunnel_status()
    if current["running"]:
        return {"error": f"Self-tunnel already running at {current['public_url']}"}

    proc = subprocess.Popen(
        ["cloudflared", "tunnel", "--url", f"http://localhost:{port}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    output_buffer = []
    found_url = {"value": None}

    def reader():
        for line in proc.stdout:
            output_buffer.append(line)
            match = TUNNEL_URL_RE.search(line)
            if match and found_url["value"] is None:
                found_url["value"] = match.group(0)

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    thread.join(timeout=20)

    public_url = found_url["value"]
    data = _load()
    data["self_tunnel_pid"] = proc.pid
    data["self_tunnel_public_url"] = public_url
    data["self_tunnel_port"] = port
    _save(data)

    if not public_url:
        return {
            "error": "Tunnel started but no valid trycloudflare.com URL was detected within 20s.",
            "raw_output_tail": "".join(output_buffer[-10:]),
        }
    return self_tunnel_status()


def stop_self_tunnel() -> dict:
    data = _load()
    pid = data.get("self_tunnel_pid")
    if pid and _is_running(pid):
        os.kill(pid, 15)
    data["self_tunnel_pid"] = None
    data["self_tunnel_public_url"] = None
    _save(data)
    return self_tunnel_status()
