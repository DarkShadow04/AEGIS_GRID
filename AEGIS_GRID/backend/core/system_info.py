"""
System Telemetry
Ported from the original CLI tool's core/dashboard.py (get_local_ip, neofetch_value, etc.)
Original used shell calls to `neofetch` + subprocess for stats. This rebuild
uses psutil/platform directly so it works everywhere without depending on
neofetch being installed, and returns structured data for the web dashboard
instead of printing rich-console text.
"""
import platform
import socket
import time
from datetime import datetime

import psutil

_BOOT_TIME = psutil.boot_time()
_last_net_io = psutil.net_io_counters()
_last_net_time = time.time()


def get_local_ip() -> str | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


def uptime_str() -> str:
    seconds = int(time.time() - _BOOT_TIME)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


def get_network_throughput() -> dict:
    """Bytes/sec since the last call — first call after startup returns 0s."""
    global _last_net_io, _last_net_time
    now_io = psutil.net_io_counters()
    now_time = time.time()
    elapsed = max(now_time - _last_net_time, 0.001)

    sent_bps = max(0, (now_io.bytes_sent - _last_net_io.bytes_sent) / elapsed)
    recv_bps = max(0, (now_io.bytes_recv - _last_net_io.bytes_recv) / elapsed)

    _last_net_io = now_io
    _last_net_time = now_time

    return {
        "upload_kbps": round(sent_bps / 1024, 2),
        "download_kbps": round(recv_bps / 1024, 2),
        "total_sent_mb": round(now_io.bytes_sent / (1024**2), 1),
        "total_recv_mb": round(now_io.bytes_recv / (1024**2), 1),
    }


def get_telemetry() -> dict:
    """Returns the same category of info the CLI 'Control Matrix' showed
    (OS, host, kernel, uptime, CPU, memory) as structured JSON."""
    vm = psutil.virtual_memory()
    net_online = get_local_ip() is not None

    return {
        "timestamp": datetime.now().isoformat(),
        "os": platform.system(),
        "host": socket.gethostname(),
        "kernel": platform.release(),
        "python_version": platform.python_version(),
        "uptime": uptime_str(),
        "cpu_percent": psutil.cpu_percent(interval=0.3),
        "cpu_cores": psutil.cpu_count(logical=True),
        "memory_percent": vm.percent,
        "memory_used_gb": round(vm.used / (1024**3), 2),
        "memory_total_gb": round(vm.total / (1024**3), 2),
        "disk_percent": psutil.disk_usage("/").percent,
        "local_ip": get_local_ip(),
        "network_online": net_online,
        "network": get_network_throughput(),
    }
