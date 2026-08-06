"""
Lightweight IP Geolocation
Best-effort location lookup for the access log — free, no API key, via
ipapi.co (HTTPS on the free tier, ~1,000 lookups/day, no key needed).
This exists to give you a rough sense of where tunnel traffic is coming
from, not a precise or authoritative source: IP geolocation is city/
region-level at best, and VPNs, mobile carriers, and corporate NAT
routinely misplace it by a wide margin.

Results are cached in memory per-IP for the life of the process, so a
returning visitor doesn't burn a lookup on every single request. The
cache is not persisted — it resets on restart, which just means the
first request after a restart re-looks-up each IP once.
"""
import ipaddress

import requests

_CACHE: dict[str, str] = {}


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return True  # unparseable — don't send it out to a third party, just label it


def lookup(ip: str) -> str:
    if not ip:
        return "Unknown"
    if _is_private(ip):
        return "Local network"
    if ip in _CACHE:
        return _CACHE[ip]

    result = "Unknown"
    try:
        resp = requests.get(f"https://ipapi.co/{ip}/json/", timeout=4)
        if resp.ok:
            data = resp.json()
            if not data.get("error"):
                parts = [p for p in [data.get("city"), data.get("region"), data.get("country_name")] if p]
                if parts:
                    result = ", ".join(parts)
    except requests.RequestException:
        pass

    _CACHE[ip] = result
    return result
