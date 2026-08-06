"""
Minimal User-Agent Parser
Not a full UA-parsing library — a small, dependency-free heuristic that
covers the browsers/OSes/device types that actually show up in practice
(Chrome, Firefox, Safari, Edge, Opera / Windows, macOS, Linux, Android,
iOS / Desktop, Mobile, Tablet). Good enough to make the access log
readable at a glance; not good enough to fingerprint exact versions —
that's not the goal here.
"""


def parse(ua: str) -> dict:
    if not ua:
        return {"browser": "Unknown", "os": "Unknown", "device": "Unknown"}
    u = ua.lower()

    if "edg/" in u:
        browser = "Edge"
    elif "opr/" in u or "opera" in u:
        browser = "Opera"
    elif "chrome/" in u and "chromium" not in u:
        browser = "Chrome"
    elif "firefox/" in u:
        browser = "Firefox"
    elif "safari/" in u and "chrome/" not in u:
        browser = "Safari"
    elif "chromium" in u:
        browser = "Chromium"
    elif "curl/" in u or "wget/" in u or "python-requests" in u:
        browser = "Script/CLI client"
    else:
        browser = "Other"

    if "windows" in u:
        os_name = "Windows"
    elif "android" in u:
        os_name = "Android"
    elif "iphone" in u or "ipad" in u or "ios" in u:
        os_name = "iOS"
    elif "mac os" in u or "macintosh" in u:
        os_name = "macOS"
    elif "linux" in u:
        os_name = "Linux"
    else:
        os_name = "Other"

    if "ipad" in u or "tablet" in u:
        device = "Tablet"
    elif "mobile" in u or "iphone" in u or ("android" in u and "mobile" in u):
        device = "Mobile"
    else:
        device = "Desktop"

    return {"browser": browser, "os": os_name, "device": device}
