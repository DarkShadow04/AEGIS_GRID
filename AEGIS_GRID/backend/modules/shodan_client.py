"""
Shodan Integration
API-key-only, same pattern as every other external-data module in AEGIS
GRID: the key comes from the local secrets store (Settings panel), calls
that actually spend a credit are checked against the quota tracker first,
and every result is handed back to main.py to flow into history/Reports
the same way every other scan module's output already does.

Endpoints used (base https://api.shodan.io), verified against Shodan's own
REST API docs before building this — not guessed:
  - GET  /shodan/host/{ip}   passive lookup of what Shodan's crawlers have
                              already recorded about that host. NOT an
                              active scan of the target — safe to expose
                              broadly. Free (no credit cost).
  - GET  /shodan/host/search  full-text/filter search across Shodan's
                              index. Costs query credits.
  - GET  /api-info            account plan + credits remaining. Free.
  - POST /shodan/scan         asks Shodan to actively (re)crawl the given
                              IP(s) right now. Costs scan credits. Only
                              request this for hosts you're authorized to
                              test — the same rule this tool already
                              applies to nmap.
  - GET  /dns/resolve         hostname -> IP. Free.

Configured account: Membership tier — 100 query credits/month, 100 scan
credits/month, 16 monitored IPs, all search filters except `vuln` and
`tag`. The quota tracker approximates credit spend as 1 call = 1 credit
for search/scan (the same "requests as a proxy" approach already used for
AnyAPI's token quota) — a faceted or multi-page search can cost Shodan
more than one real credit, so this is a conservative floor, not an exact
mirror of Shodan's own ledger. account_info() returns the real number.
"""
import requests

from core import secrets_store, quota_tracker

BASE = "https://api.shodan.io"


def _key() -> str | None:
    return secrets_store.get_key("shodan_api_key")


def _no_key_error() -> dict:
    return {"error": "Shodan API key not configured. Add it in Settings."}


def _summarize_host(data: dict) -> dict:
    ports = sorted(set(data.get("ports", [])))
    vulns = data.get("vulns") or []
    if isinstance(vulns, dict):
        vulns = list(vulns.keys())

    findings = []
    for cve in vulns:
        findings.append({"severity": "critical", "header": cve, "message": f"Shodan lists {cve} against this host."})
    tags = [t.lower() for t in (data.get("tags") or [])]
    if "honeypot" in tags:
        findings.append({"severity": "medium", "message": "Shodan tags this host as a likely honeypot."})

    return {
        "ip": data.get("ip_str"),
        "org": data.get("org"),
        "isp": data.get("isp"),
        "country": data.get("country_name"),
        "city": data.get("city"),
        "os": data.get("os"),
        "hostnames": data.get("hostnames", []),
        "domains": data.get("domains", []),
        "ports": ports,
        "last_update": data.get("last_update"),
        "vulns": vulns,
        "tags": data.get("tags", []),
        "services": [
            {
                "port": item.get("port"),
                "transport": item.get("transport"),
                "product": item.get("product"),
                "version": item.get("version"),
                "banner": (item.get("data") or "")[:300],
            }
            for item in data.get("data", [])
        ],
        "findings": findings,
    }


def host_lookup(ip: str, history: bool = False) -> dict:
    """Passive read of Shodan's existing database for this host — doesn't
    touch the target, not gated against a credit limit."""
    api_key = _key()
    if not api_key:
        return _no_key_error()
    try:
        resp = requests.get(
            f"{BASE}/shodan/host/{ip}",
            params={"key": api_key, "history": str(history).lower(), "minify": "false"},
            timeout=15,
        )
        if resp.status_code == 404:
            return {"ip": ip, "error": "No information available for this host in Shodan's database."}
        if resp.status_code == 401:
            return {"error": "Shodan key rejected (401 Unauthorized)."}
        resp.raise_for_status()
        return _summarize_host(resp.json())
    except requests.RequestException as e:
        return {"error": str(e)}


def search(query: str, facets: str | None = None, page: int = 1) -> dict:
    """Uses query credits — gated against the monthly quota."""
    api_key = _key()
    if not api_key:
        return _no_key_error()

    gate = quota_tracker.check("shodan", "search")
    if not gate["allowed"]:
        return {"error": f"Shodan query-credit quota reached ({gate['blocked_by']}). Skipped to protect your limit."}

    params = {"key": api_key, "query": query, "page": page}
    if facets:
        params["facets"] = facets
    try:
        resp = requests.get(f"{BASE}/shodan/host/search", params=params, timeout=20)
        quota_tracker.record("shodan", "search")
        if resp.status_code == 401:
            return {"error": "Shodan key rejected (401 Unauthorized)."}
        resp.raise_for_status()
        data = resp.json()
        return {
            "query": query,
            "total": data.get("total", 0),
            "page": page,
            "facets": data.get("facets", {}),
            "results": [
                {
                    "ip": m.get("ip_str"),
                    "port": m.get("port"),
                    "org": m.get("org"),
                    "product": m.get("product"),
                    "hostnames": m.get("hostnames", []),
                    "country": (m.get("location") or {}).get("country_name"),
                    "banner": (m.get("data") or "")[:200],
                }
                for m in data.get("matches", [])
            ],
        }
    except requests.RequestException as e:
        return {"error": str(e)}


def account_info() -> dict:
    """GET /api-info — free, doesn't cost a credit."""
    api_key = _key()
    if not api_key:
        return _no_key_error()
    try:
        resp = requests.get(f"{BASE}/api-info", params={"key": api_key}, timeout=10)
        if resp.status_code == 401:
            return {"error": "Shodan key rejected (401 Unauthorized)."}
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        return {"error": str(e)}


def request_scan(ips: str) -> dict:
    """Active on-demand scan request — Shodan itself crawls the given
    IP(s) right now. Costs scan credits. Only request this for hosts you
    are authorized to test — same rule as every other active-scan feature
    in this tool, nmap included."""
    api_key = _key()
    if not api_key:
        return _no_key_error()

    gate = quota_tracker.check("shodan", "scan")
    if not gate["allowed"]:
        return {"error": f"Shodan scan-credit quota reached ({gate['blocked_by']}). Skipped to protect your limit."}

    try:
        resp = requests.post(f"{BASE}/shodan/scan", params={"key": api_key}, data={"ips": ips}, timeout=15)
        quota_tracker.record("shodan", "scan")
        if resp.status_code == 401:
            return {"error": "Shodan key rejected (401 Unauthorized)."}
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        return {"error": str(e)}


def dns_resolve(hostnames: str) -> dict:
    """GET /dns/resolve — free, comma-separated hostname(s) -> IP."""
    api_key = _key()
    if not api_key:
        return _no_key_error()
    try:
        resp = requests.get(f"{BASE}/dns/resolve", params={"hostnames": hostnames, "key": api_key}, timeout=10)
        if resp.status_code == 401:
            return {"error": "Shodan key rejected (401 Unauthorized)."}
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        return {"error": str(e)}
