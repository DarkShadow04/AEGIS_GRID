"""
DNS Recon
New module — pulls A/AAAA/MX/TXT/NS/CNAME records for a domain. Passive,
read-only, standard recon step (same category as InfoGate was aiming for,
done natively instead of shelling out to third-party installer scripts).
"""
import dns.resolver
import dns.exception

RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]


def lookup(domain: str, timeout: int = 5) -> dict:
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    result = {"domain": domain, "records": {}, "findings": []}

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            result["records"][rtype] = [str(r).strip('"') for r in answers]
        except dns.resolver.NoAnswer:
            result["records"][rtype] = []
        except dns.resolver.NXDOMAIN:
            return {"domain": domain, "error": "Domain does not exist (NXDOMAIN)."}
        except dns.exception.DNSException as e:
            result["records"][rtype] = []
            result.setdefault("warnings", []).append(f"{rtype} lookup failed: {str(e)[:150]}")

    # Light heuristics worth surfacing, not just raw records
    txt_records = " ".join(result["records"].get("TXT", []))
    if "v=spf1" not in txt_records:
        result["findings"].append({"severity": "medium", "message": "No SPF record found — domain may be more susceptible to email spoofing."})
    if not any("v=DMARC1" in r for r in result["records"].get("TXT", [])):
        result["findings"].append({"severity": "low", "message": "No DMARC record found at the apex TXT set (DMARC actually lives at _dmarc.<domain> — check separately)."})

    return result
