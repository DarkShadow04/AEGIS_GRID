"""
IP / File / URL Reputation Module
Ported from: AbuseLPDB (AbuseIPDB) and Dark_Console (VirusTotal)
API keys come from the local secrets store (Settings panel). Every call
checks the quota tracker first and is skipped (not just logged) if it
would exceed your free-tier limits — protects your quota from ever being
silently burned past what you have.
"""
import requests

from core import secrets_store, quota_tracker

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VT_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
VT_URL_URL = "https://www.virustotal.com/api/v3/urls"


def check_ip_abuseipdb(ip: str, max_age_days: int = 90) -> dict:
    api_key = secrets_store.get_key("abuseipdb_api_key")
    if not api_key:
        return {"error": "AbuseIPDB API key not configured. Add it in Settings."}

    gate = quota_tracker.check("abuseipdb", "check")
    if not gate["allowed"]:
        return {"error": f"AbuseIPDB daily quota reached ({gate['blocked_by']}). Skipped to protect your limit."}

    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": max_age_days}
    try:
        resp = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=10)
        quota_tracker.record("abuseipdb", "check")
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {
            "ip": ip,
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "is_tor": data.get("isTor"),
        }
    except requests.RequestException as e:
        return {"error": str(e)}


def check_ip_virustotal(ip: str) -> dict:
    api_key = secrets_store.get_key("virustotal_api_key")
    if not api_key:
        return {"error": "VirusTotal API key not configured. Add it in Settings."}

    gate = quota_tracker.check("virustotal", "lookup")
    if not gate["allowed"]:
        return {"error": f"VirusTotal quota reached ({gate['blocked_by']}). Skipped to protect your limit."}

    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(VT_IP_URL.format(ip=ip), headers=headers, timeout=10)
        quota_tracker.record("virustotal", "lookup")
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "ip": ip,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "reputation": attrs.get("reputation"),
        }
    except requests.RequestException as e:
        return {"error": str(e)}
