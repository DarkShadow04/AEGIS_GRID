"""
NEL (Network Error Logging) Checker
Ported from: nel_check
Checks whether a site implements the browser NEL/Reporting API — the
NEL and Report-To (or the newer Reporting-Endpoints) response headers
that let a browser report connection failures back to the site owner.
Not having these isn't a vulnerability, but sites that care about
reliability/observability usually set them.
"""
import json

import requests


def check_nel(url: str, timeout: int = 10) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = {"url": url, "reachable": False, "findings": []}
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
        result["reachable"] = True
        result["status_code"] = resp.status_code

        nel_header = resp.headers.get("NEL")
        report_to_header = resp.headers.get("Report-To")
        reporting_endpoints = resp.headers.get("Reporting-Endpoints")

        result["nel_present"] = nel_header is not None
        result["report_to_present"] = report_to_header is not None
        result["reporting_endpoints_present"] = reporting_endpoints is not None

        if nel_header:
            try:
                result["nel_policy"] = json.loads(nel_header)
            except json.JSONDecodeError:
                result["nel_policy"] = nel_header

        if report_to_header:
            try:
                result["report_to_policy"] = json.loads(report_to_header)
            except json.JSONDecodeError:
                result["report_to_policy"] = report_to_header

        if reporting_endpoints:
            result["reporting_endpoints"] = reporting_endpoints

        if not nel_header and not reporting_endpoints:
            result["findings"].append({
                "severity": "low",
                "message": "No NEL/Reporting-Endpoints header found. The site won't receive browser-side reports of failed connection attempts (useful for catching CDN/DNS issues real users hit that server logs never see).",
            })
        elif nel_header and not report_to_header and not reporting_endpoints:
            result["findings"].append({
                "severity": "low",
                "message": "NEL header present but no Report-To/Reporting-Endpoints destination configured — reports have nowhere to go.",
            })

        return result
    except requests.RequestException as e:
        return {"url": url, "reachable": False, "error": str(e)[:300]}
