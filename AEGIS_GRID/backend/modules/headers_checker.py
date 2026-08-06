"""
Security Headers Checker
Checks a target URL's response headers against a broad set of security,
CORS, caching, and reporting headers, with severity + remediation guidance.

Headers are split into two groups:
  - Actionable security headers: missing = a real finding (severity + fix).
  - Informational headers: reported either way, but NOT treated as
    "missing = bad" — several of these are deprecated (X-XSS-Protection,
    Feature-Policy, Expect-CT, the legacy X-Content-Security-Policy) or
    conditional on the site being an API/using CORS/Flash, where absence
    is completely normal. Blindly telling every site to "add" a dead or
    situational header would be inaccurate, not just noisy — Public-Key-Pins
    is the sharpest example: it's actively dangerous to add today (it was
    removed from browsers and can cause real lockouts), so it's flagged as
    a finding only if it's PRESENT, not if it's absent.
"""
import requests

REQUIRED_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "high", "informational": False,
        "fix": "Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' to enforce HTTPS.",
    },
    "Content-Security-Policy": {
        "severity": "high", "informational": False,
        "fix": "Define a Content-Security-Policy to restrict allowed script/style/frame sources and mitigate XSS.",
    },
    "X-Content-Type-Options": {
        "severity": "medium", "informational": False,
        "fix": "Add 'X-Content-Type-Options: nosniff' to prevent MIME-sniffing attacks.",
    },
    "X-Frame-Options": {
        "severity": "medium", "informational": False,
        "fix": "Add 'X-Frame-Options: DENY' or use CSP frame-ancestors to prevent clickjacking.",
    },
    "Cross-Origin-Opener-Policy": {
        "severity": "medium", "informational": False,
        "fix": "Add 'Cross-Origin-Opener-Policy: same-origin' to isolate your page from cross-origin popups/windows (mitigates some side-channel and tab-napping attacks).",
    },
    "Cross-Origin-Embedder-Policy": {
        "severity": "medium", "informational": False,
        "fix": "Add 'Cross-Origin-Embedder-Policy: require-corp' if you need cross-origin isolation (e.g. for SharedArrayBuffer); pairs with Cross-Origin-Opener-Policy.",
    },
    "Referrer-Policy": {
        "severity": "low", "informational": False,
        "fix": "Add 'Referrer-Policy: strict-origin-when-cross-origin' to limit referrer leakage.",
    },
    "Permissions-Policy": {
        "severity": "low", "informational": False,
        "fix": "Add a Permissions-Policy header to restrict access to browser features (camera, mic, geolocation).",
    },
    # --- Informational: deprecated headers (absence is fine, presence noted) ---
    "X-XSS-Protection": {
        "severity": "low", "informational": True,
        "fix": "Deprecated — modern browsers removed or ignore this filter; Content-Security-Policy is the current replacement. Not recommended to add.",
    },
    "Feature-Policy": {
        "severity": "low", "informational": True,
        "fix": "Deprecated — superseded by Permissions-Policy. No action needed if Permissions-Policy is present.",
    },
    "Expect-CT": {
        "severity": "low", "informational": True,
        "fix": "Deprecated — Chrome removed support in 2022; Certificate Transparency is now enforced independently. Not recommended to add.",
    },
    "X-Content-Security-Policy": {
        "severity": "low", "informational": True,
        "fix": "Legacy pre-standard alias for Content-Security-Policy. Use the standard CSP header instead.",
    },
    "Public-Key-Pins": {
        "severity": "medium", "informational": True, "finding_if_present": True,
        "fix": "HPKP is deprecated and removed from all major browsers, and misconfiguration historically caused permanent site lockouts. Remove this header if present — it does nothing protective today and only carries legacy risk.",
    },
    # --- Informational: conditional/situational (absence is normal) ---
    "Content-Security-Policy-Report-Only": {
        "severity": "low", "informational": True,
        "fix": "Testing companion to CSP for monitoring policy violations before enforcing — only relevant if you're actively tuning a CSP rollout.",
    },
    "Access-Control-Allow-Origin": {
        "severity": "low", "informational": True,
        "fix": "Only relevant for APIs/cross-origin resources. If present, make sure it isn't '*' combined with credentials — that combination is a real CORS misconfiguration.",
    },
    "Access-Control-Allow-Methods": {"severity": "low", "informational": True, "fix": "CORS header — only relevant for cross-origin APIs."},
    "Access-Control-Allow-Headers": {"severity": "low", "informational": True, "fix": "CORS header — only relevant for cross-origin APIs."},
    "Access-Control-Allow-Credentials": {"severity": "low", "informational": True, "fix": "CORS header — only relevant if cookies/auth need to be sent cross-origin."},
    "Access-Control-Expose-Headers": {"severity": "low", "informational": True, "fix": "CORS header — only relevant if the client needs access to non-default response headers."},
    "Access-Control-Max-Age": {"severity": "low", "informational": True, "fix": "CORS header — controls preflight cache duration, a performance optimization, not a security requirement."},
    "X-Permitted-Cross-Domain-Policies": {
        "severity": "low", "informational": True,
        "fix": "Only relevant if serving Flash/PDF content cross-domain (rare on modern sites). Set to 'none' if you do serve such content and don't need cross-domain access.",
    },
    "Clear-Site-Data": {
        "severity": "low", "informational": True,
        "fix": "Situational — typically set on logout endpoints to clear cookies/storage/cache, not expected sitewide.",
    },
    "Content-Disposition": {
        "severity": "low", "informational": True,
        "fix": "Per-response, not sitewide — controls whether a browser downloads vs. displays a specific response (e.g. file downloads).",
    },
    "X-DNS-Prefetch-Control": {
        "severity": "low", "informational": True,
        "fix": "Minor privacy header controlling background DNS prefetching. Set to 'off' if you want to avoid leaking prefetch DNS queries.",
    },
    "Content-Language": {
        "severity": "low", "informational": True,
        "fix": "Accessibility/SEO header, not a security control.",
    },
    "Cache-Control": {
        "severity": "low", "informational": True,
        "fix": "Highly context-dependent — static assets should cache, pages with sensitive/personal data should set 'no-store'. Check case by case rather than treating absence as a blanket finding.",
    },
    "Expires": {
        "severity": "low", "informational": True,
        "fix": "Legacy caching header, largely superseded by Cache-Control's max-age directive.",
    },
    "Pragma": {
        "severity": "low", "informational": True,
        "fix": "HTTP/1.0-era caching directive, generally unnecessary in modern deployments.",
    },
    "Report-To": {
        "severity": "low", "informational": True,
        "fix": "Reporting-endpoint header for CSP violations, deprecation warnings, and NEL — see the dedicated NEL check for network-error reporting specifically.",
    },
}


def get_check_info() -> list:
    """What this scan checks and why — used by the dashboard's info dialog."""
    return [
        {
            "header": header,
            "severity": meta["severity"],
            "informational": meta["informational"],
            "why_it_matters": meta["fix"],
        }
        for header, meta in REQUIRED_HEADERS.items()
    ]


def check_headers(url: str, timeout: int = 10) -> dict:
    """Fetch a URL and evaluate its response headers against REQUIRED_HEADERS."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = {"url": url, "reachable": False, "findings": [], "present": [], "info_headers": []}
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
        result["reachable"] = True
        result["status_code"] = resp.status_code
        # resp.headers is a case-insensitive dict (headers can legally come
        # back in any case, e.g. all-lowercase over HTTP/2) — keep it as-is
        # instead of flattening into a plain dict, or lookups below silently
        # fail and everything reports as "missing".
        result["raw_headers"] = dict(resp.headers)

        for header, meta in REQUIRED_HEADERS.items():
            present = header in resp.headers

            if meta.get("finding_if_present") and present:
                result["findings"].append({
                    "header": header, "status": "present (should be removed)",
                    "severity": meta["severity"], "recommendation": meta["fix"],
                })
                continue

            if not meta["informational"] and not present:
                result["findings"].append({
                    "header": header, "status": "missing",
                    "severity": meta["severity"], "recommendation": meta["fix"],
                })
            elif present:
                bucket = "present" if not meta["informational"] else "info_headers"
                result[bucket].append({"header": header, "value": resp.headers[header]})
    except requests.RequestException as e:
        result["error"] = str(e)

    return result
