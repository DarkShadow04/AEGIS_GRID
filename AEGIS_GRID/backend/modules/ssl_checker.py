"""
SSL/TLS Certificate Checker
New module (not ported from an existing repo) — checks a host's TLS cert
for expiry, issuer, subject, and negotiated protocol/cipher. Common gap in
DIY security toolkits; genuinely useful for catching certs about to expire
or hosts still negotiating old TLS versions. Stdlib only (ssl + socket).
"""
import socket
import ssl
from datetime import datetime, timezone


def check_certificate(hostname: str, port: int = 443, timeout: int = 10) -> dict:
    hostname = hostname.replace("https://", "").replace("http://", "").split("/")[0]

    context = ssl.create_default_context()
    result = {"hostname": hostname, "port": port}

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                result["protocol"] = ssock.version()
                result["cipher"] = ssock.cipher()[0] if ssock.cipher() else None

                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_remaining = (not_after - datetime.now(timezone.utc)).days

                result["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                result["subject"] = dict(x[0] for x in cert.get("subject", []))
                result["not_before"] = not_before.isoformat()
                result["not_after"] = not_after.isoformat()
                result["days_remaining"] = days_remaining
                result["expired"] = days_remaining < 0

                findings = []
                if days_remaining < 0:
                    findings.append({"severity": "critical", "message": "Certificate has expired."})
                elif days_remaining < 14:
                    findings.append({"severity": "high", "message": f"Certificate expires in {days_remaining} days."})
                elif days_remaining < 30:
                    findings.append({"severity": "medium", "message": f"Certificate expires in {days_remaining} days."})

                if result["protocol"] in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    findings.append({"severity": "high", "message": f"Outdated protocol negotiated: {result['protocol']}. Upgrade to TLS 1.2+."})

                result["findings"] = findings
                return result
    except ssl.SSLCertVerificationError as e:
        return {"hostname": hostname, "port": port, "error": f"Certificate verification failed: {str(e)[:200]}"}
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        return {"hostname": hostname, "port": port, "error": f"Connection failed: {str(e)[:200]}"}
