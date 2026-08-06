"""
AEGIS GRID — Unified Security Command Center
Quota-aware multi-provider AI (Anthropic/OpenAI/Gemini/Groq/OpenRouter/
AnyAPI/Ollama), background nmap jobs with live progress, and an embedded
chatbot for analysis, report drafting, and troubleshooting.

Run: uvicorn main:app --reload --port 8000
"""
import asyncio
import json
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from core import (
    system_info,
    server_manager,
    health,
    secrets_store,
    key_tester,
    quota_tracker,
    applog,
    chatbot,
    history,
    job_manager,
    mailer,
    custom_commands,
    runtime_config,
    access_log,
)
from modules import headers_checker, nmap_scanner, ip_reputation, ai_analyzer, ssl_checker, dns_recon, nel_checker, shodan_client

app = FastAPI(title="AEGIS GRID — Command Center")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten before exposing beyond localhost
    allow_methods=["*"],
    allow_headers=["*"],
)


async def _log_access(session_id: str, ip: str, user_agent: str, method: str, path: str) -> None:
    try:
        await asyncio.to_thread(access_log.record, session_id, ip, user_agent, method, path)
    except Exception:
        pass  # visitor logging must never be able to break an actual request


@app.middleware("http")
async def access_log_middleware(request: Request, call_next):
    """Session/visitor tracking for when this is tunneled and shared — see
    core/access_log.py. Session id is a cookie set on first contact; IP is
    read from X-Forwarded-For/X-Real-IP first (what most tunnel providers
    set), falling back to the raw socket peer. Logging itself runs as a
    fire-and-forget background task so it never adds latency to the
    actual response, and respects the access_log_enabled toggle in
    Access & Limits (checked inside access_log.record itself)."""
    is_new_session = "agrid_sid" not in request.cookies
    session_id = request.cookies.get("agrid_sid") or access_log.new_session_id()
    # Decide whether to log BEFORE running the handler, not after: if this
    # very request is the one flipping access_log_enabled to False, we still
    # want that toggle-off itself on the record — checking post-handler
    # would make the disable action silently swallow its own log entry,
    # which is confusing to audit later ("did I actually turn this off, or
    # did it just stop logging with no trace of why").
    should_log = runtime_config.get("access_log_enabled")

    response = await call_next(request)

    if is_new_session:
        response.set_cookie("agrid_sid", session_id, max_age=60 * 60 * 24 * 30, samesite="lax")

    if should_log:
        ip = (
            request.headers.get("x-forwarded-for", "").split(",")[0].strip()
            or request.headers.get("x-real-ip", "")
            or (request.client.host if request.client else "")
        )
        asyncio.create_task(_log_access(session_id, ip, request.headers.get("user-agent", ""), request.method, request.url.path))
    return response


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------
class HeaderCheckRequest(BaseModel):
    url: str


class NmapRequest(BaseModel):
    target: str
    profile: str = "default"


class NmapCustomRequest(BaseModel):
    target: str
    args: str


class SaveCustomCommandRequest(BaseModel):
    label: str
    cmd: str


class SslCheckRequest(BaseModel):
    hostname: str
    port: int = 443


class DnsLookupRequest(BaseModel):
    domain: str


class NelCheckRequest(BaseModel):
    url: str


class MailReportRequest(BaseModel):
    to_email: str
    subject: str
    body_text: str
    pdf_base64: str | None = None
    filename: str | None = None


class IPCheckRequest(BaseModel):
    ip: str


class ShodanSearchRequest(BaseModel):
    query: str
    facets: str | None = None
    page: int = 1


class ShodanScanRequest(BaseModel):
    ips: str


class ShodanDnsRequest(BaseModel):
    hostnames: str


class FullAssessmentRequest(BaseModel):
    url: str
    ip: str | None = None
    nmap_profile: str = "default"
    ai_provider: str = "anthropic"


class HostRequest(BaseModel):
    workspace: str
    port: int = 8080


class SelfTunnelRequest(BaseModel):
    port: int = 8000


class SettingsRequest(BaseModel):
    anthropic_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    virustotal_api_key: str | None = None
    gemini_api_key: str | None = None
    openai_api_key: str | None = None
    groq_api_key: str | None = None
    openrouter_api_key: str | None = None
    ollama_base_url: str | None = None
    anyapi_api_key: str | None = None
    shodan_api_key: str | None = None
    smtp_host: str | None = None
    smtp_port: str | None = None
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from: str | None = None


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    message: str
    history: list[ChatMessage] = []
    provider: str = "anthropic"
    mode: str = "descriptive"


# ---------------------------------------------------------------------------
# Control Matrix — system telemetry + health
# ---------------------------------------------------------------------------
@app.get("/api/telemetry")
def telemetry():
    return system_info.get_telemetry()


@app.get("/api/health")
def health_check():
    return health.run_health_check()


@app.websocket("/ws/telemetry")
async def ws_telemetry(ws: WebSocket):
    """Live-streams telemetry every 2s for the dashboard's real-time graphs."""
    await ws.accept()
    try:
        while True:
            await ws.send_text(json.dumps(system_info.get_telemetry()))
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        pass


# ---------------------------------------------------------------------------
# Server / Tunnel — hosting a workspace + public exposure
# ---------------------------------------------------------------------------
@app.get("/api/server/status")
def server_status():
    return server_manager.status()


@app.post("/api/server/start")
def server_start(req: HostRequest):
    result = server_manager.start_server(req.workspace, req.port)
    applog.log_event("server", f"start_server({req.workspace}, {req.port}) -> {result}")
    return result


@app.post("/api/server/stop")
def server_stop():
    return server_manager.stop_server()


@app.post("/api/tunnel/start")
def tunnel_start():
    result = server_manager.start_tunnel()
    applog.log_event("server", f"start_tunnel -> {result}")
    return result


@app.post("/api/tunnel/stop")
def tunnel_stop():
    return server_manager.stop_tunnel()


@app.get("/api/tunnel/self/status")
def self_tunnel_status():
    return server_manager.self_tunnel_status()


@app.post("/api/tunnel/self/start")
def self_tunnel_start(req: SelfTunnelRequest):
    result = server_manager.start_self_tunnel(req.port)
    applog.log_event("server", f"start_self_tunnel(port={req.port}) -> {result}")
    return result


@app.post("/api/tunnel/self/stop")
def self_tunnel_stop():
    return server_manager.stop_self_tunnel()


# ---------------------------------------------------------------------------
# Settings — local API key management. Keys are saved to config/secrets.json
# on disk only (gitignored), never returned in full, never logged.
# ---------------------------------------------------------------------------
@app.get("/api/settings/keys")
def get_key_status():
    return secrets_store.status()


@app.post("/api/settings/keys")
def save_keys(req: SettingsRequest):
    saved = []
    for name, value in req.model_dump().items():
        if value is not None:
            secrets_store.set_key(name, value)
            saved.append(name)
    applog.log_event("settings", f"Keys updated: {saved}")  # names only, never values
    return {"saved": saved, "status": secrets_store.status()}


@app.delete("/api/settings/keys/{key_name}")
def delete_key(key_name: str):
    if key_name not in secrets_store.KNOWN_KEYS:
        return {"error": f"Unknown key: {key_name}"}
    secrets_store.set_key(key_name, "")
    applog.log_event("settings", f"Key removed: {key_name}")
    return {"deleted": key_name, "status": secrets_store.status()}


@app.post("/api/settings/keys/test")
def test_keys():
    """Makes one real, minimal call per configured key to confirm it works.
    Never echoes the key value back."""
    return key_tester.test_all()


# ---------------------------------------------------------------------------
# Quota — live usage vs. your free-tier limits across every provider
# ---------------------------------------------------------------------------
@app.get("/api/quota")
def quota_summary():
    return quota_tracker.full_summary()


# ---------------------------------------------------------------------------
# Security Sessions — scan modules
# ---------------------------------------------------------------------------
@app.post("/api/scan/headers")
def scan_headers(req: HeaderCheckRequest):
    result = headers_checker.check_headers(req.url, timeout=runtime_config.get("timeout_headers"))
    applog.log_event("scan", f"headers({req.url}) -> {len(result.get('findings', []))} findings")
    history.save_entry("headers", req.url, result)
    return result


@app.get("/api/scan/headers/info")
def headers_info():
    return headers_checker.get_check_info()


@app.post("/api/scan/nmap")
def scan_nmap(req: NmapRequest):
    result = nmap_scanner.scan_target(req.target, profile=req.profile, timeout=runtime_config.get("timeout_nmap"))
    applog.log_event("scan", f"nmap({req.target}, {req.profile})")
    history.save_entry("nmap", req.target, result, command=f"nmap ({req.profile} profile)")
    return result


@app.post("/api/scan/nmap/validate")
def validate_nmap_command(req: NmapCustomRequest):
    """Check a custom command without running it — used for live validation as the user types."""
    return nmap_scanner.validate_custom_args(req.args)


@app.post("/api/scan/nmap/custom")
def scan_nmap_custom(req: NmapCustomRequest):
    result = nmap_scanner.scan_target_custom(req.target, req.args, timeout=runtime_config.get("timeout_nmap"))
    applog.log_event("scan", f"nmap_custom({req.target}, '{req.args}')")
    history.save_entry("nmap", req.target, result, command=f"nmap {req.args}")
    return result


@app.post("/api/scan/nmap/job")
def start_nmap_job(req: NmapCustomRequest):
    """No fixed timeout — runs until nmap finishes or you cancel it. Poll
    /api/scan/nmap/job/{id} for live progress."""
    validation = nmap_scanner.validate_custom_args(req.args)
    if not validation["ok"]:
        return {"error": validation["error"]}
    if not nmap_scanner._nmap_available():
        return {"error": "nmap is not installed on this host."}
    job_id = job_manager.start_nmap_job(req.target, validation["tokens"], f"nmap {req.args}", nmap_scanner.parse_nmap_xml)
    applog.log_event("scan", f"nmap_job started({req.target}, '{req.args}') -> {job_id}")
    return {"job_id": job_id}


@app.get("/api/scan/nmap/job/{job_id}")
def get_nmap_job(job_id: str):
    job = job_manager.get_job(job_id)
    if job is None:
        return {"error": "Job not found."}
    if job["status"] in ("done", "failed") and not job.get("history_saved"):
        history.save_entry("nmap", job["target"], job.get("result") or {"error": job.get("error")}, command=job["command"])
        job_manager.mark_history_saved(job_id)
    return job


@app.delete("/api/scan/nmap/job/{job_id}")
def cancel_nmap_job(job_id: str):
    cancelled = job_manager.cancel_job(job_id)
    return {"cancelled": cancelled}


@app.get("/api/settings/nmap-commands")
def list_custom_nmap_commands():
    return custom_commands.list_commands()


@app.post("/api/settings/nmap-commands")
def save_custom_nmap_command(req: SaveCustomCommandRequest):
    validation = nmap_scanner.validate_custom_args(req.cmd)
    if not validation["ok"]:
        return {"error": f"Can't save — {validation['error']}"}
    return custom_commands.add_command(req.label, req.cmd)


@app.delete("/api/settings/nmap-commands/{entry_id}")
def delete_custom_nmap_command(entry_id: str):
    return {"deleted": custom_commands.delete_command(entry_id)}


# ---------------------------------------------------------------------------
# Access & Limits — adjustable timeouts/restrictions, and the visitor log
# ---------------------------------------------------------------------------
class RuntimeConfigSetRequest(BaseModel):
    key: str
    value: bool | int


@app.get("/api/settings/runtime-config")
def get_runtime_config():
    return runtime_config.get_all()


@app.post("/api/settings/runtime-config")
def set_runtime_config(req: RuntimeConfigSetRequest):
    result = runtime_config.set_value(req.key, req.value)
    if "error" in result:
        applog.log_event("settings", f"runtime_config set failed: {req.key} -> {req.value}: {result['error']}", level="error")
    else:
        applog.log_event("settings", f"runtime_config {req.key} -> {result['value']}")
        if req.key == "access_log_enabled":
            # Always land this one explicitly, regardless of the general
            # before/after gating the middleware uses for everything else —
            # this is the one event you most need proof of either way: when
            # monitoring itself was turned on or off.
            state = "ON" if result["value"] else "OFF"
            access_log.record("system", "-", "AEGIS GRID Settings", "POST", "/api/settings/runtime-config", action_override=f"Access logging turned {state}")
    return result


@app.delete("/api/settings/runtime-config/{key}")
def reset_runtime_config(key: str):
    result = runtime_config.reset_value(key)
    applog.log_event("settings", f"runtime_config {key} reset to default")
    return result


@app.get("/api/access-log")
def get_access_log(limit: int = 200):
    return {"events": access_log.recent(limit), "summary": access_log.summary()}


@app.delete("/api/access-log")
def clear_access_log():
    access_log.clear()
    applog.log_event("server", "Access log cleared.")
    return {"cleared": True}


@app.post("/api/scan/ssl")
def scan_ssl(req: SslCheckRequest):
    result = ssl_checker.check_certificate(req.hostname, req.port, timeout=runtime_config.get("timeout_ssl"))
    applog.log_event("scan", f"ssl({req.hostname}:{req.port})")
    history.save_entry("ssl", f"{req.hostname}:{req.port}", result)
    return result


@app.post("/api/scan/dns")
def scan_dns(req: DnsLookupRequest):
    result = dns_recon.lookup(req.domain)
    applog.log_event("scan", f"dns({req.domain})")
    history.save_entry("dns", req.domain, result)
    return result


@app.post("/api/scan/nel")
def scan_nel(req: NelCheckRequest):
    result = nel_checker.check_nel(req.url, timeout=runtime_config.get("timeout_nel"))
    applog.log_event("scan", f"nel({req.url})")
    history.save_entry("nel", req.url, result)
    return result


@app.post("/api/scan/ip-reputation")
def scan_ip(req: IPCheckRequest):
    result = {
        "abuseipdb": ip_reputation.check_ip_abuseipdb(req.ip),
        "virustotal": ip_reputation.check_ip_virustotal(req.ip),
    }
    applog.log_event("scan", f"ip_reputation({req.ip})")
    history.save_entry("ip_reputation", req.ip, result)
    return result


@app.get("/api/shodan/host/{ip}")
def shodan_host(ip: str, with_history: bool = False):
    """Passive lookup of Shodan's own database for this host — not an
    active scan, safe to expose broadly. Free (no credit cost)."""
    result = shodan_client.host_lookup(ip, history=with_history)
    applog.log_event("scan", f"shodan_host({ip})")
    history.save_entry("shodan_host", ip, result)
    return result


@app.post("/api/shodan/search")
def shodan_search(req: ShodanSearchRequest):
    """Uses query credits."""
    result = shodan_client.search(req.query, facets=req.facets, page=req.page)
    applog.log_event("scan", f"shodan_search('{req.query}')")
    history.save_entry("shodan_search", req.query, result)
    return result


@app.get("/api/shodan/account")
def shodan_account():
    """Free — credits remaining, plan, monitored IPs."""
    return shodan_client.account_info()


@app.post("/api/shodan/scan")
def shodan_scan(req: ShodanScanRequest):
    """Active on-demand scan request — Shodan itself crawls the given
    IP(s) right now. Uses scan credits. Only request this for hosts you
    are authorized to test — same rule as nmap."""
    result = shodan_client.request_scan(req.ips)
    applog.log_event("scan", f"shodan_scan_request({req.ips})")
    history.save_entry("shodan_scan", req.ips, result)
    return result


@app.post("/api/shodan/dns/resolve")
def shodan_dns_resolve(req: ShodanDnsRequest):
    """Free — hostname(s) -> IP, via Shodan's own DNS database."""
    result = shodan_client.dns_resolve(req.hostnames)
    applog.log_event("scan", f"shodan_dns_resolve({req.hostnames})")
    history.save_entry("shodan_dns", req.hostnames, result)
    return result


@app.post("/api/assess/full")
def full_assessment(req: FullAssessmentRequest):
    findings = {
        "headers": headers_checker.check_headers(req.url, timeout=runtime_config.get("timeout_headers")),
        "nmap": nmap_scanner.scan_target(req.url, profile=req.nmap_profile, timeout=runtime_config.get("timeout_nmap")),
    }
    if req.ip:
        findings["ip_reputation"] = {
            "abuseipdb": ip_reputation.check_ip_abuseipdb(req.ip),
            "virustotal": ip_reputation.check_ip_virustotal(req.ip),
        }
    ai_result = ai_analyzer.analyze_findings(findings, provider=req.ai_provider)
    applog.log_event("scan", f"full_assessment({req.url}) via {req.ai_provider}")
    combined = {"findings": findings, "ai_analysis": ai_result}
    history.save_entry("full_assessment", req.url, combined, command=f"full assessment via {req.ai_provider}")
    return combined


# ---------------------------------------------------------------------------
# History — every scan result, persisted for the Reports tab
# ---------------------------------------------------------------------------
@app.get("/api/history")
def list_history():
    return history.list_entries()


@app.get("/api/history/{entry_id}")
def get_history_entry(entry_id: str):
    entry = history.get_entry(entry_id)
    if entry is None:
        return {"error": "Not found"}
    return entry


@app.delete("/api/history/{entry_id}")
def delete_history_entry(entry_id: str):
    deleted = history.delete_entry(entry_id)
    return {"deleted": deleted}


@app.delete("/api/history")
def clear_history():
    history.clear_all()
    return {"cleared": True}


# ---------------------------------------------------------------------------
# Assistant — embedded chatbot for analysis, reports, troubleshooting
# ---------------------------------------------------------------------------
@app.post("/api/chat")
def chat(req: ChatRequest):
    chat_history = [{"role": h.role, "content": h.content} for h in req.history]
    return chatbot.chat(req.message, chat_history, provider=req.provider, mode=req.mode)


@app.get("/api/logs")
def get_logs(n: int = 50):
    return applog.recent(n)


# ---------------------------------------------------------------------------
# Email — send a report to a user-entered address via configured SMTP
# ---------------------------------------------------------------------------
@app.post("/api/reports/email")
def email_report(req: MailReportRequest):
    import base64

    attachment_bytes = base64.b64decode(req.pdf_base64) if req.pdf_base64 else None
    result = mailer.send_report_email(req.to_email, req.subject, req.body_text, attachment_bytes, req.filename)
    applog.log_event("mail", f"report email to {req.to_email}: {'sent' if result.get('sent') else result.get('error')}")
    return result


@app.get("/api/status")
def root():
    return {"status": "online", "service": "AEGIS GRID Command Center"}


# ---------------------------------------------------------------------------
# Serve the dashboard itself from this same backend process. This is what
# makes remote/tunnel usage actually work: if you only tunnel the frontend's
# separate static file server, the dashboard loads but every API call still
# points at "localhost:8000" on the REMOTE VIEWER's machine, not yours — so
# nothing works. Tunnel THIS server instead (the one running main:app) and
# the dashboard + API share the same origin automatically.
# ---------------------------------------------------------------------------
_frontend_dir = Path(__file__).resolve().parent.parent / "frontend"
if _frontend_dir.is_dir():
    app.mount("/", StaticFiles(directory=str(_frontend_dir), html=True), name="dashboard")
