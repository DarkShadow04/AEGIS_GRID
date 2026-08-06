"""
System Doctor / Health Check
Reports dependency status and which providers actually have a usable key
configured. BUG FIX: this used to check os.environ directly, which never
reflected keys saved through the Settings tab (those live in
secrets_store/config/secrets.json, not the process environment) — so the
dashboard showed keys as "not set" even after you configured and tested
them successfully. Now checks secrets_store.get_key() the same way every
scan module actually does, so this reflects reality.
"""
import importlib.util
import shutil

from core import secrets_store
from modules import ollama_client


def check_command(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def check_module(module: str) -> bool:
    return importlib.util.find_spec(module) is not None


def run_health_check() -> dict:
    checks = {
        "nmap_installed": check_command("nmap"),
        "cloudflared_installed": check_command("cloudflared"),
        "requests_installed": check_module("requests"),
        "psutil_installed": check_module("psutil"),
        "anthropic_key_set": bool(secrets_store.get_key("anthropic_api_key")),
        "abuseipdb_key_set": bool(secrets_store.get_key("abuseipdb_api_key")),
        "virustotal_key_set": bool(secrets_store.get_key("virustotal_api_key")),
        "gemini_key_set": bool(secrets_store.get_key("gemini_api_key")),
        "openai_key_set": bool(secrets_store.get_key("openai_api_key")),
        "groq_key_set": bool(secrets_store.get_key("groq_api_key")),
        "openrouter_key_set": bool(secrets_store.get_key("openrouter_api_key")),
        "anyapi_key_set": bool(secrets_store.get_key("anyapi_api_key")),
        "ollama_reachable": ollama_client.is_available(),
    }

    required = ["requests_installed", "psutil_installed"]
    core_ok = all(checks[k] for k in required)
    ai_configured = any(
        checks[k] for k in ["anthropic_key_set", "gemini_key_set", "openai_key_set", "groq_key_set", "openrouter_key_set", "anyapi_key_set", "ollama_reachable"]
    )

    score = sum(1 for v in checks.values() if v)
    total = len(checks)

    return {
        "checks": checks,
        "core_ok": core_ok,
        "ai_configured": ai_configured,
        "score": f"{score}/{total}",
        "status": "healthy" if core_ok else "issues detected",
    }
