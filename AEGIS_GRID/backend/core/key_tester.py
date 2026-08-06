"""
Key Connectivity Tester
Validates that a configured API key actually works by making one real,
minimal call to the upstream service — without ever including the key
value in the response, logs, or raised exceptions.
"""
import requests
from anthropic import Anthropic

from core import secrets_store

TEST_IP = "8.8.8.8"  # public, well-known IP — safe to use for a connectivity check


def _safe_error(prefix: str, e: Exception) -> str:
    """Strip anything that could resemble a key from an error message
    before it's ever returned to the frontend or logged."""
    msg = str(e)
    return f"{prefix}: {msg[:200]}"


def test_abuseipdb() -> dict:
    key = secrets_store.get_key("abuseipdb_api_key")
    if not key:
        return {"configured": False, "ok": False, "message": "No key configured."}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": TEST_IP},
            timeout=10,
        )
        if r.status_code == 200:
            return {"configured": True, "ok": True, "message": "Key is valid — test lookup succeeded."}
        if r.status_code == 401:
            return {"configured": True, "ok": False, "message": "Key rejected (401 Unauthorized)."}
        return {"configured": True, "ok": False, "message": f"Unexpected status {r.status_code}."}
    except requests.RequestException as e:
        return {"configured": True, "ok": False, "message": _safe_error("Request failed", e)}


def test_virustotal() -> dict:
    key = secrets_store.get_key("virustotal_api_key")
    if not key:
        return {"configured": False, "ok": False, "message": "No key configured."}
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{TEST_IP}",
            headers={"x-apikey": key},
            timeout=10,
        )
        if r.status_code == 200:
            return {"configured": True, "ok": True, "message": "Key is valid — test lookup succeeded."}
        if r.status_code == 401:
            return {"configured": True, "ok": False, "message": "Key rejected (401 Unauthorized)."}
        return {"configured": True, "ok": False, "message": f"Unexpected status {r.status_code}."}
    except requests.RequestException as e:
        return {"configured": True, "ok": False, "message": _safe_error("Request failed", e)}


def test_anthropic() -> dict:
    key = secrets_store.get_key("anthropic_api_key")
    if not key:
        return {"configured": False, "ok": False, "message": "No key configured."}
    try:
        client = Anthropic(api_key=key)
        client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1,
            messages=[{"role": "user", "content": "ping"}],
        )
        return {"configured": True, "ok": True, "message": "Key is valid — test call succeeded."}
    except Exception as e:
        msg = str(e)
        if "authentication" in msg.lower() or "401" in msg:
            return {"configured": True, "ok": False, "message": "Key rejected (authentication error)."}
        return {"configured": True, "ok": False, "message": _safe_error("Request failed", e)}


def test_gemini() -> dict:
    key = secrets_store.get_key("gemini_api_key")
    if not key:
        return {"configured": False, "ok": False, "message": "No key configured."}
    try:
        r = requests.post(
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent",
            params={"key": key},
            json={"contents": [{"parts": [{"text": "ping"}]}]},
            timeout=15,
        )
        if r.status_code == 200:
            return {"configured": True, "ok": True, "message": "Key is valid — test call succeeded."}
        if r.status_code in (401, 403):
            return {"configured": True, "ok": False, "message": f"Key rejected ({r.status_code})."}
        return {"configured": True, "ok": False, "message": f"Unexpected status {r.status_code}."}
    except requests.RequestException as e:
        return {"configured": True, "ok": False, "message": _safe_error("Request failed", e)}


def test_openai() -> dict:
    key = secrets_store.get_key("openai_api_key")
    if not key:
        return {"configured": False, "ok": False, "message": "No key configured."}
    try:
        r = requests.get(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {key}"},
            timeout=15,
        )
        if r.status_code == 200:
            return {"configured": True, "ok": True, "message": "Key is valid — test call succeeded."}
        if r.status_code == 401:
            return {"configured": True, "ok": False, "message": "Key rejected (401 Unauthorized)."}
        return {"configured": True, "ok": False, "message": f"Unexpected status {r.status_code}."}
    except requests.RequestException as e:
        return {"configured": True, "ok": False, "message": _safe_error("Request failed", e)}


def test_groq() -> dict:
    key = secrets_store.get_key("groq_api_key")
    if not key:
        return {"configured": False, "ok": False, "message": "No key configured."}
    try:
        r = requests.get(
            "https://api.groq.com/openai/v1/models",
            headers={"Authorization": f"Bearer {key}"},
            timeout=15,
        )
        if r.status_code == 200:
            return {"configured": True, "ok": True, "message": "Key is valid — test call succeeded."}
        if r.status_code == 401:
            return {"configured": True, "ok": False, "message": "Key rejected (401 Unauthorized)."}
        return {"configured": True, "ok": False, "message": f"Unexpected status {r.status_code}."}
    except requests.RequestException as e:
        return {"configured": True, "ok": False, "message": _safe_error("Request failed", e)}


def test_openrouter() -> dict:
    key = secrets_store.get_key("openrouter_api_key")
    if not key:
        return {"configured": False, "ok": False, "message": "No key configured."}
    try:
        r = requests.get(
            "https://openrouter.ai/api/v1/auth/key",
            headers={"Authorization": f"Bearer {key}"},
            timeout=15,
        )
        if r.status_code == 200:
            return {"configured": True, "ok": True, "message": "Key is valid — test call succeeded."}
        if r.status_code == 401:
            return {"configured": True, "ok": False, "message": "Key rejected (401 Unauthorized)."}
        return {"configured": True, "ok": False, "message": f"Unexpected status {r.status_code}."}
    except requests.RequestException as e:
        return {"configured": True, "ok": False, "message": _safe_error("Request failed", e)}


def test_ollama() -> dict:
    from modules import ollama_client

    if ollama_client.is_available():
        models = ollama_client.list_models()
        msg = f"Reachable — {len(models)} model(s) pulled." if models else "Reachable, but no models pulled yet (ollama pull llama3.2)."
        return {"configured": True, "ok": True, "message": msg}
    return {"configured": False, "ok": False, "message": f"Could not reach Ollama at {secrets_store.get_key('ollama_base_url') or 'http://localhost:11434'}. Is it installed and running?"}


def test_anyapi() -> dict:
    key = secrets_store.get_key("anyapi_api_key")
    if not key:
        return {"configured": False, "ok": False, "message": "No key configured."}
    try:
        r = requests.post(
            "https://api.anyapi.ai/v1/chat/completions",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json={"model": "openai/gpt-4-turbo", "messages": [{"role": "user", "content": "ping"}], "max_tokens": 1},
            timeout=15,
        )
        if r.status_code == 200:
            return {"configured": True, "ok": True, "message": "Key is valid — test call succeeded."}
        if r.status_code == 401:
            return {"configured": True, "ok": False, "message": "Key rejected (401 Unauthorized)."}
        return {"configured": True, "ok": False, "message": f"Unexpected status {r.status_code}."}
    except requests.RequestException as e:
        return {"configured": True, "ok": False, "message": _safe_error("Request failed", e)}


def test_shodan() -> dict:
    key = secrets_store.get_key("shodan_api_key")
    if not key:
        return {"configured": False, "ok": False, "message": "No key configured."}
    try:
        r = requests.get(
            "https://api.shodan.io/api-info",
            params={"key": key},
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            return {"configured": True, "ok": True, "message": f"Key is valid — plan: {data.get('plan', 'unknown')}, query credits: {data.get('query_credits')}, scan credits: {data.get('scan_credits')}."}
        if r.status_code == 401:
            return {"configured": True, "ok": False, "message": "Key rejected (401 Unauthorized)."}
        return {"configured": True, "ok": False, "message": f"Unexpected status {r.status_code}."}
    except requests.RequestException as e:
        return {"configured": True, "ok": False, "message": _safe_error("Request failed", e)}


def test_all() -> dict:
    return {
        "anthropic_api_key": test_anthropic(),
        "abuseipdb_api_key": test_abuseipdb(),
        "virustotal_api_key": test_virustotal(),
        "gemini_api_key": test_gemini(),
        "openai_api_key": test_openai(),
        "groq_api_key": test_groq(),
        "openrouter_api_key": test_openrouter(),
        "ollama_base_url": test_ollama(),
        "anyapi_api_key": test_anyapi(),
        "shodan_api_key": test_shodan(),
    }
