"""
Ollama Client — local LLM failover
No API key needed. Talks to a local Ollama instance (default localhost:11434).
This is the last link in the fallback chain: hosted providers can run out of
credit or hit rate limits, a local model on your own hardware can't.

Install: https://ollama.com — then `ollama pull llama3.2` (or any model)
and `ollama serve` (usually runs automatically after install).
"""
import requests

from core import secrets_store, runtime_config

DEFAULT_BASE_URL = "http://localhost:11434"


def _base_url() -> str:
    return secrets_store.get_key("ollama_base_url") or DEFAULT_BASE_URL


def is_available() -> bool:
    try:
        r = requests.get(f"{_base_url()}/api/tags", timeout=3)
        return r.ok
    except requests.RequestException:
        return False


def list_models() -> list:
    try:
        r = requests.get(f"{_base_url()}/api/tags", timeout=3)
        if not r.ok:
            return []
        return [m["name"] for m in r.json().get("models", [])]
    except requests.RequestException:
        return []


def generate(prompt: str, system: str = "", model: str = "llama3.2") -> dict:
    base_url = _base_url()
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    try:
        resp = requests.post(
            f"{base_url}/api/chat",
            json={"model": model, "messages": messages, "stream": False},
            # Local CPU-only inference can genuinely take several minutes,
            # especially with this tool's system prompt (log tail + health +
            # quota context) attached on top of the user's question. This
            # used to be a hardcoded 120s that cut off legitimate in-progress
            # generations. Now configurable from Access & Limits in Settings
            # instead of needing a source edit — see core/runtime_config.py.
            timeout=runtime_config.get("timeout_ollama"),
        )
        if not resp.ok:
            return {"error": f"Ollama request failed ({resp.status_code}): {resp.text[:300]}"}
        data = resp.json()
        text = data.get("message", {}).get("content", "")
        if not text:
            return {"error": "Ollama returned an empty response — is the model actually pulled? (ollama pull " + model + ")"}
        return {"text": text}
    except requests.ConnectionError:
        return {"error": f"Could not reach Ollama at {base_url}. Is it installed and running? (ollama serve)"}
    except requests.RequestException as e:
        return {"error": f"Ollama request failed: {str(e)[:200]}"}
