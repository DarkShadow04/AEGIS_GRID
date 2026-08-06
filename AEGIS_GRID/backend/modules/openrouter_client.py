"""
OpenRouter Client
OpenAI-compatible chat API, routed to a free (":free" suffix) model by
default so it works with a $0 account. Quota-gated per the free-usage
limits you provided: 20 RPM / 50 RPD under 10 lifetime credits purchased,
20 RPM / 1000 RPD at 10+.  Defaults to the more conservative 50 RPD tier —
update core/quota_tracker.py's LIMITS if you've purchased credits.
"""
import requests

from core import secrets_store, quota_tracker, runtime_config

CHAT_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_FREE_MODEL = "meta-llama/llama-3.1-8b-instruct:free"


def generate(prompt: str, system: str = "", model: str = DEFAULT_FREE_MODEL) -> dict:
    api_key = secrets_store.get_key("openrouter_api_key")
    if not api_key:
        return {"error": "OpenRouter API key not configured. Add it in Settings."}

    gate = quota_tracker.check("openrouter", "free_model")
    if not gate["allowed"]:
        return {"error": f"OpenRouter quota reached ({gate['blocked_by']}). Skipped to protect your limit."}

    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    try:
        resp = requests.post(
            CHAT_URL,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": model, "messages": messages},
            timeout=runtime_config.get("timeout_openrouter"),
        )
        quota_tracker.record("openrouter", "free_model")
        if not resp.ok:
            try:
                err = resp.json().get("error", {})
                detail = err.get("message", resp.text[:300])
            except ValueError:
                detail = resp.text[:300]
            return {"error": f"OpenRouter request failed ({resp.status_code}): {detail}"}
        data = resp.json()
        text = data["choices"][0]["message"]["content"]
        return {"text": text}
    except requests.RequestException as e:
        return {"error": f"OpenRouter request failed: {str(e)[:200]}"}
    except (KeyError, IndexError):
        return {"error": "OpenRouter returned an unexpected response shape.", "raw": resp.text[:500]}
