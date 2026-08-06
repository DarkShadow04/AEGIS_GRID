"""
AnyAPI Client
OpenAI-compatible chat API. Free tier: 100,000 ₳nyTokens/day.
"""
import requests

from core import secrets_store, quota_tracker, runtime_config

CHAT_URL = "https://api.anyapi.ai/v1/chat/completions"
DEFAULT_MODEL = "openai/gpt-4-turbo"


def generate(prompt: str, system: str = "", model: str = DEFAULT_MODEL) -> dict:
    api_key = secrets_store.get_key("anyapi_api_key")
    if not api_key:
        return {"error": "AnyAPI key not configured. Add it in Settings."}

    gate = quota_tracker.check("anyapi", "chat")
    if not gate["allowed"]:
        return {"error": f"AnyAPI quota reached ({gate['blocked_by']}). Skipped to protect your limit."}

    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    try:
        resp = requests.post(
            CHAT_URL,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": model, "messages": messages},
            timeout=runtime_config.get("timeout_anyapi"),
        )
        quota_tracker.record("anyapi", "chat")
        if not resp.ok:
            try:
                err = resp.json().get("error", {})
                detail = err.get("message", resp.text[:300]) if isinstance(err, dict) else str(err)[:300]
            except ValueError:
                detail = resp.text[:300]
            return {"error": f"AnyAPI request failed ({resp.status_code}): {detail}"}
        data = resp.json()
        text = data["choices"][0]["message"]["content"]
        return {"text": text}
    except requests.RequestException as e:
        return {"error": f"AnyAPI request failed: {str(e)[:200]}"}
    except (KeyError, IndexError):
        return {"error": "AnyAPI returned an unexpected response shape.", "raw": resp.text[:500]}
