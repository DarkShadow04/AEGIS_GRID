"""
OpenAI Client
Alternate AI analysis provider. Quota-gated per-model against your
reported limits: gpt-5.5 / gpt-5.5-pro (3 RPM, 50 RPD, 900K TPD,
10K TPM), gpt-image (10 RPM, 50 RPD).
"""
import requests

from core import secrets_store, quota_tracker, runtime_config

CHAT_URL = "https://api.openai.com/v1/chat/completions"


def generate(prompt: str, system: str = "", model: str = "gpt-5.5") -> dict:
    api_key = secrets_store.get_key("openai_api_key")
    if not api_key:
        return {"error": "OpenAI API key not configured. Add it in Settings."}

    gate = quota_tracker.check("openai", model)
    if not gate["allowed"]:
        return {"error": f"OpenAI quota reached for {model} ({gate['blocked_by']}). Skipped to protect your limit."}

    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    try:
        resp = requests.post(
            CHAT_URL,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": model, "messages": messages},
            timeout=runtime_config.get("timeout_openai"),
        )
        quota_tracker.record("openai", model)
        if not resp.ok:
            # OpenAI returns 429 for BOTH true rate-limiting and for
            # "exceeded current quota / no billing" — they read identically
            # as a bare status code but very differently in the response
            # body, which is where the real cause actually is.
            try:
                err = resp.json().get("error", {})
                detail = f"{err.get('type', 'unknown')}: {err.get('message', resp.text[:300])}"
            except ValueError:
                detail = resp.text[:300]
            return {"error": f"OpenAI request failed ({resp.status_code}): {detail}"}
        data = resp.json()
        text = data["choices"][0]["message"]["content"]
        return {"text": text}
    except requests.RequestException as e:
        return {"error": f"OpenAI request failed: {str(e)[:200]}"}
    except (KeyError, IndexError):
        return {"error": "OpenAI returned an unexpected response shape.", "raw": resp.text[:500]}
