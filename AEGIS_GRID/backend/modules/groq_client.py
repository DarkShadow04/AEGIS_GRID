"""
Groq Client
OpenAI-compatible chat API. Quota-gated per the free-tier limits you
provided: llama-3.3-70b-versatile (30 RPM, 1K RPD, 12K TPM, 100K TPD),
llama-3.1-8b-instant (30 RPM, 14.4K RPD, 6K TPM, 500K TPD).
"""
import requests

from core import secrets_store, quota_tracker, runtime_config

CHAT_URL = "https://api.groq.com/openai/v1/chat/completions"


def generate(prompt: str, system: str = "", model: str = "llama-3.3-70b-versatile") -> dict:
    api_key = secrets_store.get_key("groq_api_key")
    if not api_key:
        return {"error": "Groq API key not configured. Add it in Settings."}

    gate = quota_tracker.check("groq", model)
    if not gate["allowed"]:
        return {"error": f"Groq quota reached for {model} ({gate['blocked_by']}). Skipped to protect your limit."}

    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    try:
        resp = requests.post(
            CHAT_URL,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": model, "messages": messages},
            timeout=runtime_config.get("timeout_groq"),
        )
        quota_tracker.record("groq", model)
        if not resp.ok:
            try:
                err = resp.json().get("error", {})
                detail = f"{err.get('type', 'unknown')}: {err.get('message', resp.text[:300])}"
            except ValueError:
                detail = resp.text[:300]
            return {"error": f"Groq request failed ({resp.status_code}): {detail}"}
        data = resp.json()
        text = data["choices"][0]["message"]["content"]
        return {"text": text}
    except requests.RequestException as e:
        return {"error": f"Groq request failed: {str(e)[:200]}"}
    except (KeyError, IndexError):
        return {"error": "Groq returned an unexpected response shape.", "raw": resp.text[:500]}
