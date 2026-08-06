"""
Gemini Client
Free-tier Google Gemini client for use as an alternate AI analysis
provider. Quota-gated against your reported free-tier limits
(60 RPM / 100K TPM / 100 RPD).
"""
import requests

from core import secrets_store, quota_tracker, runtime_config

GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"


def generate(prompt: str, system: str = "", model: str = "gemini-2.0-flash") -> dict:
    api_key = secrets_store.get_key("gemini_api_key")
    if not api_key:
        return {"error": "Gemini API key not configured. Add it in Settings."}

    gate = quota_tracker.check("gemini", "generate")
    if not gate["allowed"]:
        return {"error": f"Gemini quota reached ({gate['blocked_by']}). Skipped to protect your limit."}

    body = {"contents": [{"parts": [{"text": prompt}]}]}
    if system:
        body["systemInstruction"] = {"parts": [{"text": system}]}

    try:
        resp = requests.post(
            GEMINI_URL.format(model=model),
            params={"key": api_key},
            json=body,
            timeout=runtime_config.get("timeout_gemini"),
        )
        quota_tracker.record("gemini", "generate")
        if not resp.ok:
            # Surface the real reason (rate limit vs. quota vs. bad model vs.
            # invalid key) instead of a generic status-code message — the
            # response body is where Gemini actually explains what happened.
            try:
                detail = resp.json().get("error", {}).get("message", resp.text[:300])
            except ValueError:
                detail = resp.text[:300]
            return {"error": f"Gemini request failed ({resp.status_code}): {detail}"}
        data = resp.json()
        text = data["candidates"][0]["content"]["parts"][0]["text"]
        return {"text": text}
    except requests.RequestException as e:
        return {"error": f"Gemini request failed: {str(e)[:200]}"}
    except (KeyError, IndexError):
        return {"error": "Gemini returned an unexpected response shape.", "raw": resp.text[:500]}
