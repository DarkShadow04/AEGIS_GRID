"""
AI Gateway
Single entry point for "ask an LLM" across every provider AEGIS GRID
supports. Both ai_analyzer.py and chatbot.py call through here instead of
duplicating per-provider branching.

Supports an explicit provider choice, or provider="auto" which walks a
fallback chain — skipping unconfigured providers, trying each configured
one in order, and stopping at the first success. The chain ends at Ollama,
which needs no API key and can't run out of quota, so "auto" always has a
final option as long as Ollama is installed and running locally.
"""
from core import secrets_store, runtime_config
from modules import gemini_client, openai_client, groq_client, openrouter_client, anyapi_client, ollama_client

FALLBACK_ORDER = ["anthropic", "openai", "gemini", "groq", "openrouter", "anyapi", "ollama"]


def _call_anthropic(prompt: str, system: str) -> dict:
    api_key = secrets_store.get_key("anthropic_api_key")
    if not api_key:
        return {"error": "Anthropic API key not configured."}
    try:
        from anthropic import Anthropic

        client = Anthropic(api_key=api_key, timeout=runtime_config.get("timeout_anthropic"))
        resp = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1500,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(b.text for b in resp.content if b.type == "text")
        return {"text": text}
    except Exception as e:
        return {"error": f"Anthropic request failed: {str(e)[:300]}"}


PROVIDER_FUNCS = {
    "anthropic": _call_anthropic,
    "openai": lambda p, s: openai_client.generate(p, system=s),
    "gemini": lambda p, s: gemini_client.generate(p, system=s),
    "groq": lambda p, s: groq_client.generate(p, system=s),
    "openrouter": lambda p, s: openrouter_client.generate(p, system=s),
    "anyapi": lambda p, s: anyapi_client.generate(p, system=s),
    "ollama": lambda p, s: ollama_client.generate(p, system=s),
}


def ask(prompt: str, system: str = "", provider: str = "anthropic") -> dict:
    if provider != "auto":
        fn = PROVIDER_FUNCS.get(provider)
        if not fn:
            return {"error": f"Unknown provider: {provider}"}
        result = fn(prompt, system)
        if "error" not in result:
            result["provider"] = provider
        return result

    attempts = []
    for name in FALLBACK_ORDER:
        result = PROVIDER_FUNCS[name](prompt, system)
        if "error" not in result:
            result["provider"] = name
            if attempts:
                result["fallback_from"] = attempts
            return result
        attempts.append({"provider": name, "error": result["error"]})

    return {"error": "All configured providers failed (or none are configured). See attempts.", "attempts": attempts}
