"""
AI Analysis Layer
Takes raw findings from the scanner modules and asks an AI provider to
produce a prioritized risk summary + remediation plan. Routes through
core/ai_gateway.py, so "auto" mode falls back across every configured
provider — Anthropic, OpenAI, Gemini, Groq, OpenRouter, then local Ollama.
"""
import json

from core import ai_gateway, applog

SYSTEM_PROMPT = """You are a security analyst assistant. You will be given raw \
findings from automated scans (HTTP security headers, nmap port/service scans, \
IP reputation checks, sandbox lookups) run against infrastructure the user owns or \
is authorized to test. Produce:
1. An overall risk rating (Low/Medium/High/Critical) with one-sentence justification.
2. A prioritized list of findings, each with: what it is, why it matters, and a \
concrete remediation step.
3. Any quick wins vs longer-term hardening work.
Be concise and specific. Do not repeat raw data verbatim; synthesize it.
Match your answer's length to the question — a simple finding gets a short \
explanation, a genuinely complex one gets more room. Do not pad with generic \
security advice, disclaimers, or restating the question. Give the user exactly \
enough to act on, no more."""


def analyze_findings(findings: dict, provider: str = "anthropic") -> dict:
    prompt = f"Here are the scan findings as JSON:\n\n{json.dumps(findings, indent=2)}\n\nAnalyze and produce the risk summary and remediation plan."
    result = ai_gateway.ask(prompt, system=SYSTEM_PROMPT, provider=provider)

    if "error" in result:
        applog.log_event("ai", result["error"], level="error")
        return result

    applog.log_event("ai", f"Risk analysis generated via {result.get('provider', provider)}")
    return {"analysis": result["text"], "provider": result.get("provider", provider), "fallback_from": result.get("fallback_from")}
