"""
AEGIS GRID Assistant (Chatbot)
Conversational assistant embedded in the dashboard, grounded in this
instance's live context (recent logs, health, quota state). Routes through
core/ai_gateway.py, so "auto" mode falls back across every configured
provider — Anthropic, OpenAI, Gemini, Groq, OpenRouter, then local Ollama.
"""
from core import applog, quota_tracker, health, ai_gateway

SYSTEM_PROMPT_TEMPLATE = """You are the embedded assistant inside AEGIS GRID, a \
security scanning and hosting command center. You help the user with:
- interpreting scan findings (security headers, nmap, IP reputation, sandbox results)
- drafting reports in markdown from findings they give you or that appear in context
- troubleshooting errors, dependency issues, and configuration problems in THIS tool
- explaining what a log entry or quota state means and what to do about it

You are not a general-purpose assistant — stay focused on this tool and security \
topics related to what the user is working on here. Be concise and concrete. When \
asked for a report, produce clean markdown. When asked about an error, give the \
most likely cause first, then the fix.

Match your answer's length and depth to the actual question. A quick factual \
question gets a short, direct answer. A genuinely complex troubleshooting or \
analysis question earns more space. Never pad with generic advice, disclaimers, \
or restating what was asked — give exactly what's needed to answer or act, and stop.

{mode_instruction}

Current tool context:
--- Recent log tail ---
{log_tail}

--- Health check ---
{health_summary}

--- Quota state (services nearing or at limit) ---
{quota_summary}
"""

MODE_INSTRUCTIONS = {
    "short": (
        "Response mode: SHORT. Main points only — a tight bullet list or a few short "
        "lines. No background explanation, no caveats, no restating the question. If "
        "asked about a list of findings/CVEs, give each one a single line: what it is "
        "and why it matters, nothing more."
    ),
    "descriptive": (
        "Response mode: DESCRIPTIVE. Give a full, detailed explanation — what each "
        "item is, why it matters, and the relevant context. Use headers or numbered "
        "sections when there are multiple items. This is the default depth."
    ),
    "poc": (
        "Response mode: PROOF OF CONCEPT. For each item, use this exact structure: "
        "Issue, Affected component, Preconditions, How it could be exploited "
        "(describe the mechanism and attacker's approach conceptually — do not "
        "provide ready-to-run exploit code, working payloads, or step-by-step "
        "weaponized commands), Impact, Remediation. Apply this structure "
        "consistently across every item, the way a pentest report would."
    ),
}


def _quota_warnings() -> str:
    summary = quota_tracker.full_summary()
    warnings = []
    for service, endpoints in summary.items():
        for endpoint, periods in endpoints.items():
            for period, stats in periods.items():
                if stats["pct"] >= 70:
                    warnings.append(f"{service}/{endpoint}: {stats['used']}/{stats['limit']} per {period} ({stats['pct']}%)")
    return "\n".join(warnings) if warnings else "(all services well within quota)"


def _build_system_prompt(mode: str = "descriptive") -> str:
    return SYSTEM_PROMPT_TEMPLATE.format(
        mode_instruction=MODE_INSTRUCTIONS.get(mode, MODE_INSTRUCTIONS["descriptive"]),
        log_tail=applog.tail_as_text(20),
        health_summary=str(health.run_health_check()["checks"]),
        quota_summary=_quota_warnings(),
    )


def chat(message: str, history: list[dict], provider: str = "anthropic", mode: str = "descriptive") -> dict:
    system_prompt = _build_system_prompt(mode)
    convo = "\n".join(f"{h['role']}: {h['content']}" for h in history)
    prompt = f"{convo}\nuser: {message}" if convo else message

    result = ai_gateway.ask(prompt, system=system_prompt, provider=provider)

    if "error" in result:
        applog.log_event("chat", result["error"], level="error")
        return result

    applog.log_event("chat", f"Chat reply generated via {result.get('provider', provider)} ({len(result['text'])} chars)")
    return {"reply": result["text"], "provider": result.get("provider", provider), "fallback_from": result.get("fallback_from")}
