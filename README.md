# AEGIS GRID — Unified Security Command Center

Your `ShadowNexus` CLI, rebuilt as a web-hosted command center: live system
telemetry, workspace hosting + tunnel, and a Security Sessions suite
(headers / nmap / IP reputation / AI-driven risk reports),
all quota-aware against your actual free-tier limits, plus an embedded
chatbot for analysis, report drafting, and troubleshooting.

Only scan/host targets you own or are explicitly authorized to test.

## What's new in this build (v16 — chat PDF export, Clear, New Chat)

- **Download chat as PDF** — a button in the chat panel builds a formatted transcript (You/Assistant
  turns, generation timestamp, message count, active response mode) using the same jsPDF setup
  already used for scan reports, and downloads it client-side. No server round-trip.
- **Clear** — wipes the current chat (confirms first if there's anything in it).
- **New Chat** — same as Clear, but offers to save a PDF first if the chat isn't empty, so starting
  fresh doesn't mean losing anything you'd want to keep. This is what "so I don't have to use the
  same chat and cluster everything up" turns into: a clean slate on demand, with an easy out to keep
  a copy of what came before.
- All three read from `chatHistory` (the same array already driving the actual `/api/chat` calls),
  not the DOM — so the export is exactly what was sent/received, without the "context attached" or
  "thinking..." UI-only lines cluttering it.

## What's new in this build (v15 — Access & Limits: editable timeouts, visitor log)

- **New "Access & Limits" tab.** Two things live there:
  - **Limits & Timeouts** — every AI-provider and scan-tool timeout that used to be a hardcoded
    constant (including the Ollama one from the last round) is now editable from the UI, takes
    effect immediately with no restart, and is bounds-checked so a typo can't set something silly.
    `backend/core/runtime_config.py` is the source of truth.
  - **Access Log** — once you tunnel this and share the link, every visitor gets a session
    (cookie-based), and every request is logged with IP, best-effort location, device/browser, and
    a human-readable action. Meant to answer "who's using this and what are they doing" when it's
    not just you anymore. `backend/core/access_log.py`, `geoip.py`, `ua_parser.py`.
- **Read this before you rely on the access log**: the IP recorded is read from
  `X-Forwarded-For`/`X-Real-IP` first (what most tunnel providers set), falling back to the raw
  socket peer. If your tunnel type doesn't set either header, every visitor will show as the
  tunnel's own address instead of their real one — there's no way to detect that mismatch from
  inside this process, so verify it once against a device whose real IP you know before trusting it
  for more than a rough sense of activity. Location is a free, approximate IP lookup (ipapi.co, no
  key needed) — city/region-level at best, and VPNs/carrier NAT will misplace it.
- Toggle logging entirely, or set retention, from the Server section of Limits & Timeouts. Turning
  it on/off is itself always recorded in the log, on either side of the toggle, specifically so you
  have proof of when monitoring was and wasn't active — see FINDINGS.md #45.
- Found and fixed a real concurrency bug while building this: the access log's read-modify-write to
  disk wasn't locked, so two requests landing at the same instant could silently drop one one's
  entry. Confirmed it actually happened under a concurrent test, then fixed it with a lock. Detailed
  in FINDINGS.md #44.

## What's new in this build (v14 — chat response modes, Ollama timeout/loading fix)

- **Chat now has three response modes** — Short, Descriptive, PoC — as buttons above the input.
  Short gives main points only; Descriptive is the previous default depth; PoC structures every
  item as Issue / Affected component / Preconditions / How it could be exploited / Impact /
  Remediation, like a pentest report — described conceptually, not handed back as working exploit
  code.
- **Ollama's 120s request timeout raised to 600s.** Root cause confirmed from a live "Read timed
  out (read timeout=120)" case where Ollama itself was healthy — local CPU-only generation with
  this tool's attached context was just legitimately taking longer than the old ceiling allowed.
- **Live elapsed-time loading indicator in chat** — a ticking `⟳ <stage>... Ns` line (loading →
  reading → structuring) instead of the panel looking frozen while waiting on a response, with an
  extra note when Ollama is selected since local inference is the slowest path. This is a staged
  indicator based on real elapsed time, not true token-by-token streaming — see FINDINGS.md #42 for
  why, and CHECKLIST.md Phase 15 for what a streaming follow-up would take.

## What's new in this build (v13 — Shodan integration)

- **Shodan added as a Security Sessions module** — API-key-only, same pattern as every other
  external-data integration (key via `secrets_store`, quota-gated where Shodan actually charges
  credits, results auto-flow into Reports for PDF/TXT/email export like every other scan).
- **`modules/shodan_client.py`** — built against Shodan's real, verified REST API contract (not
  guessed): `GET /shodan/host/{ip}` (passive lookup of Shodan's own database — not an active scan,
  free), `GET /shodan/host/search` (query credits), `GET /api-info` (free — credits remaining),
  `POST /shodan/scan` (on-demand active crawl — scan credits, carries the same "only scan what
  you're authorized to test" framing as nmap), `GET /dns/resolve` (free).
- **Quota tracker extended** for your Membership tier: 100 query credits/month, 100 scan
  credits/month, tracked as 1 call ≈ 1 credit (a conservative floor, same approximation already
  used for AnyAPI's token quota — `account_info()` has Shodan's own real number if it matters).
- New Security Sessions card: host lookup (with optional history), search (with facets), on-demand
  scan request, DNS resolve, and a "Check Credits Remaining" button.
- New Settings card for the Shodan key, wired into the existing key test/save/delete flow.

## What's new in this build (v10 — Hybrid Analysis removed, remote access, nmap expansion)

- **Hybrid Analysis removed entirely** — didn't fit the tool's needs; every trace of it is gone
  (module, endpoints, settings, quota tracking).
- **Remote access now has a real button.** Settings → Backend Connection & Remote Access → Start
  Remote Access tunnels the backend itself. This is different from the Server & Tunnel tab's
  workspace tunnel, which hosts an unrelated static site.
- **Custom Nmap Command Library** — save your own flag combos in Settings, reuse them from the
  Command Library dropdown's new "Custom" category.
- **Fixed:** `-p80,443` (attached port syntax) was incorrectly rejected — valid nmap syntax, now works.
- **Substantially expanded the nmap flag allowlist** — see FINDINGS.md for the full list and the
  reasoning on what's still excluded and why (two narrow categories: arbitrary file I/O, and
  attribution-evasion flags that implicate third-party hosts — not about scan aggressiveness).
- **Header checks expanded from 6 to 29**, covering the full standard security/CORS/caching/reporting
  header set — with accurate handling of deprecated headers (flagged as informational, not "add this").
- **Fixed:** chat window expand no longer covers/hides the toggle icon.

## Remote access setup

1. Go to **Settings → Backend Connection & Remote Access**
2. Confirm the port matches what you ran `uvicorn` with (default 8000)
3. Click **Start Remote Access** — takes up to 20s
4. Open the resulting `trycloudflare.com` URL on any other device

This requires `cloudflared` installed on the host. It's a genuinely public URL with no
authentication in front of it by default — see the security note further down before leaving this
running unattended.

## What's new in this build (v9 — rename, remote access, and a lot of bug fixes)

- **Renamed to AEGIS GRID** (see NAMING.md) — CIPHERGRID read as a cracking-tool
  name, not a defensive security product.
- **Remote/tunnel access actually works now.** The dashboard is served directly
  by the backend (same origin), and the frontend auto-detects its API base
  instead of hardcoding localhost. Tunnel the backend itself — see "Remote
  usage" below.
- **Critical fix:** the health check used to read environment variables
  instead of your actual saved keys, so it always showed them as unconfigured
  even after you set and tested them. Fixed.
- **Hybrid Analysis rebuilt** against the real, verified API (submit → poll
  job state → fetch summary once ready), instead of the guessed endpoint that
  was 400-ing before.
- **Nmap:** no more fixed timeout — long scans run as a background job with a
  live progress bar and a Cancel button. Command Library reorganized into
  Basic / Aggressive / Vulnerability+Script categories, plus a real UI bug
  (category switching could close the whole panel) found and fixed via
  browser testing, not just code review.
- **New:** real-time network speed graph, NEL (Network Error Logging) checker,
  AnyAPI as a 7th AI provider, SMTP-based report emailing, expandable chat window.
- **Fixed:** Settings layout breaking on long API keys, Command Library
  visually clashing with the card below it.

## What's new in this build (v8 — AI diversification + UX fixes)

- **Root cause of "AI doesn't work":** confirmed via the improved error messages from last round —
  all three hosted providers were at $0 credit or exceeded free-tier quota. Not a bug in AEGIS GRID.
- **New providers:** Groq and OpenRouter (both OpenAI-compatible, quota-gated to your real limits),
  and **Ollama** — a local LLM that needs no API key and can't run out of quota, the actual failover.
- **Auto fallback chain:** pick "Auto" in any AI provider dropdown and it walks Anthropic → OpenAI →
  Gemini → Groq → OpenRouter → Ollama, stopping at the first one that works.
- **Fixed:** nmap timeout error now explains what to do about it (lighter profile, narrower port range)
  instead of just reporting the failure
- **New:** every scan button shows live status (● running / ✓ done / ✗ failed)
- **New:** Server & Tunnel show immediate "starting.../stopping..." feedback and guard against
  double-clicks while an action is in progress
- **New:** Findings Severity Breakdown chart — pick any past scan from a dropdown, click a bar to see
  the specific findings behind it, Clear button resets the chart view without touching your history
- **New:** explicit delete button in the Reports detail view

## What's new in this build (v7 — bug fixes from live testing)

- **Fixed:** card hover no longer blurs text (was a 3D-transform compositing issue, not an actual blur filter)
- **Fixed:** local server and public tunnel now show real, clickable links instead of static/broken text
- **Fixed:** chat/AI errors now show the real cause (billing vs. rate-limit vs. other) instead of a generic status code
- **New: Reports tab** — every scan is now saved to persistent history, browsable, and exportable as a formatted TXT or PDF (headings, metadata, findings, footer)

## What's new in this build (v6)

- **Redesigned Control Matrix** — now mirrors your CLI screenshot's bracket
  checklist and box layout directly, driven by live data.
- **Custom Nmap commands** — a "Command Library" of 18 curated flag
  combinations (research-grounded, not guessed), plus a free-text box for
  your own flags. Every custom command is validated against an allowlist
  before it ever reaches nmap — file I/O, source spoofing, decoy, and
  idle-scan flags are rejected outright, since those are abuse vectors once
  a scanner is reachable over a network API instead of a local terminal.
- **Headers info dialog** — click the ⓘ next to Headers & IP Checks to see
  exactly what the scan checks and why, sourced live from the backend.
- **SSL/TLS certificate checker** and **DNS recon** — two new modules
  (cert expiry/protocol, A/AAAA/MX/TXT/NS/CNAME + SPF/DMARC presence).
- **Contextual "Ask AI" button** on every scan result — opens the chat
  assistant pre-loaded with that specific result so you can ask about it
  directly, instead of re-explaining what you just ran.
- **New chat icon + terminal-style panel**, 3D opening animation, and a
  tips section listing exactly what the assistant can help with.
- **3D-animated openings** throughout — the chat panel, the headers info
  modal, and the command library dropdown all use a shared perspective/
  scale entrance animation instead of instant show/hide.

## What's new from v5

- **Quota tracking** — every external call (AbuseIPDB, VirusTotal, Gemini,
  OpenAI, Hybrid Analysis) is checked against your real limits *before* it
  fires, and skipped rather than burning quota once you're at the ceiling.
  Live gauges in the **Quota** tab.
- **Multi-provider AI** — pick Anthropic, Gemini, or OpenAI per analysis or
  chat request, so one provider's free-tier ceiling doesn't block you.
  check, and quota state.

## Structure

```
backend/
  core/
    system_info.py     — live CPU/mem/uptime/network
    server_manager.py  — local hosting + cloudflared tunnel
    health.py           — dependency/security health scoring
    secrets_store.py    — local, gitignored API key storage
    key_tester.py       — live per-key connectivity test, never echoes the key
    quota_tracker.py    — sliding-window quota enforcement, all 5 providers
    applog.py            — rolling event/error log (chatbot context)
    chatbot.py            — embedded assistant, multi-provider
    runtime_config.py, access_log.py, geoip.py, ua_parser.py — Access & Limits tab backing
  modules/
    headers_checker.py, nmap_scanner.py, ip_reputation.py — scan modules
    shodan_client.py     — Shodan host lookup/search/scan/dns, quota-tracked
    gemini_client.py, openai_client.py — alt AI providers
    ai_analyzer.py       — multi-provider risk analysis
  main.py               — FastAPI app, all endpoints
frontend/
  index.html            — Control Matrix / Server & Tunnel / Security
                           Sessions / Quota / Settings / Chat
CHECKLIST_V5.md          — what was built, what's left to test on your end
FINDINGS.md              — audit findings + bugs caught during testing
NAMING.md                — why "AEGIS GRID"
```

## Setup

```bash
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

nmap and cloudflared should be on the host if you want those features:
```bash
sudo apt install nmap
# cloudflared: https://github.com/cloudflare/cloudflared/releases
```

## Run

```bash
uvicorn main:app --reload --port 8000
```

Open `frontend/index.html` in a browser. It talks to `http://localhost:8000`
by default — change it in the Settings tab if hosting the backend elsewhere.

## API keys — Settings tab

Enter whichever keys you have in the **Settings** tab: Anthropic, AbuseIPDB,
VirusTotal, Gemini, OpenAI, Groq, OpenRouter, AnyAPI, Shodan — plus Ollama's
base URL if you're running it locally (no key needed, just install it and
`ollama pull llama3.2`, then `ollama serve`). They're saved to
`backend/config/secrets.json` only — gitignored, chmod 600, never returned
in full by the API. Hit **Test** next to any key for a live, minimal
connectivity check that never echoes the key value, even on failure.

Pick **Auto** in any AI provider dropdown to use the fallback chain instead
of a single provider — useful exactly when a hosted provider is out of
credit, which is the actual failure mode this was built for.

## Your actual limits, as configured

| Service | Endpoint | Limit |
|---|---|---|
| AbuseIPDB | check | 1,000 / day |
| AbuseIPDB | report | 1,000 / day |
| AbuseIPDB | reports, check-block | 100 / day |
| AbuseIPDB | blacklist, bulk-report, bulk-check, clear-address | 5 / day |
| VirusTotal | lookup | 4/min · 500/day · 15,500/month |
| Gemini | generate (free tier) | 60 RPM · 100K TPM · 100 RPD |
| OpenAI | gpt-5.5, gpt-5.5-pro | 3 RPM · 50 RPD · 10K TPM · 900K TPD |
| OpenAI | gpt-image | 10 RPM · 50 RPD |
| Shodan | search (query credits) | 100 / month (Membership tier) |
| Shodan | scan (scan credits) | 100 / month (Membership tier) |
| Shodan | host lookup, dns/resolve, api-info | free — not gated |

Edit `core/quota_tracker.py`'s `LIMITS` dict if any of these change (e.g. you
upgrade a tier).

## API reference

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/telemetry` | GET | System stats snapshot |
| `/ws/telemetry` | WS | Live telemetry stream (2s) |
| `/api/health` | GET | Dependency/security health check |
| `/api/server/*`, `/api/tunnel/*` | GET/POST | Workspace hosting + tunnel |
| `/api/tunnel/self/status` \| `/start` \| `/stop` | GET/POST | Remote access — tunnels this backend itself |
| `/api/settings/nmap-commands` | GET/POST | List / save a custom nmap command |
| `/api/settings/nmap-commands/{id}` | DELETE | Remove a custom nmap command |
| `/api/scan/headers` | POST | Header scan |
| `/api/scan/headers/info` | GET | What the header scan checks (for the ⓘ dialog) |
| `/api/scan/nmap` | POST `{target, profile}` | Preset-profile nmap scan |
| `/api/scan/nmap/validate` | POST `{target, args}` | Validate a custom command without running it |
| `/api/scan/nmap/custom` | POST `{target, args}` | Run a validated custom nmap command (synchronous, 30 min backstop) |
| `/api/scan/nmap/job` | POST `{target, args}` | Start an async nmap job — no fixed timeout |
| `/api/scan/nmap/job/{id}` | GET | Poll job status/progress; DELETE to cancel |
| `/api/scan/nel` | POST `{url}` | Network Error Logging header check |
| `/api/reports/email` | POST `{to_email, subject, body_text, pdf_base64?}` | Email a report via configured SMTP |
| `/api/scan/ip-reputation` | POST | AbuseIPDB + VirusTotal |
| `/api/shodan/host/{ip}` | GET `?with_history=` | Passive Shodan host lookup — free, not a scan |
| `/api/shodan/search` | POST `{query, facets?, page?}` | Shodan search — uses query credits |
| `/api/shodan/account` | GET | Shodan plan + credits remaining — free |
| `/api/shodan/scan` | POST `{ips}` | On-demand Shodan scan request — uses scan credits, authorized-targets-only |
| `/api/shodan/dns/resolve` | POST `{hostnames}` | Shodan's own DNS resolve — free |
| `/api/settings/runtime-config` | GET/POST/DELETE `{key}` | View / edit / reset an adjustable timeout or limit |
| `/api/access-log` | GET `?limit=` \| DELETE | Visitor/session log — view or clear |
| `/api/scan/ssl` | POST `{hostname, port?}` | TLS certificate check |
| `/api/scan/dns` | POST `{domain}` | DNS record recon |
| `/api/assess/full` | POST `{url, ip?, nmap_profile?, ai_provider?}` | Full scan + AI report |
| `/api/settings/keys` | GET/POST/DELETE | Key management (masked) |
| `/api/settings/keys/test` | POST | Live-test all configured keys |
| `/api/quota` | GET | Usage vs. limit, every provider |
| `/api/chat` | POST `{message, history, provider}` | Embedded assistant |
| `/api/logs` | GET `?n=50` | Recent app log tail |
| `/api/history` | GET | List all saved scan results (summary) |
| `/api/history/{id}` | GET | Full data for one saved scan result |
| `/api/history/{id}` | DELETE | Remove one entry |
| `/api/history` | DELETE | Clear all history |

## What was audited and what changed

See `FINDINGS.md`. Highlights: hardcoded live API keys were found in your
old `AbuseLPDB`/`Dark_Console` repos (rotate those); a header-checker bug
that reported every security header as missing on servers using lowercase
header names was caught via live testing against `github.com` and fixed.

## Next steps you may want

- Auth in front of the API before exposing this beyond localhost
- Persist scan history so Security Sessions shows trend-over-time
- Docker Compose for backend + frontend together
- Live-test Gemini/OpenAI against your real keys and quotas
  once deployed (couldn't be done from this sandbox — no external network,
  no keys)
