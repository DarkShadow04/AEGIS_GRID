# Rebuild Checklist — v5 ("AEGIS GRID")

## Naming
- [x] New product name chosen: **AEGIS GRID** — see NAMING.md for reasoning + alternates

## Phase 1 — Quota-Aware API Layer (new, per your limits)
- [x] `core/quota_tracker.py` — generic sliding-window tracker (minute/hour/day/month), config-driven
- [x] Hardcode your exact free-tier limits: AbuseIPDB (8 endpoints), VirusTotal (4/min·500/day·15.5K/mo),
      Gemini free tier (60 RPM·100K TPM·100 RPD), OpenAI gpt-5.5 & gpt-5.5-pro (3 RPM·50 RPD·900K TPD·10K TPM),
      gpt-image (10 RPM·50 RPD), Hybrid Analysis (sandbox 100/day, API 200/min·2000/hr)
- [x] Every external call checks quota BEFORE calling (never burns quota on a call we know will fail/isn't worth making)
- [x] Every external call records usage AFTER a real response
- [x] `/api/quota` endpoint + dashboard tab with live gauges per service/endpoint

## Phase 2 — New Provider Integrations
- [x] `modules/gemini_client.py` — Google Gemini REST client, quota-tracked
- [x] `modules/openai_client.py` — OpenAI REST client (chat + image), quota-tracked
- [x] `modules/hybrid_analysis.py` — sandbox submission + lookup client, quota-tracked
- [x] `ai_analyzer.py` upgraded to multi-provider: pick Anthropic / Gemini / OpenAI per request or config
- [x] Settings tab extended with all 5 keys (Anthropic, AbuseIPDB, VirusTotal, Gemini, OpenAI, Hybrid Analysis)

## Phase 3 — AI Chatbot (new)
- [x] `core/applog.py` — rolling app log (errors, scan events) the bot can read
- [x] `core/chatbot.py` — conversational assistant with tool context (recent findings, logs, quota state, health)
- [x] `/api/chat` endpoint — analysis Q&A, report drafting, error/dependency troubleshooting
- [x] Dashboard chat panel, persistent across tabs

## Phase 4 — Dashboard Rebuild (CLI-parity + 3D)
- [x] Control Matrix redesigned to match the CLI's bracket-checklist / box-header aesthetic, live-driven
- [x] Three.js wireframe backdrop for genuine 3D depth (not just CSS tilt)
- [x] Real-time: telemetry every 2s via WebSocket (kept), quota + health polling tightened to 5s
- [x] Quota gauges, chat panel, settings — all wired to real endpoints

## Phase 5 — Test everything
- [x] Quota tracker: simulate hitting each limit type (minute/day/month), confirm blocks before the real call fires
- [x] Gemini/OpenAI/Hybrid Analysis clients: verified graceful "not configured" + quota-exceeded paths (no live paid calls possible without your keys — flagged as your next manual test)
- [x] Chatbot: verified it correctly assembles context (logs/findings/quota) and calls the configured provider
- [x] Full app boot + route registration test
- [x] Frontend structural check (balanced tags/braces)

## Known gaps to test on your end (need your real keys / your network)
- [ ] Live Gemini/OpenAI/Hybrid Analysis calls against real quotas (I can't call these from this sandbox — no key, no external network)
- [ ] Confirm the exact Gemini/OpenAI model identifiers still match what your account exposes when you deploy (model names shift)
- [ ] Load-test the quota tracker under concurrent requests (current implementation is single-process, file-backed — fine for personal use, not for multi-worker deployment)

## Phase 7 — v6: Custom Nmap, New Modules, UI Rebuild (this round)
- [x] Nmap custom-command mode: allowlist validator + blocked-flag list, tested against
      9 valid commands and 11 abuse/injection attempts — all correct
- [x] Command Library: 18 curated nmap flag combinations, custom-built animated dropdown
- [x] Headers info dialog: backend-driven (`/api/scan/headers/info`), 3D-animated modal
- [x] SSL/TLS certificate checker module — tested live against real domains
- [x] DNS recon module (A/AAAA/MX/TXT/NS/CNAME + SPF/DMARC heuristics) — tested live
- [x] Contextual "Ask AI" button on every scan result, reuses chat panel with injected context
- [x] New chat icon (terminal-in-hexagon SVG) + 3D opening animation + tips section
- [x] Removed "formerly ShadowNexus" branding throughout
- [x] Full headless browser test suite (Playwright): tab nav, chat, command library,
      headers modal, quota tab — all against a live backend
- [x] Found + fixed a real UI bug via synthetic-click testing (card hover-tilt shifting
      the dropdown out from under the cursor) — see FINDINGS.md #10
- [x] JS syntax validated (`node --check`), zero console errors across full interaction test

## Still open (flagged honestly, not swept under the rug)
- [ ] Live Gemini/OpenAI/Hybrid Analysis calls against your real quotas — needs your keys + normal network, can't be done from this sandbox
- [ ] cdnjs.cloudflare.com (Chart.js, Three.js) couldn't be loaded in this sandbox to visually verify the 3D backdrop and charts render — stubbed for logic testing; verify visually once you run this on a machine with normal internet
- [ ] No auth in front of the API — still the top priority before exposing this beyond localhost, now more true than before given the larger surface area (nmap execution, chat, 6 API integrations)

## Phase 8 — Bug fixes from your live testing round
- [x] **Card hover blur** — removed perspective/rotateX 3D tilt from `.card:hover` (a real CSS
      gotcha: 3D transforms force non-integer-pixel compositing, blurring text even with no blur
      filter applied). Replaced with a flat translateY+glow lift. Verified via computed-style check:
      hover transform is now a pure 2D matrix with zero rotation component.
- [x] **Local server / tunnel links** — `server_manager.status()` now returns a real `local_url`
      (`http://<local_ip>:<port>`), rendered as a clickable link. Tunnel URL extraction rewritten to
      use a strict regex (`https://[a-zA-Z0-9-]+\.trycloudflare\.com`) on a background-threaded reader
      instead of a naive substring match — the old version could grab a generic banner/docs mention
      of "trycloudflare.com" instead of your actual assigned subdomain, which is almost certainly what
      produced the literal "trycloudflare.com..." text you saw. Verified against simulated realistic
      cloudflared output containing both a decoy line and the real URL — correctly extracts only the real one.
- [x] **Chat/AI errors hiding the real cause** — OpenAI and Gemini clients now parse and surface the
      actual response body on failure (e.g. distinguishing `insufficient_quota`/billing issues from a
      true `rate_limit_exceeded`), instead of a bare generic status-code message. Verified against
      mocked responses matching both real-world error shapes.
- [x] **Reports tab** — new persistent scan history (`core/history.py`), a Reports tab listing every
      past scan with click-to-view detail, and TXT + PDF export per entry (headings, metadata, command
      used, findings, footer). PDF export tested with the real jsPDF library (not a mock) — confirmed
      valid, correctly structured 1-page PDF output.

## Security note (added per your message)
- Live API keys were pasted directly into chat during this session. Flagged immediately: chat history
  is not a safe place to hand off secrets, regardless of intent, and all six should be rotated. None
  were used, stored, or repeated in any output.

## Phase 9 — AI diversification + UX fixes from your live testing round 2
- [x] Root cause confirmed: all 3 hosted providers were at $0 credit / exceeded free quota (this is
      exactly what the error-surfacing fix from last round was built to reveal — confirmed working)
- [x] `modules/ollama_client.py` — local LLM, no API key, can't run out of quota. Tested: correctly
      reports unreachable when Ollama isn't running, with an actionable message
- [x] `modules/groq_client.py`, `modules/openrouter_client.py` — OpenAI-compatible clients, quota-gated
      to your real reported limits
- [x] `core/ai_gateway.py` — single entry point for all 6 providers now; "auto" mode walks a fallback
      chain (Anthropic → OpenAI → Gemini → Groq → OpenRouter → Ollama), skipping unconfigured ones.
      Tested: correctly reports why each provider was skipped, and correctly succeeds on Ollama when
      it's the only one available
- [x] `ai_analyzer.py` and `chatbot.py` refactored to route through the gateway — both got fallback
      support for free, no duplicated logic
- [x] Settings tab: added Groq, OpenRouter, and Ollama (base URL, no key needed) cards
- [x] Provider dropdowns (Full Assessment, Chat) now include Auto/Groq/OpenRouter/Ollama
- [x] Nmap timeout error message rewritten with actionable guidance (lighter profile, narrower port range)
- [x] Per-scan status indicators (● running / ✓ done / ✗ failed) added to every scan button
- [x] Server & Tunnel: immediate "starting.../stopping..." text + button-click guarding to prevent
      double-clicks while an action is in flight
- [x] Findings Severity Breakdown: dropdown to view findings from any past scan (via history), bars
      are now clickable to show the specific findings behind that severity count, and a Clear button
      that resets the chart view only — verified it does NOT touch backend history
- [x] Reports: added an explicit "Delete This Report" button in the detail view (the per-row × was
      already there from the previous round, in case that wasn't obvious)
- [x] Full test suite: backend logic (ai_gateway fallback chain, quota tracker) via direct calls;
      frontend logic (status indicators, chart click/clear, dropdown) via a backend-independent
      Playwright test with injected data; all 35 API routes confirmed registered

## Known gap
- [ ] AnyAPI and aimlapi.com were NOT integrated — the info shared was too sparse (no concrete
      endpoint/auth pattern) to build confidently without guessing at a wrong API contract. Groq and
      OpenRouter cover the same "extra free-tier diversity" need with actually-documented APIs. Happy
      to add either if you can share their API docs/endpoint format.
- [ ] Live end-to-end test of the new providers against real accounts wasn't possible this round —
      this sandbox's combined server+browser-automation testing hit environment limits partway through
      (unrelated to the code itself; isolated backend-logic and frontend-logic tests both passed clean)

## Phase 10 — v9: rename, remote access, async nmap, new integrations, bug fixes
- [x] Renamed AEGIS GRID → **AEGIS GRID** throughout (backend, frontend, filenames, generated reports)
- [x] **Critical bug fixed**: health check was reading `os.environ` instead of the secrets store, so
      the dashboard showed keys as "not set" even after configuring + testing them successfully via
      Settings. Verified: save a key through secrets_store, health check now reflects it immediately.
- [x] **Remote/tunnel access fixed**: the dashboard now mounts as static files served directly by the
      FastAPI backend (main.py), and the frontend auto-detects its API base from `window.location.origin`
      instead of hardcoding localhost:8000. Tunnel the backend itself (not the old separate workspace
      file server) and remote usage now actually works end-to-end.
- [x] **Hybrid Analysis rebuilt against the real, verified API** (the original guessed wrong and 400'd):
      `submit/url-for-analysis` with `environment_id`, `report/{job_id}/state` for polling, `report/{job_id}/summary`
      for the finished report, `search/hash` (GET) for instant hash lookups. Confirmed environment ID 160 =
      Windows 10 64-bit directly from a real report you shared.
- [x] Declined to add idle-scan (`-sI`), decoy (`-D`)/MAC-spoofing, source-port manipulation, packet
      fragmentation, FTP bounce (`-b`), and `--script-args=unsafe=1` to the nmap command library — these
      specifically evade attribution or implicate third-party hosts, a different risk category from
      aggressive-but-attributable scanning. Added the legitimate parts of the requested list instead
      (full port range, `-sV -O`, `--script vuln`).
- [x] **Nmap timeout removed** for the primary custom-scan path — converted to a real background job
      system (`core/job_manager.py`) with live progress parsed from nmap's own `--stats-every` output,
      a progress bar, and a Cancel button. Tested with real nmap execution end-to-end (status transitions
      running → done, correct final result).
- [x] Command Library reorganized into **Basic / Aggressive / Vulnerability+Script** categories as requested
- [x] **Real bug found and fixed via actual browser testing**: switching command-library categories
      destroyed the very tab element the user just clicked (via innerHTML rebuild), which made the
      outside-click-to-close listener misfire and immediately close the panel. Fixed by keeping the tab
      bar's DOM nodes stable across category switches instead of rebuilding them every time. Verified:
      panel now stays open through category switches, real clicks fill the input correctly, and
      clicking genuinely outside still closes it.
- [x] Command Library dropdown glitch (visual overlap with Hybrid Analysis card) fixed by elevating the
      whole parent card's stacking context via `:has()` while its dropdown is open, rather than relying
      on a z-index that only ranked it against its own card's children
- [x] Settings input-overflow bug fixed at the root: capped the masked-key preview length (backend) +
      `min-width:0` on grid cards (the actual CSS-grid overflow cause) + `overflow-wrap` as defense in depth
- [x] Real-time network speed graph added next to CPU/Memory (`psutil.net_io_counters()` delta-based)
- [x] `nel_checker.py` — Network Error Logging header checker, ported from nel_check, tested live
- [x] AnyAPI added as a 7th AI provider (verified real endpoint via search before building, learned from
      the Hybrid Analysis mistake)
- [x] AI provider fallback chain extended: Anthropic → OpenAI → Gemini → Groq → OpenRouter → AnyAPI → Ollama
- [x] SMTP-based email-report feature — `core/mailer.py`, Settings card, Send button in Reports detail
      (uses your own mail account, not another third-party API key)
- [x] Chat window expand/collapse toggle added
- [x] AI system prompts (both analysis and chat) updated to explicitly scope response length/depth to
      the actual question instead of always maximal detail

## Test coverage note (transparency)
This round's testing environment was unusually unstable for combined server+browser-automation tests
(server processes intermittently failed to start even in isolation, unrelated to any code change).
Coverage achieved:
- Backend logic: verified via direct Python calls for health check fix, job_manager (real nmap execution,
  confirmed status transitions and progress field), network throughput calculation, NEL checker (live
  against github.com/pypi.org), mask() length fix — all passing
- Frontend logic: verified via a backend-independent Playwright suite covering the rename, dropdown
  fix (including catching and fixing the category-switch bug above), NEL/AnyAPI/SMTP UI elements,
  provider dropdown options, network chart, chat expand toggle, and the settings-overflow fix — all passing
- NOT achieved this round: a full live end-to-end browser test of the async nmap job UI against a running
  backend (attempted multiple times, environment failed to cooperate). The backend job system was proven
  correct in isolation and the frontend polling logic was code-reviewed and structurally verified; do a
  manual smoke test of Security Sessions → Nmap → Run Scan once you're running this yourself.

## Phase 11 — v10: Hybrid Analysis removal, remote access, nmap flag expansion, headers
- [x] Hybrid Analysis removed entirely — module, all endpoints, quota entries, settings key,
      key tester, health check, frontend card/JS/settings — verified zero references remain
- [x] **Self-tunnel for remote access** — `core/server_manager.py` gained `start_self_tunnel()`/
      `stop_self_tunnel()`, independent state from the existing workspace tunnel, new Settings UI
      with a Start/Stop button. This tunnels the backend itself (dashboard + API, same origin),
      which is what actually makes remote usage work per last round's fix.
- [x] **Custom Nmap Command Library** — `core/custom_commands.py` (persisted, validated at save
      time), new Settings section to add/list/delete, integrated as a 4th "Custom" category in the
      Command Library dropdown. Tested: save, list, delete, and rejection of invalid/blocked flags
      at save time — all correct.
- [x] **Fixed the exact reported bug**: `-p80,443` (attached port-list syntax, no space) was
      rejected by the validator even though it's valid nmap syntax — the validator only handled the
      space-separated form. Fixed, plus the same attached-value handling extended to probe-type
      flags (`-PS80,443` etc).
- [x] **Substantially expanded the nmap allowlist** — added ACK/Window/Maimon/SCTP scan types,
      all ping-probe variants, DNS/exclude/timing/performance tuning, version/OS-detection tuning,
      `--script-args` (blocking only the literal `unsafe=1`/`true` toggle), debug verbosity. Declined
      only two categories, explained directly to the user: arbitrary file read/write, and
      attribution-evasion/third-party-implicating flags (decoy, idle/zombie scan, MAC/source-port
      spoofing, fragmentation, FTP bounce) — flagged as more relevant, not less, given this same
      round adds public tunnel exposure.
- [x] **Headers checker expanded from 6 to 29 headers**, covering the full pasted list. Corrected
      several severity/relevance classifications rather than copying the source verbatim — X-XSS-Protection,
      Feature-Policy, Expect-CT, and the legacy X-Content-Security-Policy are deprecated and marked
      informational (not "add this"); Public-Key-Pins is flagged as a finding only if *present*, since
      it's actively dangerous today, not if absent; CORS/caching/language headers marked informational
      since their absence is normal for non-API/non-caching-sensitive sites. Verified live against
      github.com: correctly found COOP/COEP/Permissions-Policy missing (real gaps) while correctly
      not flagging deprecated X-XSS-Protection presence as either good or bad.
- [x] Chat expand bug fixed two ways: toggle icon z-index raised above the panel's, and the expanded
      panel now anchors clear of the icon's corner entirely instead of extending into it — verified
      via `elementFromPoint` at the icon's screen position, confirming the icon (not the panel) is
      what actually receives clicks even while expanded.

## Test coverage note
Live combined server+browser tests were unreliable in this session again (server processes
intermittently failed to even start, independent of any code — confirmed by the same failure on a
bare `curl` with no other logic involved). Everything above was verified via direct backend function
calls (all passing, including live checks against github.com for headers and real nmap execution for
the flag fixes) and a backend-independent Playwright suite for the frontend (custom command library
UI, self-tunnel UI, Hybrid Analysis removal, chat expand fix — all passing). Do a manual smoke test of
the self-tunnel button and custom command library once you're running this yourself.

## Phase 12 — v11: nmap results bug, Clear buttons, 3D polish
- [x] **Real root cause of "nmap shows no results" found and fixed** — not a timeout, not the
      allowlist. Confirmed directly: nmap's XML summarizes ports as `<extraports state="closed"
      count="1000"/>` with NO individual `<port>` elements when every scanned port shares the same
      state (verified this happens even against 127.0.0.1 with a real listener, if the open port
      isn't in the scanned range). The parser only ever read individual `<port>` tags, so a
      completely legitimate "0 open, 1000 closed, host is up" result rendered identically to
      "nothing happened." Rewrote `_parse_nmap_xml` to surface host status, timeout state, the
      closed/filtered summary, and top-level scan stats. Verified against both a real all-closed
      scan and a real open-port scan (regression-checked) — both now show accurate, self-explanatory
      results instead of an ambiguous empty array.
- [x] Clear buttons added to every Security Sessions card (Full Assessment, Headers & IP, Nmap,
      SSL/DNS/NEL) plus a dedicated Clear on Session Output — reset inputs/status/progress for that
      card only, never touch saved history. Tested each individually.
- [x] 3D backdrop rebuilt as a red-green duality pair — two counter-rotating wireframe icosahedrons
      (green outer, red inner) plus a mixed red/green particle field, replacing the single green
      shape + blue particles. Banner glow, card top-border accent, and hover states updated to match.
      Verified error-free with a corrected test harness (added `THREE.Color` to the stub, which
      surfaced that the harness — not the actual code — was the gap).

## Phase 13 — v12: crash recovery, nmap re-verification, terminal UI
- [x] **Sandbox container was recycled mid-session** — `/home/claude` was wiped. Recovered from the
      last delivered zip in `/mnt/user-data/outputs` (v11) and reapplied everything from this
      session on top of it: the NSE script-output parsing fix, terminal UI, and a full naming sweep.
- [x] **Nmap script-output bug reapplied and reverified**: `--script vuln`/`banner`/`auth`/etc.
      results were being silently discarded (parser only read `state`/`service`, never `<script>`
      elements). Fixed and reverified live with a real banner-emitting TCP server after nmap was
      reinstalled post-reset — confirmed `scripts: [{"id": "banner", "output": "220 Test Banner..."}]`
      now appears correctly.
- [x] All 20 Command Library entries revalidated against the actual validator post-recovery — still
      all syntactically valid (confirming the original "doesn't produce output" complaint was the
      script-parsing bug above, not bad command syntax).
- [x] **Live Terminal panel** added to Security Sessions — real streaming for nmap async jobs (pulls
      from `job_manager`'s already-captured `log_tail`), synthetic command+result echo for the
      synchronous scans (headers/ip/ssl/dns/nel) so the whole tab has consistent terminal-style
      feedback. Verified via Playwright: panel renders, command/output lines display correctly, no
      JS errors.
- [x] Final naming sweep across the whole codebase — found and fixed real stale "CIPHERGRID"
      references in `quota_tracker.py`, `system_info.py`, `ai_gateway.py`, and — most importantly —
      `chatbot.py`'s actual system prompt text, which would have had the AI assistant refer to
      itself as "CIPHERGRID" to the user. All fixed. Historical changelog mentions in
      README/FINDINGS/CHECKLIST/NAMING left as-is since those are accurate past-tense history, not
      current branding.

## Explicitly deferred (by user's own request, given repeated implementation friction)
- **Password protection**: user tried for two weeks on their own before this conversation and hit
  persistent issues; agreed to push this to a dedicated future version rather than force it in now.
  Nothing auth-related is in the current codebase — starting clean is one less thing to rip out later.
- **Hacker-themed boot/welcome screen + time-aware "Master" greeting**: originally scoped as
  post-login flow. Since login is deferred, this should be rebuilt as a standalone loading animation
  (no password gate) if picked up later — decoupling it from auth entirely rather than reviving it
  half-tied to a feature that no longer exists in the codebase.
- **Session/access log** (who's accessing the tool, device, browser, location, IP): same story —
  was originally a login-event log. Without login, this would need to become lightweight visit
  tracking instead (e.g. a `/api/track-visit` endpoint called once per page load), which is a
  meaningfully different feature than what was scoped, not just a smaller version of it.

## Phase 14 — v13: Shodan integration
- [x] `backend/modules/shodan_client.py` — built against Shodan's real, verified REST API contract
      (checked developer docs before writing any code, learned from the Hybrid Analysis mistake of
      guessing): `GET /shodan/host/{ip}` (passive, free), `GET /shodan/host/search` (query credits),
      `GET /api-info` (free), `POST /shodan/scan` (scan credits), `GET /dns/resolve` (free).
- [x] `secrets_store.py` — `shodan_api_key` added to `KNOWN_KEYS`, same local/gitignored storage as
      every other key.
- [x] `quota_tracker.py` — `shodan` service added: `search` and `scan` gated at 100/month each
      (Membership tier, 1 call ≈ 1 credit, conservative floor — same approximation as AnyAPI's
      token quota); host lookup, dns/resolve, and api-info left ungated since Shodan doesn't charge
      for them.
- [x] `key_tester.py` — `test_shodan()` added via the free `/api-info` call, wired into `test_all()`.
- [x] `main.py` — 5 new endpoints (`/api/shodan/host/{ip}`, `/search`, `/account`, `/scan`,
      `/dns/resolve`), each calling `history.save_entry()` so results flow into Reports for
      PDF/TXT/email export automatically — confirmed the Reports export path is fully generic
      (`buildReportText`/`buildReportPdfDoc` serialize any entry), so no extra work was needed there.
- [x] Frontend — new "Shodan" card in Security Sessions (host lookup w/ optional history, search
      w/ facets, on-demand scan carrying the same "only scan what you're authorized to test" framing
      as nmap, DNS resolve, Check Credits Remaining button), new Settings key card, wired into
      `clearCard()` and the `loadKeyStatus`/`saveKey`/`testKey` maps.
- [x] Tested: backend boots clean with all 5 routes registered; no-key path returns the correct
      error from every function; directly verified the quota gate blocks a search before it ever
      calls the real Shodan API once 100 calls are recorded in a month window; JS syntax validated
      with `node --check`; every new element ID referenced in JS confirmed to exist exactly once in
      the HTML.
- [ ] Live call against a real Shodan key wasn't possible this round — no key, no external network
      from this sandbox. Do a manual smoke test of each of the four actions (host lookup, search,
      scan request, dns resolve) plus Check Credits Remaining once you're running this yourself.

## Phase 15 — v14: chat response modes + Ollama timeout/loading fix
- [x] **Root cause of the "Ollama not working" report confirmed, not assumed.** Live evidence (your
      own screenshot) showed `Read timed out. (read timeout=120)` while Ollama's own server was up
      and a separate terminal chat against it was working, just slow. `modules/ollama_client.py` had
      a hardcoded 120s `requests` timeout on a synchronous, non-streaming call — legitimate CPU-only
      generations (especially with this tool's attached log-tail/health/quota system-prompt context
      on top) were being cut off mid-generation, not actually hanging. Bumped to 600s.
- [x] **Loading/reading/structuring indicator with a live elapsed-time counter**, requested
      explicitly: the chat panel now shows a ticking `⟳ <stage>... Ns` line while waiting on any
      provider (0–4s "Loading model & reading context", 4–12s "Reading your findings", 12s+
      "Structuring response"), with an extra one-time hint when the provider is Ollama specifically
      ("local inference, can take a couple of minutes"). This directly replaces the old "nothing
      visible happens until it either replies or the request dies" behavior from the screenshots.
- [x] **Three response-mode buttons** (Short / Descriptive / PoC) added above the chat input — sent
      as `mode` on `/api/chat`, consumed in `core/chatbot.py`'s system prompt:
      - **Short** — main points only, tight bullets, no restating the question.
      - **Descriptive** — full explanation with context, the previous default depth.
      - **PoC** — a consistent per-finding structure (Issue / Affected component / Preconditions /
        How it could be exploited / Impact / Remediation) matching how a pentest report is
        organized. Deliberately scoped to describe exploitation *mechanism*, not hand back working
        exploit code or weaponized step-by-step commands — same authorized-testing framing already
        used everywhere else in this tool (nmap, Shodan scan requests).
- [x] Tested: system prompt builder confirmed to inject the right mode instruction for all three
      modes plus a safe fallback to Descriptive on an unrecognized mode value; `/api/chat` endpoint
      wired through end-to-end; backend recompiles clean, all 50 routes still register; frontend JS
      re-validated with `node --check`.
- [ ] **Not done / needs your live environment**: true token-by-token streaming from Ollama wasn't
      built this round — what's here is a staged elapsed-time indicator on top of the existing
      request/response call, not a persistent stream. It fixes the timeout and the "looks frozen"
      problem, but a genuinely long generation still won't show partial text until it's fully done.
      If that's still not enough once you've tried it live, real streaming (via Ollama's own
      `stream: true` NDJSON response over a WebSocket) is the next step up — flagging it rather than
      claiming this round already did it.

## Phase 16 — v15: Access & Limits (editable timeouts + visitor/session log)
- [x] `core/runtime_config.py` — every hardcoded timeout across the AI providers (Anthropic, OpenAI,
      Gemini, Groq, OpenRouter, AnyAPI, Ollama) and scan tools (nmap, headers, ssl, nel) moved to a
      bounds-checked, editable store. Every client module and the relevant `main.py` call sites now
      read from it instead of a literal number; takes effect immediately, no restart, no caching at
      import time.
- [x] `core/access_log.py`, `core/geoip.py`, `core/ua_parser.py` — session/visitor log for when this
      is tunneled and shared: cookie-based session id, IP (X-Forwarded-For/X-Real-IP first), free
      approximate geolocation (ipapi.co, no key), a small dependency-free UA parser for browser/OS/
      device, and a human-readable action label per request.
- [x] `main.py` — new `access_log_middleware`, fire-and-forget so logging never adds latency to the
      actual response; new endpoints for both features (`/api/settings/runtime-config`,
      `/api/access-log`).
- [x] Frontend — new "Access & Limits" tab: Limits & Timeouts (grouped, editable, Save/Reset per
      setting) and Access Log (summary + table, Refresh/Clear). All visitor-controlled fields
      (path, forwarded IP, geoip result) go through a new `escapeHtml()` before hitting `innerHTML` —
      this data can come from an untrusted visitor once tunneled, so it's treated as such rather
      than assumed safe because it originates from "just a log."
- [x] **Two real bugs found and fixed during testing, not just written and assumed correct:**
      1. The access-log's `_label_for()` catch-all for `"/"` was matching via `.startswith("/")`,
         which is true for every path — every unmapped request was mislabeled "Loaded the dashboard"
         instead of falling back to the raw path. Caught by testing `/api/status` specifically,
         fixed by requiring an exact match for the root path.
      2. The access log's read-modify-write to its JSON file had no lock. Ran 10 threads × 30 writes
         concurrently and lost entries to the race, confirmed with a raw count mismatch before the
         fix and an exact match after adding a `threading.Lock` around the load+append+save. Applied
         the same lock to `runtime_config.py`'s read-modify-write for the same reason, pre-emptively.
- [x] **A design bug, not just a code bug**: checking `access_log_enabled` *inside* `record()` meant
      the request that disables logging flips the flag before its own entry gets written, so the
      disable action silently swallowed its own audit trail. Traced this via a live uvicorn
      integration test (not just unit tests) that counted events across a disable/enable sequence
      and caught the off-by-one. Fixed by deciding whether to log *before* `call_next` in the
      middleware, and — since that alone would make the *enable* action symmetrically invisible for
      the opposite reason — added a guaranteed, always-recorded entry specifically for this one
      toggle regardless of before/after state, so both directions are provably visible in the log.
- [ ] **Not done**: true token-by-token Ollama streaming (still open from Phase 15). The access log
      currently has no UI-side auto-refresh/live-tail — it's Refresh-button-driven, not push-based;
      a `/ws/access-log` stream would be the natural next step if you want it updating in real time
      while watching it.

## Phase 17 — v16: chat PDF export, Clear, New Chat
- [x] Chat panel: three new buttons — **PDF** (download the current chat as a formatted transcript),
      **New Chat** (offers to save a PDF first if there's anything to lose, then clears), **Clear**
      (wipes immediately, with a confirm). All client-side, no backend changes this round.
- [x] `buildChatPdfDoc()` mirrors the existing `buildReportPdfDoc()` styling (same fonts, header
      bar, footer line) so a chat transcript looks like it belongs next to the scan report PDFs
      rather than being a visibly different one-off.
- [x] Reads from `chatHistory`, the array already backing the real `/api/chat` calls — not scraped
      from the DOM — so the PDF is an accurate transcript of what was actually sent/received, and
      doesn't pick up UI-only lines like the "thinking..." indicator or the "context attached"
      marker.
- [ ] Not done: no server-side persistence of past chats — "New Chat" clears the in-memory
      transcript entirely rather than filing it into a browsable list of previous sessions. If you
      want to come back to an old conversation later rather than just having its PDF, that's a
      bigger feature (server-side chat history, like the existing scan-history/Reports system) and
      hasn't been scoped yet.

