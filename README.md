<div align="center">
  <img src="favicon2.ico" width="88" alt="CHOMBEZA">

  <h1>CHOMBEZA Bug Bounty Pro</h1>
  <p><strong>A cyberpunk-themed VAPT &amp; bug-bounty toolkit with resumable scans, a live findings feed, and a built-in Blind-XSS server.</strong></p>

  [![Version](https://img.shields.io/badge/Version-2.4-0bf?style=for-the-badge)](https://github.com/archnexus707/chombeza)
  [![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org)
  [![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-ff2e88?style=for-the-badge)](#-installation)
  [![Status](https://img.shields.io/badge/Status-Active%20Development-00ff66?style=for-the-badge)](#-roadmap)
  [![License](https://img.shields.io/badge/License-Proprietary-red?style=for-the-badge)](LICENSE.txt)

  <sub>Created by <b>Dickson Godwin Massawe</b> — <a href="https://github.com/archnexus707">@archnexus707</a></sub>
</div>

---

> **⚠ Authorized use only.** CHOMBEZA is a dual-use security testing tool. Run it only against targets you own or have **explicit written permission** to test. Unauthorized scanning is illegal in most jurisdictions.

---

## 📋 Table of Contents

- [✨ What's new in 2.4](#-whats-new-in-24)
- [✨ What's new in 2.3](#-whats-new-in-23)
- [✨ What's new in 2.2](#-whats-new-in-22)
- [✨ What's new in 2.1](#-whats-new-in-21)
- [🚀 Highlights](#-highlights)
- [📥 Installation](#-installation)
- [⚡ Quick Start](#-quick-start)
- [📖 Full usage guide](USAGE.md) — workflows, mid-scan ops, bug-bounty scenarios, troubleshooting
- [🖥️ The GUI, piece by piece](#️-the-gui-piece-by-piece)
- [💻 CLI reference](#-cli-reference)
- [🔁 Resumable scans](#-resumable-scans)
- [📊 Live Findings Feed + Live Traffic](#-live-findings-feed--live-traffic)
- [🎨 Themes](#-themes)
- [🎯 Vulnerability coverage](#-vulnerability-coverage)
- [🔐 Authentication](#-authentication)
- [🤖 AI Enhancement (Bring-Your-Own-Key)](#-ai-enhancement-bring-your-own-key)
- [📄 Reports](#-reports)
- [⌨️ Keyboard shortcuts](#️-keyboard-shortcuts)
- [📁 Project structure](#-project-structure)
- [🛠️ Building from source](#️-building-from-source)
- [🗺️ Roadmap](#️-roadmap)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)
- [👨‍💻 Author](#-author)

---

## ✨ What's new in 2.4

A bug-bounty-yield iteration. Three high-leverage detection families (subdomain takeover, content discovery, multi-account authz replay), three coverage adds (race conditions, OAuth flaws, HTTP method tampering), a hardened auth layer (auto-rotation + circuit breaker + manual refresh), live-traffic filtering, and a queue/scan stability pass. ~9 new modules, 4 new finding types, 1 new top-tab cleanup.

| Area | What changed |
|---|---|
| **Auto-rotation: session/CSRF tokens** | Real apps (Django, Laravel, Rails, ASP.NET) rotate CSRF tokens mid-session. CHOMBEZA now extracts fresh tokens from every response — `Set-Cookie` (`csrftoken`/`sessionid`/`XSRF-TOKEN`), `<meta name="csrf-token">`, hidden form fields (`csrfmiddlewaretoken`/`authenticity_token`/`_token`/`__RequestVerificationToken`), and `X-CSRF-Token` response headers — and silently fans them out to every live worker session + `auth_manager.config`. The next request goes out with the fresh token; the "expired" detector never even fires. ([core/auth_rotation.py](core/auth_rotation.py)) |
| **Re-auth circuit breaker** | Three-tier protection against the "attempt #531, #532..." re-auth death spiral that happens when a target's auth backend is broken: ≤3 consecutive fails per host → 5-min cooldown · ≤30 re-auths per scan total · ≥5s minimum between attempts on the same host · "useless re-auth" detection (refresh said OK but cookies didn't change → counts as a fail). User gets a toast pointing to Tools → Refresh Auth instead of an infinite log spew. |
| **Manual Refresh Auth (mid-scan)** | New `Tools → 🔑 Refresh Auth` modal. Paste a fresh cookie / bearer / CSRF from your browser dev-tools and CHOMBEZA fans the credentials across every live worker session AND persists them to `auth_manager.config` so future workers inherit. Fixes the prior "throwaway session" bug where Refresh Auth silently updated nothing. |
| **HTTP method fuzzing — safety-tiered** | Always-on (zero risk): `OPTIONS` probe per route shape + `HEAD vs GET` authz-bypass diff. Off-by-default (gated): `DELETE / PUT / PATCH` and method-override headers (`X-HTTP-Method-Override: DELETE`). Three nested gates must ALL pass before a destructive verb is sent: (1) `Settings → Aggressive Verb Fuzzing` ticked, (2) OPTIONS confirmed the verb in `Allow:` ("TRUE_POSITIVE only" — never sends a verb the server didn't claim to support), (3) URL doesn't match payment/billing/charge/transfer keywords unless second flag set. Per-dispatch console + toast warning. Confirmation modal on enable. ([core/method_fuzz.py](core/method_fuzz.py)) |
| **3 new method-tampering findings** | `HTTP Method Authz Bypass (HEAD)` (HIGH, CWE-863) · `HTTP Verb Tampering (DELETE/PUT/PATCH)` (CRITICAL, CWE-650) · `HTTP Method Override Honored` (HIGH, CWE-650). All emitted with auth-inherited probe-request comparisons against GET to confirm the bypass before firing. |
| **Subdomain takeover (51 fingerprints)** | DNS-resolves the apex + 20 common prefixes, HTTP-probes each, and matches CNAME + body against 51 services pulled from the can-i-take-over-xyz database (AWS S3, Cloudfront, GitHub Pages, Heroku, Shopify, Tumblr, Azure, Bitbucket, Webflow, Zendesk, Surge, Fastly, Netlify, Pantheon, Ghost, Helpscout, Tilda, Strikingly, UserVoice, Statuspage, …). 12 concurrent workers; HIGH severity per match. ([core/takeover_check.py](core/takeover_check.py), [core/takeover_fingerprints.py](core/takeover_fingerprints.py)) |
| **Content discovery** | 248-path wordlist + 27 sensitive-file paths (`.git/HEAD`, `.env*`, `wp-config.php.bak`, `db.sqlite`, `phpinfo.php`, …) with wildcard-baseline filtering so 200-OK-everything targets don't carpet-bomb the report. Surfaces hidden directories, backup files, exposed source. ([core/content_discovery.py](core/content_discovery.py)) |
| **Multi-account authz replay** | Pastes a SECOND set of credentials (User-B) into Settings → Multi-Account Authz Replay; after discovery, every protected URL the primary session got 200 on is replayed with the secondary session. URLs where User-B also gets 200 (with similar shape) become **HIGH-severity Broken Access Control** findings (CWE-639). Login-page / shape-similarity filters reject false positives. ([core/authz_replay.py](core/authz_replay.py)) |
| **Race conditions (HTTP/2 single-packet attack)** | Burst N parallel requests at a known race-window endpoint (transfer / pay / redeem / coupon-redemption) and look for divergent responses. Uses `httpx` HTTP/2 single-packet attack when `h2` is installed; falls back to threaded HTTP/1.1 with `threading.Barrier`. CWE-362. ([core/race_condition.py](core/race_condition.py)) |
| **OAuth 2.0 / OIDC flaw detection** | Five sub-checks per discovered authorize endpoint: redirect_uri validation (open redirect via attacker callback), missing `state` (CSRF), implicit flow (token in URL fragment), PKCE not enforced for public clients, scope over-issuance. Auto-discovers `/oauth/authorize`, `/connect/authorize`, etc. ([core/oauth_check.py](core/oauth_check.py)) |
| **AI-driven adaptive payload obfuscation** | When deep / stealth / aggressive scan + AI is configured, the LLM proposes obfuscated payload variants tailored to the discovered tech stack + WAF + parameter encoding (URL-encoded / base64 / hex / JWT / high-entropy). Process-lifetime cache (256 entries, LRU) so the same (vuln, base, encoding, waf) doesn't re-prompt. Sanitizes destructive variants. ([core/ai_features.py](core/ai_features.py), [core/payload_intel.py](core/payload_intel.py)) |
| **Live Traffic Monitor: filter bar + body search** | Status-class chips (2xx / 3xx / 4xx / 5xx / other) toggle row visibility · method dropdown filter (POST-only mode etc.) · live URL substring filter · `Ctrl+F` body search across request_headers + request_body + response_headers + response_body with prev/next navigation + match-count label. Newly-added rows respect the active filter. Late status updates (via `add_response`) re-evaluate the row's status class. ([ui/live_traffic_window.py](ui/live_traffic_window.py)) |
| **Queue stability: cap + smart payload reduction + ETA** | Hard total-task cap (default 50,000) prevents runaway queue builds. When the cap looms, payload count per vuln type is auto-trimmed before the queue overflows. Progress beat now emits phase ("param injection" / "probe layer") + done/total + ETA every 2s. Stall watchdog warns when no task added for >15s. ([core/scanner.py](core/scanner.py)) |
| **Per-origin checker dedup** | Header / cookie / path-segment fuzzing now collapses by origin and by route shape — same `/users/<id>` route gets one OPTIONS / one path-fuzz set, not 100 (one per concrete user id). Cuts queue size on REST-heavy targets by 90%+ without dropping coverage. |
| **Sidebar removed; top-tabs only nav** | Cleaner UI. The tab bar + `Ctrl+1..9` shortcuts + `Ctrl+K` command palette already covered every nav case the sidebar duplicated. Reclaims ~180 px of horizontal real estate. |
| **PDF export fix** | Dedicated PDF code path with diagnostic error messages (replaces the earlier silent fallback that just said "Failed to generate" with no clue why). |
| **Duplicate report fix** | Idempotency cache at the top of `generate_report()` so calling it twice in the same scan no longer writes two side-by-side files with the same id. |
| **Render fixes** | Scroll-area transparency caused tab content to ghost-overlay during fast tab switches — fixed with explicit opaque QSS rules on `QScrollArea` + `QAbstractScrollArea`. Matrix-rain bleed-through behind tab content fixed via 3-layer opaque central widget (palette + ID-scoped QSS). High-contrast Recent: / Scan Type: labels (`#e5e7eb`) — were unreadable on the dark theme. |
| **AI adaptive learning visibility** | Strengthened `_LEARNING_SYSTEM` prompt to actively flag concrete FPs (`manifest.webmanifest`, login-redirect URL-encoded params, …). Per-finding triage results now visible as colored pills in the report; learning-loop writes are logged to the AI Console tab. |

## ✨ What's new in 2.3

A big iteration focused on adaptive intelligence, coverage breadth, accuracy, workflow, and visualization. Roughly 15 new modules + 3 new GUI tabs + 5 new visualization panels. For a chronological log, see [CHANGELOG.md](CHANGELOG.md).

| Area | What changed |
|---|---|
| **AI few-shot triage** | Every triage prompt is now seeded with the prior scan's confirmed-TP payloads + FP signatures. Verdict accuracy sharpens with each repeat scan of the same target. ([core/ai_memory.py](core/ai_memory.py), [core/ai_features.py](core/ai_features.py)) |
| **Discovery upgrades** | (a) JS source-map mining harvests endpoint paths from leaked `.js.map` files. (b) OpenAPI / Swagger / GraphQL auto-discovery probes ~30 well-known spec paths + runs GraphQL introspection. (c) Subdomain enumeration via crt.sh + small DNS bruteforce (opt-in). ([core/sourcemap_miner.py](core/sourcemap_miner.py), [core/api_discovery.py](core/api_discovery.py), [core/subdomain_enum.py](core/subdomain_enum.py)) |
| **DOM-aware XSS verification** | After a payload reflects, CHOMBEZA loads the URL in headless Chrome, hooks `alert/confirm/prompt/eval`, and only confirms XSS at 99% confidence if a JS side-effect actually fires. CSP-protected reflections are silently suppressed. ([core/xss_dom_verifier.py](core/xss_dom_verifier.py)) |
| **Adaptive per-host concurrency** | Replaces the static global limiter with per-host token buckets that back off on 429/503 (exp 2→32s) AND ramp up on sustained healthy traffic (×1.4 up to ×2.5 base after 30 healthy 2xx with median < 600ms). ([core/engagement.py](core/engagement.py)) |
| **Cross-scan diff / trend mode** | Stable per-finding fingerprints saved at `reports/scan_history/`. Every subsequent scan auto-computes `new` / `unchanged` / `fixed` / `regressed`. Renders as a dedicated HTML report section + a new 📈 TRENDS tab. ([core/scan_diff.py](core/scan_diff.py)) |
| **Per-finding replay artefacts** | Every finding now carries a copy-pasteable `curl` one-liner + a HAR-1.2 dict importable into Burp / ZAP / Caido. Renders in the report's Replay sections. ([core/replay_export.py](core/replay_export.py)) |
| **Differential SQLi timing baselines** | Blind time-based SQLi now requires payload latency to exceed the per-endpoint baseline median by ≥2.5s absolute AND ≥2× ratio. Kills "this URL was just slow today" false positives. |
| **Capture proxy mode** | New 🕸️ PROXY tab. Point your browser at `127.0.0.1:8888`, exercise the target manually, every request lands in a live table. Closes the SPA + multi-step-auth coverage gap. HTTP is fully intercepted; HTTPS recorded by host:port via CONNECT (deliberately no on-the-fly cert generation). ([core/proxy_capture.py](core/proxy_capture.py)) |
| **CMS scanner** | Per-host fingerprint for WordPress / Drupal / Joomla / Magento / Shopify with a curated version → CVE map (Drupalgeddon, WP 5.x SQLi, Joomla com_fields, Magento mail RCE, etc.). Enable `cms` in HUNT. ([core/cms_scanner.py](core/cms_scanner.py)) |
| **Webhook notifications** | Mid-scan + post-scan push to Slack / Discord / Telegram / generic JSON. Auto-detects platform from URL (Telegram = `tgbot://<token>/<chat_id>`). Severity-filtered, deduped per (finding, URL). ([core/notifications.py](core/notifications.py)) |
| **WAF mid-scan bypass burst** | When `WAFDetector` fingerprints a WAF (Cloudflare / Akamai / AWS / Imperva / ModSecurity / F5 / etc.), CHOMBEZA fires a one-shot burst of level-3 mutated payloads (URL double-encoding, mixed-case hex, comment obfuscation, base64) against the most-parameterised URLs already discovered. |
| **MCP server** | Pure-stdlib JSON-RPC over stdio. Exposes 6 tools (`list_scans`, `get_scan`, `query_findings`, `get_finding`, `compare_scans`, `get_ai_memory`) + `chombeza://` resources to Claude Desktop / Cursor / mcp-cli. ([core/mcp_server.py](core/mcp_server.py), [mcp_serve.py](mcp_serve.py)) |
| **GUI: Target Intel row** | Three new cards on RESULTS: discovery-source breakdown, per-host health (rate + state pill + median latency), AI brief for the current target. ([ui/intel_panels.py](ui/intel_panels.py)) |
| **GUI: Live Activity row** | Findings Timeline sparkline (severity-coloured bars over scan time) + URL Hotspots card (top URLs ranked by request volume + finding badge). ([ui/viz_panels.py](ui/viz_panels.py)) |
| **GUI: 🧠 AI CONSOLE + 📈 TRENDS tabs** | Live LLM activity feed (prompts/responses/memory writes with token + cost estimates) + cross-scan dashboard reading from `scan_history/`. |
| **GUI: Toast notifications** | Non-blocking transient pop-ups for WAF detected, prior intel loaded, HIGH+ findings, FP marks. Auto-stack bottom-right; fade-in/out. |
| **GUI: Right-click context menu** | On any finding row: copy URL / parameter / payload / curl, open in browser, mark as false positive. |
| **GUI: Recent targets + Scan Again** | Dropdown of the last 10 (target, scan-type) pairs + one-click re-run of the most recent. |
| **Queue stats banner** | Per-vuln-type breakdown table with count / pct / ASCII bar + build duration + queue rate. Replaces the one-line "Queued N tasks" with something that actually tells you where the queue went. |
| **Navigation: menubar + Ctrl+K palette** | Top tabs are still the primary nav; on top of that there's a proper File/View/Tools/Help menubar with `Ctrl+1..9` shortcuts for every tab, plus a `Ctrl+K` fuzzy command palette over every tab + common scanner actions (Start/Stop/Scan Again/Open Last Report/Shortcuts). ([ui/navigation.py](ui/navigation.py)) |
| **Text contrast pass** | Replaced every `palette(Mid)` text usage in the new viz/intel panels with explicit high-contrast colors (`#cbd5e1`, `#9ca3af`, `#e5e7eb`) plus bumped font weights on small labels. Fixes the "I can't see this text" issue on the dark cyberpunk theme. |

## ✨ What's new in 2.2

| Area | What changed |
|---|---|
| **AI Enhancement (BYO API key)** | Optional LLM layer: per-finding triage (TP / FP / uncertain), pre-scan strategy briefs from prior memory, post-scan learning loop that gets smarter at the next scan, and one-click HackerOne-format PoC writeups for HIGH/CRITICAL findings. Supports **Claude / OpenAI / DeepSeek / Ollama** — Ollama is local + privacy-safe. The tool runs identically with no key set. |
| **Adaptive Scan Memory** | Per-target JSON memory in `reports/ai_memory/`. After each scan, the LLM extracts FP signatures, confirmed-TP payloads, tech fingerprints, and "where to look next time". The next scan reads that brief and starts smarter. Cross-target lessons are promoted to a global memory. |
| **Vulnerability dedup by name** | Same vuln type (e.g. XSS) detected at 9 different paths used to count as 9 findings. Now it's 1 finding with 9 affected-instance rows in the report — accurate severity counts and a clean per-finding card. |
| **9 new vulnerability checkers** | NoSQLi, LDAP injection, XPath injection, JWT (alg=none + weak HMAC bruteforce + missing claims), Mass Assignment / Excessive Data Exposure, GraphQL introspection, IDOR (numeric/UUID swap), Broken Access Control (admin-path probe), Subdomain Takeover (DNS + fingerprint match). Total active checkers: 18 → 26. |
| **Tightened existing checkers** | SQLi error-based now requires SQL-shaped payload + DB-driver-specific patterns (no more "MySQL" mention triggering FPs). SQLi blind requires SLEEP-shaped payload + matching response time. HTTP Methods drops DELETE/PUT (REST APIs use them). Version Disclosure requires actual version digits. Backup Files requires 200 OK + non-HTML body. XSS only checks the payload that was sent for the param being attacked. |
| **Richer reports** | New per-finding fields: **OWASP Top 10** mapping, **Likelihood**, **Exploit Complexity**, **Verification status** (Active vs Passive), **AI verdict pill** (when AI enabled), **Affected Instances** sub-table for grouped findings. New top-level sections: **Scan Metadata**, **Limitations & Caveats** (lists stub vuln types user enabled), **AI Strategy Brief**, **Glossary** appendix. |
| **OS-aware compatibility map** | Each vuln type in the HUNT tab now shows a status icon: 🟡 stub (no detection logic), 🔒 OS-risky, ⛔ missing dep. New `🖥️ ENVIRONMENT` panel above the target field shows OS / Python / Chrome / Selenium / PyYAML status. |
| **Crash detection + diagnostics** | Global `sys.excepthook` + `threading.excepthook` write timestamped tracebacks to `reports/crash.log`. On startup, banner shown if crash.log was modified in the last 10 min. ScannerThread crashes pop a GUI dialog instead of the app freezing. Per-task context (URL + vuln_type + worker name) included in dump. |
| **GUI: Scan Dashboard Strip** | Always-visible cyber-styled bar below the tab row showing target / scan-type / elapsed / progress / req-per-sec / severity pills. Three states: idle (welcome message), active (live values + accent underline), done (frozen final stats). |
| **GUI: Live Visualization** | Severity donut + top-vuln-name bar chart on the RESULTS tab that grow live as findings arrive. Mirror the report visuals but in-app. |
| **GUI: HUNT vuln-type UX** | Collapsible category groups with per-category "Select all" + "(N of M)" counter, preset selector (OWASP Top 10 / Real checkers only / Stubs only / All / None / Custom), and search box. |
| **Phased progress bar** | "Scan Progress (Discovery)" → "(Queueing tasks)" → "(Injection)" → "(OOB SSRF wait)" → "(AI postprocess)" → "(Generating report)" → "(Complete)" — visible from any tab. |
| **CLI flags for AI** | `--ai-provider {claude,openai,deepseek,ollama}` `--ai-key` `--ai-model` `--ai-host` `--ai-test` `--ai-disabled`. The `--ai-test` flag round-trips a tiny request to confirm credentials and exits. |

## ✨ What's new in 2.1

| Area | What changed |
|---|---|
| **JS-rendered app support** | Discovery now renders entry-point URLs in headless Chrome and harvests runtime-injected anchors, forms, and XHR/fetch endpoints via the Chrome DevTools Protocol. Modern React/Vue/Angular SPAs — previously invisible to the static crawler — are now scannable. Works on Windows, Linux, and macOS via the same code path. Toggle with `js_rendering: auto\|on\|off` in `config.json`. |
| **17 vuln checks (was 9)** | SSTI, LFI, RCE, XXE, CORS, CSP, Open Redirect, CRLF now have real detection logic — each with unit tests covering both positive and false-positive cases. SSRF kept as explicit stub pending an OOB listener. |
| **Live Findings Feed** | New right-hand dock shows every finding as a neon card the moment it's detected — no more waiting for the scan to finish. Filter chips, search, pause, jump-to-Traffic, and unread badge when hidden. |
| **Resumable scans** | SQLite-backed scan store. Ctrl+C a 30-minute scan at minute 22, then `--resume <id>` to pick up exactly where you left off. Crash-safe (WAL journal). |
| **5 cohesive cyberpunk themes** | Neon Glow · Cyberpunk · Matrix · Dark Mode · Color Blind Safe — all driven by one theme engine with per-theme accent/glow/hover states. |
| **Cross-platform installers** | Robust `install.bat` and `install.sh` with Python version checks, graceful optional-dep fallback, Chrome detection, and auto-generated `run.bat` / `run.sh` launchers. |
| **Stable screenshots** | Chrome driver is reused across captures instead of spawning a new one per vuln (massive memory fix on big scans). Deduped per URL+vuln_type, capped at 50 per scan, graceful shutdown. |
| **CLI upgrades** | `--list-scans`, `--resume SCAN_ID`, `--delete-scan SCAN_ID`. |
| **Fixed HiDPI** | Scaling is pinned to 1× on Windows (where Qt over-scales) but honors system DPI on Linux/macOS — 4K displays now render at the correct size everywhere. |

---

## 🚀 Highlights

- 🎯 **Full scan pipeline** — discovery ➜ parameter extraction ➜ injection ➜ verification ➜ screenshot ➜ AI triage ➜ report
- 🤖 **AI Enhancement (BYO API key)** — Claude / OpenAI / DeepSeek / Ollama. Per-finding TP/FP triage with few-shot examples from prior memory, one-click PoC writeups. Tool runs identically without it.
- 🧠 **Adaptive Scan Memory** — every scan teaches the LLM about the target so the next scan starts smarter (focus areas, known FPs, confirmed TP payloads, tech stack)
- 🧩 **JS-aware discovery** — renders SPAs in headless Chrome, mines JS source-maps, auto-discovers OpenAPI/Swagger/GraphQL specs
- 🌐 **Subdomain enumeration** — crt.sh + DNS bruteforce, optional auto-expand into scope
- 🕸️ **Capture proxy mode** — analyst proxies their browser through CHOMBEZA, manual traffic becomes scan tasks
- 🛡️ **40+ active vulnerability checkers** — XSS (with DOM-aware verification), SQLi (error + blind with per-endpoint baselines), SSTI, LFI, RCE, XXE, OOB SSRF, CORS, CSP, Open Redirect, CRLF, NoSQLi, LDAPi, XPathi, JWT, Mass Assignment, GraphQL, IDOR, Broken Access Control, Subdomain Takeover (51 fingerprints), Multi-Account Authz Replay, Race Conditions (HTTP/2 single-packet attack), OAuth flaws (5 sub-checks), HTTP Method Authz Bypass / Verb Tampering, CMS fingerprint, HPP, Exception Handling, SRI, Mixed Content, JS Library Versions, TLS Audit, CSRF, File Upload, Default Credentials + 6 passive header checks
- 🔐 **Hardened auth layer** — auto-detects rotated session/CSRF tokens (Django/Laravel/Rails/ASP.NET) and silently fans them out to every worker · re-auth circuit breaker stops infinite retry loops on broken auth backends · `Tools → Refresh Auth` modal for paste-fresh-creds-mid-scan
- ⚠️ **Method tampering with safety tiers** — OPTIONS + HEAD authz-bypass always on (zero risk) · DELETE/PUT/PATCH gated by opt-in + OPTIONS-confirmed `Allow:` + critical-path heuristic (payment/billing/charge blocked unless second flag set)
- 📈 **Cross-scan trend mode** — automatic new/unchanged/fixed/regressed diff vs prior scan, with a dedicated GUI tab + HTML report section
- 📤 **Per-finding replay** — copy-pasteable `curl` + HAR-1.2 export importable into Burp / ZAP / Caido
- 🔔 **Webhook notifications** — mid-scan + post-scan push to Slack / Discord / Telegram / generic JSON
- 🤖 **MCP server** — Claude Desktop / Cursor / mcp-cli can query findings naturally ("show me HIGHs on foo.test this week")
- ⚡ **Adaptive per-host concurrency** — exponential backoff on 429/503, ramp-up on healthy traffic, WAF mid-scan bypass burst
- 🔁 **Vuln dedup by name** — one finding card per vuln type with all affected paths/parameters listed; accurate severity counts
- 📡 **Live Findings Feed** — vulns slide in as they're detected with `× N` counter that bumps when same-name detections merge
- 📊 **Live Visualization** — severity donut + bar charts grow live on RESULTS tab; persistent dashboard strip visible from any tab
- 🔁 **Resume anywhere** — paused scans survive crashes, reboots, power loss
- 📊 **Live Traffic Monitor** — request/response viewer with severity highlights and bi-directional jump-to
- 🎯 **Built-in Blind-XSS callback server** on port 5000 (used for OOB SSRF correlation)
- 🧪 **Payload Laboratory** — generate, obfuscate, and replay payloads
- 📸 **Evidence screenshots** — headless Chrome, single-driver reuse, embedded in reports
- 🔐 **Authentication** — cookies, Bearer tokens, or automated form login with CSRF handling
- 🌐 **Proxies** — HTTP(S) and SOCKS
- 📄 **Multi-format reports** — HTML (styled with OWASP / Likelihood / Complexity / AI verdict pills), PDF (ReportLab fallback), JSON, CSV
- 🖥️ **OS compatibility map** — per-vuln-type icons in HUNT tab tell you what works on your OS / what's a stub
- 💥 **Crash detection** — global excepthooks + per-worker task context written to `reports/crash.log`
- ⌨️ **Keyboard-first** — `Ctrl+F` search, `Ctrl+/` pause feed, `Ctrl+Shift+F` toggle dock, `Ctrl+Shift+K` clear

---

## 📥 Installation

### Windows

```bat
git clone https://github.com/archnexus707/chombeza.git
cd chombeza

:: Run the installer (creates venv, installs deps, drops run.bat)
install.bat

:: Launch
run.bat                            :: GUI
run.bat https://target.tld         :: CLI scan
```

The installer:
- Requires **Python 3.8+** (checked automatically)
- Creates a local `venv/`
- Installs core dependencies from [requirements.txt](requirements.txt)
- *Tries* optional extras from [requirements-optional.txt](requirements-optional.txt) but never fails the install if they don't build (weasyprint needs GTK — it's fine to skip)
- Warns if **Chrome / Chromium** isn't detected (needed for evidence screenshots)

### Linux / macOS

```bash
git clone https://github.com/archnexus707/chombeza.git
cd chombeza

bash install.sh

./run.sh                           # GUI
./run.sh https://target.tld        # CLI scan
```

The Linux/macOS installer detects your OS and prints distro-specific hints for any system packages you may need (Chromium, Pango, libxkbcommon, etc.). macOS installs via `brew` hints.

#### System packages you'll likely want

<details>
<summary>Debian / Ubuntu</summary>

```bash
sudo apt install -y python3-venv python3-dev \
                    libgl1 libxkbcommon0 libdbus-1-3 libfontconfig1 \
                    chromium-browser

# Optional (for WeasyPrint PDF export):
sudo apt install -y libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libgdk-pixbuf-2.0-0
```
</details>

<details>
<summary>Fedora / RHEL</summary>

```bash
sudo dnf install -y python3-devel mesa-libGL libxkbcommon dbus-libs fontconfig chromium
```
</details>

<details>
<summary>Arch</summary>

```bash
sudo pacman -S --needed python-pip libxkbcommon dbus fontconfig chromium
```
</details>

<details>
<summary>macOS (brew)</summary>

```bash
brew install python pkg-config
brew install --cask google-chrome
# Optional for WeasyPrint:
brew install pango cairo gdk-pixbuf libffi
```
</details>

---

## ⚡ Quick Start

```bash
# GUI
python main.py

# Quick scan
python main.py https://target.tld --scan-type quick

# Deep scan, 20 threads, XSS + SQLi only
python main.py https://target.tld --scan-type deep --threads 20 --vuln-types xss sqli

# List saved/paused scans and resume one
python main.py --list-scans
python main.py --resume 59b9522a45b4

# Standalone Blind-XSS callback server (no scan)
python main.py --blind-xss --blind-xss-port 5000

# Through a proxy
python main.py https://target.tld --proxy http://127.0.0.1:8080
```

---

## 🖥️ The GUI, piece by piece

```
┌─────────────────────────────────────────────────────────────────┬─────────────────────┐
│  CHOMBEZA BUG BOUNTY PRO            [▼ Theme]   [⛶]             │                     │
│  ═══════════════════════════════════════════════════════════     │  ◉ LIVE FINDINGS    │
│  [🔍 HUNT] [📊 RESULTS] [🎯 BLIND XSS] [🧪 LAB] [⚙ SETTINGS]  │  [⏸] [🗑]  count    │
│                                                                  │                     │
│         (active tab content)                                     │  [ALL] [CRIT] [HIGH]│
│                                                                  │  [search findings…] │
│  ─────────────────────────────────────────────                  │                     │
│  💻 CHOMBEZA CONSOLE       [🗑 Clear]                           │  ┌────────────────┐ │
│  > ...                                                           │  │ █  HIGH  XSS   │ │
│  Scan Progress: [████████████░░░░░░░] 62%                       │  │    /search…q=1 │ │
│  [Ready to hunt...]    [📊 Live Traffic]  ● Blind XSS: Active   │  │ VIEW ⎘ ↗ 📊 ✕  │ │
│                                                                  │  └────────────────┘ │
│                                                                  │   (more cards…)     │
└─────────────────────────────────────────────────────────────────┴─────────────────────┘
                                                                      ^
                                                                      │
                                                      Live Findings Feed (dockable)
```

Tabs:
1. **🔍 HUNT** — target URL, scan type, vuln-type checkboxes, thread/delay sliders, start/stop
2. **📊 RESULTS** — severity stats, discovery info, the full vuln tree + details pane, export buttons
3. **🎯 BLIND XSS** — server status, payload strings to copy, callback list
4. **🧪 PAYLOAD LAB** — generate obfuscated payloads (base64, unicode, HTML entities, JSFuck, etc.)
5. **⚙ SETTINGS** — concurrency, timeouts, proxy, user-agent, auth, optional features. Also home of the **⚠️ Aggressive Verb Fuzzing** opt-in (DELETE/PUT/PATCH) — off by default, two-step opt-in modal, OPTIONS-confirmation gate, and critical-path heuristic that blocks payment / billing / charge URLs unless a second flag is also set.

The **Live Findings Feed** dock on the right is independent of the active tab — it receives every finding in real time no matter where you are. Drag it to the left, float it on a second monitor, or close it and bring it back with `Ctrl+Shift+F`.

---

## 💻 CLI reference

```
usage: main.py [-h] [--list-scans] [--resume SCAN_ID] [--delete-scan SCAN_ID]
               [--scan-type {quick,deep,stealth,aggressive}]
               [--threads THREADS] [--timeout TIMEOUT] [--delay DELAY]
               [--output OUTPUT] [--format {html,json,csv,pdf,all}]
               [--blind-xss] [--blind-xss-port PORT]
               [--no-screenshot] [--proxy PROXY] [--user-agent UA]
               [--vuln-types VULN [VULN ...]] [--config PATH]
               [--ai-provider {claude,openai,deepseek,ollama}]
               [--ai-key KEY] [--ai-model MODEL] [--ai-host URL]
               [--ai-test] [--ai-disabled]
               [target]
```

### Core flags

| Flag | Effect |
|---|---|
| `target` | Target URL (optional when using `--list-scans` / `--resume` / `--ai-test`) |
| `--scan-type` | `quick`, `deep`, `stealth`, `aggressive` (default: `quick`) |
| `--threads N` | Concurrent worker threads (default 10, cap 100) |
| `--timeout N` | Request timeout in seconds |
| `--delay MS` | Delay between requests (ms) |
| `--vuln-types ...` | Restrict to specific vuln types |
| `--proxy URL` | HTTP/HTTPS/SOCKS proxy |
| `--user-agent S` | Custom User-Agent |
| `--no-screenshot` | Skip evidence screenshots |
| `--blind-xss` | Start Blind-XSS callback server in-process |
| `--blind-xss-port` | Port for the Blind-XSS server (default 5000) |
| `--output NAME` | Report name prefix |
| `--format` | `html`, `json`, `csv`, `pdf`, or `all` |
| `--config PATH` | Use a custom `config.json` |
| `--list-scans` | Print saved scans (id, status, target, pending/done/vulns) |
| `--resume SCAN_ID` | Resume a paused scan |
| `--delete-scan SCAN_ID` | Remove a saved scan from the store |

### AI / LLM enhancement flags (Bring-Your-Own-Key)

| Flag | Effect |
|---|---|
| `--ai-provider {claude,openai,deepseek,ollama}` | Enable AI features with the chosen LLM provider |
| `--ai-key KEY` | API key for the chosen provider (ignored for ollama) |
| `--ai-model MODEL` | Model override (e.g. `claude-haiku-4-5-20251001`, `gpt-4o-mini`, `deepseek-chat`, `llama3.1`) |
| `--ai-host URL` | Ollama host URL (default `http://localhost:11434`, ignored for cloud providers) |
| `--ai-test` | Test the AI connection and exit (no scan). Returns exit code 0 on success, 1 on failure |
| `--ai-disabled` | Force-disable AI for this run, even if config has a key set |

---

## 🔁 Resumable scans

Every scan is persisted to a SQLite database at `reports/scans.db` with three tables — `scans`, `queued_tasks`, `vulnerabilities` — linked by `scan_id`. WAL journal mode means it's crash-safe.

```bash
# Run scan normally
python main.py https://target.tld --scan-type deep

# Kill it with Ctrl+C mid-flight. Console will print:
⏸  Scan paused with 2,347 tasks remaining. Resume with:  --resume 59b9522a45b4

# Later — reboot, crash, whatever — pick up exactly where it stopped:
python main.py --list-scans
python main.py --resume 59b9522a45b4
```

The store also fingerprints each finding by `(name, url-path, parameter, cwe)` which lays the groundwork for future **differential scanning** (show only what changed since the last run).

---

## 📊 Live Findings Feed + Live Traffic

Two views, one signal bus. When the scanner finds something, it emits `vulnerability_detected` once; **both** the Findings Feed and the Live Traffic window subscribe.

### Findings Feed (right dock)

Each finding becomes a **neon card** with:

- Severity color strip (red / orange / amber / green / cyan)
- Severity badge with glowing drop-shadow
- Finding name · timestamp · URL · parameter · payload preview
- **Actions:** `VIEW` (jump to Results tab) · `⎘ PAYLOAD` (copy) · `↗ URL` (open in browser) · `📊 TRAFFIC` (jump to the matching row in Live Traffic) · `✕` (dismiss)
- Entry glow pulse fades from 24 px → 6 px over 1.2 s

**Controls:** filter chips (All / Crit / High / Med / Low / Info), search box, pause toggle, clear, total counter, unread-count badge when the dock is hidden.

### Live Traffic window

Existing request/response tree with a per-row status-code color, response-time, and payload viewer. Clicking `📊 TRAFFIC` on a Findings Feed card opens this window and scrolls to the exact request that triggered the finding.

Both are fed by the same `traffic_signals.vulnerability_detected` signal, so they can never drift out of sync.

---

## 🎨 Themes

Five hand-tuned palettes, one engine ([ui/styles.py](ui/styles.py)):

| Key | Name | Primary / Secondary |
|---|---|---|
| `neon` | **Neon Glow** | Hot pink `#ff2e88` / Cyan `#00e5ff` — Miami Vice × Blade Runner |
| `cyberpunk` | **Cyberpunk** | Electric yellow `#fcee09` / Red `#ff003c` — Cyberpunk 2077 on deep purple |
| `matrix` | **Matrix** | Phosphor green `#00ff66` / Bright green `#39ff14` — classic terminal dystopia |
| `dark` | **Dark Mode** | Ice blue `#00d9ff` / Silver-blue `#a8c5ff` — minimalist futuristic |
| `color_blind` | **Color Blind Safe** | Orange `#ff9500` / Blue `#0099ff` — deuteranopia/protanopia-safe, still cyber |

Every theme includes consistent:
- Button hover that floods with the accent color
- Focus rings (2 px) on inputs
- Live progress gradients
- Scrollbar handles with gradient fills
- Tooltip borders in the accent color
- Tab bar with three distinct states (default / hover / selected)
- Cascading matrix-rain or floating particles matching the accent

The top-level `GlitchLabel` header renders a **live scanline** sliding top-to-bottom in the theme's accent plus occasional red chromatic-aberration lines — pure CRT interference.

---

## 🎯 Vulnerability coverage

### ✅ Fully implemented (26 active checkers + 6 passive header checks)

**Injection family**
| Check | Severity | Detection method |
|---|---|---|
| **XSS** | HIGH | Sent payload contains an XSS marker (`<script`, `<svg`, `onerror`, …) AND reflects un-encoded in HTML/JS/JSON response |
| **SQLi (error-based)** | CRITICAL | SQL-shaped payload sent + DB-driver-specific error pattern (`You have an error in your SQL syntax`, `ORA-NNNNN`, `Warning: mysql_fetch_*`, `[Microsoft][ODBC]`, …) |
| **SQLi (blind, time-based)** | HIGH | `SLEEP(N)` / `WAITFOR DELAY` / `pg_sleep(N)` / `BENCHMARK(...)` / `DBMS_PIPE` payload sent + observed response time ≥ 80% of requested delay |
| **SSTI** | CRITICAL | Arithmetic expression evaluated server-side (e.g. `{{7777*7}}` → `54439`), or engine error leak (Jinja2 / Freemarker / Velocity / Liquid) |
| **LFI** | CRITICAL | `/etc/passwd`, `boot.ini`, `win.ini`, `wp-config.php`, or PHP source retrieved via path traversal |
| **OS Command Injection** | CRITICAL | Shell-output signatures (`uid=/gid=/groups=`, `Volume in drive`, `\Windows\System32`, `Active code page`) in response |
| **XXE** | CRITICAL | File content retrieved via external entity expansion in XML payload |
| **NoSQL Injection** | HIGH | Mongo-style operator payload (`$ne`/`$gt`/`$where`/…) sent + auth-bypass markers in response or 200 from auth endpoint |
| **LDAP Injection** | HIGH | `*` / `()` payload + LDAP driver error (`javax.naming`, `LDAP: error code`, …) |
| **XPath Injection** | HIGH | `\| //*` payload + XPath driver error (`XPathException`, `libxml2 xpath`, …) |
| **CRLF Injection** | HIGH | Injected header name+value appears verbatim in response headers |
| **OOB SSRF** | CRITICAL | Payload contains a unique token pointing at the BlindXSS server; correlated post-scan when the callback arrives |

**Auth / access control**
| Check | Severity | Detection method |
|---|---|---|
| **JWT analysis** | INFO → CRITICAL | Detect JWTs in headers/body. Flag missing `exp`/`iat`/`sub` (info), test `alg=none` acceptance (critical), bruteforce HS256 against 53 weak secrets (critical) |
| **IDOR** | HIGH | Detect numeric/UUID ID in URL path → probe sibling IDs (1, 2, ±1) with reused auth → if response materially differs (>20% unique vs baseline + 200 OK), fire |
| **Broken Access Control** | HIGH | Per-host one-time sweep of admin paths (`/admin`, `/api/admin/*`, `/internal`, `/console`) WITHOUT auth. 200 OK with non-login body = finding |
| **Mass Assignment / Excessive Data Exposure** | HIGH | POST/PUT/PATCH with privilege fields (`is_admin`, `role`, `verified`, `balance`, `plan`, …) accepted AND echoed in response |
| **Open Redirect** | MEDIUM | User-supplied URL ends up in actual `Location:` redirect chain (not just echoed in response URL) |
| **Multi-Account Authz Replay** | HIGH | Replays every protected URL the primary session got 200 on with a secondary (User-B) session; URLs where User-B also gets 200 with similar shape become BAC findings (CWE-639). Login-page filter rejects "both got the login form" FPs |
| **HTTP Method Authz Bypass (HEAD)** | HIGH | HEAD returns 200 where GET requires auth (302→login / 401 / 403). Auth filter matches by verb instead of by path. CWE-863 |
| **HTTP Verb Tampering (DELETE/PUT/PATCH)** | CRITICAL | Destructive verb returns 2xx where GET requires auth — verb-based authz bypass. ONLY fires when user opted in to aggressive verb fuzzing AND OPTIONS confirmed the verb is supported. CWE-650 |
| **HTTP Method Override Honored** | HIGH | POST + `X-HTTP-Method-Override: DELETE` returns 2xx — framework rewires verb internally and skips auth. CWE-650 |
| **Race Condition** | HIGH | Burst N parallel requests at a state-changing endpoint (transfer/pay/redeem). HTTP/2 single-packet attack when `h2` installed; threaded HTTP/1.1 fallback otherwise. Divergent responses or success > expected = vulnerable. CWE-362 |
| **OAuth Flaws (5 sub-checks)** | HIGH → CRITICAL | redirect_uri validation (open redirect via attacker callback) · missing `state` (CSRF) · implicit flow (token in URL fragment) · PKCE not enforced for public clients · scope over-issuance |

**Misconfiguration / disclosure**
| Check | Severity | Detection method |
|---|---|---|
| **CORS Misconfiguration** | HIGH / MED / INFO | `ACAO: *` + `credentials: true`, `ACAO: null`, or non-target echoed origin |
| **Weak CSP** | LOW | `'unsafe-inline'`, `'unsafe-eval'`, or wildcard source present |
| **GraphQL Introspection** | MEDIUM | Passive (`__schema` already in response) OR active POST `{__schema{...}}` to `/graphql`/`/api/graphql`/`/v1/gql` |
| **Subdomain Takeover** | HIGH | DNS-resolve apex + 20 common prefixes; HTTP-probe each; match against **51 fingerprints** pulled from the can-i-take-over-xyz database (S3, Cloudfront, GitHub Pages, Heroku, Shopify, Tumblr, Azure, Bitbucket, Webflow, Zendesk, Surge, Fastly, Netlify, Pantheon, Ghost, Helpscout, Tilda, Strikingly, UserVoice, Statuspage, …) |
| **Content Discovery** | INFO → MEDIUM | 248-path wordlist + 27 sensitive-file paths (`.git/HEAD`, `.env*`, `wp-config.php.bak`, `db.sqlite`, `phpinfo.php`, `id_rsa`, …) with wildcard-baseline filter so 200-OK-everything targets don't poison the report. Sensitive paths bumped to MEDIUM |
| **Directory Listing** | MEDIUM | `Index of /`, `Parent Directory`, `<title>Index of` markers |
| **Version Disclosure** | LOW | `Server:` / `X-Powered-By:` / `X-AspNet-Version:` etc. with version-pattern (digits.digits) — bare names like "nginx" no longer trigger |
| **Dangerous HTTP Methods** | MEDIUM | `TRACE` / `TRACK` / `CONNECT` in `Allow:` header (DELETE/PUT removed — they're normal in REST APIs) |
| **Insecure Cookies** | LOW | `Set-Cookie` missing `HttpOnly` / `Secure` |
| **Missing Security Headers** | INFO | Missing CSP / HSTS / X-Frame-Options / X-Content-Type-Options / Referrer-Policy |
| **Exposed Backup / Source File** | MEDIUM | URL ends with `.bak` / `.sql` / `.zip` / `.tar.gz` / etc. AND status is 200 OK with non-HTML body (no FP on `/downloads/release.zip`) |

**Nuclei templates** (10 ships in `nuclei_templates/`, more loadable)
- `dotenv-exposure`, `git-exposure`, `phpinfo-exposure`, `wp-config-backup`
- `tomcat-manager`, `debug-mode-exposed`, `missing-hsts`
- `server-version-disclosure`, `spring-actuator-exposed`

All 26 have unit tests in [test_new_checkers.py](test_new_checkers.py), [test_fp_smoke.py](test_fp_smoke.py), [test_new_features.py](test_new_features.py). Run anytime:
```
venv/Scripts/python.exe test_new_checkers.py    # Windows
venv/Scripts/python.exe test_fp_smoke.py
venv/Scripts/python.exe test_new_features.py
venv/Scripts/python.exe test_ai_smoke.py
```

### 🚧 Framework ready, detection logic pending

These dispatch and accept payloads today but don't yet emit findings. The HUNT tab marks them with a 🟡 stub icon, and they're listed in the report's **Limitations & Caveats** section so a clean report isn't misread as "no issues found":

| Category | Pending checks |
|---|---|
| Configuration | HTTP Smuggling, Web Cache Poisoning |
| Access Control | Privilege Escalation |
| Modern API | WebSocket, API Fuzzing, gRPC, Serverless |
| Infrastructure | Cloud Metadata, DNS Rebinding, Port Scanning |
| Advanced | Prototype Pollution, Race Condition, Deserialization, Memory Corruption |

Contributions welcome — the stub method signatures in [core/scanner.py](core/scanner.py) are already wired to the dispatcher, so a new checker is literally "replace `pass` with logic and add a unit test".

---

## 🔐 Authentication

Configure in [config.json](config.json) or via the GUI Settings tab:

```json
{
  "auth": {
    "enabled": true,
    "cookie": "sessionid=abc; csrftoken=xyz",
    "bearer_token": "",
    "login_url": "https://target.tld/login",
    "username": "user",
    "password": "pass",
    "username_field": "username",
    "password_field": "password",
    "extra_fields": { "csrf_token": "" }
  }
}
```

**Three modes:**

1. **Cookie** — paste a session cookie string
2. **Bearer token** — for API scanning
3. **Form login** — CHOMBEZA fetches the login page, parses the form (including CSRF tokens), submits, and carries the session cookies through every scan request

The auth manager does a post-login success check (looks for common success/failure strings, new cookies, and password-field absence).

### Mid-scan auth — three new safety nets (2.4)

Real targets rotate session cookies and CSRF tokens. CHOMBEZA handles all three failure modes without you babysitting the scan:

1. **Auto-rotation** — every response is parsed for fresh `csrftoken` / `sessionid` / `XSRF-TOKEN` cookies, `<meta name="csrf-token">` tags, hidden form fields (`csrfmiddlewaretoken` / `authenticity_token` / `_token` / `__RequestVerificationToken`), and `X-CSRF-Token` response headers. New values are silently fanned out to every live worker session + `auth_manager.config`. Django, Laravel, Rails, ASP.NET MVC all rotate this way; you don't see it happen, but the next request goes out with the fresh token.
2. **Re-auth circuit breaker** — when the auth backend itself is broken (returning 403 to every login attempt), CHOMBEZA stops after 3 consecutive failures on the same host (5-min cooldown), 30 attempts globally, with a 5s minimum gap between attempts. A toast pops pointing you to `Tools → Refresh Auth` instead of spamming "attempt #531, #532..." into your console for an hour.
3. **Manual Refresh Auth (mid-scan)** — `Tools → 🔑 Refresh Auth` opens a modal to paste a fresh cookie / bearer / CSRF from your browser dev-tools. The new credentials apply to every live worker session AND persist to `auth_manager.config` so future workers inherit them too.

---

## 🤖 AI Enhancement (Bring-Your-Own-Key)

**AI is always optional.** CHOMBEZA runs identically with no API key. When a key is configured, you get four extra capabilities on top of the normal scan:

1. **Per-finding triage** — every detected finding goes to the LLM with its evidence + URL + parameter; the LLM returns `true_positive` / `false_positive` / `uncertain` plus a confidence score and one-line reasoning. Shown as a colored pill in the report and stored on the finding.
2. **Pre-scan strategy brief** — if this target was scanned before, the LLM reads the per-target memory and produces "focus areas / watch for / lower priority" guidance for the upcoming scan. Logged to console + included in the report.
3. **Adaptive memory loop** — after the scan, the LLM extracts FP signatures, confirmed-TP payloads, tech fingerprints, and "what to focus on next time" from the findings, and merges them into the target's memory file. **The next scan starts smarter.**
4. **PoC writeup generation** — for each HIGH/CRITICAL finding, a one-click HackerOne-format writeup (title / summary / steps to reproduce / impact / remediation / references). Saves 10–20 min per submission.

### Supported providers

| Provider | Setup | Privacy | Cost |
|---|---|---|---|
| **Ollama** (recommended for pentest engagements) | `ollama pull llama3.1` | ✅ Local — nothing leaves your host | Free |
| **Claude** (Anthropic) | Get key from console.anthropic.com | sends finding data to Anthropic | ~$0.05 / scan (Haiku 4.5) |
| **DeepSeek** (cheapest paid) | Get key from platform.deepseek.com | sends finding data to DeepSeek | ~$0.01 / scan |
| **OpenAI** (ChatGPT) | Get key from platform.openai.com | sends finding data to OpenAI | ~$0.05 / scan (gpt-4o-mini) |

### Configure in the GUI

`Settings tab` → `🤖 AI ENHANCEMENT` panel:
- Tick **Enable AI features**
- Pick the **Provider** dropdown
- Paste your **API Key** (masked input)
- Optional **Model** override (e.g. `claude-haiku-4-5-20251001`, `gpt-4o-mini`, `deepseek-chat`, `llama3.1`)
- For Ollama, set the **Host URL** (default `http://localhost:11434`)
- Toggle individual features: **Per-finding triage** / **PoC writeup** / **Learning loop** / **Redact PII outbound**
- Click **🔌 Test Connection** — green/red status shown immediately

### Configure via CLI

```bash
# Run a scan with AI on Claude
python main.py https://target.tld --ai-provider claude --ai-key sk-ant-...

# Same with DeepSeek (cheaper)
python main.py https://target.tld --ai-provider deepseek --ai-key sk-...

# Local + privacy-safe (Ollama)
python main.py https://target.tld --ai-provider ollama --ai-model llama3.1

# Just test the connection (no scan)
python main.py --ai-test --ai-provider deepseek --ai-key sk-...

# Force-disable AI for one run even if config has a key
python main.py https://target.tld --ai-disabled
```

### PII redaction (cloud providers only)

Before any finding evidence leaves the host, an outbound filter strips:
- Email addresses → `[email]`
- AWS / OpenAI / GitHub / Google / Slack API keys → `[provider-key]`
- PEM private-key blocks → `[private-key-block]`
- US SSNs and phone numbers → `[ssn]` / `[phone]`

Toggle off in Settings if you trust your provider with raw data. **Skipped for Ollama** since data stays on your host anyway.

### Adaptive memory file format

Per-target memory lives at `reports/ai_memory/<host_sha1>.json`:

```json
{
  "host": "app.example.com",
  "scans": [
    {"scan_id": "abc123", "date_iso": "2026-05-12 09:07:17",
     "stats": {"high": 2, "low": 1, "total": 3}}
  ],
  "fp_signatures": [
    {"checker": "sqli", "pattern": "MySQL", "reason": "appears in marketing copy"}
  ],
  "tp_payloads": [
    {"vuln": "xss", "payload": "<svg/onload=1>", "context": "next= param on /login"}
  ],
  "tech_inferences": ["Django", "Cloudflare WAF"],
  "future_focus": ["test JWT alg=none on /api/v2/auth"],
  "last_updated_iso": "2026-05-12 09:08:01"
}
```

Lists are capped (last 20 scans, 200 patterns) so files stay bounded. Cross-target lessons promoted to `reports/ai_memory/_global.json`.

---

## 📄 Reports

Generated into `reports/` under the scan id. Every report shares the same data source (the SQLite vulnerability store), so the outputs are always consistent.

| Format | What's in it |
|---|---|
| **HTML** | Styled report with severity charts, CVSS scores, embedded screenshots, full request/response traces, remediation roadmap. Opens in any browser. |
| **PDF** | ReportLab-rendered (portable, no GTK required). WeasyPrint fallback available if installed. |
| **JSON** | Machine-readable. Same schema as the SQLite store — useful for piping into other tools. |
| **CSV** | Flat table of findings for spreadsheets / dashboards. |

---

## ⌨️ Keyboard shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+F` | Show Findings Feed + focus search |
| `Ctrl+/` | Pause / resume live feed |
| `Ctrl+Shift+F` | Toggle Findings Feed visibility |
| `Ctrl+Shift+K` | Clear all feed cards |

Dock layout is persisted between sessions — drag it to the left, close CHOMBEZA, reopen, it's still on the left.

---

## 📁 Project structure

```
chombeza/
├── main.py                       # Entry point (GUI + CLI dispatcher, HiDPI, crash hooks)
├── config.json                   # Default runtime config (incl. ai.* defaults)
├── requirements.txt              # Core pure-python deps (cross-platform)
├── requirements-optional.txt     # Optional extras (PDF/plotting + AI SDKs)
├── install.bat / install.sh      # OS-aware installers
├── run.bat / run.sh              # Generated launchers
│
├── core/
│   ├── scanner.py                # Orchestration, worker pool, 26 checkers, dedup-by-name
│   ├── discovery.py              # Static crawler + form/param extraction
│   ├── js_discovery.py           # Headless-Chrome SPA renderer (CDP-based API capture)
│   ├── headless_browser.py       # Cross-platform Chrome detection + driver factory
│   ├── auth.py                   # Cookie / Bearer / form-login manager
│   ├── engagement.py             # Scope, per-host rate limiting, WAF detector, session keeper
│   ├── mutators.py               # Payload mutation engine for WAF bypass
│   ├── payloads.py / payloads.json  # Payload database (20 keys, 1287 payloads)
│   ├── screenshot.py             # Selenium-based evidence capture (single-driver)
│   ├── scan_store.py             # SQLite persistence for resumable scans + dedup
│   ├── report.py                 # HTML / PDF / JSON / CSV generators (OWASP / CWE / Likelihood / Verification)
│   ├── blind_xss.py              # Flask-based callback server (also drives OOB SSRF)
│   ├── nuclei_loader.py          # YAML Nuclei template loader (subset)
│   ├── os_compat.py              # OS detection + per-vuln compatibility map
│   ├── ai_client.py              # AIClient abstract + Claude/OpenAI/DeepSeek/Ollama
│   ├── ai_memory.py              # Per-target + global JSON memory store
│   ├── ai_features.py            # Triage / strategy / learning / PoC + PII redaction
│   ├── session.py / utils.py     # Proxy, rate limit, helpers
│
├── ui/
│   ├── main_window.py            # Root QMainWindow, tabs, AI panel, dashboard strip
│   ├── findings_feed.py          # Live Findings Feed dock (cards + dedup counter + filters)
│   ├── live_traffic_window.py    # Live Traffic Monitor (tree + details tabs)
│   ├── styles.py                 # Theme engine + 5 cyberpunk palettes (palette extended)
│   ├── widgets.py                # Custom widgets (GlitchLabel, NeonButton, ScanDashboardStrip, LiveSeverityDonut, LiveCategoryBars, …)
│
├── templates/
│   └── report_vapt_pro.html      # Jinja2 report template (with AI verdict + PoC sections)
│
├── nuclei_templates/             # YAML Nuclei templates that ship in-tree
│   ├── exposures/                # .env, .git, phpinfo, wp-config backups
│   ├── misconfigs/               # tomcat-manager, debug-mode, missing-hsts
│   └── disclosure/               # server-version, spring-actuator
│
├── test_*.py                     # Smoke tests for checkers, dedup, mutators,
│                                  # engagement layer, FP/TP pairs, AI integration
│
└── reports/                      # Generated output (gitignored)
    ├── scans.db                  # SQLite for resumable scans
    ├── crash.log                 # Native + Python crash dumps with task context
    ├── screenshots/              # Per-finding screenshots
    └── ai_memory/                # Adaptive AI memory (per-target + _global.json)
```

---

## 🛠️ Building from source

### Dependencies
- Python **3.8+**
- Qt 5 (installed automatically via `PyQt5` wheel)
- Chrome or Chromium on `PATH` (for screenshot evidence)

### Build steps
```bash
git clone https://github.com/archnexus707/chombeza.git
cd chombeza

# Windows
install.bat

# Linux / macOS
bash install.sh
```

### Sanity check
```bash
# Core payload DB loads, scanner class imports, theme engine builds
python -c "from core.scanner import Scanner; from ui.styles import THEMES; print('OK', len(THEMES), 'themes')"
```

### Running tests
```bash
python test_full_screenshot.py       # End-to-end screenshot + report flow
python test_scan.py                  # Scanner smoke test
```

---

## 🗺️ Roadmap

### Shipped

- [x] **JS-rendered app support** — headless Chrome-backed discovery for SPA/PWA/React-Vue-Angular targets. (2.1)
- [x] **Nuclei template compatibility** — YAML loader; 9 templates ship in `nuclei_templates/`. (2.1)
- [x] **JSON body fuzzing** — mutate fields inside `application/json` request bodies for modern REST/GraphQL APIs. (2.1)
- [x] **Path-parameter fuzzing** — attack REST segments like `/users/{id}/orders/{order_id}`. (2.1)
- [x] **OOB SSRF** — wired through the BlindXSS server with token-correlation. (2.1)
- [x] **AI triage + writeup** — Claude / OpenAI / DeepSeek / Ollama. Per-finding TP/FP triage, adaptive memory, HackerOne-format PoC generation. (2.2)
- [x] **Vuln dedup by name** — 9 XSS detections at 9 paths = 1 finding × 9 instances. (2.2)
- [x] **9 new checkers** — NoSQLi, LDAPi, XPathi, JWT, Mass Assignment, GraphQL, IDOR, BAC, Subdomain Takeover. (2.2)
- [x] **OS-aware compatibility map** — per-vuln-type icons in HUNT tab. (2.2)
- [x] **Crash detection** — global excepthooks + per-task context in `reports/crash.log`. (2.2)

### Coming next (phases scheduled)

**Phase 2 — Discovery boost**
- [ ] **JS-source endpoint extraction** — parse loaded `.js` for `fetch()`/`axios`/`XHR` URLs (5-10× more API endpoints on SPAs)
- [ ] **OpenAPI / Swagger / Postman / HAR import** — point at a spec file, auto-discover every endpoint with parameter types
- [ ] **Smart form auto-fill** — crawler reaches post-login pages without explicit auth config

**Phase 3 — OOB platform**
- [ ] **DNS callback server** alongside BlindXSS for proper Blind XXE / Log4Shell / Blind RCE detection (extends the existing OOB SSRF infra)

**Phase 4 — Workflow features**
- [ ] **Multi-target campaign mode** — `--targets targets.txt` for bulk scans + combined report
- [ ] **Scheduled scans** — cron-style recurring runs with Slack/Discord webhook on critical findings
- [ ] **Diff / trend mode** — `--compare-to <prev_scan_id>` shows "+3 critical, -2 high since last scan"
- [ ] **CI/CD integration** — JUnit XML output + `--fail-on critical,high` exit codes + GitHub Actions snippet

**Phase 5 — Detection rounds**
- [ ] **CSRF detection** — form discovery + missing-token POST attempt
- [ ] **Default credentials check** — `admin:admin` / `admin:password` on detected login forms
- [ ] **WordPress / Joomla / Drupal CMS scanner** — version + vulnerable plugin detection
- [ ] **Cache poisoning + Web cache deception** — `X-Forwarded-Host` / cache-key manipulation

**Phase 6 — Power user**
- [ ] **Plugin / extension API** — drop-in `plugins/` directory for custom checkers without forking core
- [ ] **Burp/ZAP-style proxy mode** — `mitmproxy` on `:8080`, browse manually, every request becomes a scan task

### Backlog (future ideas)

- [ ] **Browser-recorded authentication** — click "Record" → non-headless Chrome opens → log in manually → cookies/localStorage captured automatically
- [ ] **Command palette (Ctrl+K)** — fuzzy-searchable keyboard nav for every toggle, saved scan, and theme
- [ ] **Remediation tracking dashboard** — store fix status, re-verify on demand, track SLA aging
- [ ] **Compliance mapping export** — PCI-DSS / ISO 27001 / NIST per finding

---

## 🤝 Contributing

Pull requests welcome. Good first issues:

- Fill in one of the "placeholder" vuln checkers (`_check_ssti`, `_check_lfi`, etc.) — signatures in [core/scanner.py](core/scanner.py) are stubbed and ready
- Add a new theme to [ui/styles.py](ui/styles.py) — add a `CyberTheme` instance to the `THEMES` dict and it's instantly available in the dropdown
- New payload pack in [core/payloads.json](core/payloads.json)
- Translations for the GUI strings

Before submitting:
```bash
python -c "
import ast
for p in ['main.py', 'core/scanner.py', 'core/scan_store.py',
          'ui/main_window.py', 'ui/styles.py', 'ui/findings_feed.py']:
    ast.parse(open(p, 'r', encoding='utf-8').read(), p)
    print('OK', p)
"
```

---

## 📄 License

Proprietary — see [LICENSE.txt](LICENSE.txt). Non-commercial and educational use encouraged; commercial licensing available on request. Early-access plans will keep the core GUI + scan + report flow free and open-source while offering paid tiers for cloud scheduling, team features, and AI triage.

---

## 👨‍💻 Author

**Dickson Godwin Massawe** — [@archnexus707](https://github.com/archnexus707)

Security researcher · bug-bounty hunter · full-stack developer.
Based in Tanzania 🇹🇿.

- 🌐 GitHub — [github.com/archnexus707](https://github.com/archnexus707)
- 📧 Contact — via GitHub issues or profile
- 🎯 Hunting at — [HackerOne](https://hackerone.com/) · [Bugcrowd](https://bugcrowd.com/) · [Intigriti](https://intigriti.com/)

Built with `PyQt5`, `requests`, `BeautifulSoup`, `Selenium`, `ReportLab`, `Jinja2`, and too much coffee.

---

<div align="center">

  <sub>⚠ CHOMBEZA is for authorized security testing only. Use it responsibly.</sub>

  <br>

  <sub>If this project helps you find a bug, <b>⭐ star the repo</b> and consider sponsoring.</sub>

</div>
