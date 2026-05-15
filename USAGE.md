# CHOMBEZA Bug Bounty Pro — Usage Guide

This document describes the operational use of CHOMBEZA Bug Bounty Pro on Microsoft Windows and Linux/macOS systems. It is intended for security analysts, penetration testers, and bug bounty researchers using the application against properly authorised targets.

> **Authorised Use Only.** CHOMBEZA Bug Bounty Pro must be used exclusively against systems that the operator owns or for which the operator possesses explicit, written permission to perform security testing. Unauthorised scanning is unlawful in most jurisdictions and may incur civil and criminal penalties. The author and licensor accept no responsibility for unauthorised use.

---

## Contents

0. [Installation](#0-installation)
1. [Verifying the Installation](#1-verifying-the-installation)
2. [Operating Modes: Graphical and Command-Line](#2-operating-modes-graphical-and-command-line)
3. [Selecting a Scan Profile](#3-selecting-a-scan-profile)
4. [Authentication Configuration](#4-authentication-configuration)
5. [Performing a Scan via the Graphical Interface](#5-performing-a-scan-via-the-graphical-interface)
6. [Performing a Scan via the Command Line](#6-performing-a-scan-via-the-command-line)
7. [In-Scan Operations](#7-in-scan-operations)
8. [Pause, Resume and Persistence](#8-pause-resume-and-persistence)
9. [Interpreting Reports](#9-interpreting-reports)
10. [AI Enhancement (Bring Your Own Key)](#10-ai-enhancement-bring-your-own-key)
11. [Recommended Workflows](#11-recommended-workflows)
12. [Aggressive Verb Fuzzing (DELETE, PUT, PATCH)](#12-aggressive-verb-fuzzing-delete-put-patch)
13. [Commercial Licensing and Activation](#13-commercial-licensing-and-activation)
14. [Troubleshooting](#14-troubleshooting)
15. [Platform-Specific Notes](#15-platform-specific-notes)
16. [Support and Licensing](#16-support-and-licensing)

---

## 0. Installation

CHOMBEZA Bug Bounty Pro is distributed as a platform-native installer. Download the appropriate file for your operating system from the [official Releases page](https://github.com/archnexus707/chombeza/releases/latest).

### Windows

| Step | Action |
|---|---|
| 1 | Download `CHOMBEZA-BugBounty-Pro-Setup-v5.0.0.exe` |
| 2 | Double-click the installer. Follow the wizard. The wizard requests acknowledgement of the 30-day evaluation licence terms. |
| 3 | Launch from Start Menu → CHOMBEZA Bug Bounty Pro, or from a terminal: `chombeza` |

The installer places the application in `C:\Program Files\CHOMBEZA\` by default. User data (reports, logs, licence file) is stored in `%LOCALAPPDATA%\CHOMBEZA\` so non-administrator users can run the application without elevated permissions.

### Linux (Debian, Ubuntu, Kali, Parrot, and other Debian-derived distributions)

| Step | Action |
|---|---|
| 1 | Download `chombeza_5.0.0_amd64.deb` |
| 2 | Install: `sudo dpkg -i chombeza_5.0.0_amd64.deb` |
| 3 | Install any missing dependencies: `sudo apt -f install` |
| 4 | Launch from the Applications menu (Security category) or from any terminal: `chombeza` |

The package places the application binary at `/opt/chombeza/`, creates a launcher symlink at `/usr/bin/chombeza`, and registers a desktop menu entry. User data is stored in `~/.config/CHOMBEZA/`.

### macOS

A native installer for macOS is not currently distributed. macOS users may build from source per the developer instructions in [BUILD.md](BUILD.md).

### Verifying the install

After installation, launching the application should display the main interface with a title bar reading:

> CHOMBEZA Bug Bounty Pro - TRIAL (30 day(s) left, contact archnexus707@gmail.com)

This indicates the 30-day evaluation period has commenced. See [Section 13](#13-commercial-licensing-and-activation) for activation procedures.

If the application does not launch, see [Section 14](#14-troubleshooting).

---

## 1. Verifying the Installation (Developer / Build-from-Source)

This section applies to **developers** who have built CHOMBEZA from source via `install.bat` (Windows) or `bash install.sh` (Linux/macOS). End-users who installed from the official `.exe` or `.deb` package may skip to [Section 2](#2-operating-modes-graphical-and-command-line).

After completing the source installation, confirm the runtime environment:

### Windows

Open PowerShell in the project directory and execute:

```powershell
venv\Scripts\python.exe -c "from core.scanner import Scanner; from ui.styles import THEMES; print('OK', len(THEMES), 'themes,', sum(1 for _ in Scanner().payload_db.payloads), 'payload types')"
```

### Linux and macOS

```bash
venv/bin/python -c "from core.scanner import Scanner; from ui.styles import THEMES; print('OK', len(THEMES), 'themes,', sum(1 for _ in Scanner().payload_db.payloads), 'payload types')"
```

A successful response resembles `OK 5 themes, 22 payload types`. If an error is returned, re-run the installer.

### AI Connectivity Check (Optional)

If an AI provider has been configured, verify connectivity without performing a scan:

```bash
# Windows
venv\Scripts\python.exe main.py --ai-test --ai-provider claude --ai-key sk-ant-...

# Linux / macOS
venv/bin/python main.py --ai-test --ai-provider claude --ai-key sk-ant-...
```

The command exits with status 0 on success and status 1 on failure.

---

## 2. Operating Modes: Graphical and Command-Line

### Graphical Interface

| Operating System | Launch Command |
|---|---|
| Windows | `run.bat` (or double-click) |
| Linux / macOS | `./run.sh` |

The main window presents five primary tabs across the upper navigation: **HUNT**, **RESULTS**, **BLIND XSS**, **PAYLOAD LAB**, and **SETTINGS**. The Live Findings Feed dock is anchored to the right by default and may be repositioned or hidden.

### Command-Line Interface

| Operating System | Command Pattern |
|---|---|
| Windows | `run.bat https://target.example --scan-type quick` |
| Linux / macOS | `./run.sh https://target.example --scan-type quick` |

The Python interpreter may be invoked directly when convenient:

```bash
# Windows
venv\Scripts\python.exe main.py [arguments]

# Linux / macOS
venv/bin/python main.py [arguments]
```

---

## 3. Selecting a Scan Profile

Scan profiles are defined in [config.json](config.json) and may be overridden per execution using the `--threads`, `--timeout`, and `--delay` arguments.

| Profile | Threads | Payloads / Parameter | Crawl Depth | Inter-Request Delay | Recommended Use |
|---|---:|---:|---:|---:|---|
| `quick` | 5 | 10 | 2 | 50 ms | Initial reconnaissance and scope verification. |
| `deep` | 10 | 30 | 5 | 100 ms | Standard production engagement profile. |
| `stealth` | 2 | 5 | 3 | 500 ms | Targets with strict rate limits or active monitoring. |
| `aggressive` | 20 | 50 | 8 | 0 ms | Owned test environments only. May trigger WAF protections. |

**Recommended practice:** initiate with the `quick` profile to validate scope and authentication, then proceed to the `deep` profile for the engagement proper.

---

## 4. Authentication Configuration

CHOMBEZA Bug Bounty Pro supports three authentication mechanisms.

### 4.1 Cookie Authentication

1. Authenticate to the target through a standard web browser.
2. Open the browser developer tools and navigate to **Application** or **Storage**, then **Cookies**.
3. Copy the cookie string (e.g. `sessionid=AbCd...; csrftoken=XyZ...`).
4. Apply the value through one of the following:
   - **Graphical interface:** SETTINGS tab, Authentication section, Cookie field
   - **Configuration file:**
     ```json
     "auth": {
       "enabled": true,
       "cookie": "sessionid=AbCd...; csrftoken=XyZ..."
     }
     ```

The application automatically detects rotated `csrftoken`, `sessionid`, and `XSRF-TOKEN` cookies during a scan and propagates the new values to all worker threads. This handles standard rotation behaviour observed in Django, Laravel, Rails, and ASP.NET frameworks.

### 4.2 Bearer Token Authentication

Suitable for API endpoints that accept JSON Web Tokens or opaque bearer credentials.

```json
"auth": {
  "enabled": true,
  "bearer_token": "eyJhbGciOiJI..."
}
```

The `Bearer` prefix is added by the application and must not be included in the configured value. Automatic rotation detection applies to `X-CSRF-Token` response headers.

### 4.3 Form-Based Authentication

The application performs the login on behalf of the user.

```json
"auth": {
  "enabled": true,
  "login_url": "https://target.example/login",
  "username": "operator",
  "password": "p@ssw0rd",
  "username_field": "email",
  "password_field": "password",
  "extra_fields": { "remember_me": "1" }
}
```

The authentication manager retrieves the login page, parses the form (including any hidden CSRF tokens), submits credentials, and re-uses the resulting session cookies for the duration of the scan.

### 4.4 Mid-Scan Credential Refresh

If the authenticated session expires during a scan, a notification is displayed. To supply fresh credentials without restarting:

> **Tools menu → Refresh Authentication**

A modal dialog accepts new cookie, bearer token, and CSRF values. The new credentials are propagated to every active worker thread and persisted to the authentication manager so that subsequently spawned workers also inherit them. The scan continues uninterrupted.

---

## 5. Performing a Scan via the Graphical Interface

1. Launch the application using `run.bat` (Windows) or `./run.sh` (Linux/macOS).
2. On the **HUNT** tab, enter the target URL in the **Target URL** field.
3. Select a **Scan Type**. The `quick` profile is recommended for initial validation; `deep` for the substantive engagement.
4. (Optional) Adjust the enabled vulnerability classes. Presets are provided for OWASP Top 10, real checkers only, and stubs only.
5. Click **START SCAN**.
6. Monitor the **Console** panel for progress. Findings appear in the Live Findings Feed as they are discovered.
7. On completion, switch to the **RESULTS** tab and select any finding to view details and request/response evidence.
8. Click **Export Report** and select the desired format (HTML, PDF, JSON, or CSV).

### Recommended Pre-Scan Configuration

- **Multi-Account Authorisation Replay** (SETTINGS): Provide a secondary set of credentials (User-B). After discovery, every URL accessible to the primary session is replayed using the secondary session. Successful matches are reported as Broken Access Control findings (CWE-639), historically the highest-paying class on bug bounty programmes.
- **AI Enhancement** (SETTINGS): Provide an API key to enable per-finding triage and automated proof-of-concept generation.
- **Subdomain Enumeration** (SETTINGS): Enable to query Certificate Transparency logs (crt.sh) and perform DNS bruteforce prior to discovery. Adds approximately 10 to 20 seconds.

---

## 6. Performing a Scan via the Command Line

### Basic Invocation

```bash
# Windows
run.bat https://target.example --scan-type quick

# Linux / macOS
./run.sh https://target.example --scan-type quick
```

### Common Variants

```bash
# Deep scan with 20 threads, restricted to XSS and SQLi
run.bat https://target.example --scan-type deep --threads 20 --vuln-types xss sqli

# Through an upstream proxy (e.g. Burp Suite on TCP/8080)
run.bat https://target.example --proxy http://127.0.0.1:8080

# Custom User-Agent and PDF report output
run.bat https://target.example --user-agent "Researcher/1.0" --format pdf

# Standalone Blind XSS callback server (no scan; supports OOB SSRF detection)
run.bat --blind-xss --blind-xss-port 5000

# Disable evidence screenshots (useful on headless systems without Chrome)
run.bat https://target.example --no-screenshot

# Use an alternate configuration file
run.bat https://target.example --config configs/client-acme.json
```

### Scan Lifecycle Management

```bash
# Enumerate persisted (paused) scans
run.bat --list-scans

# Resume a paused scan from its persisted state
run.bat --resume 59b9522a45b4

# Remove a persisted scan from the local store
run.bat --delete-scan 59b9522a45b4
```

### Licence Management

```bash
# Print the current machine's licence fingerprint and exit
chombeza --fingerprint

# Capture the fingerprint to clipboard (Windows)
chombeza --fingerprint | clip

# Capture the fingerprint to clipboard (Linux)
chombeza --fingerprint | xclip -selection clipboard
```

### AI Provider Arguments

```bash
# Anthropic Claude
run.bat https://target.example --ai-provider claude --ai-key sk-ant-...

# DeepSeek
run.bat https://target.example --ai-provider deepseek --ai-key sk-...

# Local inference via Ollama (no external network calls)
run.bat https://target.example --ai-provider ollama --ai-model llama3.1

# Force-disable AI for a single execution
run.bat https://target.example --ai-disabled
```

---

## 7. In-Scan Operations

The following controls remain active for the duration of a running scan:

| Action | Location | Description |
|---|---|---|
| Stop the scan | HUNT tab — STOP button | Initiates graceful shutdown. In-flight requests complete within approximately two seconds. |
| Refresh authentication | Tools menu — Refresh Authentication | Modal dialog for supplying fresh cookies, bearer tokens, or CSRF values. |
| Show machine fingerprint | Tools menu — Show Machine Fingerprint… | Modal showing the 32-character licence fingerprint with a Copy button. Available regardless of trial state. See [Section 13](#13-commercial-licensing-and-activation). |
| Import licence file | Tools menu — Import Licence File… | File picker to install a `.lic` file at any time, including during an active trial (pre-paying customers). Verifies signature, fingerprint, and expiry before installing. |
| Live Traffic Monitor | Tools menu — Live Traffic | Hierarchical view of all requests and responses. Supports filtering by status class, method, and URL substring. Body content search is invoked with `Ctrl+F`. |
| Live Findings Feed | Right dock (toggle: `Ctrl+Shift+F`) | Findings appear as they are discovered. Supports filtering by severity, full-text search, and pause. |
| Command palette | `Ctrl+K` | Fuzzy search across all tabs and primary scanner actions. |

### Notable Notifications

- **Auto-rotation absorbed** — A rotated CSRF or session token has been detected and applied across all worker threads. No operator action is required.
- **Authentication retry suspended** — The auto-refresh circuit breaker has opened after three consecutive failed re-authentication attempts on the same host. A manual refresh through Tools → Refresh Authentication is required.
- **Destructive request dispatched** — A DELETE, PUT, or PATCH request has been issued (only when the operator has enabled aggressive verb fuzzing).
- **Session expired** — Mid-scan credential expiry detected. Use Tools → Refresh Authentication to supply fresh credentials.

---

## 8. Pause, Resume and Persistence

All scan state is persisted to a SQLite database at `reports/scans.db` using WAL journaling, providing tolerance against unexpected termination.

```bash
# Initiate a scan
run.bat https://target.example --scan-type deep
```

To pause, press `Ctrl+C` in the command-line interface or click **STOP** in the graphical interface. The console will display:

```
Scan paused with 2,347 tasks remaining. Resume with:  --resume 59b9522a45b4
```

To resume the scan:

```bash
run.bat --list-scans          # locate the scan identifier
run.bat --resume 59b9522a45b4
```

The vulnerability store, queued tasks, and accumulated statistics are restored. The final report incorporates the complete finding set across all execution segments.

---

## 9. Interpreting Reports

Reports are generated under `reports/<scan_id>/` in each requested format.

### HTML Report (Recommended)

Open `reports/<scan_id>/report.html` in any modern web browser.

The report comprises:

- **Executive Summary** — Severity counts and AI-generated strategic brief (when AI is enabled).
- **Findings** — Per-finding cards displaying severity, OWASP Top 10 mapping, CWE classification, exploit likelihood, exploit complexity, verification mode (active or passive), AI verdict (when enabled), affected URLs and parameters, payload detail, request/response evidence, and embedded screenshots.
- **Trend Analysis** — When prior scan data exists for the same target, the report shows new, unchanged, fixed, and regressed findings relative to the previous scan.
- **Replay Artefacts** — Each finding includes a `curl` command and a HAR 1.2 dictionary suitable for import into Burp Suite, OWASP ZAP, or Caido.
- **Limitations and Caveats** — Lists vulnerability types enabled in the scan that are stub implementations, ensuring that an absence of findings is not misinterpreted as evidence of absence.

### PDF Report

Equivalent content in a portable format. Generated using ReportLab (no GTK required); WeasyPrint is used as a fallback when available.

### JSON and CSV Reports

Machine-readable outputs. The JSON schema mirrors the SQLite store; the CSV format presents one finding per row for spreadsheet analysis.

---

## 10. AI Enhancement (Bring Your Own Key)

CHOMBEZA Bug Bounty Pro operates fully without an AI provider. When a provider is configured, the following capabilities become available:

1. **Per-finding triage** — Each finding receives a true positive, false positive, or uncertain verdict with a one-sentence justification, presented as a coloured indicator in the report.
2. **Pre-scan strategy briefing** — When prior memory exists for the target, the AI provides focus-area guidance prior to discovery.
3. **Adaptive memory** — On scan completion, the AI extracts false-positive signatures, confirmed-true-positive payloads, technology fingerprints, and forward-looking guidance, merging them into the target's memory file. Subsequent scans benefit from accumulated knowledge.
4. **Proof-of-concept generation** — Each high-severity or critical finding receives a HackerOne-format writeup including title, summary, reproduction steps, impact statement, and remediation guidance.

### Supported Providers

| Provider | Setup | Data Privacy | Approximate Cost / Scan |
|---|---|---|---|
| Ollama (recommended for engagements) | `ollama pull llama3.1` and configure host URL | Fully local | None |
| Anthropic Claude | API key from console.anthropic.com | Data transmitted to Anthropic | ~USD 0.05 (Haiku 4.5) |
| DeepSeek | API key from platform.deepseek.com | Data transmitted to DeepSeek | ~USD 0.01 |
| OpenAI | API key from platform.openai.com | Data transmitted to OpenAI | ~USD 0.05 (gpt-4o-mini) |

### Configuration via the Graphical Interface

In the SETTINGS tab, AI Enhancement section:

- Enable AI features.
- Select a provider from the dropdown.
- Enter the API key (input is masked).
- Optionally specify a model override.
- Click **Test Connection** to verify the credentials.

### Configuration via the Command Line

```bash
# Persisted to config.json on first --ai-test
run.bat --ai-test --ai-provider deepseek --ai-key sk-...

# Subsequent scans use the saved configuration
run.bat https://target.example --scan-type deep
```

### Personally Identifiable Information Redaction

For cloud providers (not Ollama), an outbound filter removes the following from finding data prior to transmission:

- Email addresses
- API credentials for AWS, OpenAI, GitHub, and Slack
- PEM-formatted private keys
- US Social Security Numbers and telephone numbers

Redaction may be disabled in SETTINGS when the operator trusts the provider with raw data.

---

## 11. Recommended Workflows

### 11.1 Initial Reconnaissance (Approximately 15 Minutes)

```bash
# Step 1: Validate scope and authentication
run.bat https://target.example --scan-type quick --vuln-types xss sqli cors security_headers

# Step 2: Review findings (open reports/<scan_id>/report.html)

# Step 3: Full deep scan on validated in-scope hosts
run.bat https://target.example --scan-type deep
```

### 11.2 Authenticated Scan with Mid-Scan Expiry Handling

```bash
# Configure auth.cookie in config.json or via the GUI, then:
run.bat https://target.example --scan-type deep
```

If the session expires:

- A notification appears: "Session expired. Open Tools → Refresh Authentication."
- Open Tools → Refresh Authentication, paste fresh credentials, and click Apply.
- All workers (current and future) immediately use the new credentials. No restart is required.

If the authentication backend is unresponsive (login consistently returns 403):

- After three consecutive failed re-authentications on the same host, the circuit breaker opens for five minutes.
- A notification appears: "Authentication retry suspended. Use Tools → Refresh Authentication."
- Resolve the underlying issue and use Tools → Refresh Authentication to re-arm.

### 11.3 Multi-Account Broken Access Control Hunt

1. Authenticate as User-A (privileged or paying account) and capture the cookie.
2. Authenticate as User-B (unprivileged or free account) in a separate browser profile and capture that cookie.
3. In SETTINGS → Multi-Account Authorisation Replay, paste User-B's cookie and enable the feature.
4. Initiate a deep scan with User-A's credentials as the primary authentication.
5. After discovery, every URL successfully accessed by User-A is replayed as User-B. Successful access by User-B produces a Broken Access Control finding (CWE-639).

### 11.4 Subdomain Takeover Survey

1. In SETTINGS → Subdomain Enumeration, enable the feature with both crt.sh and DNS bruteforce.
2. Initiate a deep scan; the takeover check executes automatically against every discovered subdomain.
3. Findings appear under the Subdomain Takeover vulnerability type (HIGH severity per match) with the platform name and remediation guidance.

### 11.5 Single-Page Application or API-Heavy Targets

The application renders entry-point URLs in headless Chrome to capture runtime XHR and fetch requests, mines `.js.map` files for endpoint discovery, and probes approximately 30 well-known paths for OpenAPI, Swagger, and GraphQL specifications.

```bash
# JavaScript rendering is enabled by default
run.bat https://spa.target.example --scan-type deep
```

For targets requiring multi-step manual authentication that the crawler cannot reproduce:

1. Open Tools → Capture Proxy.
2. Configure the operating browser to use `127.0.0.1:8888` as its proxy.
3. Manually exercise the application (log in, navigate, submit forms).
4. Each captured request becomes a scan task. Initiate a normal scan; captured tasks execute alongside discovered tasks.

---

## 12. Aggressive Verb Fuzzing (DELETE, PUT, PATCH)

> **Operational Warning.** Destructive HTTP verbs may permanently delete or modify data on the target system. Unauthorised use against production systems is the most common cause of bug bounty programme termination.

By default, CHOMBEZA Bug Bounty Pro issues only `OPTIONS` and `HEAD` requests as part of method-tampering probes. Both are defined by RFC 9110 to have no side effects. Destructive verbs (DELETE, PUT, PATCH) are disabled by default and require explicit, multi-step opt-in.

### Acceptable Use

- Test or staging environments owned and controlled by the operator.
- Bug bounty programmes whose scope explicitly authorises destructive testing.
- Environments with verified database snapshots that may be restored.

### Unacceptable Use

- Production environments.
- Programmes that do not explicitly authorise destructive testing.
- Any environment whose state cannot be restored.

### Activation Procedure

1. SETTINGS → Aggressive Verb Fuzzing → enable "Send DELETE, PUT, and PATCH requests".
2. A confirmation modal appears. Confirm only if the use case meets the criteria above.
3. Save settings.

The application will:

- Issue an `OPTIONS` request first to retrieve the `Allow` header for each route.
- Issue a destructive verb only against routes that the server has advertised as supporting it ("true positive only" policy).
- Display a console warning and notification for each destructive request issued.

### Critical-Path Override (Disabled by Default)

A second checkbox, "Also test payment, billing, charge, and transfer paths", controls whether destructive testing is permitted against URLs containing financially significant keywords. This option remains disabled by default and presents a stronger confirmation modal when enabled.

### Findings Produced

- **HTTP Method Authorisation Bypass (HEAD)** — Issued without opt-in. Indicates that GET requires authentication while HEAD does not.
- **HTTP Verb Tampering (DELETE, PUT, PATCH)** — Issued only with opt-in. Indicates that a destructive verb succeeds where GET requires authentication.
- **HTTP Method Override Honoured** — Indicates that a `POST` request with `X-HTTP-Method-Override: DELETE` is honoured by the framework, bypassing verb-based authentication filters.

---

## 13. Commercial Licensing and Activation

CHOMBEZA Bug Bounty Pro ships with a **30-day evaluation licence**. After the evaluation period, the application requires a commercial licence to continue. This section covers the operator-side activation procedure.

### 13.1 Subscription Tiers

| Subscription | Tier | Maximum Machines |
|---|---|---:|
| Monthly | Single | 1 |
| Monthly | Team | 5 |
| Annual | Single | 1 |
| Annual | Team | 5 |

For pricing and procurement, contact the licensor (see [Section 16](#16-support-and-licensing)).

### 13.2 During the Evaluation Period

- The application title bar displays the remaining trial days.
- All features are unlocked; no scan or report functionality is restricted.
- The CLI prints a reminder during the final seven days.

### 13.3 Retrieving the Machine Fingerprint

Each commercial licence is bound to one or more machine fingerprints. To obtain the fingerprint of a system:

| Method | Procedure |
|---|---|
| Graphical interface | Tools menu → **Show Machine Fingerprint…**. A dialog displays the 32-character hexadecimal fingerprint with a Copy button. |
| Command line | `chombeza --fingerprint`. Prints the fingerprint to standard output and exits. Pipe-friendly: `chombeza --fingerprint \| clip` (Windows) or `\| xclip -selection clipboard` (Linux). |
| Trial-expired Activation dialog | Appears automatically once the trial has expired. The fingerprint is shown with a Copy button alongside the contact email. |

The fingerprint is non-sensitive and may be transmitted by email, instant message, or any other means.

### 13.4 Procurement Procedure

1. Retrieve the machine fingerprint(s) for the system(s) to be licensed.
2. Send the fingerprint(s) to the licensor along with proof of payment, requesting either a Single or Team licence and either Monthly or Annual subscription.
3. Upon processing, the licensor returns a `.lic` file by email reply.

For team licences, collect fingerprints from up to five machines and submit them together. The same `.lic` file then activates the application on all listed machines.

### 13.5 Installing a Licence File

Three installation paths are supported. All result in the licence being placed at the canonical location:

| Operating System | Canonical Location |
|---|---|
| Windows | `%APPDATA%\CHOMBEZA\license.lic` |
| Linux | `~/.config/CHOMBEZA/license.lic` |
| macOS | `~/Library/Application Support/CHOMBEZA/license.lic` |

#### Path A — During an active evaluation (pre-paying customers)

> Tools menu → **Import Licence File…**

A file picker opens. Browse to the `.lic` file received from the licensor and select it. The application verifies the signature, machine fingerprint, and expiry before installing. The new licence takes effect on next launch.

#### Path B — After the evaluation has expired

The Activation Required dialog appears automatically when CHOMBEZA Bug Bounty Pro is launched. Click **Load Licence File…**, select the `.lic`, and the application proceeds to the main interface upon successful verification.

#### Path C — Manual installation (advanced)

Copy the `.lic` file directly to the canonical location, renaming it to `license.lic`. The next application launch detects and applies it automatically.

### 13.6 Verification Behaviour

When a licence file is verified, the application performs the following checks in order:

1. **Signature verification** using the embedded Ed25519 public key. Tampered files are rejected as "License signature is invalid."
2. **Issuance date validation.** Files with an `issued_at` timestamp in the future are rejected as a clock-rollback indicator.
3. **Machine fingerprint match.** The local machine's fingerprint must appear in the licence's `machine_fingerprints` list.
4. **Expiry check.** The current time must precede the licence's `expires_at` timestamp.

If any check fails, the application displays a descriptive error message and does not install the licence.

### 13.7 Renewals and Replacements

When the subscription period approaches expiry, the title bar shows the remaining days. Contact the licensor to purchase a renewal. The replacement `.lic` is installed by overwriting the existing file via any of the three installation paths above. There is no service interruption when the replacement arrives prior to the existing licence's expiry.

To add machines to a Team licence (within the five-machine cap) or to migrate a licence to a new computer, send the additional or new fingerprint(s) to the licensor for re-issuance.

### 13.8 Licensed Status Indicators

When a valid licence is in effect:

- Title bar text: `CHOMBEZA Bug Bounty Pro` (no trial countdown shown)
- About dialog: displays the licensed customer name and renewal date
- Console banner on launch: `Licensed to <customer> (<tier>, N day(s) until renewal)`

When fewer than 30 days remain on a licence, the CLI emits a renewal reminder on each launch.

---

## 14. Troubleshooting

### `run.sh: not found` (Linux / macOS)

The launcher is created automatically by the installer. If absent, re-run `bash install.sh`. As a fallback:

```bash
chmod +x run.sh
# or invoke Python directly:
venv/bin/python main.py [arguments]
```

### "Failed to generate PDF" or WeasyPrint Warning

ReportLab is the default PDF backend and operates without external dependencies. The WeasyPrint warning is informational. To enable the WeasyPrint backend:

```bash
# Debian / Ubuntu
sudo apt install -y libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libgdk-pixbuf-2.0-0

# macOS
brew install pango cairo gdk-pixbuf libffi

# Windows: WeasyPrint requires GTK runtime; the ReportLab fallback is sufficient.
```

### "Chrome / Chromium not found"

Evidence screenshots and DOM-aware XSS verification require Chrome or Chromium. The scan continues without these features when the browser is unavailable.

| Operating System | Installation Command |
|---|---|
| Windows | Download from https://www.google.com/chrome/ |
| Debian / Ubuntu | `sudo apt install chromium-browser` |
| Fedora / RHEL | `sudo dnf install chromium` |
| Arch | `sudo pacman -S chromium` |
| macOS | `brew install --cask google-chrome` |

### Discovery Phase Appears Stalled

The console emits a stall watchdog warning if no progress is recorded for 15 seconds. If this occurs, the discovery phase is blocked on a slow target operation (DNS resolution or page load). Terminate with `Ctrl+C` and re-run with reduced scope or the `quick` profile.

### Repeated CSRF Token Expiry Notifications

Resolved in version 2.4. The circuit breaker now suspends retries after three consecutive failures per host. If the issue persists on version 2.4 or later, the authentication backend is genuinely unresponsive; use Tools → Refresh Authentication to supply fresh credentials.

### Application Window Does Not Appear (Linux Headless or SSH)

PyQt5 requires an X server. On headless systems, use the offscreen Qt platform plugin:

```bash
QT_QPA_PLATFORM=offscreen ./run.sh https://target.example --scan-type quick
```

Alternatively, run the graphical interface over SSH X forwarding (`ssh -X`).

### Permission Errors Writing to `reports/`

If the application is being run as a different user (e.g. inside a Docker container), ensure that the directory is writable:

```bash
mkdir -p reports && chmod 755 reports
```

### `ModuleNotFoundError` After Update

Re-run the installer to acquire updated dependencies:

```bash
# Windows
install.bat

# Linux / macOS
bash install.sh
```

### Crash Dialog at Startup or During Scan

Crash details are written to `crash.log` in the user data directory:

- Windows: `%LOCALAPPDATA%\CHOMBEZA\crash.log`
- Linux: `~/.local/share/CHOMBEZA/crash.log`
- macOS: `~/Library/Application Support/CHOMBEZA/crash.log`

Each entry includes a timestamp and the per-task context (URL, vulnerability type, worker thread name). Include this file when reporting an issue.

---

## 15. Platform-Specific Notes

### Windows

- The installer creates `run.bat` and a `venv\` virtual environment.
- High-DPI scaling is fixed at 1× on Windows due to Qt's tendency to over-scale; Linux and macOS honour the system DPI setting.
- In PowerShell, use `run.bat <arguments>` or `venv\Scripts\python.exe main.py <arguments>`.
- The standard error redirect pattern in PowerShell is `2>$null` rather than `2>/dev/null`.

### Linux

- The installer creates `run.sh` and a `venv/` virtual environment.
- Required system packages: `python3-venv`, `python3-dev`, `libgl1`, `libxkbcommon0`, `libdbus-1-3`, `libfontconfig1`, and a Chromium browser. Optional for WeasyPrint PDF generation: `libpango-1.0-0`, `libpangoft2-1.0-0`, `libcairo2`, `libgdk-pixbuf-2.0-0`.
- For headless operation: `QT_QPA_PLATFORM=offscreen ./run.sh ...`.
- Under SELinux, Chromium invoked through Selenium may be blocked. If screenshots fail with permission errors, temporarily set `setenforce 0` to confirm SELinux as the cause.

### macOS

- `brew install python pkg-config` followed by `brew install --cask google-chrome` covers the standard installation requirements.
- ARM-based Mac systems (M1 and later) are supported with native Python wheels for all dependencies as of version 2.4. If a build error occurs, install `pkg-config` first.
- macOS Gatekeeper may quarantine the chromedriver binary on first use. Authorise it through System Settings → Privacy and Security.

### Containerised and Continuous Integration Environments

CHOMBEZA Bug Bounty Pro can operate headlessly within Docker containers and CI pipelines:

```bash
QT_QPA_PLATFORM=offscreen \
  python main.py https://target.example \
    --scan-type deep \
    --no-screenshot \
    --format json \
    --ai-disabled
```

Combine with `--list-scans` and `--resume` to distribute long-running scans across multiple pipeline stages.

---

## 16. Support and Licensing

CHOMBEZA Bug Bounty Pro is supplied under a 30-day evaluation licence. Continued use beyond the evaluation period requires a commercial licence.

For licensing inquiries, support requests, and feature suggestions, please contact:

> **Dickson Massawe (archnexus)**
> Email: archnexus707@gmail.com

For technical issues during the evaluation period, please include the contents of `crash.log` (path varies by platform; see [Section 14](#14-troubleshooting)) where applicable.
