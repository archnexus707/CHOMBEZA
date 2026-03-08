# CHOMBEZA Bug Bounty Pro (Community / Free Libraries)

⚠️ **Use only on systems you own or have explicit permission to test.**  
CHOMBEZA is intended for authorized security testing (bug bounty / VAPT).

## Project Structure

```
CHOMBEZA/
  main.py
  config.json
  requirements.txt
  core/
    scanner.py
    auth.py
    report.py
    screenshot.py
    payloads.py
    payloads.json
    session.py
    utils.py
    blind_xss.py
  ui/
    main_window.py
    live_traffic_window.py
    styles.py
    widgets.py
  reports/
    screenshots/
  templates/
```

## Install (Linux / macOS)

```bash
chmod +x install.sh
./install.sh
source venv/bin/activate
python main.py
```

## Install (Windows)

1. Run:

```bat
install.bat
```

2. Then:

```bat
venv\Scripts\activate
python main.py
```

## CLI Usage

```bash
python main.py https://target.com --scan-type deep --threads 20
python main.py https://target.com --blind-xss
```

## Authentication (Cookie + Bearer + Auto-login)

Open **Settings → AUTHENTICATION**:

- **Cookie String**: `sessionid=...; csrftoken=...`
- **Bearer Token**: put token only (without `Bearer `)
- **Auto-login**:
  - Login URL
  - Username / Password
  - Optional overrides if your login form uses custom field names

CHOMBEZA will:
1) bootstrap auth once (login if configured)  
2) reuse cookies/headers across all scanner worker sessions.

## Optional: Playwright browser install (only if you want that screenshot backend)

```bash
playwright install
```

If WeasyPrint PDF fails on Linux, install system deps (depends on distro).  
CHOMBEZA will still fall back to other PDF methods if WeasyPrint is unavailable.
