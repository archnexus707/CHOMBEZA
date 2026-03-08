# 🐞 CHOMBEZA Bug Bounty Pro

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.1.0-blue?style=for-the-badge&logo=python" alt="Version 2.1.0">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License MIT">
  <img src="https://img.shields.io/badge/Python-3.7%2B-yellow?style=for-the-badge&logo=python" alt="Python 3.7+">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=for-the-badge" alt="Platform">
</p>

<p align="center">
  <b>Advanced Security Testing Toolkit for Bug Hunters & VAPT Professionals</b><br>
  ⚡ 50+ Vulnerability Types • Live Traffic Monitoring • Professional Reports • Blind XSS Server ⚡
</p>

<p align="center">
  <i>Created by <b>Dickson Godwin Massawe (archnexus707)</b></i>
</p>

---

## 📋 **Table of Contents**

- [✨ Features](#-features)
- [📥 Installation](#-installation)
  - [Windows](#windows)
  - [Linux / macOS](#linux--macos)
- [🚀 Quick Start](#-quick-start)
  - [GUI Mode](#gui-mode)
  - [CLI Mode](#cli-mode)
- [🔐 Authentication](#-authentication)
- [🎯 Vulnerability Coverage](#-vulnerability-coverage)
- [📊 Reports](#-reports)
- [📁 Project Structure](#-project-structure)
- [🛠️ Building from Source](#️-building-from-source)
- [📦 Download Installer](#-download-installer)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

---

## ✨ **Features**

### 🔍 **Comprehensive Vulnerability Detection**

| Category | Vulnerabilities |
|----------|----------------|
| **Injection** | XSS, SQLi (Error/Union/Blind), NoSQLi, LDAPi, XPATHi, SSTI, LFI, RCE, XXE, SSRF |
| **Configuration** | JWT, CORS, CSP, HTTP Smuggling, Web Cache, Open Redirect, CRLF |
| **Access Control** | IDOR, Privilege Escalation, Broken Access, Mass Assignment |
| **API & Modern** | GraphQL, WebSocket, API Fuzzing, gRPC, Serverless |
| **Infrastructure** | Subdomain Takeover, Cloud Metadata, DNS Rebinding, Port Scanning |
| **Advanced** | Prototype Pollution, Race Condition, Deserialization, Memory Corruption |

### 🖥️ **Professional GUI**

- 🎨 **Cyberpunk-themed interface** with 5 visual themes (Neon, Cyberpunk, Matrix, Dark, Color Blind)
- 📊 **Live Traffic Monitoring** - Real-time request/response viewer with filtering
- 🎯 **Blind XSS Server** - Built-in callback server on port 5000
- 🧪 **Payload Laboratory** - Generate and test custom payloads
- 📸 **Screenshot Evidence** - Automatic capture of vulnerabilities
- 🔧 **Settings Panel** - Full control over scan parameters

### ⚡ **Performance & Stealth**

- 🚀 **Multi-threaded scanning** (up to 100 concurrent threads)
- 🛡️ **WAF Evasion** - Smart payload delivery techniques
- 🔄 **Rate Limiting** - Avoid being blocked
- 🌐 **Proxy Support** - HTTP, HTTPS, SOCKS proxies
- 🔐 **Authentication** - Cookies, Bearer tokens, Form login with auto-detection

### 📊 **Professional Reporting**

- 📄 **Multiple Formats**: HTML, PDF, JSON, CSV
- 🖼️ **Embedded Screenshots** - Visual proof of vulnerabilities
- 📈 **CVSS Scoring** - Industry-standard severity ratings
- 📋 **Executive Summary** - Business-friendly overview
- 🔧 **Remediation Guidance** - Actionable fix recommendations
- 📅 **Remediation Roadmap** - Priority-based action plan

### 🧠 **ML-Powered False Positive Reduction**

- 🤖 **Trainable ML model** that learns from your feedback
- 📊 **Real-time classification** of findings (True Positive / False Positive / Uncertain)
- 🔄 **Continuous improvement** as you validate findings
- 📈 **Confidence scoring** for each vulnerability

---

## 📥 **Installation**

### **Windows**

<details>
<summary>Click to expand Windows installation instructions</summary>

#### Option 1: Download Installer (Recommended)

1. Download the latest installer from [Releases](https://github.com/archnexus707/CHOMBEZA/releases)
2. Run `CHOMBEZA_Setup_v2.0.exe`
3. Follow the installation wizard
4. Launch from Desktop or Start Menu

#### Option 2: Install from Source

```batch
:: Clone repository
git clone https://github.com/archnexus707/CHOMBEZA.git
cd CHOMBEZA

:: Run installer
install.bat

:: Activate environment
venv\Scripts\activate

:: Launch CHOMBEZA
python main.py
```
</details>

### **Linux / macOS**

<details>
<summary>Click to expand Linux/macOS installation instructions</summary>

```bash
# Clone repository
git clone https://github.com/archnexus707/CHOMBEZA.git
cd CHOMBEZA

# Make installer executable
chmod +x install.sh

# Run installer
./install.sh

# Activate environment
source venv/bin/activate

# Launch CHOMBEZA
python main.py
```
</details>

---

## 🚀 **Quick Start**

### **GUI Mode**

```bash
# Simply run without arguments
python main.py
```

### **CLI Mode**

```bash
# Quick scan
python main.py https://example.com --scan-type quick

# Deep scan with 20 threads
python main.py https://example.com --scan-type deep --threads 20

# Test specific vulnerabilities
python main.py https://example.com --vuln-types xss sqli ssrf

# Start Blind XSS server only
python main.py --blind-xss --blind-xss-port 5000

# Use proxy
python main.py https://example.com --proxy http://127.0.0.1:8080

# Authenticated scan
python main.py https://example.com --auth-cookie "session=abc123"

# Generate report only
python main.py https://example.com --format pdf --output my_report
```

---

## 🔐 **Authentication**

CHOMBEZA supports multiple authentication methods. Configure them in **Settings → AUTHENTICATION**:

| Method | Description | Example |
|--------|-------------|---------|
| **Cookie String** | Session cookies for authenticated areas | `sessionid=abc123; csrftoken=xyz789` |
| **Bearer Token** | JWT or API tokens (without "Bearer " prefix) | `eyJhbGciOiJIUzI1NiIs...` |
| **Auto-login** | Automatic form-based login | URL, username, password |

CHOMBEZA will:
1. Bootstrap authentication once at scan start
2. Reuse cookies/headers across all scanner worker sessions
3. Automatically refresh sessions when needed

---

## 🎯 **Vulnerability Coverage**

| # | Type | # | Type | # | Type |
|---|------|---|------|---|------|
| 1 | Cross-Site Scripting (XSS) | 18 | Web Cache Poisoning | 35 | DNS Rebinding |
| 2 | SQL Injection | 19 | Open Redirect | 36 | Port Scanning |
| 3 | Blind SQL Injection | 20 | CRLF Injection | 37 | Prototype Pollution |
| 4 | NoSQL Injection | 21 | IDOR | 38 | Race Condition |
| 5 | LDAP Injection | 22 | Privilege Escalation | 39 | Deserialization |
| 6 | XPath Injection | 23 | Broken Access Control | 40 | Memory Corruption |
| 7 | SSTI | 24 | Mass Assignment | 41 | XXE |
| 8 | LFI | 25 | GraphQL Introspection | 42 | SSRF |
| 9 | RCE | 26 | WebSocket Hijacking | 43 | ...and more! |
| 10 | JWT Attacks | 27 | API Fuzzing | | |

---

## 📊 **Reports**

CHOMBEZA generates professional, Acunetix-style reports including:

- 📄 **Executive Summary** with risk scoring
- 📊 **Vulnerability Heat Maps** by category
- 📈 **CVSS Scoring** with vectors
- 🔍 **Detailed Findings** with evidence
- 📸 **Screenshot Evidence** embedded
- 📨 **Request/Response traces**
- 💡 **Remediation guidance**
- 📅 **Remediation Roadmap** with priorities

---

## 📁 **Project Structure**

```
CHOMBEZA/
├── main.py                 # Main entry point
├── config.json             # Configuration file
├── requirements.txt        # Python dependencies
├── core/                   # Core modules
│   ├── scanner.py          # Main scanner engine
│   ├── auth.py             # Authentication manager
│   ├── report.py           # Report generator
│   ├── screenshot.py       # Screenshot capture
│   ├── payloads.py         # Payload database
│   ├── session.py          # Session management
│   ├── utils.py            # Utilities
│   ├── blind_xss.py        # Blind XSS server
│   ├── cache.py            # Response caching
│   ├── ml_fp_reducer.py    # ML false positive reduction
│   ├── state.py            # Scan state persistence
│   └── checkers/           # Modular vulnerability checkers
│       └── xss_checker.py  # XSS detection
├── api/                    # REST API server
│   └── server.py           # API implementation
├── ui/                     # User interface
│   ├── main_window.py      # Main GUI window
│   ├── live_traffic_window.py # Traffic monitor
│   ├── styles.py           # UI themes
│   └── widgets.py          # Custom widgets
├── plugins/                # Plugin system
│   └── waf_detector_plugin.py # Example plugin
├── examples/               # Example scripts
│   └── api_client_example.py # API client example
├── templates/              # HTML report templates
├── reports/                # Generated reports
│   └── screenshots/        # Vulnerability screenshots
└── installer/              # Windows installer output
    └── CHOMBEZA_Setup_v2.0.exe # Compiled installer
```

---

## 🛠️ **Building from Source**

### **Build Executable with PyInstaller**

```bash
# Install PyInstaller
pip install pyinstaller

# Build standalone executable
pyinstaller --onefile --windowed --icon=favicon2.ico --name=CHOMBEZA ^
  --add-data "core;core" --add-data "ui;ui" --add-data "templates;templates" ^
  --add-data "api;api" --add-data "plugins;plugins" --add-data "config.json;." ^
  --hidden-import PyQt5.sip main.py
```

### **Build Installer with Inno Setup**

1. Download and install [Inno Setup](https://jrsoftware.org/isdl.php)
2. Run the compiler:
```bash
ISCC.exe chombeza_installer.iss
```

---

## 📦 **Download Installer**

Ready-to-use Windows installer available on the [Releases Page](https://github.com/archnexus707/CHOMBEZA/releases):

- ✅ No Python installation required
- ✅ All dependencies bundled
- ✅ One-click installation
- ✅ Desktop and Start Menu shortcuts

---

## 🤝 **Contributing**

Contributions are welcome! Here's how you can help:

1. 🐛 **Report bugs** by opening issues
2. 💡 **Suggest features** via issues
3. 🔧 **Submit pull requests** for fixes/features
4. 📝 **Improve documentation**
5. 🌐 **Add new payloads** to the database
6. 🔌 **Create plugins** for new vulnerability types

---

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE.txt](LICENSE.txt) file for details.

---

## 👨‍💻 **Author**

**Dickson Godwin Massawe (archnexus707)**

- GitHub: [@archnexus707](https://github.com/archnexus707)
- Email: dicksonmassawe707@gmail.com

---

<p align="center">
  <b>Happy Hunting! 🐞</b><br>
  <i>Use responsibly and only on authorized systems</i>
</p>

<p align="center">
  <a href="https://github.com/archnexus707/CHOMBEZA/stargazers">
    <img src="https://img.shields.io/github/stars/archnexus707/CHOMBEZA?style=social" alt="GitHub stars">
  </a>
  <a href="https://github.com/archnexus707/CHOMBEZA/network/members">
    <img src="https://img.shields.io/github/forks/archnexus707/CHOMBEZA?style=social" alt="GitHub forks">
  </a>
  <a href="https://github.com/archnexus707/CHOMBEZA/issues">
    <img src="https://img.shields.io/github/issues/archnexus707/CHOMBEZA?style=social" alt="GitHub issues">
  </a>
</p>
