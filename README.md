<div align="center">
  <img src="favicon2.ico" width="80" alt="CHOMBEZA Logo">
  <h1>🐞 CHOMBEZA Bug Bounty Pro</h1>
  <p><strong>Advanced Security Testing Toolkit for Bug Hunters & VAPT Professionals</strong></p>
</div>

<div align="center">
  
  [![Version](https://img.shields.io/badge/Version-2.0-brightgreen?style=for-the-badge&logo=github)](https://github.com/dkhacker707/chombeza)
  [![Python](https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python)](https://www.python.org)
  [![Platform](https://img.shields.io/badge/Platform-Windows%20|%20Linux-orange?style=for-the-badge&logo=windows)](https://github.com/dkhacker707/chombeza)
  [![License](https://img.shields.io/badge/License-Proprietary-red?style=for-the-badge&logo=legal)](EULA.txt)
  [![Downloads](https://img.shields.io/badge/Downloads-1K+-purple?style=for-the-badge&logo=download)](https://github.com/dkhacker707/chombeza/releases)
  
</div>

<div align="center">
  <h3>⚡ 50+ Vulnerability Types • Live Traffic Monitoring • Professional Reports • Blind XSS Server ⚡</h3>
  <p><i>Created by <b>Dickson Godwin Massawe (archnexus707)</b></i></p>
</div>

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
- [📚 Documentation](#-documentation)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)
- [👨‍💻 Author](#-author)

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
cd chombeza

:: Run installer
install.bat

:: Activate environment
venv\Scripts\activate

:: Launch CHOMBEZA
python main.py


### **Linux/macOS**
# Clone repository
git clone https://github.com/archnexus707/CHOMBEZA.git
cd chombeza

# Make installer executable
chmod +x install.sh

# Run installer
./install.sh

# Activate environment
source venv/bin/activate

# Launch CHOMBEZA
python main.py

🚀 Quick Start

GUI Mode
# Simply run without arguments
python main.py

CLI Mode
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



