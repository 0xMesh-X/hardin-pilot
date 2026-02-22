<div align="center">
  <img src="logo.png" alt="Hardin Pilot Logo" width="600" />
</div>

# Hardin Pilot

> **AI-Powered Linux Security Configuration Auditor**

Hardin Pilot is a robust, automated CLI tool that scans your Linux system for configuration files across 55+ services, deeply analyzes them using advanced AI models, and generates comprehensive PDF security reports alongside actionable remediation commands.

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

---

> [!CAUTION]
> **IMPORTANT NOTE REGARDING AI MODELS**
> This tool was exclusively vetted, QA'd, and optimized over hours of rigorous testing using the **`gemini-2.5-flash`** model (specifically utilizing its deep "thinking" capabilities). 
> 
> **We strongly advise sticking to Google Gemini as your primary provider.** While other API providers (like OpenAI, Groq, or Local LMStudio endpoints) are technically supported via the setup menu, their JSON parsing abilities have **not** been extensively tested and they may act unpredictably when handling complex, multi-layered Linux configurations. Use them at your own risk.

---

## 🌟 Key Features

- **Massive Discovery Scanner**: Automatically detects configuration files for 55+ standard Linux services (SSH, Nginx, Apache, MySQL, Docker, Kubernetes, etc.) and gracefully handles custom `conf.d` structures.
- **Provider-Agnostic Deep AI Analysis**: Supports **Google Gemini** (free-tier out of the box), **OpenAI** (ChatGPT), or **Local / Custom APIs** (LMStudio, Ollama, DeepSeek, Groq). Hardin utilizes deep "thinking" cognitive layers (where available) to reason through complex misconfigurations.
- **Auto-Remediation Workflow**: Doesn't just find problems. Hardin generates exact, safe terminal commands (`sed`, etc.) to instantly fix all discovered vulnerabilities. It saves these to `~/.hardin/last_remediation.sh` so you can review your PDF first and independently execute the fixes later with `hardin --apply`.
- **Beautiful PDF Reporting**: Compiles service-by-service findings into a clean, merged, professional PDF document for compliance and review.
- **Stateful Crash Recovery**: Network interrupted? Rate-limited? Hardin tracks progress. Just re-run the tool and it picks up exactly where it left off.
- **Rich Interactive CLI**: Beautiful terminal output with progress bars, severity color-coding, and an interactive first-time setup wizard.

---

## 🛠️ Tech Stack

- **Language**: Python 3.10+
- **AI Integration**: `google-genai` and `openai` SDKs
- **Reporting Generator**: `reportlab` & `PyPDF2`
- **CLI Framework**: `rich`, `rich.prompt`, & standard `argparse`

---

## 📦 Prerequisites

- A Linux environment (Ubuntu/Debian, CentOS, RHEL, Arch, WSL2, MacOS)
- Python 3.10 or higher
- An API Key from Google (Gemini) or a compatible LLM provider

---

## 🚀 Getting Started

### 1. The Automated Installer (Recommended)

The absolute fastest way to get Hardin running is to use the included installation script. This script automatically updates package lists, ensures `python3-venv` is present, creates an isolated environment, and installs the tool globally on your path.

```bash
# Clone the repository
git clone https://github.com/0xMesh-X/hardin-pilot.git
cd hardin-pilot

# Run the automated install script
chmod +x install.sh
sudo ./install.sh

# Launch Hardin
hardin
```

### 2. Manual Installation

If you prefer to manage the virtual environment yourself:

```bash
# Clone and enter directory
git clone https://github.com/0xMesh-X/hardin-pilot.git
cd hardin-pilot

# Setup your virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies and the tool
pip install -e .

# Launch Hardin
hardin
```

---

## ⚙️ Configuration & Usage

The first time you run `hardin`, an interactive wizard will launch to help you configure your preferred AI provider.

### The Setup Wizard

```bash
hardin
```

The wizard will ask you to choose between:

1. **Google Gemini**: The default. Generous free tier via Google AI Studio. (Includes choices like `gemini-2.5-flash`, `gemini-2.5-pro`, and `gemini-2.0-flash-thinking-exp`). Provide the number matching your choice.
2. **OpenAI**: For those with ChatGPT/OpenAI API keys. (Experimental).
3. **Local / Custom API**: For offline, private AI (like LMStudio running on `http://localhost:1234/v1`) or alternative providers (like Groq or DeepSeek). (Experimental).

The wizard will provide you the exact URL where you can generate the required API key based on your choice. Configurations are saved securely to `~/.hardin/config.json`.

### CLI Commands

| Command | Description |
|---|---|
| `hardin` | Runs the standard scan. Analyzes configs, generates the PDF, and securely saves the pending fixes. |
| `hardin --apply` | Instantly executes the pending remediation script generated by your last complete scan. |
| `hardin --list` | Scans the system and simply lists which services it found, without sending data to the AI. |
| `hardin --no-resume` | Clears previous tracking state and forces a fresh, complete scan from scratch. |
| `hardin --scan /path/to/extra/config` | Explicitly targets an extra directory to scan, in addition to the defaults. |
| `hardin --set-key ""` | Explicitly overwrite the API key. |
| `hardin --reset` | Wipes the entire local configuration (`config.json`) and state caches, forcing the interactive setup wizard to launch anew. |

---

## 🏗️ Architecture

```text
┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Scanner   │────▶│   Analyzer   │────▶│   Reporter   │────▶│   Output     │
│             │     │              │     │              │     │              │
│ Discovers   │     │ Routes to    │     │ Generates    │     │ Merged PDF   │
│ configs by  │     │ Gemini/OpenAI│     │ per-service  │     │ + bash fix   │
│ service     │     │              │     │ PDFs, merges │     │ remediation  │
└─────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
```

1. **Scan Phase (`scanner.py`)**: Traverses known paths (like `/etc/ssh`, `/etc/nginx`) checking for existence and reading file contents safely. Truncates massive files to prevent token overflows.
2. **Analysis Phase (`analyzer.py`)**: Injects the configuration text into a highly specific security prompt. Leverages the AI model's "thinking/reasoning" engines (if available) to evaluate the configs, ultimately extracting a clean JSON response.
3. **State Management (`state.py`)**: Intervenes between network calls to record progress instantly to `~/.hardin/state.json`, protecting you against connection losses or hard-coded API Rate Limits.
4. **Reporting Phase (`reporter.py`)**: Renders beautifully stylized PDF pages (using Arial/Helvetica to avoid missing font errors) on a service-by-service basis and merges them into one cohesive compliance document. Auto-generates the remediation bash script to `~/.hardin/last_remediation.sh`.
5. **CLI Logic Engine (`cli.py`)**: Orchestrates the rich visual interface, progress bars, API configuration workflows, argument parsing, and subprocess executions for applying fixes.

### Supported Services

Hardin natively knows where to look for over 55 common configuration structures, including:
`ssh`, `nginx`, `apache2`, `mysql`, `postgresql`, `redis`, `samba`, `vsftpd`, `postfix`, `bind`, `dhcp`, `ntp`, `rsyslog`, `sudo`, `cron`, `pam`, `ufw`, `iptables`, `fail2ban`, `sysctl`, `fstab`, `docker`, `kubernetes`, `snmp`, `nfs`, `systemd`, `apparmor`, `selinux`, `modprobe`, `squid`, `openvpn`, `wireguard`, `mongodb`, `memcached`, `tomcat`, `php`, `haproxy`... and a massive `miscellaneous` catch-all for any other `.conf` files living in root `/etc/`.

---

## 🔧 Troubleshooting

### "Are my files being sent to the cloud?"

Yes, unless you use the **Local / Custom API** option. If you are auditing extremely sensitive production networks, it is recommended to run a local model like `llama3` or `qwen2.5-coder` on a dedicated machine and point Hardin's API Base URL to it via the setup wizard.

### "I'm hitting Rate Limits!"

Free-tier API keys limit how many requests you can make per minute and per day.
- If it's a Per-Minute limit, Hardin will automatically pause, wait, and retry with exponential backoff.
- If it's a Per-Day limit, Hardin will save your exact state. Wait 24 hours (or switch to a new provider) and just run `hardin` again to continue from exactly where you stopped.

### "PDF Font Errors"

Hardin uses standard `Helvetica` and `Helvetica-Bold` built into PDF readers to avoid relying on external `.ttf` files that might not be installed on bare-bones server environments. PDF generation should work fluidly on entirely headless Linux boxes.

---

## 📜 License

MIT License. See [LICENSE](LICENSE) for details.
