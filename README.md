<div style="text-align: center;">
  <img src="https://github.com/0xMesh-X/hardin-pilot/raw/master/logo.png" alt="Pyhardin Logo" width="600" />
</div>

# Pyhardin

> **AI-Powered Linux Security Configuration Auditor**

Pyhardin is a robust, automated CLI tool that scans your Linux system for configuration files across 55+ services,
deeply analyzes them using advanced AI models, and generates comprehensive PDF security reports alongside actionable
remediation commands.

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

---

> [!CAUTION]
> **IMPORTANT NOTE REGARDING AI MODELS**
> This tool was exclusively vetted, QA'd, and optimized over hours of rigorous testing using the **`gemini-2.5-flash`**
> model (specifically using its deep "thinking" capabilities).
>
> **We strongly advise sticking to Google Gemini as your primary provider.** While other API providers (like OpenAI,
> Groq, or Local LMStudio endpoints) are technically supported via the setup menu, their JSON parsing abilities have **not
** been extensively tested, and they may act unpredictably when handling complex, multi-layered Linux configurations. Use
> them at your own risk.

---

## 🌟 Key Features

- **Massive Discovery Scanner**: Automatically detects configuration files for 55+ standard Linux services (SSH, Nginx,
  Apache, MySQL, Docker, Kubernetes, etc.) and gracefully handles custom `conf.d` structures.
- **Provider-Agnostic Deep AI Analysis**: Supports **Google Gemini** (free-tier out of the box), **OpenAI** (ChatGPT),
  or **Local / Custom APIs** (LMStudio, Ollama, DeepSeek, Groq). Pyhardin uses deep "thinking" cognitive layers (where available) to reason through complex misconfigurations.
- **Auto-Remediation Workflow**: Doesn't just find problems. Pyhardin generates exact, safe terminal commands (`sed`,
  etc.) to instantly fix all discovered vulnerabilities. It saves these to `~/.pyhardin/last_remediation.sh` so you can
  review your PDF first and independently execute the fixes later with `pyhardin --apply`.
- **FastAPI + HTMX Dashboard**: Prefer a GUI over the terminal? Pyhardin includes a blazing-fast, lightweight web
  dashboard. Run `pyhardin --gui` to review findings, tweak API settings, view prompts in structured tables, and
  download PDFs straight from your browser.
- **Beautiful PDF Reporting**: Compiles service-by-service findings into a clean, merged, professional PDF document for
  compliance and review.
- **Stateful Crash Recovery**: Network interrupted? Rate-limited? Pyhardin tracks progress. Just re-run the tool, and it
  picks up exactly where it left off.
- **Rich Interactive CLI**: Beautiful terminal output with progress bars, severity color-coding, and an interactive
  first-time setup wizard.

---

## 🛠️ Tech Stack

- **Core Language**: Python 3.10+
- **AI Integration**: `google-genai` and `openai` SDKs
- **Reporting Generator**: `reportlab` & `PyPDF2`
- **CLI Framework**: `rich`, `rich.prompt`, & standard `argparse`
- **Web Dashboard**: `fastapi`, `htmx`, `tailwind-css`, `jinja2`, and `aiofiles`

---

## 📦 Prerequisites

- A Linux environment (Ubuntu/Debian, CentOS, RHEL, Arch, WSL2, MacOS)
- Python 3.10 or higher
- An API Key from Google (Gemini) or a compatible LLM provider

---

## 🚀 Getting Started

Pyhardin follows a **"One Source of Truth"** philosophy. All dependencies are managed strictly via the modern
`pyproject.toml` standard. This repository purposefully excludes lockfiles (`uv.lock`, `Pipfile`, etc.) to remain
package-manager neutral and allow your local environment to resolve the best compatible versions.

### 1. PyPI (Recommended)

The easiest way to installation is via the official Python Package Index:

```bash
# Core CLI only (Ultra-lightweight)
pip install pyhardin

# CLI + Web GUI Dashboard
pip install "pyhardin[gui]"
```

### 2. Alternative Package Managers

If you prefer to isolate Pyhardin in its own environment, you can use any of the popular package managers:

#### Using `pip` and `venv`

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install pyhardin
```

#### Using `uv`

```bash
uv venv
source .venv/bin/activate
uv pip install pyhardin
```

#### Using `pipenv`

```bash
pipenv install pyhardin
pipenv shell
pyhardin
```

#### Using `conda` (Recommended)

```bash
# Create the environment from the included file
conda env create -f environment.yml

# Activate it
conda activate pyhardin

# Launch Pyhardin
pyhardin
```

### 3. The Automated Installer (From Source)

The absolute fastest way to get Pyhardin running from source is to use the included installation script. This script
automatically updates package lists, ensures `python3-venv` is present, creates an isolated environment, and installs
the tool globally on your path.

```bash
# Clone the repository
git clone https://github.com/alqinae/pyhardin.git
cd pyhardin

# Run the automated install script
chmod +x install.sh
sudo ./install.sh

# Run from anywhere!
pyhardin
```

### 4. Manual Installation (Development)

If you prefer to manage the source code yourself:

```bash
# Clone and enter directory
git clone https://github.com/alqinae/pyhardin.git
cd pyhardin
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies and the tool
pip install -e .

# Launch Pyhardin
pyhardin
```

---

## ⚙️ Configuration & Usage

The first time you run `pyhardin`, an interactive wizard will launch to help you configure your preferred AI provider.

### The Setup Wizard

```bash
pyhardin
```

The wizard will ask you to choose between:

1. **Google Gemini**: The default. Generous free tier via Google AI Studio. (Includes choices like `gemini-2.5-flash`,
   `gemini-2.5-pro`, and `gemini-2.0-flash-thinking-exp`). Provide the number matching your choice.
2. **OpenAI**: For those with ChatGPT/OpenAI API keys. (Experimental).
3. **Local / Custom API**: For offline, private AI (like LMStudio running on `http://localhost:1234/v1`) or alternative
   providers (like Groq or DeepSeek). (Experimental).

The wizard will provide you with the exact URL where you can generate the required API key based on your choice.
Configurations are saved securely to `~/.pyhardin/cli_config.json` and `~/.pyhardin/web_config.json`.

### CLI Commands

| Command                                 | Description                                                                                                                 |
|-----------------------------------------|-----------------------------------------------------------------------------------------------------------------------------|
| `pyhardin`                              | Runs the standard CLI interactive scan. Analyzes configs locally and generates the PDF.                                     |
| `pyhardin --gui`                        | **New!** Launches the FastAPI web dashboard at `http://localhost:8000` for a rich visual experience.                        |
| `pyhardin --gui --port 8080`            | Launches the web dashboard on a custom port instead of the default `8000`.                                                  |
| `pyhardin --apply`                      | Instantly executes the pending remediation script generated by your last complete scan.                                     |
| `pyhardin --show <ID> --show-prompts`   | Views the detailed report (and LLM structured prompt tables) for a past scan ID.                                            |
| `pyhardin --delete <ID>`                | Permanently deletes a specific scan report from local history.                                                              |
| `pyhardin --list`                       | Scans the system and simply lists which services it found, without sending data to the AI.                                  |
| `pyhardin --history`                    | Displays a table of all your historical local CLI and GUI scans.                                                            |
| `pyhardin --no-resume`                  | Clears previous tracking state and forces a fresh, complete scan from scratch.                                              |
| `pyhardin --resume-id <ID>`             | Explicitly resumes a specific historical incomplete scan.                                                                   |
| `pyhardin --scan /path/to/extra/config` | Explicitly targets an extra directory to scan, in addition to the defaults.                                                 |
| `pyhardin --set-key ""`                 | Explicitly overwrite the API key.                                                                                           |
| `pyhardin --reset`                      | Wipes the entire local configuration (`cli_config.json`, `web_config.json`) and state caches, forcing the interactive setup wizard to launch anew. |

### Remote Dashboard Access (Cloud Providers)

If you are running Pyhardin on a remote server and want to access the Web GUI (`pyhardin --gui`) from your local
browser, you need to ensure **Port 8000 (TCP)** is open in both your server's local firewall and your cloud provider's
network security group.

#### AWS (EC2)

1. Go to the EC2 Dashboard → **Security Groups**.
2. Select the Security Group attached to your instance.
3. Click **Edit inbound rules** → **Add rule**.
4. Type: `Custom TCP`, Port Range: `8000`, Source: `My IP` (Recommended) or `0.0.0.0/0` (Anywhere).

#### Google Cloud (GCP)

1. Go to VPC Network -> **Firewall**.
2. Click **Create Firewall Rule**.
3. Name: `allow-pyhardin-8000`, Targets: `All instances in the network` (or specific tags), Source filter:
   `IPv4 ranges` -> `0.0.0.0/0`.
4. Specified protocols and ports: Check `tcp` and type `8000`.

#### Microsoft Azure

1. Go to Virtual Machines → Select your VM → **Networking**.
2. Click **Add inbound port rule**.
3. Destination port ranges: `8000`, Protocol: `TCP`, Action: `Allow`.

#### UFW / IPTables (Local Server Firewall)

If your Linux instance is also running a local firewall (like `ufw`), you must allow the port natively in the terminal
before the dashboard can receive traffic:

```bash
sudo ufw allow 8000/tcp
```

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

1. **Scan Phase (`scanner.py`)**: Traverses known paths (like `/etc/ssh`, `/etc/nginx`) checking for existence and
   reading file contents safely. Truncates massive files to prevent token overflows.
2. **Analysis Phase (`analyzer.py`)**: Injects the configuration text into a highly specific security prompt. Leverages
   the AI model's "thinking/reasoning" engines (if available) to evaluate the configs, ultimately extracting a clean
   JSON response.
3. **State Management (`state.py`)**: Intervenes between network calls to record progress instantly to
   `~/.pyhardin/state.json`, protecting you against connection losses or hard-coded API Rate Limits.
4. **Reporting Phase (`reporter.py`)**: Renders beautifully stylized PDF pages (using Arial/Helvetica to avoid missing
   font errors) on a service-by-service basis and merges them into one cohesive compliance document. Auto-generates the
   remediation bash script to `~/.pyhardin/last_remediation.sh`.
5. **CLI Logic Engine (`cli.py`)**: Orchestrates the rich visual interface, progress bars, API configuration workflows,
   argument parsing, and subprocess executions for applying fixes.

### Supported Services

Pyhardin natively knows where to look for over 55 common configuration structures, including:
`ssh`, `nginx`, `apache2`, `mysql`, `postgresql`, `redis`, `samba`, `vsftpd`, `postfix`, `bind`, `dhcp`, `ntp`,
`rsyslog`, `sudo`, `cron`, `pam`, `ufw`, `iptables`, `fail2ban`, `sysctl`, `fstab`, `docker`, `kubernetes`, `snmp`,
`nfs`, `systemd`, `apparmor`, `selinux`, `modprobe`, `squid`, `openvpn`, `wireguard`, `mongodb`, `memcached`, `tomcat`,
`php`, `haproxy`... and a massive `miscellaneous` catch-all for any other `.conf` files living in root `/etc/`.

---

## 🔧 Troubleshooting

### "Are my files being sent to the cloud?"

Yes, unless you use the **Local / Custom API** option. If you are auditing extremely sensitive production networks, it
is recommended to run a local model like `llama3` or `qwen2.5-coder` on a dedicated machine and point Pyhardin's API Base
URL to it via the setup wizard.

### "I'm hitting Rate Limits!"

Free-tier API keys limit how many requests you can make per minute and per day.

- If it's a Per-Minute limit, Pyhardin will automatically pause, wait, and retry with exponential backoff.
- If it's a Per-Day limit, Pyhardin will save your exact state. Wait 24 hours (or switch to a new provider) and just run
  `pyhardin` again to continue from exactly where you stopped.

### "PDF Font Errors"

Pyhardin uses standard `Helvetica` and `Helvetica-Bold` built into PDF readers to avoid relying on external `.ttf` files
that might not be installed on bare-bones server environments. PDF generation should work fluidly on entirely headless
Linux boxes.

---

## 📜 License

MIT License. See [LICENSE](LICENSE) for details.
