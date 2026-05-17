<p align="center">
  <img width="450" height="400" alt="logo1" src="https://github.com/user-attachments/assets/1f7a1239-81f2-416a-982b-af6938b35136" />
</p>


<p align="center">
  <strong>AI-Powered Chrome Extension Security Analysis</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#quick-start-docker">Quick Start</a> •
  <a href="#installation">Installation</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#license">License</a>
</p>

---

## Overview

**ThreatXtension** is a comprehensive security analysis tool for Chrome browser extensions. It combines static analysis (SAST), threat intelligence (VirusTotal), and AI-powered assessment to help security researchers, malware analysts, and browser security teams identify malicious behavior in browser extensions.

<p align="center">
  <img src="images/ui.png" alt="ThreatXtension Logo" width="800"/>
</p>

## Features

### Multi-Layer Analysis
- **Permissions Analysis**: Risk assessment of manifest permissions and host access
- **SAST Scanning**: Custom Semgrep rules targeting banking fraud, credential theft, data exfiltration
- **VirusTotal Integration**: File hash reputation checks against 70+ antivirus engines
- **Entropy Analysis**: Detect obfuscated/packed code using Shannon entropy and pattern matching
- **WebStore Reputation**: User ratings, developer info, and trust signals

### AI-Powered Threat Assessment
- **Executive Summaries**: Natural language risk assessment with actionable recommendations
- **Multi-LLM Support**: OpenAI, WatsonX, Ollama, RITS
- **Context-Aware Analysis**: Each finding analyzed with full extension context

### Multiple Interfaces
- **Web UI**: React frontend with real-time analysis dashboard
- **CLI**: Fast command-line analysis with rich console output
- **REST API**: FastAPI backend with OpenAPI documentation
- **MCP Server**: Claude Desktop integration via Model Context Protocol

---

## Quick Start (Docker)

The fastest way to run ThreatXtension is with Docker.

```bash
# 1. Clone the repository
git clone https://github.com/barvhaim/ThreatXtension.git
cd ThreatXtension

# 2. Configure environment
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY (required)
# Optionally add VIRUSTOTAL_API_KEY for threat intelligence

# 3. Build and run
docker compose up --build

# 4. Access the application
# Web UI: http://localhost:8007
# API Docs: http://localhost:8007/docs
```

### Docker Commands

```bash
make docker-build    # Build container
make docker-up       # Start container (foreground)
make docker-down     # Stop container
make docker-logs     # View logs
```

### Scan an Extension

**Via Web UI:** Navigate to http://localhost:8007 and either:
- Paste a Chrome Web Store URL
- Enter an extension ID (32-character string, e.g., `gbbilodpoldeopifonmibfboicpafpjo`)
- Upload a local `.crx` or `.zip` file

**Via API:**
```bash
# Option 1: Scan from Chrome Web Store URL
curl -X POST http://localhost:8007/api/scan/trigger \
  -H "Content-Type: application/json" \
  -d '{"url": "https://chromewebstore.google.com/detail/extension-name/extension-id"}'

# Option 2: Scan using extension ID (downloads from chrome-stats.com)
curl -X POST http://localhost:8007/api/scan/trigger \
  -H "Content-Type: application/json" \
  -d '{"url": "gbbilodpoldeopifonmibfboicpafpjo"}'

# Option 3: Upload and scan a local file
curl -X POST http://localhost:8007/api/scan/upload \
  -F "file=@/path/to/extension.crx"

# Get results
curl http://localhost:8007/api/scan/results/{extension_id}
```

---

## Installation (Local Development)

### Prerequisites

- **Python 3.11+**
- **Node.js 20+** (for frontend)
- **uv** package manager ([Installation](https://docs.astral.sh/uv/getting-started/installation/))

### Setup

```bash
# Clone the repository
git clone https://github.com/barvhaim/ThreatXtension.git
cd ThreatXtension

# Install Python dependencies
uv sync

# Install frontend dependencies
cd frontend && npm install && cd ..

# Configure environment
cp .env.example .env
# Edit .env with your API keys
```

### Run Locally

```bash
# Option 1: CLI - Analyze from Chrome Web Store URL
make analyze URL=https://chromewebstore.google.com/detail/example/abcdef

# Option 1b: CLI - Analyze using extension ID (requires CHROMESTATS_API_KEY)
uv run threatxtension analyze --id gbbilodpoldeopifonmibfboicpafpjo

# Option 1c: CLI - Analyze local file
make analyze-file FILE=/path/to/extension.crx
uv run threatxtension analyze --file /path/to/extension.crx
uv run threatxtension analyze --file /path/to/extension.zip

# Option 2: Web UI (run both in separate terminals)
make api        # Start FastAPI backend (port 8007)
make frontend   # Start React frontend (port 5173)
```

<p align="center">
  <img src="images/cli.png" alt="ThreatXtension CLI" width="800"/>
</p>

---

## Configuration

### Environment Variables

Create a `.env` file from the template:

```bash
cp .env.example .env
```

**Required:**
```bash
LLM_PROVIDER=openai
LLM_MODEL=gpt-4o
OPENAI_API_KEY=sk-...
```

**Optional:**
```bash
VIRUSTOTAL_API_KEY=...      # For threat intelligence
CHROMESTATS_API_KEY=...     # For extension ID downloads via chrome-stats.com
LANGSMITH_API_KEY=...       # For LLM tracing/debugging
```

### Supported LLM Providers

| Provider | LLM_PROVIDER | Recommended Models |
|----------|--------------|-------------------|
| OpenAI | `openai` | `gpt-4o`, `gpt-4-turbo` |
| WatsonX (IBM) | `watsonx` | `meta-llama/llama-3-3-70b-instruct` |
| Ollama (Local) | `ollama` | `llama3`, `mistral` |
| RITS (IBM Research) | `rits` | `meta-llama/llama-3-3-70b-instruct` |

### Custom Semgrep Rules

Located in `src/threatxtension/config/custom_semgrep_rules.yaml`:

| Rule ID | Category | Description |
|---------|----------|-------------|
| `banking.form_hijack.submit_intercept` | Form hijacking | Form submit interception |
| `banking.cred_sniff.password_input_hooks` | Credential theft | Password field listeners |
| `banking.ext.webrequest.redirect` | Network hijacking | WebRequest redirect abuse |
| `banking.exfil.generic_channels` | Data exfiltration | sendBeacon/Image.src abuse |
| `banking.obfuscation.eval_newfunc` | Code injection | eval()/Function() execution |

All rules include MITRE ATT&CK mappings and CWE references.

---

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/scan/trigger` | POST | Trigger extension scan |
| `/api/scan/status/{id}` | GET | Check scan status |
| `/api/scan/results/{id}` | GET | Get complete results |
| `/api/scan/files/{id}` | GET | List extracted files |
| `/api/scan/file/{id}/{path}` | GET | Get file content |
| `/api/scan/report/{id}` | GET | Generate PDF report |
| `/api/statistics` | GET | Aggregated statistics |
| `/api/history` | GET | Scan history |
| `/health` | GET | Health check |

Full API documentation available at http://localhost:8007/docs

---

## Claude Desktop Integration (MCP)

ThreatXtension integrates with Claude Desktop via MCP (Model Context Protocol).

**Setup:**

1. Edit Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "ThreatXtension": {
      "command": "uv",
      "args": [
        "--directory",
        "/absolute/path/to/ThreatXtension",
        "run",
        "python",
        "-m",
        "threatxtension.mcp_server.main"
      ]
    }
  }
}
```

2. Restart Claude Desktop

3. Ask Claude: *"Analyze this Chrome extension: https://chromewebstore.google.com/detail/..."*

<p align="center">
  <img src="images/claude.png" alt="ThreatXtension Claude" width="800"/>
</p>

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    ThreatXtension                           │
├─────────────────────────────────────────────────────────────┤
│  Interfaces                                                 │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐       │
│  │   CLI   │  │ Web UI  │  │   API   │  │   MCP   │       │
│  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘       │
│       └────────────┴────────────┴────────────┘             │
│                         │                                   │
│  ┌──────────────────────▼──────────────────────┐           │
│  │           LangGraph Workflow                 │           │
│  │  Download → Parse → Analyze → Summarize     │           │
│  └──────────────────────┬──────────────────────┘           │
│                         │                                   │
│  ┌──────────────────────▼──────────────────────┐           │
│  │              Analyzers                       │           │
│  │  ┌────────────┐ ┌────────────┐ ┌──────────┐ │           │
│  │  │Permissions │ │   SAST     │ │ WebStore │ │           │
│  │  └────────────┘ └────────────┘ └──────────┘ │           │
│  │  ┌────────────┐ ┌────────────┐              │           │
│  │  │VirusTotal  │ │  Entropy   │              │           │
│  │  └────────────┘ └────────────┘              │           │
│  └─────────────────────────────────────────────┘           │
│                         │                                   │
│  ┌──────────────────────▼──────────────────────┐           │
│  │         LLM Summary Generation              │           │
│  │      (OpenAI / WatsonX / Ollama)            │           │
│  └─────────────────────────────────────────────┘           │
└─────────────────────────────────────────────────────────────┘
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **Semgrep** - Static analysis engine
- **LangGraph** - Workflow orchestration
- **VirusTotal** - Threat intelligence
- **React + Vite** - Frontend framework

---

<p align="center">
  Built for browser security research and extension threat intelligence
</p>

<p align="center">
  <sub>This tool is intended for legitimate security research, malware analysis, and educational purposes only.</sub>
</p>

<p align="center">
  <img src="images/logo.png" alt="ThreatXtension Logo" width="800"/>
</p>
