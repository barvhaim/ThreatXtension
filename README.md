# ThreatXtension

<p align="center">
  <img src="images/logo.png" alt="ThreatXtension Logo" width="800"/>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#configuration-files">Configuration</a> •
  <a href="#license">License</a>
</p>

---

## Overview

**ThreatXtension** is a comprehensive Python-based security analysis tool designed for Chrome extension threat intelligence. It combines static analysis with AI-powered insights to help security researchers, malware analysts, and browser security teams identify malicious behavior in browser extensions.

## Features

### 🔍 Comprehensive Analysis
- **Automated Extension Download**: Fetch extensions directly from Chrome Web Store using extension ID or URL
- **Multi-Analyzer Architecture**: Permissions, SAST (JavaScript), and Web Store reputation analysis
- **Custom Security Rules**: 10+ Semgrep rules targeting banking fraud, credential theft, and data exfiltration
- **Sensitive Domain Detection**: Identifies extensions accessing banking, government, healthcare, and corporate domains

### 🤖 AI-Powered Threat Assessment
- **LLM-Powered Analysis**: Natural language summaries of security findings
- **Multi-LLM Support**: Compatible with WatsonX, RITS, OpenAI, Ollama
- **Executive Summary Generation**: Unified risk assessment with actionable recommendations
- **Context-Aware Analysis**: Each permission and finding analyzed with full extension context

### 🖥️ Multiple Interfaces
- **CLI**: Fast command-line analysis with rich console output (Click framework)
- **Web UI**: Quick demo interface for simple web-based analysis
- **MCP Server**: FastMCP integration for Claude Code direct integration

## Installation

### Prerequisites

- **Python 3.11+**
- **uv** package manager [Installation](https://docs.astral.sh/uv/getting-started/installation/)
- **Semgrep** (included in dependencies)

### Install with uv

```bash
# Clone the repository
git clone https://github.com/barvhaim/ThreatXtension.git
cd ThreatXtension

# Install dependencies
uv sync
```

### Configuration

For AI-powered analysis features, create a `.env` file:

```bash
cp .env.example .env
# Edit .env with your LLM credentials
```

See [LLM Configuration](#llm-configuration) for details.

## Quick Start

ThreatXtension provides **multiple ways to analyze Chrome extensions**:

### 1. Command Line Interface (CLI)

The CLI provides the fastest way to analyze extensions with rich console output.

```bash
# Analyze extension
make analyze URL=<chrome_web_store_url>
```

<p align="center">
  <img src="images/cli.png" alt="ThreatXtension CLI" width="800"/>
</p>

### 2. Web UI

Quick demo interface for web-based analysis.

```bash
make ui
# or
uv run gradio src/threatxtension/ui/app.py

# Access at http://localhost:7860
```

<p align="center">
  <img src="images/ui.png" alt="ThreatXtension UI" width="800"/>
</p>

### 3. Claude Desktop Integration (MCP)

Analyze extensions directly from Claude Desktop conversations. See [MCP Server for Claude Desktop](#mcp-server-for-claude-desktop) for setup instructions.

<p align="center">
  <img src="images/claude.png" alt="ThreatXtension Claude" width="800"/>
</p>

### Example Workflow Script

Run the example script to see the complete workflow in action:

```bash
uv run example_workflow.py

# The script analyzes a sample extension and displays:
# - Extension metadata (name, version, users)
# - Permissions analysis
# - SAST findings
# - Web Store reputation
# - Executive summary with risk assessment
```

## LLM Configuration

Create a `.env` file for AI-powered features:

```bash
# LLM Provider (watsonx, rits, openai, ollama)
LLM_PROVIDER=watsonx
LLM_MODEL=meta-llama/llama-3-3-70b-instruct

# WatsonX credentials
WATSONX_URL=https://us-south.ml.cloud.ibm.com/
WATSONX_APIKEY=your_api_key
WATSONX_PROJECT_ID=your_project_id

# RITS credentials (IBM Research internal)
RITS_API_KEY=your_rits_key
RITS_API_BASE_URL=your_rits_url

# OpenAI credentials (if using openai provider)
OPENAI_API_KEY=your_openai_key

# Extension processing
CHROME_VERSION=118.0
EXTENSION_STORAGE_PATH=./extensions_storage

# Optional: LangSmith tracing
LANGSMITH_TRACING=true
LANGSMITH_API_KEY=your_langsmith_key
LANGSMITH_PROJECT=threatxtension
```

#### Supported LLM providers:
- watsonx.ai by IBM ("watsonx") [Get API Key](docs/getting_watsonx_api_key.md)
- OpenAI ("openai") - Experimental
- RITS internal IBM ("rits")
- Ollama ("ollama") - Experimental

#### Supported LLM Providers

| Provider | LLM_PROVIDER | Recommended Models |
|----------|--------------|-------------------|
| WatsonX (IBM) | `watsonx` | `meta-llama/llama-3-3-70b-instruct` |
| RITS (IBM Research) | `rits` | `meta-llama/llama-3-3-70b-instruct` |
| OpenAI | `openai` | `gpt-4-turbo`, `gpt-4o` |
| Ollama (Local) | `ollama` | `llama3`, `mistral` |

## Configuration Files

### SAST Configuration (`src/threatxtension/config/sast_config.json`)

```json
{
  "semgrep_config": "custom",
  "semgrep_config_options": {
    "custom": "config/custom_semgrep_rules.yaml",
    "javascript": "p/javascript",
    "security-audit": "p/security-audit"
  },
  "exclusion_patterns": {
    "path_segments": ["lib/", "node_modules/", "vendor/"],
    "file_patterns": ["*.min.js", "*.bundle.js"],
    "library_names": ["jquery", "react", "vue"]
  },
  "max_file_size_kb": 500,
  "scanning": {
    "batch_enabled": true,
    "parallel_enabled": true,
    "max_parallel_workers": 4
  }
}
```

#### Custom Semgrep Rules

Located in `src/threatxtension/config/custom_semgrep_rules.yaml`:

| Rule ID | Category | Description |
|---------|----------|-------------|
| `banking.form_hijack.submit_intercept` | Form hijacking | Form submit with preventDefault + fetch/XHR |
| `banking.cred_sniff.password_input_hooks` | Credential theft | Password field event listeners + network |
| `banking.ext.webrequest.redirect` | Network hijacking | chrome.webRequest redirect abuse |
| `banking.net_sniff.override_fetch_xhr` | Network sniffing | XHR/fetch prototype override |
| `banking.auto_transfer.silent_payment` | Transaction abuse | Unauthorized payment/transfer requests |
| `banking.exfil.generic_channels` | Data exfiltration | sendBeacon/Image.src/fetch exfiltration |
| `banking.csp.disable_or_weaken` | Security bypass | CSP weakening/disabling |
| `banking.obfuscation.eval_newfunc` | Code injection | eval()/Function() dynamic execution |

All rules include MITRE ATT&CK mappings and CWE references.

### Sensitive Domains (`src/threatxtension/config/sensitive_domains.json`)

```json
{
  "banking_financial": {
    "enabled": true,
    "domains": ["chase.com", "bankofamerica.com", "paypal.com", "stripe.com"]
  },
  "government_tax": {
    "enabled": false,
    "domains": ["irs.gov", "healthcare.gov"]
  }
}
```

## Integration

### MCP Server for Claude Desktop

ThreatXtension can be integrated directly into Claude Desktop as an MCP (Model Context Protocol) tool, allowing you to analyze Chrome extensions directly from your conversations with Claude.

**Prerequisites**:
- Claude Desktop installed ([Download](https://claude.ai/download))
- `uv` package manager
- Python 3.11+
- ThreatXtension cloned and dependencies installed (`uv sync`)

**Setup**:

1. **Find your Claude Desktop config file**:
   - **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
   - **Linux**: `~/.config/Claude/claude_desktop_config.json`

2. **Edit the config file** and add ThreatXtension to the `mcpServers` section:

```json
{
  "mcpServers": {
    "ThreatXtension": {
      "command": "uv",
      "args": [
        "--directory",
        "/PATH/TO/ThreatXtension",
        "run",
        "python",
        "-m",
        "threatxtension.mcp_server.main"
      ]
    }
  }
}
```

**Important**: Replace `/PATH/TO/ThreatXtension` with the absolute path to your ThreatXtension installation.

3. **Restart Claude Desktop**

4. **Verify Installation**: You should see a small hammer icon 🔨 in Claude Desktop indicating the ThreatXtension MCP server is available.

<p align="center">
  <img src="images/mcp_tool.png" alt="ThreatXtension MCP Tool" width="800"/>
</p>

**Usage in Claude Desktop**:

Once configured, you can ask Claude to analyze Chrome extensions:

```
Analyze this Chrome extension:
https://chromewebstore.google.com/detail/steam-inventory-helper/cmeakgjggjdlcpncigglobpjbkabhmjl
```

Claude will automatically use the `analyze_chrome_extension()` tool to perform a complete security analysis and provide you with:
- Extension metadata
- Risk level assessment
- Key security findings
- Recommendations

<p align="center">
  <img src="images/claude2.png" alt="ThreatXtension Claude (2)" width="800"/>
</p>

**Available MCP Tools**:
- `analyze_chrome_extension(chrome_extension_url)` - Performs complete security analysis on a Chrome Web Store extension

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **Semgrep**: For JavaScript security scanning capabilities
- **LangChain/LangGraph**: For workflow orchestration
- **Chrome Web Store**: For extension metadata and distribution

---

<p align="center">
  Built for browser security research and extension threat intelligence
</p>

<p align="center">
  <sub>⚠️ This tool is intended for legitimate security research, malware analysis, and educational purposes only. Users are responsible for ensuring compliance with applicable laws and regulations when analyzing browser extensions.</sub>
</p>
