# ThreatXtension — OpenWiki

**ThreatXtension** is an AI-powered security analysis tool for Chrome browser extensions. It
combines static analysis (SAST), threat intelligence (VirusTotal, chrome-stats.com), obfuscation
detection, and LLM-generated risk assessments to help security researchers and browser-security
teams decide whether a browser extension is safe.

This wiki explains **how the system is built and why**, for both human contributors and coding
agents. For install/run instructions aimed at end users, see the top-level [`README.md`](../README.md).

---

## What it does (in one pass)

Given a Chrome Web Store URL, a 32-character extension ID, or a local `.crx`/`.zip` file, the tool:

1. **Acquires** the extension (download from the Web Store / chrome-stats.com, or read a local file)
   and unpacks it to a working directory.
2. **Parses** `manifest.json` (permissions, host access, CSP, manifest version).
3. **Runs six analyzers in parallel-ish sequence**: permissions, SAST (Semgrep), webstore
   reputation, VirusTotal, entropy/obfuscation, and chrome-stats behavioral intelligence.
4. **Scores** the result deterministically (0–100) with [`SecurityScorer`](architecture/scoring.md).
5. **Summarizes** the findings into a natural-language executive summary using an LLM.
6. **Cleans up** temporary files (optionally retaining the extracted source for the web file viewer).

All of this is orchestrated as a [LangGraph state machine](workflows/analysis-pipeline.md).

---

## Fastest way to run

```bash
cp .env.example .env          # add OPENAI_API_KEY (required); VIRUSTOTAL/CHROMESTATS optional
docker compose up --build     # Web UI + API at http://localhost:8007
```

Or locally with `uv`:

```bash
uv sync
uv run threatxtension analyze --url https://chromewebstore.google.com/detail/<name>/<id>
uv run threatxtension analyze --id gbbilodpoldeopifonmibfboicpafpjo   # needs CHROMESTATS_API_KEY
uv run threatxtension analyze --file ./extension.crx
```

See the [Makefile](../Makefile) for all shortcuts (`make api`, `make frontend`, `make docker-up`).

---

## Documentation map

### Architecture
- [System Overview](architecture/overview.md) — components, package layout, data flow
- [Security Scoring](architecture/scoring.md) — the deterministic 0–100 risk model
- [LLM Integration](architecture/llm-integration.md) — provider abstraction, prompts, summaries

### Workflows
- [Analysis Pipeline](workflows/analysis-pipeline.md) — the LangGraph node-by-node walkthrough
- [Batch Processing](workflows/batch-processing.md) — analyzing many extensions at once

### Domain
- [Analyzers](domain/analyzers.md) — what each of the six analyzers detects and returns
- [Custom Semgrep Rules](domain/semgrep-rules.md) — banking/fraud detection ruleset & config
- [Extension Acquisition](domain/extension-acquisition.md) — input routing, download, extraction

### Interfaces
- [Interfaces Overview](interfaces/overview.md) — CLI, REST API, Web UI, MCP server
- [REST API Reference](interfaces/rest-api.md) — endpoints, scan lifecycle, persistence
- [Deployment & Docker Isolation](interfaces/deployment.md) — network-restricted scanning sandbox

---

## Key facts for contributors & agents

| Topic | Detail |
|-------|--------|
| Language / tooling | Python 3.11+, managed with `uv`; Black (100 cols), Pylint, pytest |
| Orchestration | LangGraph `StateGraph` — every node returns a `Command(goto=…, update={…})` |
| Entry point (CLI) | `threatxtension.cli.main:main` (`pyproject.toml [project.scripts]`) |
| Entry point (API) | `threatxtension.api.main:app` (`uv run threatxtension serve`) |
| Entry point (MCP) | `threatxtension.mcp_server.main` (stdio transport for Claude Desktop) |
| State shape | `WorkflowState` TypedDict — `src/threatxtension/workflow/state.py` |
| Persistence | SQLite via `src/threatxtension/api/database.py` (`data/` volume) |
| Config files | `src/threatxtension/config/*.json`, `custom_semgrep_rules.yaml` |
| Prompts | YAML templates in `src/threatxtension/llm/prompts/` |

> ⚠️ **Intended use:** legitimate security research, malware analysis, and education only.
