# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ThreatXtension is a Chrome extension security analysis tool that combines static analysis with AI-powered threat assessment. It uses a LangGraph-based workflow to analyze extensions from the Chrome Web Store, performing permissions analysis, SAST scanning, and webstore reputation analysis, then generating executive summaries via LLM.

**Requirements**: Python 3.11+ and `uv` package manager.

## Architecture

### Multi-Interface Application
- **Backend (Python)**: Core analysis engine with three interfaces:
  - CLI (`src/threatxtension/cli/`) - Click-based command-line interface
  - REST API (`src/threatxtension/api/`) - FastAPI backend for web frontend
  - MCP Server (`src/threatxtension/mcp_server/`) - FastMCP integration for Claude Desktop
- **Frontend (React)**: Production web interface (`frontend/`) using React 19 + Vite + Tailwind CSS + Radix UI

### Core Analysis Workflow (LangGraph)

The analysis workflow (`src/threatxtension/workflow/`) is a directed graph that processes extensions through these nodes:

1. **Extension Path Routing Node** - Determines if input is a URL, a bare extension ID, or a local file path
2. **Extension Metadata Node** - Fetches metadata from Chrome Web Store
3. **ChromeStats Downloader Node** - For `--id` input, downloads the extension via chrome-stats.com (requires `CHROMESTATS_API_KEY`)
4. **Extension Downloader Node** - Downloads and extracts the extension (CRX from the Web Store, or a local CRX/ZIP)
5. **Manifest Parser Node** - Parses manifest.json
6. **Extension Analyzer Node** - Runs all analyzers (permissions, SAST, webstore, VirusTotal, entropy, chromestats) one after another — `ExtensionAnalyzer.analyze()` is plain sequential calls, so a slow analyzer blocks the rest (`sast_config.json`'s `scanning.parallel_enabled` parallelizes *files within* Semgrep, not the analyzers)
7. **Summary Generation Node** - Uses LLM to generate executive summary with risk assessment
8. **Cleanup Node** - Always removes the downloaded CRX file. The extracted directory (`extensions_storage/extracted_*`) is removed unless the caller sets `keep_extracted: True` in `WorkflowState` (see `cleanup_node` in `workflow/nodes.py`). Defaults: CLI cleans up (opt in with `--keep-extracted`), MCP cleans up, the web UI keeps it so the file-viewer endpoints can read the source afterward

State management: `WorkflowState` (TypedDict) tracks workflow progress, analysis results, and executive summary.

**Routing is inside the nodes, not the graph.** `build_graph()` in `workflow/graph.py` registers
the nodes and `set_entry_point(EXTENSION_PATH_ROUTING_NODE)`, then compiles — it adds **no edges at
all**. Every node instead returns a `langgraph.types.Command(goto=..., update={...})` naming its own
successor, so the numbered sequence above is emergent, and the graph object tells you nothing about
control flow. To change the pipeline order, or to find out what actually runs after a node, edit and
read `workflow/nodes.py` — adding an edge in `graph.py` would have no effect. Node name constants
live in `workflow/node_types.py` (`chromestats_downloader_node` is the one passed as a bare string).
Failure handling follows the same pattern: on error a node returns `Command(goto=CLEANUP_NODE)` (or
`goto=END` for unroutable input), which is why cleanup always runs without a `finally` block.

### Analyzer Architecture

All analyzers inherit from `BaseAnalyzer` (`src/threatxtension/core/analyzers/__init__.py`):

- **Permissions Analyzer** (`permissions.py`) - Analyzes manifest permissions, host permissions, sensitive domains (configured in `config/sensitive_domains.json`)
- **SAST Analyzer** (`sast.py`) - Runs Semgrep with custom rules (`config/custom_semgrep_rules.yaml`) targeting banking fraud, credential theft, data exfiltration. Includes library detection and file exclusion logic
- **Webstore Analyzer** (`webstore.py`) - Scrapes Chrome Web Store for ratings, user count, developer info, privacy policy
- **VirusTotal Analyzer** (`virustotal.py`) - Integrates with VirusTotal API for threat intelligence on extension files
- **Entropy Analyzer** (`entropy.py`) - Analyzes file entropy to detect obfuscation and suspicious encoding patterns
- **ChromeStats Analyzer** (`chromestats.py`) - Behavioral/reputation intelligence via chrome-stats.com. Requires the extension ID, so it only runs for `--id` input; with `--url` or `--file` it reports `Extension ID required` and contributes 0 risk points

Additional core modules (not analyzers, but consumed by the workflow):
- `security_scorer.py` - Computes the aggregate risk score from analyzer outputs (see Risk Scoring below)
- `report_generator.py` - Builds PDF reports (served via `/api/scan/report/{id}`)
- `chromestats_downloader.py` - Downloads extensions by ID via chrome-stats.com (requires `CHROMESTATS_API_KEY`)

### Risk Scoring

**Higher means more dangerous.** `security_score` is a *risk* score: 0 is clean, 100 is critical.
The field name is historical — it is not a "how safe is this" score, and it is never inverted.
Anything that renders, thresholds, or compares it must follow that direction.

`SecurityScorer.calculate_score()` (`core/security_scorer.py`) **accumulates risk points** across
seven categories and caps the total: `security_score = min(100, total_risk)`. The scorer is
deliberately deterministic — the LLM writes prose, but **the score and risk level are never left to
the LLM**. It runs first inside `SummaryGenerator.generate()`, and its result is stamped onto the
executive summary even when the LLM call fails.

| Category | Max points (`WEIGHTS`) | Source analyzer |
|----------|-----------------------|-----------------|
| `sast` | 60 | Semgrep findings (severity-weighted) |
| `virustotal` | 50 | AV engine detections |
| `permissions` | 30 | Unreasonable / high-risk manifest permissions |
| `entropy` | 30 | Obfuscated / packed code |
| `chromestats` | 28 | Behavioral threat intelligence |
| `webstore` | 5 | Rating & user-count reputation |
| `manifest` | 5 | Missing CSP, deprecated MV2 |

The category maxima sum to 208 — deliberately over 100, so any single strong signal (e.g. one
VirusTotal hit) can push an extension into the danger zone by itself.

Risk bands (`_get_risk_level()`):

```
 0–15   → low       (green)
16–35   → medium    (yellow)
36–60   → high      (orange)
61–100  → critical  (red)
```

Bands are intentionally tight because VirusTotal and SAST may *both* be absent (VT disabled, or no
JS files to scan), so the remaining analyzers alone must be able to lift a borderline extension out
of the "low" band.

Notable rules: SAST severities cost `CRITICAL`=15 / `ERROR`=12 / `WARNING`=5 / `INFO`=1 per finding,
plus a bonus +15 (≥5 critical) or +30 (≥10 critical); a permission flagged `is_reasonable=False`
costs 5, or 10 if it's in `HIGH_RISK_PERMISSIONS`, and an `<all_urls>` / `*://*/*` host pattern adds
a flat +15; any VirusTotal malicious detection is an instant 50 (suspicious-only 25); missing CSP
+3 and deprecated Manifest V2 +2.

**`SecurityScorer` is the single source of truth for the score.** `calculate_security_score()` in
`api/main.py` reads the value the summary node already stamped onto
`state["executive_summary"]["security_score"]`, and `determine_overall_risk()` likewise prefers
`overall_risk_level`. Both keep a local weighted calculation *only* as a fallback for states that
never reached the summary node (`SummaryGenerator.generate()` returns `None` when analysis results
or the manifest are empty). Those two implementations used to run independently with different
weights, so the dashboard and the executive summary reported different numbers for the same
extension — don't reintroduce that by "fixing" the API-side math in isolation.

Changing the direction or the bands means editing `SecurityScorer`, the `api/main.py` fallback, and
the frontend threshold ladders in `TabbedResultsPanel.jsx`, `DashboardPage.jsx`,
`ScanHistoryPage.jsx`, `CacheConfirmationModal.jsx`, plus the `determineRiskLevel()` fallback in
`services/realScanService.js`. `report_generator.py` colors by `risk_level` rather than the raw
number, so it needs no threshold edits.

`risk_level` has **four** values (`low`/`medium`/`high`/`critical`). Frontend `switch`/ternary
ladders must handle `critical` explicitly — falling through to a `default` branch renders the worst
extensions with a benign badge. Note `database.py`'s statistics query counts
`WHERE risk_level = 'high'` only, so `high_risk_extensions` excludes `critical` rows.

Stored scores are **not migrated**. `/api/history` and `/api/statistics` return whatever direction
was written at scan time, so a database written by an older build will be misread by a newer one.
Clear scan history (`POST /api/clear`) when the scoring direction changes.

### LLM Integration

Multi-provider support (`src/threatxtension/llm/clients/`): WatsonX (IBM), RITS (IBM Research
internal), OpenAI, Ollama (local). The provider is chosen **at import time** from `LLM_PROVIDER`
(module-level constant in `llm/clients/__init__.py`), so changing it mid-process has no effect —
restart. `_get_base_llm_settings` normalizes per-provider parameter names (`max_new_tokens` vs
`num_predict` vs `max_tokens`) and reads several env-var aliases per key (e.g. `WATSONX_APIKEY`
or `WATSONX_API_KEY`). RITS deliberately sends only OpenAI-standard params — passing
`repetition_penalty`/`top_k` there returns a 422.

Prompts are **YAML** files in `src/threatxtension/llm/prompts/` (`executive_summary.yaml`,
`permission_analysis.yaml`, `sast_analysis.yaml`, `summary_generation.yaml`,
`webstore_analysis.yaml`), loaded by `get_prompts(prompt_file=None)`, which merges every YAML in
that directory into one dict when called with no argument. Because keys are merged flat across
files, a top-level key duplicated between two YAML files silently overwrites — keep keys unique.
Adding a prompt means dropping in a YAML file, not editing Python.

## Common Development Commands

### Python Backend

```bash
# Install dependencies
uv sync

# Format code (Black, line-length=100)
make format

# Lint code
make lint

# Run tests (pytest, tests live in top-level `tests/`)
make test

# Run a single test file / single test
uv run pytest tests/test_api_regressions.py
uv run pytest tests/test_api_regressions.py::test_upload_route_registered_once

# Run pre-commit hooks
make precommit
```

### Analyze Extensions

```bash
# CLI analysis (via Make)
make analyze URL=https://chromewebstore.google.com/detail/example/abcdef
make analyze-file FILE=/path/to/extension.crx

# With JSON output
make analyze URL=... OUTPUT=results.json
make analyze-file FILE=... OUTPUT=results.json

# Direct CLI usage — three input modes
uv run threatxtension analyze --url <chrome_web_store_url>
uv run threatxtension analyze --id <32-char-extension-id>   # downloads via chrome-stats.com
uv run threatxtension analyze --file /path/to/extension.crx # also accepts .zip

# Batch mode — one URL/ID/path per line in the input file
uv run threatxtension batch --input urls.txt --output results/
uv run threatxtension batch -i list.txt --sequential      # default is --parallel --workers 4

# Example workflow script
uv run example_workflow.py
```

Batch runs go through `core/batch_processor.py` (not the CLI's single-scan path): it fans out
`run_analysis_workflow` over a thread pool, writes per-batch state under the output dir, and
generates an aggregate report. The `/api/batch/*` endpoints wrap the same class.

### FastAPI Backend + React Frontend

```bash
# Start FastAPI server (port 8007)
make api
# or: uv run threatxtension serve --reload
# API docs at http://localhost:8007/docs

# Start React frontend (port 5173) - requires running API
make frontend
# or: cd frontend && npm run dev
```

**API Endpoints**:
- `POST /api/scan/trigger` - Trigger extension scan (body: `{"url": "..."}`; accepts a Chrome Web Store URL or a bare extension ID)
- `POST /api/scan/upload` - Upload and scan a local CRX/ZIP file (multipart `file=...`)
- `GET /api/scan/status/{extension_id}` - Check scan status
- `GET /api/scan/results/{extension_id}` - Get complete scan results
- `GET /api/scan/files/{extension_id}` - List extracted files
- `GET /api/scan/file/{extension_id}/{file_path}` - Get file content
- `GET /api/scan/report/{extension_id}` - Generate PDF report (via `report_generator.py`)
- `GET /api/statistics` - Get aggregated statistics
- `GET /api/history` - Get scan history
- `GET /api/recent` - Get recent scans
- `DELETE /api/scan/{extension_id}` - Delete scan result
- `POST /api/clear` - Clear all scan results
- `POST /api/analyze/file` - Analyze a single file's content on demand
- `POST /api/analyze/generate-sast-signature` - LLM-generate a Semgrep signature from a finding
- `POST /api/batch/analyze`, `GET /api/batch/status/{batch_id}`, `GET /api/batch/results/{batch_id}`, `GET /api/batch/list` - Batch scanning (wraps `BatchProcessor`)
- `GET /health` - Health check
- `GET /{full_path:path}` - SPA catch-all serving the built React frontend (keep new API routes under `/api/`, or the catch-all will swallow them)

### Frontend (React)

The React frontend requires a running backend API (implementation details in `frontend/src/services/`).

```bash
cd frontend

# Install dependencies
npm install

# Development server
npm run dev

# Build production bundle
npm run build

# Lint
npm run lint

# Format with Prettier
npm run format
```

## Configuration Files

### LLM Configuration (`.env`)

Copy `.env.example` and configure:
- `LLM_PROVIDER` - watsonx, rits, openai, ollama
- `LLM_MODEL` - e.g., meta-llama/llama-3-3-70b-instruct
- Provider-specific API keys (WATSONX_APIKEY, RITS_API_KEY, OPENAI_API_KEY)
- `VIRUSTOTAL_API_KEY` - for VirusTotal threat intelligence integration
- `CHROMESTATS_API_KEY` - required when using `--id` / extension-ID input mode
- `EXTENSION_STORAGE_PATH` - where downloaded extensions are stored (default: `./extensions_storage`)

### SAST Configuration (`src/threatxtension/config/sast_config.json`)

- `semgrep_config` - Custom rules location
- `exclusion_patterns` - Paths/files/libraries to skip (libraries, minified files, node_modules)
- `max_file_size_kb` - Skip files larger than this
- `scanning.parallel_enabled` - Enable parallel scanning

### Sensitive Domains (`src/threatxtension/config/sensitive_domains.json`)

Domain categories with enable/disable flags:
- `banking_financial` - Banking and payment sites
- `government_tax` - Government portals
- `healthcare_insurance` - Medical sites
- `corporate_email` - Email providers
- `crypto_trading` - Cryptocurrency exchanges

### Custom Semgrep Rules (`src/threatxtension/config/custom_semgrep_rules.yaml`)

10+ custom rules with MITRE ATT&CK mappings:
- Form hijacking (`banking.form_hijack.submit_intercept`)
- Credential sniffing (`banking.cred_sniff.password_input_hooks`)
- Network hijacking (`banking.ext.webrequest.redirect`)
- Data exfiltration (`banking.exfil.generic_channels`)
- Code injection (`banking.obfuscation.eval_newfunc`)

## Docker Deployment

ThreatXtension is containerized for easy deployment and demos.

### Quick Start with Docker

```bash
# 1. Copy and configure environment
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY

# 2. Build and run
docker compose up --build

# 3. Access the application
# Web UI: http://localhost:8007
# API Docs: http://localhost:8007/docs
# Health Check: http://localhost:8007/health
```

### Docker Commands

```bash
# Build the container
docker compose build

# Run in foreground
docker compose up

# Run in background
docker compose up -d

# View logs
docker compose logs -f

# Stop the container
docker compose down

# Run CLI inside container
docker compose exec threatxtension uv run threatxtension analyze --url <extension-url>
```

### Container Architecture

The container uses a multi-stage build:
- **Stage 1**: Node.js builds the React frontend
- **Stage 2**: Python backend serves the API and static files

Volumes:
- `./extensions_storage` - Downloaded extension files (persistent)
- `./data` - SQLite database (persistent)

### Network-Restricted Isolation (opt-in)

`docker-compose.override.yml` (auto-merged by `docker compose up`) runs a scan in containment for analyzing untrusted CRX samples. Files live in `docker/egress-proxy/`.

- The app runs on an **`internal: true`** network (no direct internet). Its only egress path is a **tinyproxy** sidecar enforcing a default-deny allowlist (`docker/egress-proxy/allowlist.txt`): Chrome Web Store, `clients2.google.com` + Google CDN wildcards for the CRX 302-redirect, ChromeStats, VirusTotal, LangSmith.
- The container is hardened: `read_only` rootfs, `cap_drop: ALL`, `no-new-privileges`, non-root `user` matching the host UID (needed because `cap_drop: ALL` removes `CAP_DAC_OVERRIDE`, so root can't bypass volume file-owner bits), and tmpfs (`/tmp`, `/scratch`) for caches with `HOME=/scratch`.
- **LLM egress routes through the proxy** via `host-gateway` on the sidecar, so a host-local provider works without opening general internet. Provider hosts are set with **`EGRESS_ALLOW_EXTRA`** (anchored regex, comma-separated) — the sidecar `entrypoint.sh` appends them to the base allowlist at start, so switching `LLM_PROVIDER` is a one-line change, not a proxy-config edit.
- The startup command is overridden to `uv run --no-sync ...` so `uv` doesn't re-resolve against PyPI (blocked by the allowlist) on every start.

Gotchas: because the app is on an internal-only network, the published `8007` UI port does **not** route — run scans via `docker compose exec threatxtension uv run --no-sync threatxtension analyze ...`. After an in-place `up --build`, a stale Docker network can leave the proxy without internet; a full `docker compose down && up` fixes it.

## MCP Server Integration

The MCP server enables Claude Desktop integration:

**Configuration** (add to `claude_desktop_config.json`):
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

**Available Tool**: `analyze_chrome_extension(chrome_extension_url)` - Returns JSON with executive summary and metadata.

## Frontend Architecture

The production frontend (`frontend/`) uses:
- **React 19** with react-router-dom for navigation
- **Tailwind CSS 4** + **Radix UI** for styling and components
- **Vite 7** for build tooling
- **Axios** for API communication

Key pages (`frontend/src/pages/`): DashboardPage, LiveScanPage, ScanHistoryPage, AnalysisPage, SettingsPage

Services (`frontend/src/services/`): realScanService (backend API), cacheService (local caching)

## Key Implementation Notes

### Extension Download Process
Extensions are downloaded from Chrome Web Store using CRX format, then extracted to `extensions_storage/`. The downloader (`src/threatxtension/core/extension_downloader.py`) handles both URLs and local file paths (including support for uploading CRX/ZIP files). Cleanup is split between two functions in `src/threatxtension/utils/extension.py`: `cleanup_downloaded_crx()` (deletes the `.crx`, always called by the cleanup node) and `cleanup_extension_dir()` (deletes the extracted directory, called by the cleanup node unless `keep_extracted` is set in the workflow state — see the Cleanup Node above).

### SAST Scanning
The SAST analyzer filters out library code, minified files, and large files before running Semgrep to reduce false positives. It detects libraries by:
1. Path patterns (`lib/`, `node_modules/`, `vendor/`)
2. Filename patterns (`*.min.js`, `*.bundle.js`)
3. Library name detection in file content

### LangGraph Workflow Execution
Each node updates the `WorkflowState` TypedDict via the `update=` field of the `Command` it returns,
and names its successor with `goto=` (see "Routing is inside the nodes" above — there are no declared
edges). The graph is compiled once and can be invoked many times.

### Multi-Analyzer Coordination
`ExtensionAnalyzer.analyze()` (`core/extension_analyzer.py`), invoked from the Extension Analyzer
Node, calls each analyzer in sequence and returns a dict whose keys are **`_analysis`-suffixed**:
`permissions_analysis`, `webstore_analysis`, `javascript_analysis`, `virustotal_analysis`,
`entropy_analysis`, `chromestats_analysis`. Note the SAST analyzer is reached through the attribute
`self.javascript_analyzer` and lands under `javascript_analysis` — the class lives in `analyzers/sast.py`,
so "sast" and "javascript" name the same thing depending on whether you're looking at the module or
the result key. Grep for both. `security_scorer.py` consumes this dict, so a new analyzer needs a
scoring branch there too, and every analyzer must return a dict even on failure — the `chromestats`
scoring regression test in `tests/test_api_regressions.py` guards exactly that.

## Testing and Quality

- **Black** formatting with 100-character line length (configured in `pyproject.toml`)
- **Pylint** for linting (`.pylintrc` configuration)
- **Pre-commit hooks** (`.pre-commit-config.yaml`) for automated checks
- **Prettier** for frontend formatting (runs on `src/**/*.{js,jsx,ts,tsx,json,css,scss,md}`)

There is no pytest config section in `pyproject.toml` and no `conftest.py` — tests rely on the
installed package (`uv sync`) rather than path manipulation. The existing suite is regression-
oriented and shows the house style: no network, no real LLM, no real extension downloads.
`monkeypatch` replaces `api_main.db` methods and `run_analysis_workflow`, FastAPI routes are
exercised with `TestClient`, and archive-handling tests build fixture ZIPs in `tmp_path` with
`EXTENSION_STORAGE_PATH` pointed there. Security invariants are covered directly (zip-slip
rejection in `extract_extension_crx`, directory-containment path checks, route registered exactly
once) — extend these rather than adding integration tests that hit the network.

`scripts/` holds standalone research helpers (`analyze_extension_patterns.py`,
`check_extension_sast.py`) that mine an already-extracted extension for candidate Semgrep
patterns. They are authoring aids for `custom_semgrep_rules.yaml`, not part of the analysis
pipeline, and are run directly with `uv run python scripts/<name>.py`.

## Notes for Future Claude Instances

- This file is the single source of agent guidance. A root `AGENTS.md` and an `openwiki/` tree used
  to duplicate it; both were removed because they had drifted (they described a Gradio UI at
  `src/threatxtension/ui/app.py` and a `make ui` target, neither of which exists — the React
  frontend replaced them). Don't reintroduce a parallel doc tree; update this file instead. The
  deleted content is recoverable from git history if you need it.

## Security Research Context

This tool analyzes potentially malicious Chrome extensions for security research, malware analysis, and educational purposes. When working with extension analysis code:
- Never improve malicious code patterns found in extensions
- Focus on detection capabilities, not evasion techniques
- All analysis is read-only and sandboxed
