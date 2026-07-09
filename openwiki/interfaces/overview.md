# Interfaces Overview

[← Back to Quickstart](../quickstart.md) · [Architecture Overview](../architecture/overview.md)

ThreatXtension exposes the same [analysis workflow](../workflows/analysis-pipeline.md) through
four interfaces. Each is a thin adapter: build a `WorkflowState`, `invoke` the graph, render or
persist the result.

| Interface | Entry point | Best for |
|-----------|-------------|----------|
| **CLI** | `threatxtension.cli.main:main` | Fast one-off / scripted analysis, batch jobs |
| **REST API** | `threatxtension.api.main:app` | Programmatic access, the React frontend backend |
| **Web UI** | `frontend/` (React + Vite) | Interactive dashboards, file browsing, PDF reports |
| **MCP server** | `threatxtension.mcp_server.main` | Claude Desktop integration |

## CLI

Source: `src/threatxtension/cli/main.py` (Click). Commands:

- `analyze` — one of `--url`, `--id`, `--file` (mutually exclusive); `--output` saves JSON;
  `--keep-extracted` retains the source; `--verbose` for debug logs. Renders Rich tables
  (metadata, VirusTotal, entropy) plus the executive summary.
- `serve` — launches the FastAPI server (`uvicorn threatxtension.api.main:app`), default port 8007.
- `batch` — bulk analysis (see [Batch Processing](../workflows/batch-processing.md)).
- `version` — prints the version.

The CLI sets `keep_extracted=False` — no file viewer, so leaving samples on disk is unnecessary.

## REST API

Source: `src/threatxtension/api/main.py` (FastAPI) + `api/database.py` (SQLite). See the full
[REST API Reference](rest-api.md). Scans run in a FastAPI `BackgroundTask`
(`run_analysis_workflow`), status is tracked in an in-memory dict, and completed results are
persisted to SQLite. The API sets `keep_extracted=True` so the web file viewer can browse source.

## Web UI

Source: `frontend/` — React 19, Vite, Tailwind, Radix UI, React Router. Pages:
`DashboardPage`, `AnalysisPage`, `ScanHistoryPage`, `SASTSignaturesPage`, `SettingsPage`.
Service modules under `frontend/src/services/` (`realScanService`, `databaseService`,
`cacheService`, `cliService`, `gptOssService`) call the REST API. In Docker the frontend is served
by the same container at `http://localhost:8007`; in local dev it runs on Vite's `:5173` and
proxies to the API.

## MCP server

Source: `src/threatxtension/mcp_server/main.py` (FastMCP, stdio transport). Exposes a single tool,
`analyze_chrome_extension(chrome_extension_url)`, which runs the workflow and returns a compact JSON
response (`executive_summary` + `extension_metadata` only) so it fits comfortably in an LLM
conversation. Configure it in Claude Desktop's `claude_desktop_config.json` per the README.

## Related pages
- [REST API Reference](rest-api.md)
- [Deployment & Docker Isolation](deployment.md)
