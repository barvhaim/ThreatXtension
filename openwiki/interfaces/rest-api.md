# REST API Reference

[← Back to Quickstart](../quickstart.md) · [Interfaces Overview](overview.md)

Sources: `src/threatxtension/api/main.py` (FastAPI app) · `src/threatxtension/api/database.py` (SQLite)

Start it with `make api` or `uv run threatxtension serve` (default `0.0.0.0:8007`). Interactive
OpenAPI docs live at `/docs`.

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/scan/trigger` | Start a scan from a Web Store URL or extension ID |
| POST | `/api/scan/upload` | Upload a `.crx`/`.zip` (≤100 MB) and scan it |
| GET | `/api/scan/status/{id}` | Poll scan status (running/completed/…) |
| GET | `/api/scan/results/{id}` | Full analysis results |
| GET | `/api/scan/report/{id}` | Generate a PDF report (`report_generator.py`) |
| GET | `/api/scan/files/{id}` | List extracted files (needs `keep_extracted`) |
| GET | `/api/scan/file/{id}/{path}` | Fetch one extracted file's content (the file viewer) |
| DELETE | `/api/scan/{id}` | Delete a stored result |
| POST | `/api/clear` | Clear all stored results |
| GET | `/api/statistics` | Aggregate stats (counts, risk distribution) |
| GET | `/api/history` | Scan history |
| GET | `/api/recent` | Recent scans |
| POST | `/api/analyze/file` | Synchronous file analysis |
| POST | `/api/analyze/generate-sast-signature` | Generate a Semgrep signature (LLM-assisted) |
| POST | `/api/batch/analyze` | Start a batch job |
| GET | `/api/batch/status/{batch_id}` · `/results/{batch_id}` · `/list` | Batch lifecycle |
| GET | `/health` | Health check |
| GET | `/{full_path:path}` | Catch-all serving the built React SPA |

## Scan lifecycle

1. **Trigger** — `POST /api/scan/trigger` calls `extract_extension_id(url)`. If the ID is already
   `running` it returns early; if already scanned it returns the cached result unless `force=true`.
   Otherwise it schedules `run_analysis_workflow(url, extension_id)` as a `BackgroundTask` and
   returns `status: running`.
2. **Run** — `run_analysis_workflow` builds a `WorkflowState` with `keep_extracted=True`,
   `await graph.ainvoke(...)`, then persists completed results to SQLite. In-memory `scan_status`
   and `scan_results` dicts track progress between the trigger and completion.
3. **Poll** — clients poll `GET /api/scan/status/{id}` then fetch `GET /api/scan/results/{id}`.

The `force` flag re-scans and clears prior cache. Uploads (`/api/scan/upload`) generate a UUID as
the extension_id, save the file into `extensions_storage/`, and reuse the same background workflow.

## Persistence (`database.py`)

A small SQLite wrapper (`Database`) manages three tables:

| Table | Contents |
|-------|----------|
| `scan_results` | One row per analyzed extension (results JSON, score, risk level, timestamps) |
| `statistics` | Rolled-up aggregates maintained by `_update_statistics()` |
| `batch_scans` | Batch job state |

Key methods: `save_scan_result`, `get_scan_result`, `get_scan_history`, `get_statistics`,
`get_risk_distribution`, `get_recent_scans`, `delete_scan_result`, `clear_all_results`. The DB path
defaults into the `data/` volume (persisted across Docker runs).

## Related pages
- [Analysis Pipeline](../workflows/analysis-pipeline.md)
- [Deployment & Docker Isolation](deployment.md)
