# Analysis Pipeline (LangGraph Workflow)

[← Back to Quickstart](../quickstart.md)

Sources:
- `src/threatxtension/workflow/graph.py` — graph construction
- `src/threatxtension/workflow/nodes.py` — node implementations
- `src/threatxtension/workflow/state.py` — `WorkflowState` + `WorkflowStatus`
- `src/threatxtension/workflow/node_types.py` — node-name constants

The core engine is a compiled LangGraph `StateGraph`. `build_graph()` wires eight nodes and sets
`extension_path_routing_node` as the entry point. Every node is a function
`(state: WorkflowState) -> Command`, where `Command(goto=…, update={…})` names the next node and
the partial state update to merge.

## The graph

```
                       ┌──────────────────────────────┐
input → extension_path_routing_node                    │
        │  extension ID → chromestats_downloader_node  │
        │  Web Store URL → extension_metadata_node → extension_downloader_node
        │  local .crx/.zip → extension_downloader_node │
        │  invalid → END (status=FAILED)               │
        ▼                                               │
   manifest_parser_node → extension_analyzer_node → summary_generation_node → cleanup_node → END
                                                                                    ▲
              (any node on error) ──────────────────────────────────────────────────┘
```

## Node responsibilities

| Node | What it does | On failure |
|------|--------------|------------|
| `extension_path_routing_node` | Classifies the input (ID / URL / local file) and routes accordingly. Uses `is_chrome_extension_id`, `is_chrome_extension_store_url`, `is_local_extension_crx_file`. | `goto=END`, `status=FAILED` |
| `extension_metadata_node` | Web Store path only: scrapes store metadata via `ExtensionMetadata`, then enriches with chrome-stats details. Metadata failures are non-fatal. | continues (metadata=None) |
| `chromestats_downloader_node` | Extension-ID path: downloads the CRX/ZIP from chrome-stats.com and extracts it. Sets `downloaded_crx_path`. | `goto=CLEANUP_NODE`, `status=FAILED` |
| `extension_downloader_node` | URL path: downloads from Web Store; local path: extracts the user file (does **not** set `downloaded_crx_path`, so it's never deleted). | `goto=CLEANUP_NODE`, `status=FAILED` |
| `manifest_parser_node` | Parses `manifest.json` via `ManifestParser`. | `goto=CLEANUP_NODE`, `status=FAILED` |
| `extension_analyzer_node` | Runs all six analyzers via `ExtensionAnalyzer.analyze()`. | `goto=CLEANUP_NODE`, `status=FAILED` |
| `summary_generation_node` | Runs `SecurityScorer` + LLM summary via `SummaryGenerator`. | `goto=CLEANUP_NODE`, `status=FAILED` |
| `cleanup_node` | Collects the extracted file list, removes temp files, sets terminal status. | preserves `FAILED` |

## WorkflowState

Defined in `workflow/state.py`. Key fields:

| Field | Meaning |
|-------|---------|
| `workflow_id` | UUID for this run |
| `chrome_extension_path` | The raw input (URL, ID, or file path) |
| `extension_dir` | Where the extension was extracted |
| `downloaded_crx_path` | Set **only** when the tool downloaded a file → marks it for deletion |
| `extension_metadata` | Web Store + chrome-stats metadata |
| `manifest_data` | Parsed manifest |
| `analysis_results` | Raw output of all six analyzers |
| `executive_summary` | LLM prose + score + breakdown |
| `extracted_files` | Relative file list captured before cleanup (for the web file viewer) |
| `keep_extracted` | If truthy, cleanup retains `extension_dir` (web UI needs it; CLI/MCP set `False`) |
| `status` | `WorkflowStatus`: pending / running / completed / failed |
| `start_time` / `end_time` / `error` | Timing + failure message |

## Cleanup semantics (important)

`cleanup_node` encodes two deliberate rules:

1. **The downloaded CRX is always deleted** (`cleanup_downloaded_crx`, guarded to only touch files
   inside `extensions_storage/`). User-provided local files are never deleted because
   `downloaded_crx_path` is left unset for them.
2. **The extracted directory is only kept when `keep_extracted` is truthy.** The web UI sets this
   `True` so its file viewer can browse the source afterward (commit `6c4fba7` made retention
   opt-in). The CLI and MCP set it `False`.

`cleanup_node` also **preserves a `FAILED` status** rather than overwriting it with `COMPLETED` —
so an error surfaced anywhere upstream survives to the caller.

## Invoking the workflow

```python
from threatxtension.workflow.graph import build_graph
from threatxtension.workflow.state import WorkflowStatus

state = {
    "workflow_id": "...", "chrome_extension_path": "<url|id|path>",
    "extension_dir": None, "extension_metadata": None, "manifest_data": None,
    "analysis_results": None, "executive_summary": None,
    "keep_extracted": False, "status": WorkflowStatus.PENDING.value,
    "start_time": "...", "end_time": None, "error": None,
}
result = build_graph().invoke(state)   # synchronous, blocks until done
```

This exact pattern appears in `cli/main.py`, `api/main.py` (`run_analysis_workflow`), and
`mcp_server/main.py`. The `example_workflow.py` script at the repo root is a runnable demo.

## Related pages
- [Extension Acquisition](../domain/extension-acquisition.md) — routing/download/extract details
- [Analyzers](../domain/analyzers.md) — what `extension_analyzer_node` runs
- [Batch Processing](batch-processing.md)
