# System Overview

[← Back to Quickstart](../quickstart.md)

ThreatXtension is a **workflow-based analysis engine** wrapped by four interchangeable interfaces.
The engine is provider- and interface-agnostic: the exact same LangGraph workflow is invoked from
the CLI, the REST API, and the MCP server. Only the input adapter and the output rendering differ.

## Layers

```
Interfaces:   CLI  •  REST API (FastAPI)  •  Web UI (React)  •  MCP server (Claude Desktop)
                                   │
                                   ▼
Orchestration: LangGraph StateGraph   (workflow/graph.py, workflow/nodes.py)
                                   │
                                   ▼
Analyzers:    Permissions • SAST • Webstore • VirusTotal • Entropy • ChromeStats
                                   │
                                   ▼
Scoring:      SecurityScorer  (deterministic 0–100)
                                   │
                                   ▼
Summary:      SummaryGenerator → LLM (OpenAI / WatsonX / Ollama / RITS)
```

## Package layout

| Path | Responsibility |
|------|----------------|
| `src/threatxtension/workflow/` | LangGraph graph, nodes, state, node-name constants |
| `src/threatxtension/core/` | Domain logic: analyzers, downloaders, parsers, scorer, summary |
| `src/threatxtension/core/analyzers/` | The six analyzer implementations + `BaseAnalyzer` |
| `src/threatxtension/llm/` | Provider-agnostic LLM client factory + YAML prompt loader |
| `src/threatxtension/config/` | JSON/YAML tunables: SAST, Semgrep rules, sensitive domains, VT, chrome-stats |
| `src/threatxtension/data/` | Reference data (e.g. `permissions_db.json`) |
| `src/threatxtension/cli/` | Click CLI (`analyze`, `serve`, `batch`, `version`) |
| `src/threatxtension/api/` | FastAPI app + SQLite persistence layer |
| `src/threatxtension/mcp_server/` | FastMCP server exposing `analyze_chrome_extension()` |
| `src/threatxtension/utils/` | Extension helpers: input routing, extraction, cleanup, hashing |
| `frontend/` | React 19 + Vite + Tailwind dashboard (separate from the Gradio-era UI) |
| `docker/egress-proxy/` | tinyproxy sidecar for network-restricted scanning |

## Data flow at a glance

1. An interface builds an initial [`WorkflowState`](../workflows/analysis-pipeline.md#workflowstate)
   dict containing the raw input under `chrome_extension_path`.
2. `build_graph().invoke(state)` runs the pipeline synchronously and returns the final state.
3. The final state carries `analysis_results` (raw per-analyzer output), `executive_summary`
   (LLM text + `security_score` + `risk_breakdown`), `extension_metadata`, and `extracted_files`.
4. Interfaces render or persist that state.

The engine is **synchronous** — LangGraph `invoke` blocks until completion. The REST API therefore
runs it in a FastAPI `BackgroundTask` and tracks progress via an in-memory `scan_status` dict plus
the SQLite results table.

## Why LangGraph?

The analysis is a linear pipeline with **conditional entry routing** (URL vs. ID vs. local file)
and **uniform error handling** (any node can jump straight to cleanup on failure). LangGraph's
`Command(goto=…, update={…})` model expresses both concerns cleanly: each node is a pure function
of the state, and failure is just a `goto=CLEANUP_NODE` with `status=FAILED`. See the
[Analysis Pipeline](../workflows/analysis-pipeline.md) page for the node-by-node behavior.

## Related pages
- [Security Scoring](scoring.md)
- [LLM Integration](llm-integration.md)
- [Analyzers](../domain/analyzers.md)
