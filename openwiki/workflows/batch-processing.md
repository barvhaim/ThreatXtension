# Batch Processing

[← Back to Quickstart](../quickstart.md) · [Analysis Pipeline](analysis-pipeline.md)

Source: `src/threatxtension/core/batch_processor.py`

`BatchProcessor` analyzes a list of extensions by running the standard
[analysis workflow](analysis-pipeline.md) once per entry. It exists so you can triage many
extensions (e.g. an allow/deny review of a fleet) without hand-driving the CLI.

## CLI usage

```bash
threatxtension batch --input urls.txt --output results/
threatxtension batch -i extensions.txt --parallel --workers 8
threatxtension batch -i list.txt --sequential
```

The input file is a plain text list — one Web Store URL, extension ID, or local file path per line
(`_load_extensions_from_file`). The API also exposes `/api/batch/analyze`, `/api/batch/status/{id}`,
`/api/batch/results/{id}`, and `/api/batch/list`.

## How it works

1. `process_from_file()` derives a `batch_id` (`batch_<stem>_<timestamp>`) and loads the list.
2. `process_batch()` dispatches to `_process_parallel` (a `ThreadPoolExecutor`, default 4 workers)
   or `_process_sequential`.
3. `_analyze_single_extension()` builds a `WorkflowState` with `workflow_id = "{batch_id}_ext_{i}"`
   and calls `build_graph().invoke(...)` — the exact same pipeline as a single scan.
4. Batch state is checkpointed via `_save_batch_state()` and a summary report is written via
   `generate_batch_report()`; its path is returned as `report_path`.

## Result shape

`process_batch()` returns a dict with `batch_id`, `total_extensions`, `completed`, `failed`,
`start_time`, `end_time`, and `report_path`. The CLI renders these as a Rich summary table with a
computed success rate.

## Notes for agents

- Parallelism is thread-based; because each workflow invocation is CPU/IO-bound (Semgrep, network,
  LLM), threads give useful concurrency despite the GIL. Tune `--workers` to your rate limits.
- Each extension is fully independent — a failure in one is captured in that entry's result and
  does not abort the batch.

## Related pages
- [Analysis Pipeline](analysis-pipeline.md)
- [REST API Reference](../interfaces/rest-api.md)
