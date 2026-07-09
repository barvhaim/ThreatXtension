# LLM Integration

[← Back to Quickstart](../quickstart.md) · [Architecture Overview](overview.md)

Sources:
- `src/threatxtension/llm/clients/__init__.py` — provider factory
- `src/threatxtension/llm/clients/provider_type.py` — provider enum
- `src/threatxtension/llm/prompts/` — YAML prompt templates
- `src/threatxtension/core/summary_generator.py` — summary orchestration

## Provider abstraction

All LLM access goes through one factory: `get_chat_llm_client(model_name, model_parameters)`.
The active provider is chosen once at import time from the `LLM_PROVIDER` env var and mapped to a
LangChain chat model:

| `LLM_PROVIDER` | LangChain class | Notes |
|----------------|-----------------|-------|
| `openai` | `ChatOpenAI` | Honors `OPENAI_BASE_URL` / `OPENAI_API_BASE` for OpenAI-compatible servers (LiteLLM, vLLM, LM Studio) |
| `watsonx` | `ChatWatsonx` | IBM WatsonX; reads `WATSONX_URL`, `WATSONX_PROJECT_ID`, `WATSONX_APIKEY` (with `WX_*` fallbacks) |
| `ollama` | `ChatOllama` | Local models; `max_tokens`→`num_predict` |
| `rits` | `ChatOpenAI` | IBM Research RITS via OpenAI-compatible `RITS_API_BASE_URL/v1` |

`_get_base_llm_settings()` normalizes each provider's parameter names (e.g. `max_tokens` vs.
`max_new_tokens` vs. `num_predict`). Imports of provider SDKs are done lazily inside the factory so
you only need the dependency for the provider you actually use.

> **Why OpenAI-compatible base URL matters:** the Docker isolation setup (see
> [Deployment](../interfaces/deployment.md)) routes the app's LLM calls to a host-side
> OpenAI-compatible endpoint through an egress proxy. Commit `f370f7b` added this support plus
> lower-temperature fallbacks.

## Prompts

Prompts are **YAML files**, one per analysis type, loaded via `get_prompts(name)`:

| File | Used by |
|------|---------|
| `permission_analysis.yaml` | `PermissionsAnalyzer` (per-permission reasonableness) |
| `sast_analysis.yaml` | `JavaScriptAnalyzer` (narrative over Semgrep findings) |
| `webstore_analysis.yaml` | `WebstoreAnalyzer` |
| `summary_generation.yaml` | `SummaryGenerator.generate()` — the standard executive summary |
| `executive_summary.yaml` | `SummaryGenerator.generate_executive_summary()` — richer C-level report |

Each is built into a LangChain `PromptTemplate` and composed into a chain:
`prompt | llm | JsonOutputParser()`. The LLM is always asked to return JSON.

## Summary generation flow

`SummaryGenerator.generate(analysis_results, manifest)`:

1. Runs [`SecurityScorer`](scoring.md) → deterministic score + breakdown.
2. Builds the `summary_generation` prompt, injecting the human-readable analysis strings for
   permissions, host permissions, webstore, SAST, and a formatted chrome-stats behavioral block.
3. Invokes the LLM (`temperature=0.05`, `max_tokens=4096`) and parses JSON into
   `summary`, `key_findings`, `recommendations`.
4. **Overwrites** `security_score` / `overall_risk_level` / `risk_breakdown` with the scorer's
   values — the LLM never determines the numeric risk.
5. On LLM failure, returns a graceful fallback that still contains the scorer's numbers.

`generate_executive_summary()` is a heavier variant producing business-impact / compliance /
ROI-style output for the `executive_summary.yaml` template.

## Default model

`SummaryGenerator` defaults to `os.getenv("LLM_MODEL", "rits/openai/gpt-oss-120b")`. Set both
`LLM_PROVIDER` and `LLM_MODEL` in `.env`. The README documents recommended models per provider.

## Related pages
- [Security Scoring](scoring.md)
- [Analyzers](../domain/analyzers.md) — the analyzers that also make per-item LLM calls
