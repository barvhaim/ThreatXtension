# Deployment & Docker Isolation

[← Back to Quickstart](../quickstart.md) · [Interfaces Overview](overview.md)

Sources:
- `Dockerfile` — multi-stage image (frontend build + Python backend)
- `docker-compose.override.yml` — network-restricted, hardened runtime
- `docker/egress-proxy/` — tinyproxy sidecar (Dockerfile, allowlist, entrypoint, config)

## Image build

The `Dockerfile` is a two-stage build:

1. **`frontend-builder`** (`node:20-alpine`) — `npm ci` + `npm run build` produces the React SPA.
2. **Python backend** (`python:3.11-slim`) — installs system deps (`git`, `curl`), Python deps via
   `uv`, and copies in the built frontend static files. One container serves both API and UI on
   port **8007**.

`docker compose up --build` runs API + UI at `http://localhost:8007`.

## Network-restricted scanning (why this exists)

Analyzing untrusted extension code is inherently risky. `docker-compose.override.yml` (added in
commit `58aa6a4`) hardens the runtime so a malicious sample can't phone home or escape to the host:

- **Internal-only network** — the app container sits on an `internal: true` network with **no route
  to the internet**. Its *only* egress path is the `egress-proxy` sidecar.
- **Egress allowlist** — `docker/egress-proxy` runs **tinyproxy** and only forwards to an anchored
  regex allowlist (`docker/egress-proxy/allowlist.txt`): Chrome Web Store, the CRX CDN hosts,
  chrome-stats.com, VirusTotal, and LangSmith. Provider/LLM hosts are **not** hard-coded — they're
  appended at container start from `EGRESS_ALLOW_EXTRA` so the allowlist adapts to your
  `LLM_PROVIDER` (OpenAI, WatsonX, Ollama, RITS, or a local host endpoint).
- **Host hardening** — `read_only` root filesystem, `cap_drop: ALL`, `no-new-privileges`, non-root
  `user`, and writable `tmpfs` scratch (`/tmp`, `/scratch`) for Semgrep/uv caches.
- **LLM routing** — inside the container `OPENAI_BASE_URL` points at `host.docker.internal:8989/v1`
  and all traffic (including the LLM) is forced through `HTTP(S)_PROXY=egress-proxy:8888`. The proxy
  reaches the host LLM on the app's behalf; the app itself has no direct route out.

> To use a real provider, set `EGRESS_ALLOW_EXTRA` to that provider's host regex (examples are
> documented inline in `docker-compose.override.yml`), e.g. `^api\.openai\.com$` for OpenAI.

## Caveat: `uv run --no-sync`

The override's command uses `uv run --no-sync` so that startup does **not** re-resolve dependencies
against PyPI — which the egress allowlist deliberately blocks. Deps are baked in at build time.

## Environment variables

Configure via `.env` (copy from `.env.example`):

- Required: `LLM_PROVIDER`, `LLM_MODEL`, and the provider's key (e.g. `OPENAI_API_KEY`).
- Optional: `VIRUSTOTAL_API_KEY`, `CHROMESTATS_API_KEY`, `LANGSMITH_API_KEY`.
- Storage: `EXTENSION_STORAGE_PATH` (default `extensions_storage/`).

## Related pages
- [LLM Integration](../architecture/llm-integration.md) — provider/base-URL handling
- [Extension Acquisition](../domain/extension-acquisition.md) — what egress hosts are needed and why
