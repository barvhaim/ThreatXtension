# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Project Overview

**ThreatXtension** is a Python-based security analysis tool for Chrome browser extensions. It combines static analysis (SAST) with AI-powered threat intelligence to identify malicious behavior patterns in browser extensions.

### Recent Updates

**Extension ID Support (2026-01-22):**
- Users can now analyze extensions using just the extension ID (32-character string)
- New `ChromeStatsDownloader` module downloads extensions from chrome-stats.com API
- Workflow routing automatically detects extension IDs and routes to chrome-stats downloader
- CLI supports `--id` flag: `threatxtension analyze --id gbbilodpoldeopifonmibfboicpafpjo`
- Frontend input field accepts URLs, extension IDs, or file uploads
- Requires `CHROMESTATS_API_KEY` environment variable for this feature

### Core Technologies
- **Python 3.11+** with `uv` package manager
- **LangGraph** for workflow orchestration (state machine-based analysis pipeline)
- **LangChain** for LLM integration and prompt management
- **Semgrep** for JavaScript static analysis with custom security rules
- **FastMCP** for Claude Desktop integration
- **Click** for CLI framework
- **Gradio** for web UI
- **FastAPI** for REST API backend
- **Rich** for terminal output formatting

### Architecture

The project follows a **workflow-based architecture** using LangGraph:

1. **Workflow Pipeline** (`src/threatxtension/workflow/`):
   - State-driven analysis flow with 7 nodes
   - Entry: `extension_path_routing_node` → determines if URL or local path
   - Nodes: metadata → downloader → manifest parser → analyzer → summary → cleanup
   - State management via `WorkflowState` TypedDict with status tracking

2. **Multi-Analyzer System** (`src/threatxtension/core/analyzers/`):
   - **PermissionsAnalyzer**: Evaluates manifest permissions against risk database
   - **JavaScriptAnalyzer**: Runs Semgrep with 10+ custom rules for banking fraud, credential theft, data exfiltration
   - **WebstoreAnalyzer**: Extracts Chrome Web Store metadata (ratings, users, developer info)

3. **LLM Integration** (`src/threatxtension/llm/`):
   - Provider-agnostic design supporting WatsonX, RITS, OpenAI, Ollama
   - YAML-based prompt templates for each analysis type
   - Context-aware analysis with full extension metadata

4. **Multiple Interfaces**:
   - **CLI** (`src/threatxtension/cli/main.py`): Primary interface with rich console output
   - **Web UI** (`src/threatxtension/ui/app.py`): Gradio-based demo interface
   - **REST API** (`src/threatxtension/api/main.py`): FastAPI backend for React frontend
   - **MCP Server** (`src/threatxtension/mcp_server/main.py`): Claude Desktop integration

## Building and Running

### Installation
```bash
# Install dependencies
uv sync

# Or using make
make install
```

### Running Analysis

**CLI (Primary Method)**:
```bash
# Analyze extension from Chrome Web Store
make analyze URL=https://chromewebstore.google.com/detail/extension-id/abcdef

# With JSON output
make analyze URL=<url> OUTPUT=results.json

# Direct command
uv run threatxtension analyze --url <chrome_web_store_url>
```

**Web UI**:
```bash
make ui
# Access at http://localhost:7860
```

**REST API + React Frontend**:
```bash
# Terminal 1: Start API server
make api
# Access API at http://localhost:8007
# API docs at http://localhost:8007/docs

# Terminal 2: Start React frontend
make frontend
# Access at http://localhost:5173
```

**Example Workflow Script**:
```bash
uv run example_workflow.py
```

### Development Commands
```bash
make format      # Format code with Black (line-length=100)
make lint        # Run Pylint
make test        # Run pytest
make precommit   # Run pre-commit hooks
make clean       # Remove caches and output files
```

## Development Conventions

### Code Style
- **Black** formatter with 100-character line length
- **Pylint** for linting (config in `.pylintrc`)
- **Pre-commit hooks** configured (`.pre-commit-config.yaml`)
- Type hints required for function signatures

### Workflow Development
- All workflow nodes must return `Command` objects (from LangGraph)
- State updates via `Command(goto=..., update={...})`
- Error handling: Set `status=FAILED` and `error` field in state
- Cleanup node preserves FAILED status (recent fix in commit f276768)

### LLM Integration
- Prompts stored as YAML files in `src/threatxtension/llm/prompts/`
- Each analyzer has dedicated prompt template
- Provider selection via `LLM_PROVIDER` environment variable
- Always include full context (manifest, metadata) in prompts

### Configuration Files
- **SAST Config**: `src/threatxtension/config/sast_config.json`
  - Semgrep rule selection, exclusion patterns, parallel scanning settings
- **Custom Rules**: `src/threatxtension/config/custom_semgrep_rules.yaml`
  - 10+ banking/fraud-specific rules with MITRE ATT&CK mappings
- **Sensitive Domains**: `src/threatxtension/config/sensitive_domains.json`
  - Domain categories for permission risk assessment

### Testing
- Test files in standard pytest structure
- Use `make test` to run test suite
- Mock LLM responses for deterministic testing

### Environment Setup
- Copy `.env.example` to `.env` for LLM credentials
- Required for AI-powered analysis features
- Supports multiple LLM providers (see README for details)

### MCP Server Integration
- Server entry point: `src/threatxtension/mcp_server/main.py`
- Exposes `analyze_chrome_extension()` tool to Claude Desktop
- Configuration in Claude's `claude_desktop_config.json`
- Uses `uv` command with absolute path to project directory

### Git Workflow
- Conventional commit messages preferred (fix:, feat:, docs:, etc.)
- Pre-commit hooks enforce code quality
- `.bobignore` excludes Bob-Shell artifacts from version control

### Key Dependencies
- `langgraph>=0.6.10` - Workflow orchestration
- `langchain>=0.3.27` - LLM framework
- `semgrep>=1.139.0` - SAST engine
- `fastmcp>=1.0` - MCP server framework
- `click>=8.1.0` - CLI framework
- `gradio>=5.49.1` - Web UI
- `fastapi>=0.115.0` - REST API
- `rich>=13.5.2` - Terminal formatting

### Project Structure Notes
- `src/threatxtension/` - Main package
- `frontend/` - React-based frontend (separate from Gradio UI)
- `docs/` - Documentation (e.g., WatsonX API key guide)
- `images/` - Screenshots and logos for README
- `extensions_storage/` - Downloaded extensions (gitignored)
- `.bob/` - Bob-Shell artifacts (gitignored)

### Important Implementation Details
1. **Workflow State**: Always use `WorkflowState` TypedDict for type safety
2. **Status Management**: Use `WorkflowStatus` enum (PENDING, RUNNING, COMPLETED, FAILED)
3. **Cleanup**: `cleanup_node` handles temporary file removal and preserves error states
4. **Extension Download**: `downloaded_crx_path` tracks files for cleanup (vs user-provided paths)
5. **Error Propagation**: Errors set in state are preserved through cleanup phase

### Security Considerations
- Tool designed for legitimate security research and malware analysis
- Custom Semgrep rules target banking fraud, credential theft, data exfiltraction
- Sensitive domain detection for privacy-critical permissions
- All analysis results include MITRE ATT&CK and CWE mappings where applicable
