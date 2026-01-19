.PHONY: help format lint test api frontend clean install analyze docker-build docker-up docker-down docker-logs

# Default target - show help
help:
	@echo "ThreatXtension - Available Make Commands"
	@echo "======================================="
	@echo ""
	@echo "Docker (Recommended):"
	@echo "  make docker-build    - Build Docker container"
	@echo "  make docker-up       - Start container (foreground)"
	@echo "  make docker-down     - Stop container"
	@echo "  make docker-logs     - View container logs"
	@echo ""
	@echo "Code Quality:"
	@echo "  make format          - Format Python code with Black"
	@echo "  make lint            - Run Pylint on source code"
	@echo "  make test            - Run pytest test suite"
	@echo "  make precommit       - Run pre-commit hooks on all files"
	@echo ""
	@echo "Run Applications (Local Development):"
	@echo "  make api             - Start FastAPI server for frontend (port 8007)"
	@echo "  make frontend        - Start React frontend dev server (port 5173)"
	@echo "  make analyze URL=... - Analyze extension from Chrome Web Store URL"
	@echo "  make analyze-file FILE=... - Analyze local CRX/ZIP file"
	@echo ""
	@echo "Development:"
	@echo "  make install         - Install dependencies with uv"
	@echo "  make clean           - Remove output files and caches"
	@echo ""

# Format code with Black
format:
	@echo "Formatting Python code with Black..."
	uv run black .
	@echo "✓ Formatting complete"

# Lint code with Pylint
lint:
	@echo "Running Pylint on source code..."
	uv run pylint src/
	@echo "✓ Linting complete"

# Run tests
test:
	@echo "Running pytest..."
	uv run pytest
	@echo "✓ Tests complete"

# Run pre-commit hooks
precommit:
	@echo "Running pre-commit hooks..."
	pre-commit run --all-files
	@echo "✓ Pre-commit checks complete"

# Start FastAPI server
api:
	@echo "Starting FastAPI server with auto-reload..."
	@echo "Access at: http://localhost:8007"
	@echo "API docs at: http://localhost:8007/docs"
	uv run threatxtension serve --reload

# Start React frontend
frontend:
	@echo "Starting React frontend development server..."
	@echo "Access at: http://localhost:5173"
	cd frontend && npm run dev

# Analyze extension via CLI from URL
analyze:
ifndef URL
	@echo "Error: URL parameter is required"
	@echo "Usage: make analyze URL=https://chromewebstore.google.com/detail/example/abcdef"
	@echo "       make analyze URL=https://... OUTPUT=results.json"
	@exit 1
endif
	@echo "Analyzing Chrome extension from URL..."
ifdef OUTPUT
	uv run threatxtension analyze --url $(URL) --output $(OUTPUT)
else
	uv run threatxtension analyze --url $(URL)
endif

# Analyze local CRX/ZIP file via CLI
analyze-file:
ifndef FILE
	@echo "Error: FILE parameter is required"
	@echo "Usage: make analyze-file FILE=/path/to/extension.crx"
	@echo "       make analyze-file FILE=/path/to/extension.zip OUTPUT=results.json"
	@exit 1
endif
	@echo "Analyzing local extension file..."
ifdef OUTPUT
	uv run threatxtension analyze --file $(FILE) --output $(OUTPUT)
else
	uv run threatxtension analyze --file $(FILE)
endif

# Install dependencies
install:
	@echo "Installing Python dependencies with uv..."
	uv sync

# Clean output and cache files
clean:
	@echo "Cleaning caches..."
	rm -rf .pytest_cache/
	rm -rf .ruff_cache/
	rm -rf **/__pycache__/
	rm -rf **/*.pyc
	@echo "✓ Cleanup complete"

# =============================================================================
# Docker Commands
# =============================================================================

# Build Docker container
docker-build:
	@echo "Building ThreatXtension Docker container..."
	docker compose build
	@echo "✓ Docker build complete"

# Start container in foreground
docker-up:
	@echo "Starting ThreatXtension container..."
	@echo "Access at: http://localhost:8007"
	docker compose up

# Start container in background
docker-up-d:
	@echo "Starting ThreatXtension container in background..."
	docker compose up -d
	@echo "✓ Container started. Access at: http://localhost:8007"

# Stop container
docker-down:
	@echo "Stopping ThreatXtension container..."
	docker compose down
	@echo "✓ Container stopped"

# View container logs
docker-logs:
	docker compose logs -f
