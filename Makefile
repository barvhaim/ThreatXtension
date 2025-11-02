.PHONY: help format lint test ui api frontend clean install analyze

# Default target - show help
help:
	@echo "ThreatXtension - Available Make Commands"
	@echo "======================================="
	@echo ""
	@echo "Code Quality:"
	@echo "  make format          - Format Python code with Black"
	@echo "  make lint            - Run Pylint on source code"
	@echo "  make test            - Run pytest test suite"
	@echo "  make precommit       - Run pre-commit hooks on all files"
	@echo ""
	@echo "Run Applications:"
	@echo "  make ui              - Start Gradio web interface (port 7860)"
	@echo "  make analyze URL=... - Analyze extension via CLI (requires URL parameter)"
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

# Start Gradio UI
ui:
	@echo "Starting Gradio web interface..."
	@echo "Access at: http://localhost:7860"
	uv run gradio src/threatxtension/ui/app.py

# Analyze extension via CLI
analyze:
ifndef URL
	@echo "Error: URL parameter is required"
	@echo "Usage: make analyze URL=https://chromewebstore.google.com/detail/example/abcdef"
	@echo "       make analyze URL=https://... OUTPUT=results.json"
	@exit 1
endif
	@echo "Analyzing Chrome extension..."
ifdef OUTPUT
	uv run threatxtension analyze --url $(URL) --output $(OUTPUT)
else
	uv run threatxtension analyze --url $(URL)
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
