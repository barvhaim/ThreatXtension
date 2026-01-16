# ThreatXtension Dockerfile
# Multi-stage build: Node.js for frontend, Python for backend

# =============================================================================
# Stage 1: Build React Frontend
# =============================================================================
FROM node:20-alpine AS frontend-builder

WORKDIR /app/frontend

# Copy package files first for better layer caching
COPY frontend/package*.json ./

# Install dependencies
RUN npm ci --silent

# Copy frontend source
COPY frontend/ ./

# Build production bundle
RUN npm run build

# =============================================================================
# Stage 2: Python Backend with Frontend Static Files
# =============================================================================
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_SYSTEM_PYTHON=1

WORKDIR /app

# Install system dependencies
# - git: required by some Python packages and semgrep
# - curl: for health checks
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv package manager
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy dependency files and README (required by pyproject.toml)
COPY pyproject.toml uv.lock README.md ./

# Copy application source code (needed for package build)
COPY src/ ./src/

# Install Python dependencies and build the project
RUN uv sync --frozen --no-dev

# Copy frontend build from stage 1
COPY --from=frontend-builder /app/frontend/dist ./static

# Create necessary directories
RUN mkdir -p extensions_storage data

# Set default environment variables
ENV EXTENSION_STORAGE_PATH=/app/extensions_storage \
    DATABASE_PATH=/app/data/threatxtension.db \
    LLM_PROVIDER=openai

# Expose the API port
EXPOSE 8007

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8007/health || exit 1

# Run the application
CMD ["uv", "run", "uvicorn", "threatxtension.api.main:app", "--host", "0.0.0.0", "--port", "8007"]
