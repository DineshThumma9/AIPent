# ==============================================================================
# AIPENT Backend — Production Dockerfile
# Container for the AIPENT FastMCP/FastAPI backend
# ==============================================================================
FROM python:3.12-slim AS base

# Install uv binary from official Astral image
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PORT=8010 \
    PATH="/backend/.venv/bin:$PATH" \
    PYTHONPATH="/backend/src"

WORKDIR /backend

# Install runtime dependencies (curl for container healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies first for efficient build caching
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project

# Copy application source code and assets
COPY src ./src
COPY bin ./bin
COPY scripts ./scripts
COPY data/wordlists ./data/wordlists

# Complete sync to install the app itself into the environment
RUN uv sync --frozen --no-dev

# Create runtime directories
RUN mkdir -p /backend/data /backend/artifacts

EXPOSE 8010

HEALTHCHECK --interval=15s --timeout=5s --retries=3 --start-period=10s \
  CMD curl -fsS http://127.0.0.1:8010/health || exit 1

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8010"]
