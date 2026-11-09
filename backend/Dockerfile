# ==============================================================================
# AIPENT Backend — Production Dockerfile
# Container for the AIPENT FastMCP/FastAPI backend
# ==============================================================================

FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/backend/src:/backend/.venv/lib/python3.12/site-packages \
    VIRTUAL_ENV=/backend/.venv \
    PATH="/backend/.venv/bin:$PATH" \
    PORT=8010

WORKDIR /backend

# Copy virtual environment, source code, tests, and static wordlists
COPY .venv /backend/.venv
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY bin ./bin
COPY scripts ./scripts
COPY tests ./tests
COPY data/wordlists ./data/wordlists

RUN mkdir -p /backend/data /backend/artifacts

EXPOSE 8010

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8010"]
