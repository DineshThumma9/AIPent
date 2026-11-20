# AIPENT backend

FastAPI + LangGraph assessment engine and Terminal CLI.

## Web API Server
```bash
uv sync
uv run uvicorn app.main:app --port 8010
```

## Terminal CLI (`./aipent`)

AIPENT provides a rich terminal CLI for running security assessments:

```bash
# Show help and key options:
./aipent --help

# Quick unattended assessment (auto-approves all human gates):
./aipent scan http://127.0.0.1:3000 -y

# Pass a query or custom objective for the agent:
./aipent scan http://127.0.0.1:3000 -r "Test for SQL injection on search endpoint" -y
./aipent scan http://127.0.0.1:3000 -q "Find OWASP Top 10 vulnerabilities" --auto-approve

# Direct shorthand syntax:
./aipent http://127.0.0.1:3000 -y

# List assessments, inspect status, steer agent, or generate report:
./aipent list
./aipent status 1
./aipent steer 1 "Focus on port 8080"
./aipent report 1
```
