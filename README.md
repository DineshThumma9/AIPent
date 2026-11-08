# AIPENT — Authorized VAPT Agent

Conversational, evidence-first vulnerability assessment and penetration testing (VAPT) agent for authorized lab targets. Built with **FastAPI**, **LangGraph**, **LangChain**, **React**, and **IBM Plex** typography — running a three-specialist orchestration loop (Recon → Discovery → Validation) with a human action gate between every action.

## What It Does

AIPENT runs an authorized VAPT against scoped targets through three specialist roles:

| Role | Mission | Tools |
|------|---------|-------|
| **Recon** | Map live ports and service facts | `recon_services` |
| **Discovery** | Turn service facts into candidate findings | `dirb_scan`, `nikto_scan`, `zap_baseline` |
| **Validation** | Test hypotheses with safe probes | `http_probe`, `sqlmap_scan` |

Every action the agent wants to run is **queued as a Step first**. Gate policy then decides whether it pauses for a human or executes on agent authority (see [`AIPENT_ACTION_POLICIES`](#environment-variables)). High-risk actions — `sqlmap_scan`, `http_probe`, `zap_baseline` — pause by default. Nothing touches the target before it has been queued, and every approved command runs exactly as shown in the approval card.

## Architecture

```
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│   Recon         │      │   Discovery     │      │   Validation    │
│ (recon_services)│─────▶│ (nikto/zap/dirb)│─────▶│ (http_probe/    │
│                 │      │                 │      │  sqlmap_scan)   │
└─────────────────┘      └─────────────────┘      └─────────────────┘
         │                         │                         │
         ▼                         ▼                         ▼
    ┌──────────┐            ┌──────────┐            ┌──────────┐
    │  GATE    │◀───────────┤  GATE    │◀───────────┤  GATE    │
    │ (human   │            │ (human   │            │ (human   │
    │  approves)│           │  approves)│           │  approves)│
    └──────────┘            └──────────┘            └──────────┘
         │                         │                         │
         └──────────────▶ Review → Report ◀──────────────────┘
```

### Layering

| Layer | Responsibility | Key Files |
|-------|---------------|-----------|
| **API** | FastAPI HTTP routes, SSE event stream | `backend/src/app/api/routes.py` |
| **Orchestration** | LangGraph three-role StateGraph, per-role toolsets | `backend/src/app/agents/graph.py` |
| **Gate** | Shared action gate — policy decides auto-approve vs. human decision | `backend/src/app/agents/gate.py` |
| **Runtime** | Background task management, per-assessment locks | `backend/src/app/runtime/runner.py` |
| **Actions** | Closed action catalogue, single execution path | `backend/src/app/actions/` |
| **Adapters** | Tool-specific parsing (nmap, nikto, zap) | `backend/src/app/adapters/` |
| **Skills** | Verification playbooks (header misconfig, sensitive storage, etc.) | `backend/src/app/skills/` |
| **Frontend** | React conversation desk, mission rail, side record | `frontend/src/` |

### Async Runtime

The backend is fully async and has no synchronous database path:

- FastAPI endpoints depend on `AsyncSession` via `app.core.db.get_session`.
- LangGraph runs on `AsyncSqliteSaver`, so checkpoint reads and writes never block the event loop.
- The application database uses `sqlite+aiosqlite` with `NullPool` (one connection per session). This avoids reusing an aiosqlite connection across event loops and keeps SQLite writer locks short-lived.
- Blocking work (scanner subprocesses, Typst compilation, artifact reads) is pushed through `asyncio.to_thread`.

### Safety Model

- **No self-execution**: The agent never runs a scanner or probe itself. It queues work; the gate executes it.
- **Policy-gated human-in-the-loop**: `AIPENT_ACTION_POLICIES` decides per action whether the gate pauses. When it pauses, the card shows the exact `argv` that will run; the human approves or rejects it.
- **Scope enforcement**: Targets and ports are validated before an action is queued, and HTTP probes validate the full URL host/port. Actions that use an agent-authored command line should stay human-gated (see the warning below).
- **Budgets**: Per-role turn caps (recon: 3, discovery: 4, validation: 8), per-run action cap, per-assessment probe cap.
- **No invented CVEs**: Findings come only from tool output and deterministic parsers.

## Quick Start

### Prerequisites

- Python 3.12+
- Docker (for MCP gateway with Kali + ZAP containers)
- `uv` package manager

### 1. Clone and Install

```bash
cd /home/dinesh/Desktop/projects/aipent
cd backend
uv sync
```

### 2. Start the Lab Target (Juice Shop)

```bash
cd /home/dinesh/Desktop/projects/aipent
docker compose -f lab.lvl1.yml up -d
```

Juice Shop will be available at `http://127.0.0.1:3000`.

### 3. Start the MCP Gateway

The gateway runs Kali (nmap, nikto, sqlmap, dirb) and ZAP in Docker containers:

```bash
cd /home/dinesh/Desktop/projects/aipent
cp deploy/mcp-zap/.env.example deploy/mcp-zap/.env
# Edit deploy/mcp-zap/.env with your ZAP_API_KEY and MCP_API_KEY
docker compose -f deploy/mcp-zap/compose.yaml up -d
./deploy/mcp-gateway/start.sh
```

The gateway listens on `http://127.0.0.1:8812/sse`.

### 4. Configure the Backend

Create `backend/.env`:

```
AIPENT_LLM_PROVIDER=groq
AIPENT_LLM_MODEL=<your-model>
AIPENT_GROQ_API_KEY=<your-key>
AIPENT_MCP_ENABLED=true
AIPENT_MCP_TRANSPORT=gateway
AIPENT_MCP_GATEWAY_URL=http://127.0.0.1:8812/sse
AIPENT_LAB_TARGET_ALIAS=host.docker.internal
```

Optional policy override (which actions need human approval):

```
AIPENT_ACTION_POLICIES='{"sqlmap_scan":{"approve":true},"nmap_scan":{"approve":false},"nikto_scan":{"approve":false},"dirb_scan":{"approve":false},"zap_baseline":{"approve":true},"http_probe":{"approve":true}}'
```

### 5. Start the Backend

```bash
cd /home/dinesh/Desktop/projects/aipent/backend
uv run uvicorn app.main:app --host 127.0.0.1 --port 8010
```

### 6. Start the Frontend

```bash
cd /home/dinesh/Desktop/projects/aipent/frontend
npm install
npm run dev
```

The desk opens at `http://localhost:5173`.

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/assessments` | GET | List all assessments |
| `/api/assessments` | POST | Create a new assessment |
| `/api/assessments/{id}` | GET | Get assessment detail (with steps, findings, approvals, audit) |
| `/api/assessments/{id}/request` | PATCH | Update the objective (409 if run is active) |
| `/api/assessments/{id}/messages` | GET | List chat messages |
| `/api/assessments/{id}/messages` | POST | Send operator/assistant message |
| `/api/assessments/{id}/events` | GET | SSE event stream |
| `/api/assessments/{id}/run` | POST | Start the agent run |
| `/api/assessments/{id}/stop` | POST | Stop/cancel the agent run |
| `/api/assessments/{id}/resume` | POST | Approve/reject a pending gate decision |
| `/api/assessments/{id}/scan` | POST | Run a manual nmap scan |
| `/api/assessments/{id}/agent` | GET | Get current agent state/view |
| `/api/assessments/{id}/report` | GET | Download the PDF report |
| `/health` | GET | Health check |

## Project Structure

```
aipent/
├── backend/
│   ├── pyproject.toml          # uv-based Python project
│   ├── src/app/
│   │   ├── main.py             # FastAPI app entry point
│   │   ├── api/
│   │   │   ├── routes.py       # REST + SSE endpoints
│   │   │   ├── schema.py       # Pydantic request/response models
│   │   │   └── queries.py      # Database read queries
│   │   ├── actions/            # Closed action catalogue + executor
│   │   │   ├── catalogue.py    # ActionSpec definitions
│   │   │   └── executor.py     # Single execution path (subprocess/MCP/HTTP)
│   │   ├── agents/             # Three-role LangGraph orchestration
│   │   │   ├── graph.py        # StateGraph + role nodes
│   │   │   ├── gate.py         # Human action gate
│   │   │   ├── tools.py        # Per-role tool lists (recon/discovery/validation)
│   │   │   ├── prompts.py      # Role system prompts
│   │   │   ├── control.py      # Role/handoff state tracking
│   │   │   ├── middleware.py   # LangGraph thinking middleware
│   │   │   └── context.py      # Context vars (assessment_id, run_id, role)
│   │   ├── core/
│   │   │   ├── config.py       # Settings (env vars)
│   │   │   ├── db.py           # Async engine, session factory, schema creation
│   │   │   ├── events.py       # SSE event replay/streaming
│   │   │   ├── log.py          # Logging
│   │   │   └── policy.py       # Per-action gate policy engine
│   │   ├── domain/
│   │   │   ├── models.py       # SQLModel tables (Assessment, Step, Finding, Approval, Audit, Message)
│   │   │   ├── correlate.py    # Canonical key deduplication
│   │   │   └── risk.py         # Risk scoring
│   │   ├── integrations/       # Juice Shop ground truth, MCP client, ZAP guided
│   │   ├── reporting/          # PDF report generation
│   │   ├── runtime/            # Background task runner
│   │   │   └── runner.py       # Per-assessment task management
│   │   └── skills/             # Verification playbooks
│   └── tests/
│       ├── test_agent_graph.py
│       ├── test_api.py
│       └── ...
├── frontend/
│   ├── src/
│   │   ├── App.tsx             # Conversation desk shell
│   │   ├── components/         # Mission conversation, side record, rail, etc.
│   │   ├── lib/                # API client, chat logic, schemas, event folding
│   │   ├── hooks/              # useAssessmentStream (SSE)
│   │   └── store.ts            # Zustand selected assessment state
│   ├── vite.config.ts
│   └── index.html
├── deploy/
│   ├── mcp-gateway/            # Docker MCP gateway (Kali + ZAP)
│   └── mcp-zap/                # ZAP + MCP server compose
├── lab.lvl1.yml                # Juice Shop lab compose
├── lab.lvl2.yml                # DVWA lab compose
└── README.md
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AIPENT_LLM_PROVIDER` | `groq` | `groq`, `mistral`, `ollama`, `gemini`, `openrouter`, `huggingface` |
| `AIPENT_LLM_MODEL` | `openai/gpt-oss-120b` | Model name |
| `AIPENT_LLM_BASE_URL` | — | Custom endpoint, e.g. `https://ollama.com` for Ollama Cloud |
| `AIPENT_OLLAMA_MODEL` | — | Ollama model id used as the provider fallback, e.g. `beam:cloud` |
| `OLLAMA_API_KEY` | — | Ollama Cloud bearer token (read unprefixed) |
| `AIPENT_GROQ_API_KEY` | — | Groq API key |
| `AIPENT_MISTRAL_API_KEY` | — | Mistral API key |
| `AIPENT_MCP_ENABLED` | `false` | Use MCP gateway instead of local tools |
| `AIPENT_MCP_TRANSPORT` | `local` | `local` or `gateway` |
| `AIPENT_MCP_GATEWAY_URL` | `http://127.0.0.1:8812/sse` | MCP gateway SSE endpoint |
| `AIPENT_LAB_TARGET_ALIAS` | `host.docker.internal` | Container-visible target alias |
| `AIPENT_JUICESHOP_URL` | `http://127.0.0.1:3000` | Juice Shop base URL for challenge tracking |
| `AIPENT_ACTION_POLICIES` | — | JSON override for gate approval policy |
| `AIPENT_DATA_DIR` | `backend/data` | Database, graph checkpoint and artifact root |
| `AIPENT_DB` | `sqlite:///…/aipent.db` | SQLAlchemy database URL (SQLite in this build) |
| `AIPENT_GRAPH_DB` | `backend/data/graph.sqlite` | LangGraph checkpoint database |
| `AIPENT_MAX_STEPS` | `12` | Max queued actions per run |
| `AIPENT_MAX_VALIDATION_PROBES` | `10` | Max HTTP probes per assessment |

## Design Principles

1. **Operator first**: Gate policy decides which actions pause. When an action is gated, the card shows the exact command and the human approves or rejects it.
2. **Evidence first**: No claim is recorded unless backed by tool output. Findings are deduplicated by canonical key; confidence is tool-reported.
3. **Scope is checked at the boundary**: Targets, ports, and exclusions are validated before an action is queued, and HTTP probes re-validate the full URL. Actions with agent-authored flags should remain human-gated.
4. **Budgets are hard**: Turn caps and action caps prevent runaway loops.
5. **Failures are recorded, not raised**: Tool failures are written to the Step record with error text, never propagated as exceptions.
6. **No invented findings**: CVEs, CVSS scores, and CWEs come only from tool output parsers.

## Safety Warnings

- This tool is for **authorized lab targets only**. Do not point it at systems you do not own or have written permission to test.
- **Auto-approval is real.** The default policy lets `recon_services`, `nmap_scan`, `nikto_scan`, and `dirb_scan` execute without a human interrupt. If an engagement requires a human to inspect every command line, set `{"approve": true}` for every action in `AIPENT_ACTION_POLICIES`.
- **Agent-authored flags need the gate.** `nmap_scan`, `nikto_scan`, `sqlmap_scan`, and `dirb_scan` accept flags from the model. Python validates the declared target, but free-form flags can add targets or override destinations (for example nmap `-iL` or sqlmap `--url`). Keep these actions human-gated, or add a per-tool flag allowlist before relying on scope enforcement.
- sqlmap can be destructive. It is policy-gated by default (requires human approval).
- Stopping a run prevents further actions, but a scanner subprocess already in flight may run to completion.
- There is **no authentication** on the API. Bind the backend to `127.0.0.1` and do not expose it to a network.
- The MCP gateway runs containerized scanners. Ensure Docker is configured securely for your environment.
- SQLite is used for simplicity; it is not suitable for multi-user or multi-worker production deployments.

## Verification

```bash
cd backend && .venv/bin/pytest -q          # 42 tests
cd frontend && npm run build               # type-check + production bundle
```