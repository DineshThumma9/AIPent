# AIPENT Code Review Evaluation

**Reviewed:** working tree after the full async migration
**Scope:** separation of concerns, code quality, best practices, logic/integration bugs
**Excluded:** tests (used only to verify behavior)
**Verification:** `backend/.venv/bin/pytest -q` → 42 passed; `frontend/npm run build` → passed

---

## Executive Summary

AIPENT is a three-role VAPT agent (Recon → Discovery → Validation) built on FastAPI, LangGraph, SQLModel, React and Typst. The architecture is genuinely safety-first: the agent never executes a tool directly, every action is queued as a `Step`, a single gate binds an `Approval` to the exact `argv`, and findings are persisted with locator-level evidence.

The async migration is complete and coherent. There is no synchronous database path left: endpoints use `AsyncSession`, the graph uses `AsyncSqliteSaver`, and blocking work is pushed to threads. The previous review's async/sync findings no longer apply.

The remaining risk is concentrated at the **trust boundary**:

1. Scope is validated on the declared target, but not on the agent-authored command line.
2. Probe evidence can unlock a verdict even when the probe failed or returned an unexpected status.
3. Stopping a run does not terminate a scanner already in flight.
4. A resume decision is not cryptographically or structurally bound to the approval the human saw.
5. The default policy auto-approves actions whose flags the model controls.

**Overall grade: B** — a well-structured, unusually disciplined prototype with real evidence handling, but not yet safe to run unattended against a shared lab.

| Area | Grade | Notes |
|------|-------|-------|
| Separation of concerns | B | Clear layers; gate and routes are doing extra work |
| Code quality | B | Typed, documented, consistent; some dead code and duplicated policy |
| Best practices | B- | Strong async/DB/validation; no auth, single-worker design, no migrations |
| Logic/integration | C+ | Core loop works; several boundary and lifecycle bugs remain |

### Changes made during this review

- Restored the policy branch in `agents/gate.py` that the async rewrite had dropped. Without it, `AIPENT_ACTION_POLICIES` was inert and every action always interrupted.
- Fixed the frontend pending-approval selection so the displayed card describes the oldest planned step — the one the gate actually executes.

---

## 1. Separation of Concerns

### What is well separated

| Concern | Location | Assessment |
|---------|----------|------------|
| HTTP routing | `api/routes.py` | Thin async routes, clear REST surface |
| Read models | `api/queries.py` | One detail loader shared by REST and SSE |
| Orchestration | `agents/graph.py` | LangGraph nodes and typed routing are isolated from transport |
| Role isolation | `agents/tools.py` | `ROLE_TOOLS` gives each role its own toolset; role refusal is enforced twice |
| Gate | `agents/gate.py` | One queue/approval/execute primitive shared by every action |
| Action catalogue | `actions/catalogue.py` | Closed set of actions and transports |
| Execution | `actions/executor.py` | One path for subprocess, MCP and HTTP probe |
| Adapters | `adapters/` | Parser per tool; no scanner logic in the graph |
| Evidence/risk | `domain/` | Deterministic canonical keys and scoring |
| Reporting | `reporting/report.py` | Database → JSON → Typst; no hand-escaped markup |
| Frontend state | `frontend/src/lib/` | API, schemas, mission derivation and event folding are separate modules |

### Concerns that need attention

| Issue | Location | Severity |
|-------|----------|----------|
| **Conversation is disconnected from orchestration** | `frontend/src/lib/chat.ts`, `agents/graph.py` | High (product) — chat intents are regex rules with canned replies. Messages are persisted, but the graph never reads them, so an operator cannot steer a live run, answer a `needs_input` handoff, or inject new evidence mid-run. Only the initial "start" message updates `assessment.request`. |
| **Gate mixes four concerns** | `agents/gate.py` | Medium — policy decision, approval persistence, interrupt orchestration and evidence recording live in one ~570-line module. Cohesive, but hard to test or replace independently. |
| **Business rules in routes** | `api/routes.py` | Medium — active-status sets, scan status transitions and audit writes live in HTTP handlers; a service layer would make them reusable and testable. |
| **API schema duplication** | `frontend/src/lib/schemas.ts` vs `backend/src/app/api/schema.py` | Medium — Zod models are hand-maintained copies of Pydantic models. Drift is caught only at runtime by `req()`. |
| **Role budgets are policy, but hardcoded** | `agents/control.py:34` | Medium — `ROLE_TURN_CAPS` cannot be configured, while `settings.max_agent_turns` exists and is unused. |
| **All tools in one module** | `agents/tools.py` | Low — ~1,000 lines for three roles; splitting per role would make the allowlists harder to drift. |

---

## 2. Code Quality

### Strengths

- **Types throughout**: `TypedDict` for graph state, `StrEnum` for statuses, frozen dataclasses for policy/config, Pydantic at API boundaries, Zod at the frontend boundary.
- **Consistent async discipline**: every read uses `await session.execute(...)`; write helpers that only call `session.add()` are deliberately synchronous and documented as such.
- **Defensive tools**: action tools return `{"error": ...}` so the model can adapt in the same turn instead of aborting the graph.
- **Single execution path**: subprocess, MCP and HTTP probe all converge on `execute_action()`; there is no second way to touch a target.
- **Evidence model**: `Evidence` points at a locator (XPath, plugin id, URL, step id) and an excerpt. This is the strongest part of the codebase.
- **Auditability**: queued actions, approvals, role turns, handoffs, step outcomes and report hashes are all persisted.
- **Frontend craft**: paper/ink/oxide CSS variables, IBM Plex, restrained motion, accessible labeling, Zod-validated API responses.

### Weaknesses

| Issue | Location | Notes |
|-------|----------|-------|
| **Dead configuration** | `core/config.py:33,36,44` | `max_agent_turns`, `run_timeout` and `llm_base_url` are never read. `zap_image` also appears unused. |
| **Dead helpers** | `actions/executor.py:357`, `agents/control.py:167`, `runtime/runner.py:75` | `completed_actions`, `run_event_count` and `reset_runner` have no callers (the first two are exported). |
| **Duplicated policy loading** | `core/config.py:109`, `agents/gate.py:59` | `Settings.action_policies()` is unused; the gate loads the JSON itself and caches it in a module global. |
| **Redundant audit events** | `agents/tools.py:931`, `agents/control.py:139` | Every handoff writes both `handoff.created` and `role.handoff`. |
| **Magic event strings** | Multiple modules | `"action.queued"`, `"action.approved"`, `"step.succeeded"` etc. are string literals; a typo is a silent observability bug. |
| **Probe budget display is wrong** | `agents/graph.py:231` | `probes_used` is counted over the latest 8 steps only, not all probe steps. Enforcement is correct in `tools.http_probe`, but the prompt under-reports usage. |
| **Non-atomic assessment creation** | `api/routes.py:45-60` | Assessment and its audit row are committed in two transactions. A crash between them leaves an untraceable row. |
| **Fragile argv fallback** | `actions/executor.py:357` | `completed_actions` uses `row.argv[-1]` without checking that `argv` is non-empty. |
| **Report MCP detection is wrong** | `reporting/report.py:97` | It tests `step.argv[0] == "mcp"`, but the executor stores the real tool argv. Gateway runs are usually reported as non-MCP. |
| **Checkpoint cleanup is incomplete** | `runtime/runner.py:82-102` | Deletes `checkpoints` and `checkpoint_blobs`, but not `checkpoint_writes`. Orphaned write rows accumulate. |

---

## 3. Best Practices

### Followed

- ✅ FastAPI dependency injection with `AsyncSession`
- ✅ Async context managers for every session; no leaked connections
- ✅ SQLite configured per connection: WAL, `foreign_keys=ON`, `busy_timeout=5000`
- ✅ `NullPool` on aiosqlite avoids cross-event-loop connection reuse
- ✅ `AsyncSqliteSaver` for the graph; no blocking checkpoint I/O
- ✅ Blocking work (`subprocess.run`, Typst, artifact reads) behind `asyncio.to_thread`
- ✅ `interrupt()` called synchronously inside async nodes — correct for LangGraph's async interrupt API
- ✅ Schema validation at both boundaries (Pydantic / Zod)
- ✅ Secrets via environment; `.env` loaded without hardcoding keys
- ✅ Graceful degradation for the Juice Shop bonus (baseline/delta failures never fail a run)
- ✅ Deterministic risk scoring with an auditable formula
- ✅ Per-assessment `asyncio.Lock` serializes start/resume/stop

### Gaps

| Practice | Status | Detail |
|----------|--------|--------|
| Authentication / authorization | ❌ | The API has no auth. Bind to `127.0.0.1`; anyone who can reach the port can run scans and approve gates. |
| Multi-worker safety | ❌ | `_tasks`, `_locks` and `_policy_cache` are process-local. Two uvicorn workers can start the same assessment twice. This is a single-worker design. |
| Graceful shutdown | ⚠️ | `lifespan` only initializes the DB. It does not cancel running tasks, dispose the engine, or close the graph saver. |
| Database migrations | ⚠️ | `_add_missing_columns` is a hand-written demo migration. A real deployment needs Alembic. |
| Rate limiting | ❌ | No limit on `/run`, `/resume`, `/messages` beyond the per-assessment lock. |
| Configuration reload | ⚠️ | `_policy_cache` never refreshes; policy changes require a restart. |
| Structured observability | ⚠️ | Logging is clean, but there are no request IDs, metrics, or trace correlation between API, graph and gate. |
| Approval concurrency | ❌ | No optimistic concurrency token; a stale client can resume a gate it no longer sees. |

---

## 4. Logic and Integration Bugs

### Critical / High

| # | Bug | Location | Impact |
|---|-----|----------|--------|
| 1 | **Scope is enforced on the declared target, not on agent-authored argv** | `agents/gate.py:114`, `agents/tools.py:176` | `check_scope()` validates only the `target` argument. `nmap_scan` appends arbitrary flags, so `-iL`, `-iR`, a second host, or an NSE script can reach out-of-scope systems. `nikto_scan` can add `-h`, and `sqlmap_scan` can add `--url`/`-r`. Because the default policy auto-approves these actions (`core/policy.py:38-46`), no human reviews the command. This breaks the stated invariant that Python enforces scope. |
| 2 | **Failed probes can confirm findings** | `agents/gate.py:357`, `actions/executor.py:174`, `agents/tools.py:798` | `run_probe()` converts connection errors into a `ProbeResult(error=...)`; the executor still marks the step `succeeded`; `_record_probe_evidence()` records evidence for any succeeded probe. `update_finding_status()` only checks `locator["tool"] == "http_probe"`, not the HTTP status or expected status. A 404, 500, or unreachable target can therefore unlock `confirmed`. Record `http_status` + `expected_status` + `matched` and require a matched probe. |
| 3 | **Stopping a run does not stop a running scanner** | `runtime/runner.py:246-254`, `actions/executor.py:174-176` | `task.cancel()` cancels the await, but the `subprocess.run` inside `asyncio.to_thread` keeps running. A stopped nmap/nikto can continue scanning after the UI says the run is stopped. Use `asyncio.create_subprocess_exec`, keep a process registry, and terminate the process group on stop. |
| 4 | **Resume decisions are not bound to an approval** | `api/schema.py:23`, `runtime/runner.py:226-242`, `agents/gate.py:242` | `DecisionIn` carries only `approved/rejected`. The gate applies the decision to whichever planned step it selects. A stale or scripted client can approve a different command than the card it saw. Add `approval_id` and `step_id` to the resume contract and verify them under the lock; return 409 on mismatch. |
| 5 | **Default policy auto-approves agent-argv scans** | `core/policy.py:38-46` | `nmap_scan`, `nikto_scan` and `dirb_scan` auto-approve while accepting model-authored flags. Even with the scope bug fixed, this contradicts the "human approves the exact command" safety story. Gate free-form-argv actions by default, or add a per-tool flag allowlist. |

### Medium

| # | Bug | Location | Impact |
|---|-----|----------|--------|
| 6 | **Step sequence race** | `agents/gate.py:85-90, 155-163` | `_next_seq()` reads `MAX(seq)` then inserts. LangChain can execute multiple tool calls concurrently, so two queued steps can receive the same `seq`. Add `UniqueConstraint(assessment_id, seq)` and retry/serialize. |
| 7 | **Probe budget is under-reported to the model** | `agents/graph.py:231` | Only the newest 8 steps are scanned for `http_probe`, so `probes_left` can look larger than it is. |
| 8 | **Audit truncation breaks the run thread** | `api/queries.py:48`, `frontend/src/lib/mission.ts:202` | Detail returns only the newest 100 audit rows. The frontend reconstructs the run by finding `agent.started`; long runs lose that marker and early thread entries. Paginate audit or return a run summary. |
| 9 | **SSE cost and dead message channel** | `core/events.py:26, 226-236` | Every client re-reads the full detail (steps, findings, evidence, approvals, 100 audit rows) every second. `EventType.MESSAGE` is declared but never emitted; messages are not streamed at all, so chat is not live across clients. |
| 10 | **Scan route can leave status `running`** | `api/routes.py:174-190` | Only `ScopeError` restores the previous status. An unexpected DB/executor error leaves the assessment stuck in `running`. Use `try/except/finally`. |
| 11 | **Per-process run registry** | `runtime/runner.py:32-33` | The per-assessment lock and task map do not cross workers. Document/force a single worker, or move coordination to the database/Redis. |
| 12 | **Incomplete checkpoint reset** | `runtime/runner.py:82-102` | `checkpoint_writes` is not deleted. Harmless functionally, but rows grow without bound across stopped runs. |
| 13 | **Frontend chat-load race** | `frontend/src/App.tsx:152-157` | A pending `loadChatMessages()` can resolve after the operator sends a message and replaces the local array, hiding the just-sent message until reload. Guard with a request token or merge by id. |
| 14 | **Unhandled create failure** | `frontend/src/App.tsx:170-175` | `handleCreate` has no `try/catch`; a failed POST produces an unhandled rejection and no visible error. |
| 15 | **Chat "stop" does not stop** | `frontend/src/lib/chat.ts:20`, `App.tsx:287-292` | The intent classifier answers with advice ("reject the gate") instead of calling `POST /stop`, while the UI has a working Stop button. The control surfaces disagree. |
| 16 | **MCP reporting is wrong** | `reporting/report.py:97` | Gateway runs are not detected because the executor stores tool argv, not `"mcp"`. The report's MCP card can be absent or misleading. |

### Low

- `loadChatMessages()` swallows failures and returns `[]`, so a broken message API looks like an empty conversation (`App.tsx:107-114`).
- No React error boundary; one render error blanks the desk.
- `handleDecision()` posts a synthetic assistant message immediately after the 202, before the graph has actually resumed; it can describe an outcome that has not happened yet.
- Final-review approvals get `roleLabel(null)` fallbacks in some chat paths; the dedicated final-review branch handles the main case.
- The report writes JSON and copies the Typst template synchronously inside an async function; files are small, so this is tolerable.
- `_clean_text()` only strips a leading `[id]`; bracketed ids in the middle of a title remain.

---

## 5. Live-Run Confirmations

An end-to-end run against Juice Shop with Ollama Cloud (`beam:cloud`) exercised the full three-role loop and confirmed several findings above:

| Observation | Confirms |
|-------------|----------|
| All three queued `http_probe` steps received `seq = 3` | #6 — `_next_seq()` race under concurrent tool calls |
| A `HEAD` probe expecting `404` returned `200` but was still marked `succeeded` | #2 — expected status is not evaluated before the step succeeds |
| Validation queued probes, handed off with `next_recommendation="review"`, and never received a post-gate turn | New: the role that requests verification never reads its own results; the graph routes directly to review |
| `http_probe` evidence was written to an artifact but not to the `Evidence` table because `finding_id` was null | New: probes that discover something outside an existing candidate finding are not represented in the report |
| `challenge_delta` was `null` even though Juice Shop solved the target challenge | New: `integrations/juiceshop._base_url()` used `host.docker.internal` whenever MCP was enabled, which does not resolve from the host backend. Fixed by adding `AIPENT_JUICESHOP_URL` (default `http://127.0.0.1:3000`) and using it directly |
| nmap reported port 3000 as `ppp` despite an HTTP fingerprint | Adapter faithfully reports nmap's service name; cosmetic accuracy issue, not a crash |

The run also exposed a model-behaviour failure that the queue contract now addresses: `gemma4:31b` queued a scan and then polled `query_steps`/`query_findings` until the inner recursion limit (40) fired. The tool result and prompts now state explicitly that a queued action is not executed in the current turn, that polling is futile, and that the model must hand off immediately.

---

## 6. File-by-File Notes

### `agents/gate.py`
Strong single-gate design and excellent comment explaining why one interrupt per node prevents approval leakage. Policy is now actually consulted. The remaining boundary problems are scope-vs-argv and the missing approval id in the resume contract.

### `agents/graph.py`
Clear three-role routing, typed handoffs and per-role transcripts. `interrupt()` inside async nodes is correct. The probe budget in `_role_digest` is derived from a truncated step list; role caps are hardcoded; `run_timeout` is not enforced.

### `agents/tools.py`
Good role split and defensive returns. Agent-owned argv is the main risk surface. `update_finding_status` needs a stronger evidence predicate. Tool docstrings are strong and should be kept.

### `actions/executor.py`
The single execution path is the right design. Two lifecycle issues: probe errors are recorded as successful steps, and subprocess cancellation cannot reach the child process.

### `runtime/runner.py`
Per-assessment locking and stale-task cleanup are solid. Process-local state limits deployment to one worker; checkpoint cleanup misses one table; stop semantics are weaker than the UI copy suggests.

### `api/routes.py`
Clean async CRUD and a consistent error shape. Move status transitions and audit writes into a service layer, make creation atomic, and make the manual scan path exception-safe.

### `core/events.py`
The snapshot-then-diff design is robust: the database is the source of truth and reconnects cannot leave a partial view. The cost is one full read per client per second. `MESSAGE` is dead.

### `core/db.py`
The async engine, `set_engine()`, `NullPool` and per-connection PRAGMAs are well judged. `make_engine()` accepts a sync SQLite URL and translates it, which is convenient for tests. Consider disposing the previous engine in `set_engine()`.

### `reporting/report.py`
Good separation of data and Typst. Fix MCP detection and consider `asyncio.to_thread` for file writes if reports grow.

### `frontend/src/lib/mission.ts`
Mission derivation is readable and defensive. The pending-approval ordering fix matters: the gate executes the oldest planned step, so the UI must show that one. `runAudit` is fragile against the backend's 100-row audit cap.

### `frontend/src/App.tsx`
Good separation of stream state, mission state and chat state. Missing error handling on create, a chat-load race, and a "stop" intent that does not call the stop endpoint.

### `frontend/src/lib/chat.ts`
Canned intent responses are useful for a demo but are not the conversational agent the product claims to be. Either wire operator messages into the graph or label this as a command palette, not a conversation.

---

## 6. Recommendations (Priority Order)

### P0 — Safety and correctness

1. **Enforce scope at the argv/process boundary.** For each tool, parse the final argv and reject extra targets and target-list flags (`nmap -iL`, `-iR`; `nikto -h`; `sqlmap --url/-r`; extra `dirb` URLs). Better: run scanners in a network namespace/firewall restricted to the approved targets. Keep free-form-argv actions human-gated by default.
2. **Require matched probe evidence for verdicts.** Persist `http_status`, `expected_status` and `matched` on probe evidence; refuse `confirmed`/`false_positive` unless at least one matched probe is linked.
3. **Make stop terminate the child process.** Replace `to_thread(subprocess.run)` with `asyncio.create_subprocess_exec` and a per-assessment process registry; terminate the process group on stop.
4. **Bind resume to `approval_id` + `step_id`.** Reject stale decisions with 409 and re-render the current gate.

### P1 — Reliability

5. Add `UniqueConstraint(assessment_id, seq)` and serialize/retry `queue_step`.
6. Fix `_role_digest` to count all probe steps; enforce `run_timeout`.
7. Paginate or summarize audit instead of hard-limiting the detail to 100 rows.
8. Emit/handle `message` events or remove the dead type; reduce SSE polling cost.
9. Make `create_assessment` atomic; make the scan route exception-safe.
10. Delete `checkpoint_writes` on reset; dispose the old engine in `set_engine()`.
11. Add graceful shutdown for tasks, the graph saver and the engine.

### P2 — Quality and product

12. Wire operator messages into the graph (steering, handoff answers, new evidence) or rename the chat surface.
13. Share API types (OpenAPI codegen or a generated TypeScript client) instead of hand-written Zod copies.
14. Extract event-type constants; remove dead helpers and unused settings; make role caps configurable.
15. Add auth/rate limiting if the API is ever exposed beyond localhost.
16. Add a React error boundary and surface message-load failures.

---

## 7. Bottom Line

The core design is sound and, in places, better than typical hackathon code: a closed action catalogue, one execution path, a real evidence graph, deterministic scoring, run-scoped handoffs and an audit trail that a reviewer can follow. The async migration is now complete and internally consistent.

The next pass should not add features. It should harden the boundary between an LLM-authored command and the target: validate argv against scope, refuse verdicts without matched probe evidence, make stop actually stop, and bind approvals to decisions. Until then, keep every agent-argv action human-gated.
