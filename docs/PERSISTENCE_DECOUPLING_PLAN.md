# Persistence Decoupling & Agent Modularity Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decouple database sessions, ORM models, and SQL queries from the LangGraph agent logic in `backend/src/app/agents/`, encapsulating all persistence into the repository layer (`backend/src/app/persistence/`).

**Architecture:** Agent nodes in `backend/src/app/agents/loop/nodes.py` become pure orchestration functions that receive `AssessmentState` and typed Pydantic payloads and return `Command(update=..., goto=...)`. All raw database operations (`get_async_session_ctx`, `session.commit()`, `select()`, and direct ORM model mutations) are moved into typed repository methods (`StepRepo`, `AuditRepo`, `FindingRepo`, `AssessmentRepo`).

**Tech Stack:** Python 3.12, SQLModel / SQLAlchemy AsyncSession, LangGraph, Pydantic v2, Pytest (`uv run pytest`).

---

## Global Constraints

- **No DB sessions in agent nodes:** `async with get_async_session_ctx()` must not appear inside `backend/src/app/agents/loop/nodes.py` or `backend/src/app/agents/loop/mission_brain.py`.
- **Pure state transitions:** Every node takes `state: AssessmentState` and returns `Command(update=..., goto=...)`.
- **Repository abstraction:** All SQL queries and table commits belong strictly under `backend/src/app/persistence/`.
- **Preserve event contracts:** Audit events (e.g. `decision.recorded`, `step.planned`, `step.succeeded`, `step.failed`) must maintain their exact payload structure for the SSE stream and frontend dashboard.
- **Zero test regressions:** All 175 existing backend unit and integration tests must pass continuously throughout each task.

## Review Focus

1. **Transaction rollbacks on failure:** If an action fails or times out, the step status must update cleanly via `StepRepo` without leaving dangling uncommitted transactions.
2. **Decision record deduplication:** `decision.recorded` must preserve the same `D-{step_id}` identifier across planning, rejection, and execution phases.
3. **Evidence board integrity:** Preloading context must not truncate or alter how `build_evidence_board` aggregates hypotheses and decisions.
4. **Context preservation across turns:** The model turn and brief rendering must receive identical data structures (`HumanMessage(content=digest)`) as prior runs.
5. **No ContextVar leaks:** Remove all legacy global ContextVars (`_current_assessment_id`) in favor of explicit method parameters.

---

## File Structure & Responsibilities

```
backend/src/app/
├── persistence/
│   ├── audit_repo.py       # Manages Audit event creation and typed decision recording
│   ├── step_repo.py        # Manages Step creation, status transitions, and Approval linking
│   ├── finding_repo.py     # Manages Finding creation, status updates, and candidate queries
│   ├── assessment_repo.py  # Manages Assessment state, targets, ports, and scope
│   └── context_loader.py   # NEW: Preloads complete assessment snapshot for agent nodes
├── agents/
│   ├── loop/
│   │   ├── nodes.py        # Pure orchestration: LangGraph nodes with zero raw SQL queries
│   │   ├── mission_brain.py# Supervisor routing & prompt construction (pure logic)
│   │   ├── direct_tools.py # Direct in-process tool handlers using repo methods
│   │   └── contracts.py    # Pydantic data schemas for node inputs/outputs
│   └── prompts.py          # Fixed system and role prompts (no DB dependencies)
```

---

## Tasks

### Task 1: Encapsulate Audit and Decision Persistence in `AuditRepo`

**Files:**
- Modify: `backend/src/app/persistence/audit_repo.py`
- Test: `backend/tests/test_persistence_audit.py`

**Interfaces:**
- Consumes: `session: AsyncSession`, assessment IDs, typed decision dictionaries
- Produces: `audit_repo.record_decision(...)`, `audit_repo.record_event(...)`

- [x] **Step 1: Write the failing test for `record_decision` on `AuditRepo`**
- [x] **Step 2: Run test to verify it fails**
- [x] **Step 3: Implement `record_decision` and `record_event` in `AuditRepo`**
- [x] **Step 4: Run test to verify it passes**
- [x] **Step 5: Commit**

```bash
git add backend/src/app/persistence/audit_repo.py backend/tests/test_persistence_audit.py
git commit -m "refactor(persistence): add typed decision and event recording to AuditRepo"
```

---

### Task 2: Encapsulate Step and Approval Lifecycle in `StepRepo`

**Files:**
- Modify: `backend/src/app/persistence/step_repo.py`
- Test: `backend/tests/test_persistence_step.py`

**Interfaces:**
- Consumes: ActionRequest, step status strings, approval reasons
- Produces: `step_repo.create_planned_step(...)`, `step_repo.record_approval(...)`, `step_repo.complete_step(...)`

- [x] **Step 1: Write the failing test for Step lifecycle methods**
- [x] **Step 2: Run test to verify it fails**
- [x] **Step 3: Implement step lifecycle methods in `StepRepo`**
- [x] **Step 4: Run test to verify it passes**
- [x] **Step 5: Commit**

```bash
git add backend/src/app/persistence/step_repo.py backend/tests/test_persistence_step.py
git commit -m "refactor(persistence): encapsulate Step and Approval lifecycle into StepRepo"
```

---

### Task 3: Create Context Preloader for Agent Briefs

**Files:**
- Create: `backend/src/app/persistence/context_loader.py`
- Test: `backend/tests/test_context_loader.py`

**Interfaces:**
- Consumes: `assessment_id: int`, `run_id: str | None`
- Produces: `load_mission_context(session, assessment_id, run_id) -> MissionContext`

- [x] **Step 1: Write the failing test for `load_mission_context`**
- [x] **Step 2: Run test to verify it fails**
- [x] **Step 3: Implement `load_mission_context`**
- [x] **Step 4: Run test to verify it passes**
- [x] **Step 5: Commit**

```bash
git add backend/src/app/persistence/context_loader.py backend/tests/test_context_loader.py
git commit -m "feat(persistence): add load_mission_context preloader"
```

---

### Task 4: Decouple Gate and Execution Nodes (`prepare`, `approve`, `execute`)

**Files:**
- Modify: `backend/src/app/agents/loop/nodes.py:L540-L1150`
- Test: `backend/tests/test_loop_nodes.py`

**Interfaces:**
- Consumes: `StepRepo`, `AuditRepo` methods from Tasks 1 & 2
- Eliminates: Direct `session.execute(select(...))`, `session.add(...)`, `session.commit()` inside `prepare_node`, `approve_node`, and `make_execute_node`.

- [ ] **Step 1: Verify baseline tests pass before editing `nodes.py`**

Run: `cd backend && uv run pytest tests/test_loop_nodes.py -v`  
Expected: PASS (13 passed)

- [ ] **Step 2: Refactor `prepare_node` to use `step_repo.create_planned_step` and `audit_repo.record_event`**

Replace manual step and approval creation with single repository call. Remove raw SQLModel queries.

- [ ] **Step 3: Refactor `approve_node` to use `step_repo.reject_step` and `audit_repo.record_decision`**

Eliminate the raw SQL update block and use `step_repo.reject_step`.

- [ ] **Step 4: Refactor `make_execute_node` to use `step_repo.complete_step` and `audit_repo.record_decision`**

Eliminate the manual status assignments and commits.

- [ ] **Step 5: Run tests and verify zero regressions**

Run: `cd backend && uv run pytest tests/test_loop_nodes.py -v`  
Expected: PASS (all 13 tests pass)

- [ ] **Step 6: Commit**

```bash
git add backend/src/app/agents/loop/nodes.py
git commit -m "refactor(agents): decouple prepare, approve, and execute nodes from direct SQL"
```

---

### Task 5: Decouple Reasoning & Routing Nodes (`intake`, `supervisor`, `brief`, `review`)

**Files:**
- Modify: `backend/src/app/agents/loop/nodes.py:L115-L390`
- Modify: `backend/src/app/agents/loop/mission_brain.py`
- Test: `backend/tests/test_supervisor_reasoning.py`

**Interfaces:**
- Consumes: `load_mission_context` from Task 3
- Eliminates: Ad-hoc `session.get(Assessment)` and inline queries in `intake_node`, `supervisor_node`, `brief_node`, and `review_node`.

- [ ] **Step 1: Run baseline tests**

Run: `cd backend && uv run pytest tests/test_supervisor_reasoning.py -v`  
Expected: PASS (12 passed)

- [ ] **Step 2: Refactor `brief_node` to consume preloaded `MissionContext`**

Replace the 15 lines of repository queries in `brief_node` with a single call to `load_mission_context(session, assessment_id, state.get("run_id"))`.

- [ ] **Step 3: Refactor `build_mission_digest` in `mission_brain.py`**

Pass `MissionContext` directly into `build_mission_digest` so `mission_brain.py` performs zero database queries.

- [ ] **Step 4: Run tests to verify routing behavior**

Run: `cd backend && uv run pytest tests/test_supervisor_reasoning.py tests/test_loop_graph.py -v`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/src/app/agents/loop/nodes.py backend/src/app/agents/loop/mission_brain.py
git commit -m "refactor(agents): decouple supervisor and brief nodes using preloaded MissionContext"
```

---

### Task 6: Purge Dead Code, Unused Shims, and Redundant Actions

**Files:**
- Delete: `backend/src/app/agents/tools.py`
- Delete: `backend/src/app/persistence/role_repo.py`
- Modify: `backend/src/app/agents/loop/nodes.py` (remove dead `nudge_node`)
- Modify: `backend/src/app/actions/catalogue.py` (remove duplicate `nmap_scan` and `nmap_nse`)
- Modify: `backend/src/app/core/policy.py` (remove duplicate policies and direct tool `hash_identify`)
- Test: `backend/tests/test_agent_wiring.py`

- [ ] **Step 1: Update imports pointing to `app.agents.tools.ROLE_TOOLS`**

Change imports in `backend/src/app/agents/loop/nodes.py` and `backend/tests/test_agent_wiring.py` to import `ROLE_TOOLS` from `app.agents.loop.tool_specs`.

- [ ] **Step 2: Delete `backend/src/app/agents/tools.py` and `backend/src/app/persistence/role_repo.py`**

```bash
git rm backend/src/app/agents/tools.py backend/src/app/persistence/role_repo.py
```

- [ ] **Step 3: Delete `nudge_node` from `backend/src/app/agents/loop/nodes.py`**

Remove the 20 lines of dead `async def nudge_node`.

- [ ] **Step 4: Clean duplicate Nmap actions in `catalogue.py` and `policy.py`**

Remove `nmap_scan` and `nmap_nse` definitions. Keep only `recon_services`.

- [ ] **Step 5: Run tests and verify clean pass**

Run: `cd backend && uv run pytest tests/test_agent_wiring.py tests/test_loop_contracts.py -v`  
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add -u backend/
git commit -m "chore(cleanup): purge legacy tools.py shim, RoleRepo, dead nudge_node, and duplicate nmap actions"
```

---

### Task 7: Full Verification and Architecture Validation

**Files:**
- Test: Entire backend test suite (`tests/`)

- [ ] **Step 1: Run the complete test suite**

Run: `cd backend && uv run pytest -v`  
Expected: 100% tests pass (175+ tests).

- [ ] **Step 2: Verify zero raw SQL queries remain in `backend/src/app/agents/loop/`**

Run:
```bash
grep -rn "select(" backend/src/app/agents/loop/ || echo "CLEAN: No raw select() calls"
grep -rn "session.commit()" backend/src/app/agents/loop/ || echo "CLEAN: No raw commit() calls"
```
Expected: `CLEAN` for both checks.

- [ ] **Step 3: Commit final plan documentation and state**

```bash
git add docs/PERSISTENCE_DECOUPLING_PLAN.md
git commit -m "docs: add persistence decoupling and modularity implementation plan"
```
