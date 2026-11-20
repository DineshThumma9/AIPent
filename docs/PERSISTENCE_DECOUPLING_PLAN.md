# Persistence Decoupling & Agent Modularity Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Completely decouple database sessions, ORM models, and raw SQL queries from the agent execution layer in `backend/src/app/agents/`, encapsulating all persistence, transaction management, and queries into the repository layer (`backend/src/app/persistence/`).

**Architecture:** 
1. **Repository Layer as Single Source of Truth:** `AuditRepo`, `StepRepo`, `FindingRepo`, and `AssessmentRepo` own all table queries (`select()`), session additions, flushes, and commits.
2. **Context Preloader:** `load_mission_context` preloads the entire assessment state (targets, open ports, recent steps, candidate findings, evidence board, steering notes) upfront into a typed `MissionContext` snapshot.
3. **Pure Agent Orchestration:** `nodes.py`, `mission_brain.py`, `reasoning.py`, and `observations.py` become pure functional or in-memory modules that consume immutable state/context snapshots and return typed commands/observations.
4. **No Multi-Session Storm:** Agent loop nodes no longer open ad-hoc `async with get_async_session_ctx()` blocks. A single session (Unit of Work) is managed at the top-level turn runner, avoiding SQLite concurrency locking and ensuring atomic rollbacks.

**Tech Stack:** Python 3.12, SQLModel / SQLAlchemy AsyncSession, LangGraph, Pydantic v2, Pytest (`uv run pytest`).

---

## Global Constraints

- **No DB sessions in agent nodes:** `async with get_async_session_ctx()` must not appear inside `backend/src/app/agents/loop/nodes.py` or `backend/src/app/agents/loop/mission_brain.py`.
- **Pure state transitions:** Every node takes `state: AssessmentState` and returns `Command(update=..., goto=...)`.
- **Zero SQL queries in agent logic:** `select(...)` calls must not exist in `backend/src/app/agents/` (including `direct_tools.py`, `observations.py`, `reasoning.py`, `control.py`).
- **Pure Observations:** `observations.py` must perform 0 database queries.
- **Preserve event contracts:** Audit events (e.g. `decision.recorded`, `step.planned`, `step.succeeded`, `step.failed`, `finding.recorded`) must maintain their exact payload structure for the SSE stream and frontend dashboard.
- **Zero test regressions:** All 177+ existing backend unit and integration tests must pass continuously throughout each task.

---

## File Structure & Responsibilities

```
backend/src/app/
├── persistence/
│   ├── base.py             # Base repository with session management
│   ├── audit_repo.py       # Audit events, typed decisions, and role/hypothesis history
│   ├── step_repo.py        # Step creation, status transitions, and Approval linking
│   ├── finding_repo.py     # Finding creation, status updates, agent finding recording, candidates
│   ├── assessment_repo.py  # Assessment state, targets, ports, scope, and risk score
│   └── context_loader.py   # Preloads complete assessment snapshot for agent nodes
├── agents/
│   ├── control.py          # DEPRECATED / ALIAS: Re-exports methods to AuditRepo for backward compatibility
│   ├── loop/
│   │   ├── nodes.py        # Pure orchestration: LangGraph nodes with zero raw SQL queries
│   │   ├── mission_brain.py# Supervisor routing & prompt construction (pure logic)
│   │   ├── direct_tools.py # Direct in-process tool handlers using typed repo methods
│   │   ├── observations.py # Pure in-memory observation constructors (0 DB calls)
│   │   ├── reasoning.py    # Domain models & pure aggregation functions for EvidenceBoard
│   │   └── contracts.py    # Pydantic data schemas for node inputs/outputs
│   └── prompts.py          # Fixed system and role prompts (no DB dependencies)
├── domain/
│   └── risk.py             # Pure risk calculation (DB mutations moved to FindingRepo/AssessmentRepo)
```

---

## Implementation Tasks

### Task 1: Encapsulate Audit and Decision Persistence in `AuditRepo` (COMPLETED)

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

### Task 2: Encapsulate Step and Approval Lifecycle in `StepRepo` (COMPLETED)

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

### Task 3: Create Context Preloader for Agent Briefs (COMPLETED)

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

### Task 4: Convert `observations.py` into Pure In-Memory Observation Builders (0 DB Calls)

**Files:**
- Modify: `backend/src/app/agents/loop/observations.py`
- Modify: `backend/src/app/agents/loop/nodes.py` (call site at L1131)
- Test: `backend/tests/test_observations.py`

**Interfaces:**
- Consumes: `step: Step`, `finding_ids: list[int] = ()`, `evidence_ids: list[int] = ()`, `target: str = ""`
- Eliminates: All SQL queries (`select(Evidence)`, `select(Finding)`) and `AsyncSession` parameter from `observation_from_step`.

- [ ] **Step 1: Write test in `backend/tests/test_observations.py` verifying pure execution**

```python
def test_observation_from_step_pure():
    step = Step(id=42, assessment_id=1, action="curl_request", status="succeeded", target="http://test")
    obs = observation_from_step(step, finding_ids=[10], evidence_ids=[100])
    assert obs.ok is True
    assert obs.action == "curl_request"
    assert obs.findings_created == [10]
    assert obs.evidence_ids == [100]
```

- [x] **Step 1: Write test for pure in-memory observation construction**
- [x] **Step 2: Refactor `observation_from_step` to be pure in-memory**
- [x] **Step 3: Update `nodes.py:1131` call site**
- [x] **Step 4: Run tests and verify zero regressions**
- [x] **Step 5: Commit**

```bash
git add backend/src/app/agents/loop/observations.py backend/src/app/agents/loop/nodes.py backend/tests/test_observations.py
git commit -m "refactor(agents): make observation_from_step a pure in-memory builder with zero db queries"
```

---

### Task 5: Decouple `direct_tools.py` via `FindingRepo`, `StepRepo`, and `AuditRepo`

**Files:**
- Modify: `backend/src/app/persistence/finding_repo.py`
- Modify: `backend/src/app/agents/loop/direct_tools.py`
- Test: `backend/tests/test_direct_tools.py`

**Interfaces:**
- Implement: `finding_repo.record_agent_finding(...)` which encapsulates the 170-line block in `direct_tools.py` (checking scope, severity ranking, canonical key generation, step evidence linking, and audit logging).
- Implement: `step_repo.get_artifact_path(step_id)` for `read_artifact` and `hash_identify_direct`.
- Eliminates: All direct `session.add(Finding)`, `session.flush()`, `session.execute(select(Finding))`, and `session.commit()` inside `direct_tools.py`. The caller/session owns the commit.

- [x] **Step 1: Write test for `finding_repo.record_agent_finding`**
- [x] **Step 2: Implement `record_agent_finding` on `FindingRepo`**
- [x] **Step 3: Simplify `direct_tools.py:record_finding`**
- [x] **Step 4: Refactor `hash_identify_direct` and `read_artifact`**
- [x] **Step 5: Run tests and verify clean execution**
- [x] **Step 6: Commit**

```bash
git add backend/src/app/persistence/finding_repo.py backend/src/app/agents/loop/direct_tools.py backend/tests/test_direct_tools.py
git commit -m "refactor(agents): move finding and artifact persistence from direct_tools to repositories"
```

---

### Task 6: Consolidate `control.py` & `reasoning.py` into `AuditRepo` and Pure Domain Models

**Files:**
- Modify: `backend/src/app/persistence/audit_repo.py`
- Modify: `backend/src/app/agents/control.py` (redirect functions to `AuditRepo`)
- Modify: `backend/src/app/agents/loop/reasoning.py`
- Test: `backend/tests/test_reasoning.py`
- Test: `backend/tests/test_agent_control.py`

**Interfaces:**
- Add to `AuditRepo`:
  - `current_role(assessment_id: int, run_id: str) -> str`
  - `role_history(assessment_id: int, run_id: str) -> list[dict]`
  - `record_role(assessment_id: int, run_id: str, role: str, ...)`
  - `record_hypothesis(assessment_id: int, run_id: str, hypothesis_id: str, ...)`
  - `update_hypothesis(assessment_id: int, run_id: str, hypothesis_id: str, ...)`
  - `get_evidence_board(assessment_id: int) -> EvidenceBoard`
- Eliminate: Raw `select(Audit)` queries inside `control.py` and `reasoning.py`.
- Keep: `control.py` as a thin compatibility wrapper that calls `AuditRepo` methods so any legacy imports remain functional.

- [x] **Step 1: Write tests for role and hypothesis methods on `AuditRepo`**
- [x] **Step 2: Implement role and hypothesis methods in `AuditRepo`**
- [x] **Step 3: Move `build_evidence_board` query logic to `AuditRepo.get_evidence_board`**
- [x] **Step 4: Update `control.py` to delegate to `AuditRepo`**
- [x] **Step 5: Run tests and verify zero regressions**
- [x] **Step 6: Commit**

```bash
git add backend/src/app/persistence/audit_repo.py backend/src/app/agents/control.py backend/src/app/agents/loop/reasoning.py
git commit -m "refactor(agents): consolidate role, hypothesis, and evidence board persistence into AuditRepo"
```

---

### Task 7: Decouple `mission_brain.py` and `domain/risk.py` from Direct Database Sessions

**Files:**
- Modify: `backend/src/app/agents/loop/mission_brain.py`
- Modify: `backend/src/app/domain/risk.py`
- Modify: `backend/src/app/persistence/assessment_repo.py`
- Test: `backend/tests/test_supervisor_reasoning.py`
- Test: `backend/tests/test_risk.py`

**Interfaces:**
- `build_mission_digest`: Accepts preloaded `MissionContext` directly instead of querying DB.
- `step_digest`: Accepts `steps: list[Step]` instead of opening `async with get_async_session_ctx()`.
- `refresh_risk`: Move database fetch and update into `AssessmentRepo.refresh_risk_score(assessment_id)`. `domain/risk.py` provides pure `summarize(findings)`.

- [x] **Step 1: Refactor `build_mission_digest` and `step_digest` in `mission_brain.py`**
- [x] **Step 2: Move DB query from `domain/risk.py` to `AssessmentRepo`**
- [x] **Step 3: Run tests and verify clean pass**
- [x] **Step 4: Commit**

```bash
git add backend/src/app/agents/loop/mission_brain.py backend/src/app/domain/risk.py backend/src/app/persistence/assessment_repo.py
git commit -m "refactor(agents): eliminate direct database sessions from mission_brain and risk domain"
```

---

### Task 8: Refactor LangGraph `nodes.py` to Pure Orchestration (Single Unit-of-Work)

**Files:**
- Modify: `backend/src/app/agents/loop/nodes.py`
- Test: `backend/tests/test_loop_nodes.py`
- Test: `backend/tests/test_loop_graph.py`

**Interfaces:**
- Consumes: Preloaded `MissionContext`, `StepRepo`, `AuditRepo`, `FindingRepo`.
- Eliminates: All 17 ad-hoc `async with get_async_session_ctx()` blocks and inline `select()` queries across `intake_node`, `supervisor_node`, `brief_node`, `prepare_node`, `approve_node`, `make_execute_node`, and `review_node`.
- Establishes: Single session context provided per turn or injected via node factories / state context.

- [x] **Step 1: Refactor `prepare_node` to use `step_repo.create_planned_step` and `audit_repo.record_event`**
- [x] **Step 2: Refactor `approve_node` to use `step_repo.record_approval` or `reject_step`**
- [x] **Step 3: Refactor `make_execute_node` to use `step_repo.complete_step` and pure `observation_from_step`**
- [x] **Step 4: Refactor `brief_node`, `supervisor_node`, and `review_node` to consume preloaded context**
- [x] **Step 5: Run tests and verify zero regressions**
- [x] **Step 6: Commit**

```bash
git add backend/src/app/agents/loop/nodes.py
git commit -m "refactor(agents): eliminate all ad-hoc sessions and raw SQL from loop nodes"
```

---

### Task 9: Clean Dead Shims, Fix Test Mock Regression, and Full Verification

**Files:**
- Delete: `backend/src/app/agents/tools.py`
- Delete: `backend/src/app/persistence/role_repo.py`
- Modify: `backend/src/app/agents/loop/nodes.py:427` (fallback for mock models lacking `config` arg)
- Modify: `backend/src/app/actions/catalogue.py` (remove duplicate `nmap_scan` and `nmap_nse`)
- Test: Entire backend test suite (`tests/`)

- [ ] **Step 1: Fix `model.ainvoke` fallback in `nodes.py:427` for older test mocks**

```python
try:
    ai = await model.ainvoke(messages, config=call_config)
except TypeError:
    ai = await model.ainvoke(messages)
```

- [ ] **Step 2: Delete dead files `backend/src/app/agents/tools.py` and `backend/src/app/persistence/role_repo.py`**

Ensure all imports point to `app.agents.loop.tool_specs` and `app.persistence.audit_repo`.

- [ ] **Step 3: Run the full test suite**

Run: `cd backend && uv run pytest -v`  
Expected: 100% tests pass (177+ tests).

- [ ] **Step 4: Verify zero raw SQL queries remain in `backend/src/app/agents/`**

Run:
```bash
grep -rn "get_async_session_ctx" backend/src/app/agents/ || echo "CLEAN: No get_async_session_ctx calls"
grep -rn "select(" backend/src/app/agents/ || echo "CLEAN: No select() calls"
grep -rn "session.commit()" backend/src/app/agents/ || echo "CLEAN: No session.commit() calls"
```
Expected: `CLEAN` for all checks.

- [ ] **Step 5: Commit final changes**

```bash
git add -u backend/
git commit -m "chore(cleanup): remove dead shims, fix mock model invocation, and verify zero db coupling in agents"
```
