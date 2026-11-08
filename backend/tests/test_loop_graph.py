"""End-to-end integration tests for Phase 2 loop.

Covers:
- Recon -> Discovery -> Validation multi-role progression with approvals
- Action approval interrupts (e.g. zap_baseline, sqlmap_scan, curl_tool)
- Resuming with approval executes exactly one step and returns observation
- Resuming with rejection appends rejected observation, continues to handoff, assessment not left AWAITING_APPROVAL
- Direct tool update_finding_status evidence guards
"""

from __future__ import annotations

import asyncio
from typing import Any
import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, AnyMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command
from sqlmodel import select

from app.actions import catalogue
from app.agents.graph.state import initial_state
from app.agents.loop.builder import build_assessment_graph_v2
from app.agents.loop.contracts import Observation
from app.agents.loop.direct_tools import update_finding_status
from app.agents.loop.mission_brain import deterministic_safe_route
from app.core.config import settings
from app.core.db import get_async_session_ctx, init_db, make_engine, set_engine
from app.domain.models import (
    Approval,
    Assessment,
    AssessmentStatus,
    Audit,
    Decision,
    Evidence,
    Finding,
    Severity,
    Step,
    StepStatus,
)


class MultiTurnScriptedModel(BaseChatModel):
    """Scripted model that returns responses in order across roles."""

    responses: list[AIMessage]
    recorded_inputs: list[list[AnyMessage]] = []

    def bind_tools(self, tools: Any, **kwargs: Any) -> Any:
        return self

    async def _agenerate(
        self,
        messages: list[AnyMessage],
        stop: list[str] | None = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> ChatResult:
        self.recorded_inputs.append(list(messages))
        idx = len(self.recorded_inputs) - 1
        if idx < len(self.responses):
            resp = self.responses[idx]
        else:
            resp = AIMessage(content="completed")
        return ChatResult(generations=[ChatGeneration(message=resp)])

    def _generate(
        self,
        messages: list[AnyMessage],
        stop: list[str] | None = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> ChatResult:
        self.recorded_inputs.append(list(messages))
        idx = len(self.recorded_inputs) - 1
        if idx < len(self.responses):
            resp = self.responses[idx]
        else:
            resp = AIMessage(content="completed")
        return ChatResult(generations=[ChatGeneration(message=resp)])

    @property
    def _llm_type(self) -> str:
        return "multi-turn-scripted-model"


@pytest.fixture
def engine(tmp_path, monkeypatch):
    engine = make_engine(f"sqlite:///{tmp_path / 'loop_graph_v2.db'}")
    asyncio.run(init_db(engine))
    set_engine(engine)
    monkeypatch.setattr(catalogue, "ARTIFACT_DIR", tmp_path / "artifacts")
    monkeypatch.setattr(settings, "agent_loop", "v2")
    return engine


@pytest.mark.asyncio
async def test_recon_discovery_validation_end_to_end_with_approval(engine, monkeypatch):
    """Test full multi-role observe-reason-act loop with human approval gate and resume."""
    # 1. Create Assessment
    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Lab Full Loop Assessment",
            request="Full assessment from recon to validation",
            targets=["127.0.0.1"],
            ports=[3000],
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)
        assessment_id = assessment.id

    # 2. Mock Executor that simulates scanners producing findings
    created_finding_ids: list[int] = []

    async def mock_executor(session, a_id, action, target=None, rationale="", step=None):
        step.status = StepStatus.SUCCEEDED.value
        step.output_path = f"/tmp/{step.id}.{action}.txt"
        step.output_sha256 = f"sha256_{step.id}"

        if action == "recon_services":
            f = Finding(
                assessment_id=a_id,
                canonical_key=f"nmap:{target}:tcp/3000",
                title="Open port 3000/tcp (http Express)",
                asset=target or "127.0.0.1",
                endpoint="tcp/3000",
                severity=Severity.LOW.value,
                status="info",
            )
            session.add(f)
            await session.flush()
            created_finding_ids.append(f.id)
            ev = Evidence(assessment_id=a_id, step_id=step.id, finding_id=f.id, category="service")
            session.add(ev)

        elif action == "zap_baseline":
            f = Finding(
                assessment_id=a_id,
                canonical_key=f"zap:{target}:missing_csrf",
                title="Missing Anti-CSRF Tokens",
                asset=target or "127.0.0.1",
                endpoint="tcp/3000/login",
                severity=Severity.MEDIUM.value,
                status="suspected",
            )
            session.add(f)
            await session.flush()
            created_finding_ids.append(f.id)
            ev = Evidence(assessment_id=a_id, step_id=step.id, finding_id=f.id, category="vulnerability")
            session.add(ev)

        elif action in ("http_probe", "curl_tool"):
            # Probe evidence linking to the ZAP finding
            target_finding_id = created_finding_ids[-1]
            ev = Evidence(
                assessment_id=a_id,
                step_id=step.id,
                finding_id=target_finding_id,
                category="probe",
                locator={"tool": "curl_tool", "http_status": 200, "finding_id": target_finding_id},
            )
            session.add(ev)

        from app.agents.control import audit
        audit(session, a_id, "step.succeeded", {"step_id": step.id, "action": action})
        await session.commit()
        return step

    # 3. Setup Scripted Model Responses
    scripted_model = MultiTurnScriptedModel(
        responses=[
            # --- RECON ---
            # Turn 1: call recon_services (auto-approved)
            AIMessage(
                content="Scanning services.",
                tool_calls=[{
                    "id": "recon_call_1",
                    "name": "recon_services",
                    "args": {"target": "127.0.0.1", "rationale": "Discover listening ports.", "profile": "fast", "ports": "3000"},
                }],
            ),
            # Turn 2: observe open port 3000 -> handoff to discovery
            AIMessage(
                content="Port 3000 HTTP mapped. Handing off to discovery.",
                tool_calls=[{
                    "id": "recon_handoff",
                    "name": "handoff",
                    "args": {
                        "summary": "Port 3000 HTTP open.",
                        "next_role": "discovery",
                        "why": "Web service present, need discovery.",
                        "confidence": 0.85,
                        "stop_reason": "surface_mapped",
                        "finding_ids": [1],
                        "step_ids": [1],
                        "open_questions": [],
                    },
                }],
            ),
            # --- DISCOVERY ---
            # Turn 3: call zap_baseline (medium risk, requires approval)
            AIMessage(
                content="Starting web baseline scan.",
                tool_calls=[{
                    "id": "zap_call_1",
                    "name": "zap_baseline",
                    "args": {"target": "127.0.0.1", "rationale": "Identify web application candidates."},
                }],
            ),
            # Turn 4: observe ZAP alerts -> handoff to validation
            AIMessage(
                content="Discovered candidate vulnerabilities. Handing off to validation.",
                tool_calls=[{
                    "id": "discovery_handoff",
                    "name": "handoff",
                    "args": {
                        "summary": "Discovered candidate CSRF finding.",
                        "next_role": "validation",
                        "why": "Candidates ready for probing.",
                        "confidence": 0.80,
                        "stop_reason": "hypotheses_tested",
                        "finding_ids": [2],
                        "step_ids": [2],
                        "open_questions": [],
                    },
                }],
            ),
            # --- VALIDATION ---
            # Turn 5: call curl_tool to probe candidate finding #2
            AIMessage(
                content="Validating candidate finding #2 with safe probe.",
                tool_calls=[{
                    "id": "curl_call_1",
                    "name": "curl_tool",
                    "args": {
                        "target": "127.0.0.1",
                        "rationale": "Verify login endpoint response.",
                        "path": "/login",
                        "method": "GET",
                        "finding_id": 2,
                    },
                }],
            ),
            # Turn 6: observe probe result -> call update_finding_status -> handoff to review
            AIMessage(
                content="Probe confirmed CSRF vulnerability.",
                tool_calls=[{
                    "id": "update_status_1",
                    "name": "update_finding_status",
                    "args": {
                        "finding_id": 2,
                        "status": "confirmed",
                        "reasoning": "Endpoint responded HTTP 200 without Anti-CSRF token headers.",
                    },
                }],
            ),
            # Turn 7: handoff to review
            AIMessage(
                content="Validation complete. Handing off to review.",
                tool_calls=[{
                    "id": "validation_handoff",
                    "name": "handoff",
                    "args": {
                        "summary": "Finding #2 confirmed via active probe.",
                        "next_role": "review",
                        "why": "All candidates evaluated.",
                        "confidence": 0.95,
                        "stop_reason": "hypotheses_tested",
                        "finding_ids": [2],
                        "step_ids": [3],
                        "open_questions": [],
                    },
                }],
            ),
        ]
    )

    monkeypatch.setattr("app.agents.loop.nodes.build_role_model", lambda role: scripted_model)

    async def mock_supervisor(digest, **kwargs):
        last_h = digest.recent_handoffs[-1] if digest.recent_handoffs else None
        return deterministic_safe_route(
            {"turns": digest.budget.get("turns", {}), "last_handoff": last_h},
            digest,
        )

    monkeypatch.setattr("app.agents.loop.nodes.run_supervisor_agent", mock_supervisor)

    # 4. Build and start graph
    checkpointer = MemorySaver()
    graph = build_assessment_graph_v2(checkpointer=checkpointer, executor=mock_executor)

    run_id = "test_run_phase2"
    init_state = initial_state(assessment_id, run_id=run_id)
    config = {"configurable": {"thread_id": f"agent-{assessment_id}"}}

    # Run step 1: Recon runs auto-approved, hands off to Discovery, Discovery requests zap_baseline -> PAUSES at approve gate
    await graph.ainvoke(init_state, config=config)

    state = await graph.aget_state(config)
    assert state.next == ("approve",)
    assert len(state.tasks) > 0
    pending_interrupt = state.tasks[0].interrupts[0].value
    assert pending_interrupt["gate"] == "action"
    assert pending_interrupt["action"] == "zap_baseline"
    assert pending_interrupt["requires_approval"] is True

    # Resume with approval for zap_baseline
    await graph.ainvoke(
        Command(resume={"decision": "approved", "actor": "analyst", "reason": "Approved zap baseline"}),
        config=config,
    )

    # Next pause: Discovery completed, handed off to Validation, Validation requested curl_tool -> PAUSES at approve gate
    state = await graph.aget_state(config)
    assert state.next == ("approve",)
    pending_curl = state.tasks[0].interrupts[0].value
    assert pending_curl["action"] == "http_probe"

    # Resume with approval for curl_tool
    await graph.ainvoke(
        Command(resume={"decision": "approved", "actor": "analyst", "reason": "Approved curl probe"}),
        config=config,
    )

    # Graph runs probe, updates finding status to confirmed, and pauses at review gate
    state = await graph.aget_state(config)
    assert state.next == ("review",)
    review_interrupt = state.tasks[0].interrupts[0].value
    assert review_interrupt["gate"] == "review"

    # Verify Finding #2 was confirmed in database
    async with get_async_session_ctx() as session:
        f2 = await session.get(Finding, 2)
        assert f2 is not None
        assert f2.status == "confirmed"


@pytest.mark.asyncio
async def test_action_approval_rejection_resumes_cleanly(engine, monkeypatch):
    """Test that a rejected action appends a rejected observation, does not execute, and continues."""
    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Lab Rejection Test",
            request="Validation test with rejection",
            targets=["127.0.0.1"],
            ports=[3000],
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)
        assessment_id = assessment.id

        # Add a candidate finding so validation role is eligible
        cand = Finding(
            assessment_id=assessment_id,
            canonical_key="test:sql_candidate",
            title="Potential SQL Injection",
            asset="127.0.0.1",
            endpoint="/login",
            severity=Severity.HIGH.value,
            status="suspected",
        )
        session.add(cand)

        # Add a service finding so discovery role is eligible
        srv = Finding(
            assessment_id=assessment_id,
            canonical_key="nmap:127.0.0.1:tcp/3000",
            title="Open port 3000 (http)",
            asset="127.0.0.1",
            endpoint="tcp/3000",
            severity=Severity.LOW.value,
            status="info",
        )
        session.add(srv)
        await session.commit()

    executed_actions: list[str] = []

    async def mock_executor(session, a_id, action, target=None, rationale="", step=None):
        executed_actions.append(action)
        step.status = StepStatus.SUCCEEDED.value
        return step

    scripted_model = MultiTurnScriptedModel(
        responses=[
            # Turn 1: call sqlmap_scan (requires approval)
            AIMessage(
                content="Testing SQL injection.",
                tool_calls=[{
                    "id": "sqlmap_call_1",
                    "name": "sqlmap_scan",
                    "args": {"target": "127.0.0.1", "rationale": "Probe SQL injection.", "parameter": "id"},
                }],
            ),
            # Turn 2: after rejection observation, model acknowledges and hands off to discovery
            AIMessage(
                content="Analyst rejected SQL injection test. Handing off to discovery.",
                tool_calls=[{
                    "id": "val_handoff_after_reject",
                    "name": "handoff",
                    "args": {
                        "summary": "SQL injection scan rejected by analyst. Returning to discovery.",
                        "next_role": "discovery",
                        "why": "Action rejected; explore alternate surface.",
                        "confidence": 0.5,
                        "stop_reason": "no_progress",
                        "finding_ids": [],
                        "step_ids": [],
                        "open_questions": ["SQL injection unconfirmed due to analyst rejection"],
                    },
                }],
            ),
            # Turn 3: discovery specialist in role discovery calls zap_baseline (requires approval)
            AIMessage(
                content="Performing discovery scan on target.",
                tool_calls=[{
                    "id": "zap_call_1",
                    "name": "zap_baseline",
                    "args": {"target": "127.0.0.1", "rationale": "Identify web application candidates."},
                }],
            ),
        ]
    )

    monkeypatch.setattr("app.agents.loop.nodes.build_role_model", lambda role: scripted_model)

    async def mock_supervisor(digest, **kwargs):
        last_h = digest.recent_handoffs[-1] if digest.recent_handoffs else None
        if not last_h:
            from app.agents.loop.contracts import RouteDecision
            return RouteDecision(next_role="validation", why="Test validation directly", confidence=0.9)
        return deterministic_safe_route(
            {"turns": digest.budget.get("turns", {}), "last_handoff": last_h},
            digest,
        )

    monkeypatch.setattr("app.agents.loop.nodes.run_supervisor_agent", mock_supervisor)

    checkpointer = MemorySaver()
    graph = build_assessment_graph_v2(checkpointer=checkpointer, executor=mock_executor)

    # Start in role validation directly
    init_state = initial_state(assessment_id, run_id="test_rejection_run")
    init_state["role"] = "validation"
    init_state["next_node"] = "brief"
    config = {"configurable": {"thread_id": f"agent-{assessment_id}"}}

    # Run until approval interrupt
    await graph.ainvoke(init_state, config=config)
    state = await graph.aget_state(config)
    assert state.next == ("approve",)

    # Resume with REJECTION
    await graph.ainvoke(
        Command(resume={"decision": "rejected", "actor": "analyst", "reason": "Too intrusive for this engagement"}),
        config=config,
    )

    # Assert executor was NEVER called for sqlmap_scan
    assert "sqlmap_scan" not in executed_actions

    # Assert step was marked REJECTED in database and approval record updated
    async with get_async_session_ctx() as session:
        step_res = await session.execute(
            select(Step).where(Step.assessment_id == assessment_id, Step.action == "sqlmap_scan")
        )
        step = step_res.scalars().first()
        assert step is not None
        assert step.status == StepStatus.REJECTED.value
        assert "Too intrusive" in (step.error or "")

        appr_res = await session.execute(
            select(Approval).where(Approval.step_id == step.id)
        )
        appr = appr_res.scalars().first()
        assert appr is not None
        assert appr.decision == Decision.REJECTED.value

    # Assert graph proceeded past rejection, routed to discovery, and paused at the next approval gate
    state = await graph.aget_state(config)
    assert state.next == ("approve",)
    assert state.values.get("role") == "discovery"
    pending_interrupt = state.tasks[0].interrupts[0].value
    assert pending_interrupt["gate"] == "action"
    assert pending_interrupt["action"] == "zap_baseline"


@pytest.mark.asyncio
async def test_update_finding_status_evidence_guard(engine):
    """Test that update_finding_status rejects confirmed without probe evidence and accepts it with evidence."""
    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Guard Test Assessment",
            request="Test evidence guard",
            targets=["127.0.0.1"],
            ports=[3000],
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        finding = Finding(
            assessment_id=assessment.id,
            canonical_key="test:unverified_finding",
            title="Potential Vulnerability",
            asset="127.0.0.1",
            endpoint="/test",
            severity=Severity.HIGH.value,
            status="suspected",
        )
        session.add(finding)
        await session.commit()
        await session.refresh(finding)
        fid = finding.id
        aid = assessment.id

    # 1. Attempt update to 'confirmed' without any probe evidence -> must be rejected
    async with get_async_session_ctx() as session:
        res = await update_finding_status(session, aid, fid, "confirmed", "Looks vulnerable")
        assert res.ok is False
        assert "error" in res.status or not res.ok

    # 2. Add probe evidence with non-null http_status
    async with get_async_session_ctx() as session:
        ev = Evidence(
            assessment_id=aid,
            finding_id=fid,
            category="probe",
            locator={"tool": "curl_tool", "http_status": 200},
        )
        session.add(ev)
        await session.commit()

    # 3. Attempt update to 'confirmed' again -> must succeed
    async with get_async_session_ctx() as session:
        res2 = await update_finding_status(session, aid, fid, "confirmed", "HTTP 200 confirms the flaw")
        assert res2.ok is True
        assert res2.status == "succeeded"

        # Verify DB updated
        f = await session.get(Finding, fid)
        assert f is not None
        assert f.status == "confirmed"
