"""Integration tests for human approval gate interactions.

Covers:
- Scenario A: Analyst approves -> action executes, step succeeds.
- Scenario B: Analyst rejects -> action skipped, step marked rejected, graph continues without stalling.
- Scenario C: Duplicate/Stale decisions -> StaleDecision raised, idempotent replays handled cleanly, NotPaused when gate not open.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any
import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command
from sqlmodel import select

from app.actions import catalogue
from app.agents.builder import build_assessment_graph_v2
from app.agents.contracts import RouteDecision
from app.agents.mission_brain import deterministic_safe_route
from app.agents.state import initial_state
from app.core.config import settings
from app.core.db import get_async_session_ctx
from app.domain.models import (
    Approval,
    Assessment,
    AssessmentStatus,
    Decision,
    Finding,
    Severity,
    Step,
    StepStatus,
)
from app.persistence.audit_repo import audit
from app.runtime import runner


class MultiTurnScriptedModel(BaseChatModel):
    responses: list[AIMessage]
    recorded_inputs: list[list[Any]] = []

    def bind_tools(self, tools: Any, **kwargs: Any) -> Any:
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
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


@pytest.mark.asyncio
async def test_gate_analyst_approves_action_executes(engine, monkeypatch, tmp_path):
    """Scenario A: Analyst Approves -> Action executes, step succeeds."""
    monkeypatch.setattr(catalogue, "ARTIFACT_DIR", tmp_path / "artifacts")
    monkeypatch.setattr(settings, "agent_loop", "v2")

    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Gate Approval Test",
            request="Run intrusive test with gate",
            targets=["127.0.0.1"],
            ports=[3000],
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)
        aid = assessment.id

    executed_steps = []

    async def mock_executor(session, a_id, action, target=None, rationale="", step=None):
        step.status = StepStatus.SUCCEEDED.value
        step.output_path = f"/tmp/{step.id}.txt"
        executed_steps.append(step.id)
        audit(session, a_id, "step.succeeded", {"step_id": step.id, "action": action})
        await session.commit()
        return step

    scripted_model = MultiTurnScriptedModel(
        responses=[
            AIMessage(
                content="Starting web baseline scan.",
                tool_calls=[{
                    "id": "zap_call_1",
                    "name": "zap_baseline",
                    "args": {"target": "127.0.0.1", "rationale": "Identify web application candidates."},
                }],
            ),
        ]
    )

    monkeypatch.setattr("app.agents.nodes.build_role_model", lambda role: scripted_model)

    async def mock_supervisor(digest, **kwargs):
        return RouteDecision(next_role="discovery", why="Test discovery with gate")

    monkeypatch.setattr("app.agents.nodes.run_supervisor_agent", mock_supervisor)

    checkpointer = MemorySaver()
    graph = build_assessment_graph_v2(checkpointer=checkpointer, executor=mock_executor)
    config = {"configurable": {"thread_id": f"gate-approve-{aid}"}}

    init = initial_state(aid)
    init["role"] = "discovery"
    init["run_id"] = "run-gate-appr"

    # The supervisor proposes a plan first; approve it to reach the action gate.
    await graph.ainvoke(init, config)
    state = await graph.aget_state(config)
    assert state.next == ("plan",)
    proposed = state.tasks[0].interrupts[0].value
    assert proposed["gate"] == "plan"
    await graph.ainvoke(
        Command(
            resume={
                "decision": "approved",
                "actor": "analyst",
                "reason": "Approved initial plan",
                "plan": proposed["plan"],
            }
        ),
        config=config,
    )

    # Run until paused at approval gate
    state = await graph.aget_state(config)
    assert state.next == ("approve",)
    pending_interrupt = state.tasks[0].interrupts[0].value
    assert pending_interrupt["gate"] == "action"
    assert pending_interrupt["action"] == "zap_baseline"
    step_id = pending_interrupt["step_id"]
    approval_id = pending_interrupt["approval_id"]

    # Resume with APPROVED decision
    decision_payload = {
        "decision": "approved",
        "step_id": step_id,
        "approval_id": approval_id,
        "rationale": "Analyst verified scope and approved",
    }
    await graph.ainvoke(Command(resume=decision_payload), config)

    # Verify execution succeeded in DB
    async with get_async_session_ctx() as session:
        step = await session.get(Step, step_id)
        assert step is not None
        assert step.status == StepStatus.SUCCEEDED.value
        assert step.id in executed_steps

        approval = await session.get(Approval, approval_id)
        assert approval is not None
        assert approval.decision == Decision.APPROVED.value


@pytest.mark.asyncio
async def test_gate_analyst_rejects_action_skipped(engine, monkeypatch, tmp_path):
    """Scenario B: Analyst Rejects -> Action skipped, step rejected, loop continues."""
    monkeypatch.setattr(catalogue, "ARTIFACT_DIR", tmp_path / "artifacts")
    monkeypatch.setattr(settings, "agent_loop", "v2")

    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Gate Rejection Test",
            request="Run intrusive test to be rejected",
            targets=["127.0.0.1"],
            ports=[3000],
        )
        session.add(assessment)

        # Candidate finding so validation role can run
        cand = Finding(
            assessment_id=1,
            canonical_key="test:sql_candidate",
            title="Potential SQL Injection",
            asset="127.0.0.1",
            endpoint="/login",
            severity=Severity.HIGH.value,
            status="suspected",
        )
        session.add(cand)
        await session.commit()
        await session.refresh(assessment)
        aid = assessment.id

    executed = []

    async def mock_executor(session, a_id, action, target=None, rationale="", step=None):
        executed.append(step.id)
        step.status = StepStatus.SUCCEEDED.value
        await session.commit()
        return step

    scripted_model = MultiTurnScriptedModel(
        responses=[
            # Turn 1: call sqlmap_scan (requires approval)
            AIMessage(
                content="Testing SQL injection.",
                tool_calls=[{
                    "id": "sqlmap_call_1",
                    "name": "sqlmap_scan",
                    "args": {
                        "target": "127.0.0.1",
                        "rationale": "Probe SQL injection.",
                        "url": "/login?id=1",
                        "parameter": "id",
                    },
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
            # Turn 3: discovery specialist requests zap_baseline (requires approval)
            AIMessage(
                content="Performing discovery scan on target.",
                tool_calls=[{
                    "id": "zap_call_2",
                    "name": "zap_baseline",
                    "args": {"target": "127.0.0.1", "rationale": "Identify web application candidates."},
                }],
            ),
        ]
    )

    monkeypatch.setattr("app.agents.nodes.build_role_model", lambda role: scripted_model)

    async def mock_supervisor(digest, **kwargs):
        last_h = digest.recent_handoffs[-1] if digest.recent_handoffs else None
        if not last_h:
            return RouteDecision(next_role="validation", why="Validation requested")
        return RouteDecision(next_role=last_h.get("next_role", "discovery"), why="Follow handoff")

    monkeypatch.setattr("app.agents.nodes.run_supervisor_agent", mock_supervisor)

    checkpointer = MemorySaver()
    graph = build_assessment_graph_v2(checkpointer=checkpointer, executor=mock_executor)
    config = {"configurable": {"thread_id": f"gate-reject-{aid}"}}

    init = initial_state(aid)
    init["role"] = "validation"
    init["run_id"] = "run-gate-rej"

    await graph.ainvoke(init, config)
    state = await graph.aget_state(config)
    assert state.next == ("plan",)
    proposed = state.tasks[0].interrupts[0].value
    assert proposed["gate"] == "plan"
    await graph.ainvoke(
        Command(
            resume={
                "decision": "approved",
                "actor": "analyst",
                "reason": "Approved initial plan",
                "plan": proposed["plan"],
            }
        ),
        config=config,
    )

    state = await graph.aget_state(config)
    assert state.next == ("approve",)
    pending_interrupt = state.tasks[0].interrupts[0].value
    step_id = pending_interrupt["step_id"]
    approval_id = pending_interrupt["approval_id"]
    assert pending_interrupt["action"] == "sqlmap_scan"

    # Resume with REJECTED decision
    decision_payload = {
        "decision": "rejected",
        "step_id": step_id,
        "approval_id": approval_id,
        "rationale": "High risk scan rejected for this target",
    }
    await graph.ainvoke(Command(resume=decision_payload), config)

    # Action was NOT executed
    assert step_id not in executed

    # Verify step and approval marked rejected
    async with get_async_session_ctx() as session:
        step = await session.get(Step, step_id)
        assert step is not None
        assert step.status == StepStatus.REJECTED.value

        approval = await session.get(Approval, approval_id)
        assert approval is not None
        assert approval.decision == Decision.REJECTED.value

    # Graph progressed past rejection, supervisor routed to discovery, and paused at next approval gate (zap_baseline)
    next_state = await graph.aget_state(config)
    assert next_state.next == ("approve",)
    next_interrupt = next_state.tasks[0].interrupts[0].value
    assert next_interrupt["gate"] == "action"
    assert next_interrupt["action"] == "zap_baseline"


@pytest.mark.asyncio
async def test_gate_stale_and_duplicate_decisions(engine, monkeypatch):
    """Scenario C: Duplicate/Stale Decision -> Safely rejected without crash."""
    launched = []

    class FakeGraph:
        def __init__(self, state):
            self._state = state
        async def aget_state(self, _config):
            return self._state

    def fake_gate_state(step_id=10, approval_id=20):
        interrupt = SimpleNamespace(
            value={"gate": "action", "step_id": step_id, "approval_id": approval_id}
        )
        return SimpleNamespace(
            next=("approve",),
            interrupts=(interrupt,),
            values={"role": "discovery"},
            tasks=[SimpleNamespace(interrupts=[interrupt])],
        )

    # 1. Stale decision check (step_id or approval_id mismatch)
    active_state = fake_gate_state(step_id=10, approval_id=20)

    async def fake_graph_active(aid):
        return FakeGraph(active_state), {}

    monkeypatch.setattr(runner, "_graph_for", fake_graph_active)
    monkeypatch.setattr(runner, "is_running", lambda aid: False)
    monkeypatch.setattr(runner, "_locks", {})
    monkeypatch.setattr(runner, "_launch", lambda aid, payload: launched.append((aid, payload)))

    with pytest.raises(runner.StaleDecision, match="this gate has already advanced"):
        await runner.resume_run(1, {"decision": "approved", "step_id": 9, "approval_id": 20})

    with pytest.raises(runner.StaleDecision, match="this approval card is stale"):
        await runner.resume_run(1, {"decision": "approved", "step_id": 10, "approval_id": 19})

    # 2. Idempotent replay: submitting identical approved decision when gate already advanced
    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Idempotent Gate",
            request="Test replay",
            targets=["127.0.0.1"],
            status=AssessmentStatus.RUNNING.value,
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)
        aid = assessment.id

        approval = Approval(
            assessment_id=aid,
            action="sqlmap_scan",
            argv=["sqlmap"],
            decision=Decision.APPROVED.value,
        )
        session.add(approval)
        await session.commit()
        await session.refresh(approval)
        appr_id = approval.id

    # Gate is no longer open (state.next is empty)
    closed_state = SimpleNamespace(next=(), interrupts=(), values={})

    async def fake_graph_closed(aid):
        return FakeGraph(closed_state), {}

    monkeypatch.setattr(runner, "_graph_for", fake_graph_closed)

    sentinel_view = SimpleNamespace(status="running", active_role="discovery")

    async def fake_get_view(aid, running=None):
        return sentinel_view

    monkeypatch.setattr(runner, "get_view", fake_get_view)

    # Replay of approved decision returns current view gracefully
    view = await runner.resume_run(aid, {"decision": "approved", "approval_id": appr_id})
    assert view is sentinel_view

    # Replay with conflicting decision raises NotPaused
    with pytest.raises(runner.NotPaused):
        await runner.resume_run(aid, {"decision": "rejected", "approval_id": appr_id})
