"""Unit tests for individual V2 loop nodes (nodes.py, mission_brain.py)."""

from __future__ import annotations

import asyncio
from datetime import datetime
import pytest
from langchain_core.messages import AIMessage, ToolMessage
from sqlmodel import select

from app.actions import catalogue
from app.agents.graph.state import AssessmentState, initial_state
from app.agents.loop.contracts import (
    ActionRequest,
    FailureSignal,
    Observation,
    RouteDecision,
)
from app.agents.loop.mission_brain import (
    MissionDigest,
    deterministic_safe_route,
    validate_route,
)
from app.agents.loop.nodes import (
    approve_node,
    brief_node,
    intake_node,
    make_execute_node,
    prepare_node,
    supervisor_node,
)
from app.core.config import settings
from app.core.db import get_async_session_ctx, init_db, make_engine, set_engine
from app.domain.models import (
    Approval,
    Assessment,
    AssessmentStatus,
    Audit,
    Decision,
    Step,
    StepStatus,
    utcnow,
)


@pytest.fixture
def engine(tmp_path, monkeypatch):
    engine = make_engine(f"sqlite:///{tmp_path / 'loop_nodes.db'}")
    asyncio.run(init_db(engine))
    set_engine(engine)
    monkeypatch.setattr(catalogue, "ARTIFACT_DIR", tmp_path / "artifacts")
    monkeypatch.setattr(settings, "agent_loop", "v2")
    return engine


async def _create_assessment() -> Assessment:
    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Lab Test",
            request="Test recon loop",
            targets=["127.0.0.1"],
            ports=[3000],
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)
        return assessment


@pytest.mark.asyncio
async def test_intake_node(engine):
    assessment = await _create_assessment()
    state = initial_state(assessment.id, run_id="run_intake_1")

    cmd = await intake_node(state)
    assert cmd.goto == "supervisor"
    assert cmd.update["targets"] == ["127.0.0.1"]
    assert cmd.update["ports"] == [3000]
    assert cmd.update["messages"] == []
    assert cmd.update["turns"] == {}


@pytest.mark.asyncio
async def test_prepare_node_creates_step_and_approval(engine):
    assessment = await _create_assessment()
    state = initial_state(assessment.id, run_id="run_prep_1")
    state["role"] = "recon"
    state["messages"] = [
        AIMessage(
            content="",
            tool_calls=[
                {
                    "id": "call_nmap_1",
                    "name": "recon_services",
                    "args": {
                        "target": "127.0.0.1",
                        "rationale": "Identify open services",
                        "profile": "fast",
                    },
                }
            ],
        )
    ]

    cmd = await prepare_node(state)
    assert cmd.goto == "approve"
    pending = cmd.update["pending_action"]
    assert pending["tool_call_id"] == "call_nmap_1"
    assert pending["action"] == "recon_services"
    assert pending["target"] == "127.0.0.1"
    assert pending["requires_approval"] is False  # recon is auto-approved by policy

    async with get_async_session_ctx() as session:
        step = await session.get(Step, pending["step_id"])
        approval = await session.get(Approval, pending["approval_id"])
        assert step is not None
        assert approval is not None
        assert step.action == "recon_services"
        assert approval.step_id == step.id


@pytest.mark.asyncio
async def test_prepare_node_returns_tool_message_on_invalid_args(engine):
    assessment = await _create_assessment()
    state = initial_state(assessment.id, run_id="run_prep_inv")
    state["role"] = "recon"
    state["messages"] = [
        AIMessage(
            content="",
            tool_calls=[
                {
                    "id": "call_bad_1",
                    "name": "recon_services",
                    "args": {
                        "target": "127.0.0.1",
                        "rationale": "Test invalid timing",
                        "timing": 999,  # invalid: timing must be <= 5
                    },
                }
            ],
        )
    ]

    cmd = await prepare_node(state)
    assert cmd.goto == "model"
    last_msg = cmd.update["messages"][-1]
    assert isinstance(last_msg, ToolMessage)
    assert last_msg.status == "error"
    assert "Schema validation error" in last_msg.content


@pytest.mark.asyncio
async def test_approve_node_auto_approves_low_risk(engine):
    assessment = await _create_assessment()
    state = initial_state(assessment.id, run_id="run_appr_1")
    state["role"] = "recon"
    state["messages"] = [
        AIMessage(
            content="",
            tool_calls=[
                {
                    "id": "call_nmap_2",
                    "name": "recon_services",
                    "args": {"target": "127.0.0.1", "rationale": "Auto approve test"},
                }
            ],
        )
    ]
    prep_cmd = await prepare_node(state)
    state["pending_action"] = prep_cmd.update["pending_action"]

    appr_cmd = await approve_node(state)
    assert appr_cmd.goto == "execute"
    assert appr_cmd.update["approval_decision"]["decision"] == "approved"

    async with get_async_session_ctx() as session:
        approval = await session.get(Approval, state["pending_action"]["approval_id"])
        assert approval.decision == Decision.APPROVED.value
        assert approval.actor == "system"


@pytest.mark.asyncio
async def test_execute_node_verifies_argv_and_produces_observation(engine):
    assessment = await _create_assessment()
    state = initial_state(assessment.id, run_id="run_exec_1")
    state["role"] = "recon"
    state["messages"] = [
        AIMessage(
            content="",
            tool_calls=[
                {
                    "id": "call_nmap_3",
                    "name": "recon_services",
                    "args": {"target": "127.0.0.1", "rationale": "Scan ports"},
                }
            ],
        )
    ]
    prep_cmd = await prepare_node(state)
    state["pending_action"] = prep_cmd.update["pending_action"]
    await approve_node(state)

    async def mock_executor(session, assessment_id, action, target=None, rationale="", step=None):
        step.status = StepStatus.SUCCEEDED.value
        step.output_path = "/tmp/test.xml"
        step.output_sha256 = "sha256_dummy"
        await session.commit()
        return step

    execute_node = make_execute_node(mock_executor)
    cmd = await execute_node(state)

    assert cmd.goto == "model"
    tool_msg = cmd.update["messages"][-1]
    assert isinstance(tool_msg, ToolMessage)
    obs = Observation.model_validate_json(tool_msg.content)
    assert obs.ok is True
    assert obs.status == "succeeded"
    assert obs.step_id == state["pending_action"]["step_id"]


def test_validate_route_guards():
    state: AssessmentState = {"turns": {"recon": 1}, "role": "recon", "nudges": 0}
    digest = MissionDigest(
        assessment_id=1,
        run_id="run_1",
        services=[{"id": 1}],
        candidates=[{"id": 2}],
    )

    # 1. Unknown role
    dec = RouteDecision(next_role="review", why="ok", confidence=0.8)
    dec_unknown = dec.model_copy(update={"next_role": "unknown"})
    safe, reason = validate_route(dec_unknown, state, digest)
    assert reason == "unknown_role"
    assert safe.next_role in ("recon", "discovery", "validation", "review")

    # 2. Override without reason
    dec_override = RouteDecision(
        next_role="discovery",
        why="skip",
        confidence=0.8,
        overrides_specialist=True,
        override_reason=None,
    )
    safe, reason = validate_route(dec_override, state, digest)
    assert reason == "missing_override_reason"

    # 3. Same role without directive
    dec_same = RouteDecision(next_role="recon", why="repeat", confidence=0.7)
    safe, reason = validate_route(dec_same, state, digest)
    assert reason == "same_role_without_directive"

    # 4. Valid route accepted
    dec_valid = RouteDecision(next_role="discovery", why="Service found", confidence=0.8)
    accepted, reason = validate_route(dec_valid, state, digest)
    assert reason is None
    assert accepted.next_role == "discovery"


def test_deterministic_safe_route_budget_exhausted():
    state: AssessmentState = {
        "turns": {"recon": 8, "discovery": 12, "validation": 16},
    }
    digest = MissionDigest(
        assessment_id=1,
        run_id="run_ex",
        services=[{"id": 1}],
        candidates=[{"id": 2}],
        budget={"turns": state["turns"]},
    )
    safe = deterministic_safe_route(state, digest)
    assert safe.next_role == "review"
    assert safe.report_ready is True
