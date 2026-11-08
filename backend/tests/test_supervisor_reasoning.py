"""Unit tests for Phase 3: supervisor reasoning, evidence board, validate_route guards, and reasoning SSE events."""

from __future__ import annotations

import asyncio
from datetime import datetime
import pytest
from langchain_core.messages import AIMessage, HumanMessage
from sqlmodel import select

from app.agents.graph.state import AssessmentState, initial_state
from app.agents.loop.brief import render_brief
from app.agents.loop.contracts import (
    ActionRequest,
    DecisionRecord,
    EvidenceBoard,
    FailureSignal,
    Hypothesis,
    RouteDecision,
)
from app.agents.loop.mission_brain import (
    MissionDigest,
    deterministic_safe_route,
    validate_route,
)
from app.agents.loop.nodes import (
    prepare_node,
    supervisor_node,
)
from app.agents.loop.reasoning import (
    build_evidence_board,
    record_hypothesis,
    update_hypothesis,
)
from app.api.queries import load_assessment_detail
from app.core.config import settings
from app.core.db import get_async_session_ctx, init_db, make_engine, set_engine
from app.core.events import EventType, StreamState
from app.domain.models import (
    Assessment,
    AssessmentStatus,
    Audit,
    Finding,
    FindingStatus,
    Step,
    utcnow,
)


@pytest.fixture
def engine(tmp_path, monkeypatch):
    test_db = tmp_path / "supervisor_reasoning.db"
    test_engine = make_engine(f"sqlite:///{test_db}")
    asyncio.run(init_db(test_engine))
    set_engine(test_engine)
    monkeypatch.setattr(settings, "agent_loop", "v2")
    return test_engine


async def _create_test_assessment() -> int:
    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Reasoning Test Target",
            request="Evaluate target security posture",
            targets=["127.0.0.1"],
            ports=[80, 443],
            exclusions=[],
            status=AssessmentStatus.RUNNING.value,
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)
        return assessment.id


@pytest.mark.asyncio
async def test_hypothesis_lifecycle_and_evidence_board(engine):
    assessment_id = await _create_test_assessment()

    async with get_async_session_ctx() as session:
        # 1. Record hypothesis H-1
        obs1 = await record_hypothesis(
            session=session,
            assessment_id=assessment_id,
            run_id="run-1",
            role="recon",
            statement="Target exposes an outdated Apache web server on port 80",
            asset="127.0.0.1",
            endpoint="http://127.0.0.1:80",
            falsifier="Server header reports nginx or modern Apache >= 2.4.50",
            evidence_ids=[101],
        )
        assert obs1.ok is True
        assert "Recorded H-1" in obs1.summary

        # 2. Record hypothesis H-2
        obs2 = await record_hypothesis(
            session=session,
            assessment_id=assessment_id,
            run_id="run-1",
            role="discovery",
            statement="Login endpoint vulnerable to SQL injection",
            asset="127.0.0.1",
            endpoint="http://127.0.0.1:80/login",
            falsifier="Parameter is securely parameterized with prepared statements",
            evidence_ids=[],
        )
        assert obs2.ok is True
        assert "Recorded H-2" in obs2.summary

        # 3. Update hypothesis H-1 confidence and status
        obs3 = await update_hypothesis(
            session=session,
            assessment_id=assessment_id,
            run_id="run-1",
            role="validation",
            hypothesis_id="H-1",
            status="supported",
            confidence=0.92,
            evidence_ids=[101, 102],
            note="Confirmed via Server header and banner grab",
        )
        assert obs3.ok is True
        assert "status=supported" in obs3.summary

        # 4. Fold into EvidenceBoard
        board = await build_evidence_board(session, assessment_id)
        assert len(board.hypotheses) == 2

        h1 = next(h for h in board.hypotheses if h.id == "H-1")
        assert h1.status == "supported"
        assert h1.confidence == 0.92
        assert h1.evidence_ids == [101, 102]

        h2 = next(h for h in board.hypotheses if h.id == "H-2")
        assert h2.status == "open"
        assert h2.confidence == 0.5


@pytest.mark.asyncio
async def test_decision_recorded_in_prepare_node(engine):
    assessment_id = await _create_test_assessment()
    state = initial_state(assessment_id)
    state["role"] = "validation"
    state["messages"] = [
        AIMessage(
            content="",
            tool_calls=[
                {
                    "id": "call_curl_1",
                    "name": "curl_tool",
                    "args": {
                        "target": "127.0.0.1",
                        "url": "http://127.0.0.1:80/login",
                        "method": "POST",
                        "data": "user=' OR 1=1--",
                        "rationale": "Test authentication bypass via SQLi probe",
                        "hypothesis_id": "H-2",
                        "expected_observation": "HTTP 200 with admin dashboard payload",
                        "would_falsify": "HTTP 401 with generic invalid credentials message",
                        "evidence_ids": [101],
                    },
                }
            ],
        )
    ]

    cmd = await prepare_node(state)
    assert cmd.goto == "approve"

    # Verify decision.recorded audit was persisted
    async with get_async_session_ctx() as session:
        res = await session.execute(
            select(Audit).where(
                Audit.assessment_id == assessment_id,
                Audit.event_type == "decision.recorded",
            )
        )
        records = res.scalars().all()
        assert len(records) >= 1
        payload = records[-1].payload
        assert payload["action"] in ("http_probe", "curl_tool")
        assert payload["hypothesis_id"] == "H-2"
        assert payload["would_falsify"] == "HTTP 401 with generic invalid credentials message"
        assert payload["outcome"] == "prepared"

        # Verify board folding picks up the decision
        board = await build_evidence_board(session, assessment_id)
        assert len(board.decisions) >= 1
        d = board.decisions[-1]
        assert d.action in ("http_probe", "curl_tool")
        assert d.hypothesis_id == "H-2"


def test_render_brief_with_evidence_board():
    assessment = Assessment(
        id=42,
        title="Test Target",
        request="Assess attack surface",
        targets=["10.0.0.5"],
        ports=[80, 443],
    )
    board = EvidenceBoard(
        hypotheses=[
            Hypothesis(
                id="H-1",
                statement="Exposed admin console without MFA",
                asset="10.0.0.5",
                status="open",
                confidence=0.6,
                falsifier="Requires MFA prompt or IP allowlist",
                created_by="discovery",
                updated_at=utcnow(),
            )
        ],
        decisions=[
            DecisionRecord(
                id="D-1",
                role="recon",
                action="nmap_scan",
                target="10.0.0.5",
                outcome="approved and executed",
                created_at=utcnow(),
            )
        ],
        open_questions=["Is port 8080 accessible externally?"],
    )
    brief = render_brief(
        assessment=assessment,
        role="discovery",
        board=board,
        services=[],
        candidates=[],
        supervisor_directive="Focus on exposed administrative interfaces",
    )

    assert "EVIDENCE BOARD" in brief
    assert "H-1 open confidence=0.60 'Exposed admin console without MFA'" in brief
    assert "OPEN QUESTIONS" in brief
    assert "Is port 8080 accessible externally?" in brief
    assert "RECENT DECISIONS" in brief
    assert "D-1 [recon] nmap_scan on 10.0.0.5" in brief
    assert "SUPERVISOR DIRECTIVE" in brief
    assert "Focus on exposed administrative interfaces" in brief


def test_validate_route_unknown_role():
    state = {"role": "recon", "turns": {}}
    digest = MissionDigest(assessment_id=1, run_id="run-1")
    # Bypass Pydantic validation via model_construct to test Python guard
    proposed = RouteDecision.model_construct(
        next_role="non_existent_role",
        why="Invalid role test",
    )
    decision, rejection = validate_route(proposed, state, digest)
    assert rejection == "unknown_role"
    assert decision.next_role in {"recon", "discovery", "validation", "review"}


def test_validate_route_override_without_reason():
    state = {"role": "recon", "turns": {}}
    digest = MissionDigest(assessment_id=1, run_id="run-1")
    proposed = RouteDecision(
        next_role="discovery",
        overrides_specialist=True,
        override_reason="",  # Missing required reason
        why="Overriding specialist",
    )
    decision, rejection = validate_route(proposed, state, digest)
    assert rejection == "missing_override_reason"


def test_validate_route_override_with_reason_accepted():
    state = {"role": "recon", "turns": {}}
    digest = MissionDigest(assessment_id=1, run_id="run-1")
    proposed = RouteDecision(
        next_role="discovery",
        overrides_specialist=True,
        override_reason="Critical service detected requiring immediate deeper directory fuzzing",
        why="Overriding specialist based on service findings",
    )
    decision, rejection = validate_route(proposed, state, digest)
    assert rejection is None
    assert decision.next_role == "discovery"
    assert decision.overrides_specialist is True


def test_validate_route_budget_exhausted():
    state = {"role": "recon", "turns": {"recon": 20}}  # Over cap
    digest = MissionDigest(assessment_id=1, run_id="run-1")
    proposed = RouteDecision(
        next_role="recon",
        why="Run recon again",
    )
    decision, rejection = validate_route(proposed, state, digest)
    assert rejection == "role_budget_exhausted"


def test_validate_route_same_role_without_directive():
    state = {"role": "discovery", "turns": {"discovery": 2}}
    digest = MissionDigest(assessment_id=1, run_id="run-1")
    proposed = RouteDecision(
        next_role="discovery",
        why="Run discovery again with same parameters",
        directive="",  # Missing directive
    )
    decision, rejection = validate_route(proposed, state, digest)
    assert rejection == "same_role_without_directive"


def test_validate_route_same_role_with_directive_accepted():
    state = {"role": "discovery", "turns": {"discovery": 2}, "nudges": 0}
    digest = MissionDigest(assessment_id=1, run_id="run-1")
    proposed = RouteDecision(
        next_role="discovery",
        why="Retry discovery with narrower directory list",
        directive="Run dirb_scan targeting /api/v2 endpoints exclusively",
    )
    decision, rejection = validate_route(proposed, state, digest)
    assert rejection is None
    assert decision.next_role == "discovery"
    assert "dirb_scan targeting /api/v2" in (decision.directive or "")


@pytest.mark.asyncio
async def test_supervisor_node_recovers_from_failure_signal(engine):
    assessment_id = await _create_test_assessment()
    state = initial_state(assessment_id)
    state["role"] = "recon"
    state["failure_signal"] = FailureSignal(
        kind="no_handoff",
        role="recon",
        summary="Specialist stalled without issuing a handoff tool call",
        attempts=3,
    ).model_dump()

    cmd = await supervisor_node(state)
    assert cmd.goto in ("brief", "review")

    # Verify audit contains supervisor.recovered event
    async with get_async_session_ctx() as session:
        res = await session.execute(
            select(Audit).where(
                Audit.assessment_id == assessment_id,
                Audit.event_type == "supervisor.recovered",
            )
        )
        rec = res.scalars().first()
        assert rec is not None
        assert rec.payload["failure_kind"] == "no_handoff"


@pytest.mark.asyncio
async def test_load_assessment_detail_includes_reasoning(engine):
    assessment_id = await _create_test_assessment()

    async with get_async_session_ctx() as session:
        await record_hypothesis(
            session=session,
            assessment_id=assessment_id,
            run_id="run-1",
            role="recon",
            statement="Database port 5432 is exposed",
            asset="127.0.0.1",
        )

        detail = await load_assessment_detail(session, assessment_id)
        assert detail is not None
        assert isinstance(detail.reasoning, EvidenceBoard)
        assert len(detail.reasoning.hypotheses) == 1
        assert detail.reasoning.hypotheses[0].statement == "Database port 5432 is exposed"


@pytest.mark.asyncio
async def test_stream_state_emits_reasoning_event(engine):
    assessment_id = await _create_test_assessment()

    async with get_async_session_ctx() as session:
        detail_initial = await load_assessment_detail(session, assessment_id)
        assert detail_initial is not None

        stream_state = StreamState(detail_initial)

        # Record a hypothesis audit event
        await record_hypothesis(
            session=session,
            assessment_id=assessment_id,
            run_id="run-1",
            role="discovery",
            statement="Stored XSS vulnerability in feedback forum",
            asset="127.0.0.1",
        )

        # Refresh detail
        detail_updated = await load_assessment_detail(session, assessment_id)
        assert detail_updated is not None

        # Compute diff
        events = stream_state.diff(detail_updated)
        reasoning_events = [e for e in events if e.type == EventType.REASONING]
        assert len(reasoning_events) == 1
        board_data = reasoning_events[0].data["board"]
        assert len(board_data["hypotheses"]) == 1
        assert board_data["hypotheses"][0]["statement"] == "Stored XSS vulnerability in feedback forum"
