"""Focused regression tests for the queue-era wiring and Phase 0 fixes.

These replace the stale ``test_agent_graph.py`` assertions while the v2 loop is
being built. They deliberately avoid a live LLM or subprocess.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest
from sqlmodel import select

from app.actions import catalogue, check_scope, get_action, resolve_argv
from app.actions import probe
from app.actions.catalogue import ScopeError
from app.agents.specialists.discovery.state import DiscoveryState
from app.agents.specialists.recon.state import ReconState
from app.agents.specialists.validation.state import ValidationState
from app.agents.tools import ROLE_TOOLS, set_context
from app.api.queries import load_assessment_detail
from app.api.schema import DecisionIn
from app.core.config import settings
from app.core.db import get_async_session_ctx, init_db, make_engine, set_engine
from app.domain.models import (
    Assessment,
    AssessmentStatus,
    Approval,
    Decision,
    Evidence,
    Finding,
    Step,
)
from app.persistence import FindingRepo, StepRepo
from app.persistence.step_repo import _step_matches
from app.runtime import runner


@pytest.fixture
def engine(tmp_path, monkeypatch):
    engine = make_engine(f"sqlite:///{tmp_path / 'wiring.db'}")
    asyncio.run(init_db(engine))
    set_engine(engine)
    monkeypatch.setattr(catalogue, "ARTIFACT_DIR", tmp_path / "artifacts")
    return engine


async def _assessment(session) -> Assessment:
    assessment = Assessment(
        title="Lab", request="lab only", targets=["127.0.0.1"], ports=[3000]
    )
    session.add(assessment)
    await session.commit()
    await session.refresh(assessment)
    return assessment


def _run(fn):
    async def runner():
        async with get_async_session_ctx() as session:
            return await fn(session)

    return asyncio.run(runner())


def test_role_tools_are_unique_and_scoped():
    expected_actions = {
        "recon": {"recon_services"},
        "discovery": {"dirb_scan", "nikto_scan", "zap_baseline"},
        "validation": {"curl_tool", "sqlmap_scan", "update_finding_status"},
    }
    assert set(ROLE_TOOLS) == {"recon", "discovery", "validation"}
    for role, tools in ROLE_TOOLS.items():
        names = [getattr(tool, "name", "") for tool in tools]
        assert len(names) == len(set(names))
        action_names = {n for n in names if n in expected_actions[role]}
        assert action_names == expected_actions[role]


def test_scope_normalizes_hosts_and_supports_cidr():
    assessment = Assessment(
        id=1,
        title="Lab",
        targets=["127.0.0.1", "Example.COM.", "10.0.0.0/24"],
        ports=[3000],
    )

    check_scope(assessment, "127.0.0.1")
    check_scope(assessment, "localhost")
    check_scope(assessment, "example.com")
    check_scope(assessment, "10.0.0.42")

    with pytest.raises(ScopeError):
        check_scope(assessment, "example.org")
    with pytest.raises(ScopeError):
        check_scope(assessment, "10.0.1.5")


def test_exclusions_override_inclusive_scope():
    assessment = Assessment(
        id=1,
        title="Lab",
        targets=["10.0.0.0/24", "localhost"],
        exclusions=["10.0.0.9", "127.0.0.1"],
        ports=[3000],
    )

    with pytest.raises(ScopeError):
        check_scope(assessment, "10.0.0.9")
    with pytest.raises(ScopeError):
        check_scope(assessment, "localhost")
    check_scope(assessment, "10.0.0.10")


def test_step_matches_distinguishes_paths_and_methods():
    step = Step(
        assessment_id=1,
        seq=1,
        action="http_probe",
        target="127.0.0.1",
        argv=[
            "http_probe",
            "GET",
            "http://127.0.0.1:3000/login",
            "{}",
            "200",
            "",
        ],
    )
    assert _step_matches(step, "127.0.0.1", {"path": "/login", "method": "GET"})
    assert not _step_matches(
        step, "127.0.0.1", {"path": "/admin", "method": "GET"}
    )
    assert not _step_matches(
        step, "127.0.0.1", {"path": "/login", "method": "POST"}
    )
    assert not _step_matches(step, "10.0.0.1", {"path": "/login"})


def test_resolve_argv_http_probe_stays_local(monkeypatch, tmp_path):
    monkeypatch.setattr(catalogue, "ARTIFACT_DIR", tmp_path)
    monkeypatch.setattr(settings, "mcp_enabled", True)
    monkeypatch.setattr(settings, "mcp_transport", "gateway")

    assessment = Assessment(
        id=1, title="Lab", targets=["127.0.0.1"], ports=[3000]
    )
    argv = resolve_argv(
        "http_probe",
        assessment,
        "127.0.0.1",
        1,
        params={
            "path": "/login?next=/",
            "method": "POST",
            "headers": {"X-Test": "1"},
            "expected_status": 401,
            "body": "a=1",
        },
    )

    assert argv[0] == "http_probe"
    assert argv[1] == "POST"
    assert argv[2] == "http://127.0.0.1:3000/login?next=/"
    assert json.loads(argv[3]) == {"X-Test": "1"}
    assert argv[4] == "401"
    assert argv[5] == "a=1"


def test_sqlmap_output_is_stdout():
    assert get_action("sqlmap_scan").output == "stdout"


def test_specialist_states_declare_steps():
    assert "steps" in ReconState.__annotations__
    assert "steps" in DiscoveryState.__annotations__
    assert "steps" in ValidationState.__annotations__


def test_decision_binds_to_a_specific_gate():
    decision = DecisionIn(
        decision="approved",
        approval_id=14,
        step_id=33,
    )
    assert decision.approval_id == 14
    assert decision.step_id == 33


def test_probe_canonical_key_includes_path_and_method():
    def payload(url: str, method: str) -> str:
        return json.dumps(
            {
                "probe_result": {
                    "url": url,
                    "method": method,
                    "status_code": 200,
                    "body_preview": "ok",
                }
            }
        )

    login = probe.parse(
        payload("http://127.0.0.1:3000/login", "GET"), "127.0.0.1", 3000
    )[0]
    admin = probe.parse(
        payload("http://127.0.0.1:3000/admin", "GET"), "127.0.0.1", 3000
    )[0]

    assert login.canonical_key != admin.canonical_key
    assert login.canonical_key == "web:probe:127.0.0.1:3000/login:GET"
    assert admin.canonical_key == "web:probe:127.0.0.1:3000/admin:GET"


def test_step_repo_dedupes_only_within_a_run(engine):
    async def body(session):
        assessment = await _assessment(session)
        repo = StepRepo(session)

        first = await repo.create_step(
            assessment=assessment,
            run_id="run-a",
            role="recon",
            action="recon_services",
            target="127.0.0.1",
            rationale="first scan",
        )
        duplicate = await repo.create_step(
            assessment=assessment,
            run_id="run-a",
            role="recon",
            action="recon_services",
            target="127.0.0.1",
            rationale="duplicate scan",
        )
        second_run = await repo.create_step(
            assessment=assessment,
            run_id="run-b",
            role="recon",
            action="recon_services",
            target="127.0.0.1",
            rationale="new run",
        )

        assert first["step_id"] != second_run["step_id"]
        assert duplicate["duplicate_of_step"] == first["step_id"]

        result = await session.execute(select(Step))
        assert len(result.scalars().all()) == 2

    _run(body)


def test_update_finding_status_requires_executed_probe_evidence(engine):
    async def body(session):
        assessment = await _assessment(session)
        finding = Finding(
            assessment_id=assessment.id,
            canonical_key="web:test:login",
            asset="127.0.0.1:3000",
            endpoint="/login",
            title="Login issue",
            severity="high",
            status="suspected",
        )
        session.add(finding)
        await session.commit()
        await session.refresh(finding)

        repo = FindingRepo(session)
        blocked = await repo.update_status(
            finding.id, assessment.id, "confirmed", "looks real"
        )
        assert "no executed http_probe evidence" in blocked["error"]

        session.add(
            Evidence(
                finding_id=finding.id,
                step_id=None,
                locator={
                    "tool": "curl_tool",
                    "url": "http://127.0.0.1:3000/login",
                    "http_status": 500,
                },
                excerpt="500",
            )
        )
        await session.commit()

        updated = await repo.update_status(
            finding.id, assessment.id, "confirmed", "quote variant returned 500"
        )
        assert updated["updated"] is True
        await session.refresh(finding)
        assert finding.status == "confirmed"

    _run(body)


def test_gate_open_respects_requires_approval(engine):
    async def body(session):
        assessment = await _assessment(session)
        assessment.status = AssessmentStatus.AWAITING_APPROVAL.value
        session.add(
            Approval(
                assessment_id=assessment.id,
                action="recon_services",
                argv=["nmap"],
                detail={"requires_approval": False},
                decision=Decision.PENDING.value,
            )
        )
        await session.commit()

        detail = await load_assessment_detail(session, assessment.id)
        assert detail is not None
        assert detail.gate_open is False

        approval = (
            await session.execute(
                select(Approval).where(
                    Approval.assessment_id == assessment.id
                )
            )
        ).scalars().one()
        approval.detail = {"requires_approval": True}
        session.add(approval)
        await session.commit()

        detail = await load_assessment_detail(session, assessment.id)
        assert detail is not None
        assert detail.gate_open is True

    _run(body)


def _gate_state(step_id: int = 33, approval_id: int = 14):
    return SimpleNamespace(
        next=("gate",),
        interrupts=(
            SimpleNamespace(
                value={
                    "gate": "action",
                    "step_id": step_id,
                    "approval_id": approval_id,
                }
            ),
        ),
        values={},
    )


def _patch_gate(monkeypatch, state, launched: list | None = None):
    class FakeGraph:
        async def aget_state(self, _config):
            return state

    async def fake_graph_for(_assessment_id):
        return FakeGraph(), {}

    monkeypatch.setattr(runner, "_graph_for", fake_graph_for)
    monkeypatch.setattr(runner, "is_running", lambda _assessment_id: False)
    monkeypatch.setattr(runner, "_locks", {})
    monkeypatch.setattr(
        runner,
        "_launch",
        lambda assessment_id, payload: launched.append((assessment_id, payload))
        if launched is not None
        else None,
    )


def test_resume_rejects_a_stale_gate(monkeypatch):
    _patch_gate(monkeypatch, _gate_state(step_id=33, approval_id=14))

    async def body():
        with pytest.raises(runner.StaleDecision):
            await runner.resume_run(
                1, {"decision": "approved", "step_id": 32, "approval_id": 14}
            )
        with pytest.raises(runner.StaleDecision):
            await runner.resume_run(
                1, {"decision": "approved", "step_id": 33, "approval_id": 13}
            )

    asyncio.run(body())


def test_resume_accepts_the_current_gate(engine, monkeypatch):
    launched: list = []
    _patch_gate(monkeypatch, _gate_state(step_id=33, approval_id=14), launched)
    sentinel = object()

    async def fake_get_view(_assessment_id, running=None):
        return sentinel

    monkeypatch.setattr(runner, "get_view", fake_get_view)

    async def body(session):
        assessment = await _assessment(session)
        decision = {
            "decision": "approved",
            "step_id": 33,
            "approval_id": 14,
        }
        view = await runner.resume_run(assessment.id, decision)

        assert view is sentinel
        assert len(launched) == 1
        assert launched[0][0] == assessment.id
        assert launched[0][1].resume == decision

    _run(body)


def test_resume_replays_an_identical_decision(engine, monkeypatch):
    _patch_gate(monkeypatch, SimpleNamespace(next=(), interrupts=(), values={}))
    sentinel = object()

    async def fake_get_view(_assessment_id, running=None):
        return sentinel

    monkeypatch.setattr(runner, "get_view", fake_get_view)

    async def body(session):
        assessment = await _assessment(session)
        approval = Approval(
            assessment_id=assessment.id,
            action="http_probe",
            argv=["http_probe"],
            decision=Decision.APPROVED.value,
        )
        session.add(approval)
        await session.commit()
        await session.refresh(approval)

        view = await runner.resume_run(
            assessment.id,
            {"decision": "approved", "approval_id": approval.id},
        )
        assert view is sentinel

        with pytest.raises(runner.NotPaused):
            await runner.resume_run(
                assessment.id,
                {"decision": "rejected", "approval_id": approval.id},
            )

    _run(body)


def test_one_action_per_specialist_turn(engine, monkeypatch):
    async def body(session):
        assessment = await _assessment(session)
        from app.agents.loop.nodes import model_node
        from langchain_core.language_models.chat_models import BaseChatModel
        from langchain_core.messages import AIMessage, HumanMessage
        from langchain_core.outputs import ChatGeneration, ChatResult

        class ScriptedTwoCalls(BaseChatModel):
            def bind_tools(self, tools, **kwargs):
                return self
            def _generate(self, messages, stop=None, run_manager=None, **kwargs):
                return ChatResult(generations=[ChatGeneration(message=AIMessage(
                    content="Running scans",
                    tool_calls=[
                        {
                            "id": "call_1",
                            "name": "recon_services",
                            "args": {"target": "127.0.0.1", "rationale": "first scan"},
                        },
                        {
                            "id": "call_2",
                            "name": "recon_services",
                            "args": {"target": "127.0.0.1", "rationale": "second scan in same turn"},
                        },
                    ],
                ))])
            @property
            def _llm_type(self):
                return "scripted-two-calls"

        monkeypatch.setattr("app.agents.loop.nodes.build_role_model", lambda role: ScriptedTwoCalls())

        state = {
            "assessment_id": assessment.id,
            "run_id": "test_run_one_action",
            "role": "recon",
            "turns": {"recon": 0},
            "nudges": 0,
            "no_progress": 0,
            "messages": [HumanMessage(content="Start recon")],
        }

        cmd = await model_node(state)
        # Verify first tool call is routed to prepare and extra call gets error ToolMessage
        assert cmd.goto == "prepare"
        extra_msg = cmd.update["messages"][-1]
        assert "Only one action tool call is executed per turn" in extra_msg.content
        assert extra_msg.tool_call_id == "call_2"

    _run(body)
