import pytest

pytest.skip(
    "stale against removed agent APIs; replaced by test_agent_wiring.py",
    allow_module_level=True,
)

import asyncio
import json

import pytest
from langchain_core.messages import AIMessage
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command
from sqlmodel import select

from app.actions import catalogue
from app.actions.executor import _active_processes, terminate_process
from app.agents import control
from app.agents.context import (
    current_assessment_id,
    current_role,
    current_run_id,
)
from app.agents.graph import (
    build_assessment_graph,
    graph_config,
    initial_state,
    prepare_run,
)
from app.agents.tools import (
    ROLE_TOOLS,
    handoff,
    http_probe,
    scan_services,
    update_finding_status,
    web_scan,
)
from app.core.config import settings
from app.core.db import (
    get_async_session_ctx,
    init_db,
    make_engine,
    set_engine,
)
from app.domain.models import (
    Assessment,
    AssessmentStatus,
    Evidence,
    Finding,
    Step,
    StepStatus,
    utcnow,
)
from app.runtime import runner


@pytest.fixture
def engine(tmp_path, monkeypatch):
    engine = make_engine(f"sqlite:///{tmp_path / 'agent.db'}")
    asyncio.run(init_db(engine))
    set_engine(engine)
    monkeypatch.setattr(catalogue, "ARTIFACT_DIR", tmp_path / "artifacts")

    async def seed():
        async with get_async_session_ctx() as session:
            session.add(
                Assessment(
                    title="Three-role lab",
                    request="Authorized loopback lab",
                    targets=["127.0.0.1"],
                    ports=[3000],
                )
            )
            await session.commit()

    asyncio.run(seed())
    return engine


@pytest.fixture
def fake_executor(tmp_path):
    class Executor:
        def __init__(self):
            self.calls = []

        async def __call__(
            self,
            session,
            assessment_id,
            action,
            target=None,
            rationale="",
            timeout=None,
            step=None,
        ):
            self.calls.append(
                {"action": action, "target": target, "argv": list(step.argv)}
            )
            step.status = StepStatus.SUCCEEDED.value
            step.exit_code = 0
            step.ended_at = utcnow()
            if action == "http_probe":
                artifact = tmp_path / f"probe-{step.id}.json"
                artifact.write_text(
                    json.dumps(
                        {
                            "probe_result": {
                                "status_code": 200,
                                "headers": {"content-type": "text/plain"},
                                "body_preview": "acquisitions secrets",
                            }
                        }
                    ),
                    encoding="utf-8",
                )
                step.output_path = str(artifact)
                step.output_sha256 = "deadbeef"
            await session.commit()
            await session.refresh(step)
            return step

    return Executor()


class ScriptedAgent:
    """Test double for one role's LLM: calls real tools, no model involved."""

    def __init__(self, role, turns):
        self.role = role
        self.turns = list(turns)
        self.calls = 0
        self.invocations = []
        self.results = []

    async def ainvoke(self, payload, config=None):
        self.invocations.append(payload)
        index = self.calls
        self.calls += 1
        actions = self.turns[index] if index < len(self.turns) else []
        for tool_object, arguments in actions:
            result = await tool_object.ainvoke(arguments)
            self.results.append((tool_object.name, result))
        return {
            "messages": [
                *payload["messages"],
                AIMessage(
                    content=f"{self.role} turn {index + 1}",
                    id=f"{self.role}-ai-{index + 1}",
                ),
            ]
        }


def _agents(scripts):
    return {
        role: ScriptedAgent(role, turns)
        for role, turns in scripts.items()
    }


def _graph(agents, executor):
    return build_assessment_graph(
        checkpointer=InMemorySaver(),
        agent_factory=lambda role: agents[role],
        executor=executor,
    )


def _patch_bonus(monkeypatch):
    async def no_baseline(*args, **kwargs):
        return None

    async def no_delta(assessment_id):
        return None

    monkeypatch.setattr(
        "app.integrations.juiceshop.capture_baseline", no_baseline
    )
    monkeypatch.setattr("app.agents.graph._challenge_delta", no_delta)


def _fake_report(tmp_path, monkeypatch):
    async def report(session, assessment_id):
        path = tmp_path / "report.pdf"
        path.write_bytes(b"%PDF-1.4 fake")
        assessment = await session.get(Assessment, assessment_id)
        assessment.report_path = str(path)
        assessment.report_sha256 = "abc123"
        await session.commit()
        return path

    monkeypatch.setattr("app.agents.graph.generate_report", report)


def _require_approval_for_all(monkeypatch):
    """Force every action to require human approval at the gate.

    Used by tests that need to exercise the interrupt/resume flow regardless
    of the default policy (which auto-approves low-risk actions).
    """
    from app.core.policy import ActionPolicy, DEFAULT_ACTION_POLICIES

    all_gated = {
        name: ActionPolicy(risk=pol.risk, approve=True)
        for name, pol in DEFAULT_ACTION_POLICIES.items()
    }
    monkeypatch.setattr("app.agents.gate._policies", lambda: all_gated)
    # Clear the cache so the new function is used.
    import app.agents.gate as _gate_module

    _gate_module._policy_cache = None


async def _run_db(fn):
    async with get_async_session_ctx() as session:
        return await fn(session)


def _db(fn):
    return asyncio.run(_run_db(fn))


def _seed_service(engine):
    async def seed():
        async with get_async_session_ctx() as session:
            finding = Finding(
                assessment_id=1,
                canonical_key="nmap:127.0.0.1:tcp/3000",
                asset="127.0.0.1",
                endpoint="tcp/3000",
                title="Open tcp/3000 (http)",
                severity="info",
                status="suspected",
            )
            session.add(finding)
            await session.commit()
            await session.refresh(finding)
            return finding.id

    return asyncio.run(seed())


def _seed_finding(engine, status="suspected"):
    async def seed():
        async with get_async_session_ctx() as session:
            finding = Finding(
                assessment_id=1,
                canonical_key="web:exposed-file:127.0.0.1:3000",
                asset="127.0.0.1",
                endpoint="/ftp/acquisitions.md",
                title="Exposed acquisitions document",
                severity="high",
                status=status,
            )
            session.add(finding)
            await session.commit()
            await session.refresh(finding)
            return finding.id

    return asyncio.run(seed())


def _prepare(actor="tester"):
    async def run():
        async with get_async_session_ctx() as session:
            await prepare_run(session, 1, actor=actor)

    asyncio.run(run())


def _resume(graph, decision="approved"):
    return asyncio.run(graph.ainvoke(
        Command(
            resume={
                "decision": decision,
                "actor": "tester",
                "reason": "test",
            }
        ),
        graph_config(1),
    ))


def _interrupt(graph):
    snapshot = asyncio.run(graph.aget_state(graph_config(1)))
    return snapshot, snapshot.interrupts[0].value


def test_three_roles_run_in_order_with_separate_transcripts(
    engine, fake_executor, tmp_path, monkeypatch
):
    _patch_bonus(monkeypatch)
    _fake_report(tmp_path, monkeypatch)
    _require_approval_for_all(monkeypatch)
    service_id = _seed_service(engine)
    finding_id = _seed_finding(engine)

    _prepare()

    agents = _agents(
        {
            "recon": [
                [(scan_services, {"target": "127.0.0.1", "rationale": "services first"})],
                [
                    (
                        handoff,
                        {
                            "summary": "Port 3000 is open; discovery can scan HTTP.",
                            "step_ids": [],
                            "next_recommendation": "discovery",
                        },
                    )
                ],
            ],
            "discovery": [
                [
                    (
                        web_scan,
                        {
                            "scanner": "nikto",
                            "target": "127.0.0.1",
                            "rationale": "configuration and exposed files",
                        },
                    )
                ],
                [
                    (
                        handoff,
                        {
                            "summary": "Nikto produced the exposed document candidate.",
                            "finding_ids": [finding_id],
                            "next_recommendation": "validation",
                        },
                    )
                ],
            ],
            "validation": [
                [
                    (
                        http_probe,
                        {
                            "method": "GET",
                            "url": "http://127.0.0.1:3000/ftp/acquisitions.md",
                            "expected_status": 200,
                            "rationale": "document should require auth",
                            "finding_id": finding_id,
                        },
                    )
                ],
                [
                    (
                        update_finding_status,
                        {
                            "finding_id": finding_id,
                            "status": "confirmed",
                            "reasoning": "GET returned 200 with the document body",
                        },
                    ),
                    (
                        handoff,
                        {
                            "summary": "The exposed document is confirmed.",
                            "finding_ids": [finding_id],
                            "next_recommendation": "review",
                        },
                    ),
                ],
            ],
        }
    )
    graph = _graph(agents, fake_executor)
    asyncio.run(graph.ainvoke(initial_state(1, "run-three"), graph_config(1)))

    for expected_action in ("recon_services", "nikto_scan", "http_probe"):
        snapshot, pending = _interrupt(graph)
        assert "gate" in snapshot.next
        assert pending["gate"] == "action"
        assert pending["action"] == expected_action
        assert pending["role"] in {"recon", "discovery", "validation"}
        _resume(graph)

    snapshot, pending = _interrupt(graph)
    assert "review" in snapshot.next
    assert pending["gate"] == "review"
    _resume(graph)

    assert asyncio.run(graph.aget_state(graph_config(1))).next == ()

    async def check(session):
        assessment = await session.get(Assessment, 1)
        assert assessment.status == "completed"
        assert assessment.report_path.endswith("report.pdf")
        history = await control.role_history(session, 1, "run-three")
        assert [row["role"] for row in history] == [
            "recon",
            "discovery",
            "validation",
        ]
        handoffs = await control.handoff_history(session, 1, "run-three")
        assert [row["role"] for row in handoffs] == [
            "recon",
            "discovery",
            "validation",
        ]
        assert handoffs[-1]["next_recommendation"] == "review"

    _db(check)

    # Each role gets its own local message list. Discovery and validation must
    # never receive the reconnaissance transcript.
    assert "recon-ai" in str(agents["recon"].invocations[-1]["messages"])
    assert "recon-ai" not in str(agents["discovery"].invocations[0]["messages"])
    assert "discovery-ai" not in str(agents["validation"].invocations[0]["messages"])
    assert service_id is not None


def test_rejected_action_is_never_executed(engine, fake_executor, tmp_path, monkeypatch):
    _patch_bonus(monkeypatch)
    _fake_report(tmp_path, monkeypatch)
    _require_approval_for_all(monkeypatch)

    agents = _agents(
        {
            "recon": [
                [(scan_services, {"target": "127.0.0.1", "rationale": "services"})],
                [
                    (
                        handoff,
                        {
                            "summary": "Recon has no further work.",
                            "next_recommendation": "review",
                        },
                    )
                ],
            ]
        }
    )
    graph = _graph(agents, fake_executor)
    asyncio.run(graph.ainvoke(initial_state(1, "run-reject"), graph_config(1)))

    pending = _interrupt(graph)[1]
    assert pending["action"] == "recon_services"

    _resume(graph, decision="rejected")
    snapshot, pending = _interrupt(graph)
    assert "review" in snapshot.next
    assert pending["gate"] == "review"
    assert fake_executor.calls == []

    async def check(session):
        result = await session.execute(select(Step))
        step = result.scalars().one()
        assert step.status == "rejected"
        assert step.error == "test"

    _db(check)


def test_each_queued_action_gets_its_own_gate(
    engine, fake_executor, tmp_path, monkeypatch
):
    """A rejected second action must not inherit the first action's approval."""
    _patch_bonus(monkeypatch)
    _fake_report(tmp_path, monkeypatch)
    _require_approval_for_all(monkeypatch)
    _seed_service(engine)
    finding_id = _seed_finding(engine)

    agents = _agents(
        {
            "recon": [
                [(scan_services, {"target": "127.0.0.1", "rationale": "services"})],
                [
                    (
                        handoff,
                        {
                            "summary": "Recon found HTTP.",
                            "next_recommendation": "discovery",
                        },
                    )
                ],
            ],
            "discovery": [
                [
                    (
                        web_scan,
                        {"scanner": "nikto", "target": "127.0.0.1", "rationale": "files"},
                    ),
                    (
                        web_scan,
                        {"scanner": "zap", "target": "127.0.0.1", "rationale": "baseline"},
                    ),
                ],
                [
                    (
                        handoff,
                        {
                            "summary": "Discovery handed the candidate to validation.",
                            "finding_ids": [finding_id],
                            "next_recommendation": "review",
                        },
                    )
                ],
            ],
            "validation": [
                [
                    (
                        http_probe,
                        {
                            "method": "GET",
                            "url": "http://127.0.0.1:3000/test",
                            "expected_status": 200,
                            "rationale": "validate candidate finding",
                            "finding_id": finding_id,
                        },
                    )
                ],
                [
                    (
                        handoff,
                        {
                            "summary": "Validation complete.",
                            "next_recommendation": "review",
                        },
                    )
                ],
            ],
        }
    )
    graph = _graph(agents, fake_executor)
    asyncio.run(graph.ainvoke(initial_state(1, "run-multi"), graph_config(1)))

    first = _interrupt(graph)[1]
    assert first["action"] == "recon_services"
    _resume(graph, decision="approved")

    second = _interrupt(graph)[1]
    assert second["action"] == "nikto_scan"
    _resume(graph, decision="approved")

    third = _interrupt(graph)[1]
    assert third["action"] == "zap_baseline"
    assert third["step_id"] not in {first["step_id"], second["step_id"]}
    _resume(graph, decision="rejected")

    fourth = _interrupt(graph)[1]
    assert fourth["action"] == "http_probe"
    _resume(graph, decision="approved")

    snapshot, pending = _interrupt(graph)
    assert "review" in snapshot.next
    assert pending["gate"] == "review"

    async def check(session):
        result = await session.execute(select(Step).order_by(Step.seq))
        steps = list(result.scalars().all())
        assert [step.action for step in steps] == [
            "recon_services",
            "nikto_scan",
            "zap_baseline",
            "http_probe",
        ]
        assert steps[0].status == "succeeded"
        assert steps[1].status == "succeeded"
        assert steps[2].status == "rejected"
        assert steps[2].error == "test"

    _db(check)

    assert [call["action"] for call in fake_executor.calls] == [
        "recon_services",
        "nikto_scan",
        "http_probe",
    ]


def test_probe_evidence_unlocks_a_verdict(engine, fake_executor, tmp_path, monkeypatch):
    _patch_bonus(monkeypatch)
    _fake_report(tmp_path, monkeypatch)
    _require_approval_for_all(monkeypatch)
    _seed_service(engine)
    finding_id = _seed_finding(engine)

    agents = _agents(
        {
            "recon": [
                [(scan_services, {"target": "127.0.0.1", "rationale": "services"})],
                [
                    (
                        handoff,
                        {
                            "summary": "Port 3000 is HTTP.",
                            "next_recommendation": "discovery",
                        },
                    )
                ],
            ],
            "discovery": [
                [
                    (
                        handoff,
                        {
                            "summary": "A candidate is ready for validation.",
                            "finding_ids": [finding_id],
                            "next_recommendation": "validation",
                        },
                    )
                ]
            ],
            "validation": [
                [
                    (
                        http_probe,
                        {
                            "method": "GET",
                            "url": "http://127.0.0.1:3000/ftp/acquisitions.md",
                            "expected_status": 200,
                            "rationale": "document should require auth",
                            "finding_id": finding_id,
                        },
                    )
                ],
                [
                    (
                        update_finding_status,
                        {
                            "finding_id": finding_id,
                            "status": "confirmed",
                            "reasoning": "GET returned 200 with the document body",
                        },
                    ),
                    (
                        handoff,
                        {
                            "summary": "The exposure is confirmed.",
                            "finding_ids": [finding_id],
                            "next_recommendation": "review",
                        },
                    ),
                ],
            ],
        }
    )
    graph = _graph(agents, fake_executor)
    asyncio.run(graph.ainvoke(initial_state(1, "run-verify"), graph_config(1)))

    assert _interrupt(graph)[1]["action"] == "recon_services"
    _resume(graph)

    pending = _interrupt(graph)[1]
    assert pending["action"] == "http_probe"
    assert pending["finding_id"] == finding_id
    _resume(graph)

    snapshot, pending = _interrupt(graph)
    assert "review" in snapshot.next
    assert pending["gate"] == "review"

    async def check(session):
        finding = await session.get(Finding, finding_id)
        assert finding.status == "confirmed"
        result = await session.execute(select(Evidence))
        evidence = result.scalars().one()
        assert evidence.locator["tool"] == "http_probe"
        assert evidence.step_id is not None

    _db(check)

    results = dict(agents["validation"].results)
    assert results["update_finding_status"]["updated"] is True


def test_role_tool_sets_are_separate_and_enforced(engine):
    recon_tools = {tool.name for tool in ROLE_TOOLS["recon"]}
    discovery_tools = {tool.name for tool in ROLE_TOOLS["discovery"]}
    validation_tools = {tool.name for tool in ROLE_TOOLS["validation"]}

    assert "scan_services" in recon_tools
    assert "nmap_scan" in recon_tools
    assert "web_scan" not in recon_tools
    assert "http_probe" not in recon_tools
    assert "web_scan" in discovery_tools
    assert "nikto_scan" in discovery_tools
    assert "sqlmap_scan" in discovery_tools
    assert "dirb_scan" in discovery_tools
    assert "http_probe" not in discovery_tools
    assert "http_probe" in validation_tools
    assert "scan_services" not in validation_tools
    assert "handoff" in recon_tools & discovery_tools & validation_tools

    token_a = current_assessment_id.set(1)
    token_r = current_run_id.set("run-policy")
    token_role = current_role.set("recon")
    try:
        refused = asyncio.run(http_probe.ainvoke(
            {
                "method": "GET",
                "url": "http://127.0.0.1:3000/",
            }
        ))
        assert "validation role" in refused["error"]

        refused_scan = asyncio.run(web_scan.ainvoke(
            {"scanner": "nikto", "target": "127.0.0.1"}
        ))
        assert "discovery role" in refused_scan["error"]
    finally:
        current_role.reset(token_role)
        current_run_id.reset(token_r)
        current_assessment_id.reset(token_a)


def test_verdict_requires_executed_probe_evidence(engine):
    finding_id = _seed_finding(engine)
    token_a = current_assessment_id.set(1)
    token_r = current_run_id.set("run-verdict")
    token_role = current_role.set("validation")
    try:
        refused = asyncio.run(update_finding_status.ainvoke(
            {
                "finding_id": finding_id,
                "status": "confirmed",
                "reasoning": "no probe yet",
            }
        ))
        assert "no executed http_probe evidence" in refused["error"]
    finally:
        current_role.reset(token_role)
        current_run_id.reset(token_r)
        current_assessment_id.reset(token_a)


def test_handoffs_are_scoped_to_one_run(engine):
    token_a = current_assessment_id.set(1)
    token_role = current_role.set("recon")

    try:
        token_r = current_run_id.set("run-a")
        first = asyncio.run(handoff.ainvoke(
            {
                "summary": "Port 3000 is open.",
                "next_recommendation": "review",
            }
        ))
        assert first["handoff_recorded"] is True
        current_run_id.reset(token_r)

        token_b = current_run_id.set("run-b")
        second = asyncio.run(handoff.ainvoke(
            {
                "summary": "Nothing else to do.",
                "next_recommendation": "review",
            }
        ))
        assert second["handoff_recorded"] is True
        current_run_id.reset(token_b)
    finally:
        current_role.reset(token_role)
        current_assessment_id.reset(token_a)

    async def check(session):
        run_a = await control.handoff_history(session, 1, "run-a")
        run_b = await control.handoff_history(session, 1, "run-b")
        assert [row["summary"] for row in run_a] == ["Port 3000 is open."]
        assert [row["summary"] for row in run_b] == ["Nothing else to do."]
        assert await control.latest_handoff(session, 1, "missing-run") is None

    _db(check)


def test_scope_duplicate_and_budget_refusals(engine, monkeypatch):
    token_a = current_assessment_id.set(1)
    token_r = current_run_id.set("run-policy")
    token_role = current_role.set("recon")
    try:
        out_of_scope = asyncio.run(scan_services.ainvoke(
            {"target": "10.0.0.1", "rationale": "not authorised"}
        ))
        assert "not in scope" in out_of_scope["error"]

        first = asyncio.run(scan_services.ainvoke(
            {"target": "127.0.0.1", "rationale": "discovery"}
        ))
        assert first["queued"] is True

        duplicate = asyncio.run(scan_services.ainvoke(
            {"target": "127.0.0.1", "rationale": "again"}
        ))
        assert duplicate["duplicate_of_step"] == first["step_id"]

        monkeypatch.setattr(settings, "max_steps", 0)
        exhausted = asyncio.run(scan_services.ainvoke(
            {"target": "127.0.0.1", "rationale": "over budget"}
        ))
        assert "budget exhausted" in exhausted["error"]
    finally:
        current_role.reset(token_role)
        current_run_id.reset(token_r)
        current_assessment_id.reset(token_a)


def test_stop_run_marks_assessment_cancelled(engine):
    """stop_run marks a running assessment cancelled and clears state."""
    async def setup():
        async with get_async_session_ctx() as session:
            assessment = Assessment(
                title="stop test",
                request="test",
                targets=["127.0.0.1"],
                ports=[3000],
                status=AssessmentStatus.RUNNING.value,
            )
            session.add(assessment)
            await session.commit()
            await session.refresh(assessment)

    asyncio.run(setup())

    result = asyncio.run(runner.stop_run(1))

    assert result.status == AssessmentStatus.CANCELLED.value

    async def check(session):
        assessment = await session.get(Assessment, 1)
        assert assessment.status == AssessmentStatus.CANCELLED.value
        assert assessment.finished_at is not None

    _db(check)


def test_stop_run_terminates_inflight_process(engine, monkeypatch):
    """stop_run terminates a registered subprocess for the assessment."""
    async def setup():
        async with get_async_session_ctx() as session:
            assessment = Assessment(
                title="stop proc test",
                request="test",
                targets=["127.0.0.1"],
                ports=[3000],
                status=AssessmentStatus.RUNNING.value,
            )
            session.add(assessment)
            await session.commit()

    asyncio.run(setup())

    # Register a fake process that is still running
    class FakeProcess:
        returncode = None

        def terminate(self):
            self.terminated = True

        def kill(self):
            self.killed = True

        async def wait(self):
            return None

    proc = FakeProcess()
    proc.terminated = False
    proc.killed = False

    _active_processes[1] = proc

    asyncio.run(runner.stop_run(1))

    assert proc.terminated is True
    assert 1 not in _active_processes
