import json

import pytest
from langchain_core.messages import AIMessage
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command
from sqlmodel import Session, select

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
from app.actions import catalogue
from app.core import db
from app.core.config import settings
from app.core.db import init_db, make_engine
from app.domain.models import (
    Assessment,
    Evidence,
    Finding,
    Step,
    StepStatus,
    utcnow,
)


@pytest.fixture
def engine(tmp_path, monkeypatch):
    engine = make_engine(f"sqlite:///{tmp_path / 'agent.db'}")
    init_db(engine)
    monkeypatch.setattr(db, "_engine", engine)
    monkeypatch.setattr(catalogue, "ARTIFACT_DIR", tmp_path / "artifacts")
    with Session(engine) as session:
        assessment = Assessment(
            title="Three-role lab",
            request="Authorized loopback lab",
            targets=["127.0.0.1"],
            ports=[3000],
        )
        session.add(assessment)
        session.commit()
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
            session.commit()
            session.refresh(step)
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

    def invoke(self, payload, config=None):
        self.invocations.append(payload)
        index = self.calls
        self.calls += 1
        actions = self.turns[index] if index < len(self.turns) else []
        for tool_object, arguments in actions:
            self.results.append((tool_object.name, tool_object.invoke(arguments)))
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
    monkeypatch.setattr(
        "app.integrations.juiceshop.capture_baseline", lambda *args, **kwargs: None
    )
    monkeypatch.setattr("app.agents.graph._challenge_delta", lambda assessment_id: None)


def _fake_report(tmp_path, monkeypatch):
    def report(session, assessment_id):
        path = tmp_path / "report.pdf"
        path.write_bytes(b"%PDF-1.4 fake")
        assessment = session.get(Assessment, assessment_id)
        assessment.report_path = str(path)
        assessment.report_sha256 = "abc123"
        session.commit()
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


def _seed_service(engine):
    with Session(engine) as session:
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
        session.commit()
        session.refresh(finding)
        return finding.id


def _seed_finding(engine, status="suspected"):
    with Session(engine) as session:
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
        session.commit()
        session.refresh(finding)
        return finding.id


def _resume(graph, decision="approved"):
    return graph.invoke(
        Command(
            resume={
                "decision": decision,
                "actor": "tester",
                "reason": "test",
            }
        ),
        graph_config(1),
    )


def _interrupt(graph):
    snapshot = graph.get_state(graph_config(1))
    return snapshot, snapshot.interrupts[0].value


def test_three_roles_run_in_order_with_separate_transcripts(
    engine, fake_executor, tmp_path, monkeypatch
):
    _patch_bonus(monkeypatch)
    _fake_report(tmp_path, monkeypatch)
    _require_approval_for_all(monkeypatch)
    service_id = _seed_service(engine)
    finding_id = _seed_finding(engine)

    with Session(engine) as session:
        prepare_run(session, 1, actor="tester")

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
    graph.invoke(initial_state(1, "run-three"), graph_config(1))

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

    assert graph.get_state(graph_config(1)).next == ()
    with Session(engine) as session:
        assessment = session.get(Assessment, 1)
        assert assessment.status == "completed"
        assert assessment.report_path.endswith("report.pdf")
        history = control.role_history(session, 1, "run-three")
        assert [row["role"] for row in history] == [
            "recon",
            "discovery",
            "validation",
        ]
        handoffs = control.handoff_history(session, 1, "run-three")
        assert [row["role"] for row in handoffs] == [
            "recon",
            "discovery",
            "validation",
        ]
        assert handoffs[-1]["next_recommendation"] == "review"

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
    graph.invoke(initial_state(1, "run-reject"), graph_config(1))

    pending = _interrupt(graph)[1]
    assert pending["action"] == "recon_services"

    _resume(graph, decision="rejected")
    snapshot, pending = _interrupt(graph)
    assert "review" in snapshot.next
    assert pending["gate"] == "review"
    assert fake_executor.calls == []

    with Session(engine) as session:
        step = session.exec(select(Step)).one()
        assert step.status == "rejected"
        assert step.error == "test"


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
    graph.invoke(initial_state(1, "run-multi"), graph_config(1))

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

    with Session(engine) as session:
        steps = session.exec(select(Step).order_by(Step.seq)).all()
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
    graph.invoke(initial_state(1, "run-verify"), graph_config(1))

    assert _interrupt(graph)[1]["action"] == "recon_services"
    _resume(graph)

    pending = _interrupt(graph)[1]
    assert pending["action"] == "http_probe"
    assert pending["finding_id"] == finding_id
    _resume(graph)

    snapshot, pending = _interrupt(graph)
    assert "review" in snapshot.next
    assert pending["gate"] == "review"

    with Session(engine) as session:
        finding = session.get(Finding, finding_id)
        assert finding.status == "confirmed"
        evidence = session.exec(select(Evidence)).one()
        assert evidence.locator["tool"] == "http_probe"
        assert evidence.step_id is not None

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
        refused = http_probe.invoke(
            {
                "method": "GET",
                "url": "http://127.0.0.1:3000/",
            }
        )
        assert "validation role" in refused["error"]

        refused_scan = web_scan.invoke(
            {"scanner": "nikto", "target": "127.0.0.1"}
        )
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
        refused = update_finding_status.invoke(
            {
                "finding_id": finding_id,
                "status": "confirmed",
                "reasoning": "no probe yet",
            }
        )
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
        first = handoff.invoke(
            {
                "summary": "Port 3000 is open.",
                "next_recommendation": "review",
            }
        )
        assert first["handoff_recorded"] is True
        current_run_id.reset(token_r)

        token_b = current_run_id.set("run-b")
        second = handoff.invoke(
            {
                "summary": "Nothing else to do.",
                "next_recommendation": "review",
            }
        )
        assert second["handoff_recorded"] is True
        current_run_id.reset(token_b)
    finally:
        current_role.reset(token_role)
        current_assessment_id.reset(token_a)

    with Session(engine) as session:
        run_a = control.handoff_history(session, 1, "run-a")
        run_b = control.handoff_history(session, 1, "run-b")
        assert [row["summary"] for row in run_a] == ["Port 3000 is open."]
        assert [row["summary"] for row in run_b] == ["Nothing else to do."]
        assert control.latest_handoff(session, 1, "missing-run") is None


def test_scope_duplicate_and_budget_refusals(engine, monkeypatch):
    token_a = current_assessment_id.set(1)
    token_r = current_run_id.set("run-policy")
    token_role = current_role.set("recon")
    try:
        out_of_scope = scan_services.invoke(
            {"target": "10.0.0.1", "rationale": "not authorised"}
        )
        assert "not in scope" in out_of_scope["error"]

        first = scan_services.invoke(
            {"target": "127.0.0.1", "rationale": "discovery"}
        )
        assert first["queued"] is True

        duplicate = scan_services.invoke(
            {"target": "127.0.0.1", "rationale": "again"}
        )
        assert duplicate["duplicate_of_step"] == first["step_id"]

        monkeypatch.setattr(settings, "max_steps", 0)
        exhausted = scan_services.invoke(
            {"target": "127.0.0.1", "rationale": "over budget"}
        )
        assert "budget exhausted" in exhausted["error"]
    finally:
        current_role.reset(token_role)
        current_run_id.reset(token_r)
        current_assessment_id.reset(token_a)
