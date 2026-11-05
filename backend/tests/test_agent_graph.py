import json

import pytest
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command
from sqlmodel import Session, select

from app.agents import control
from app.agents.context import current_assessment_id, current_run_id
from app.agents.graph import (
    build_assessment_graph,
    graph_config,
    initial_state,
    prepare_run,
)
from app.agents.tools import (
    advance_phase,
    finish,
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
            title="Agent loop lab",
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
    """Test double for the LLM: calls real tools, no model involved."""

    def __init__(self, turns):
        self.turns = list(turns)
        self.calls = 0
        self.results = []

    def invoke(self, payload, config=None):
        from langchain_core.messages import AIMessage

        index = self.calls
        self.calls += 1
        actions = (
            self.turns[index]
            if index < len(self.turns)
            else [(finish, {"reason": "script exhausted"})]
        )
        for tool_object, arguments in actions:
            self.results.append((tool_object.name, tool_object.invoke(arguments)))
        return {
            "messages": [
                *payload["messages"],
                AIMessage(content=f"turn {index + 1}", id=f"ai-{index + 1}"),
            ]
        }


def _graph(agent, executor):
    return build_assessment_graph(
        checkpointer=InMemorySaver(),
        agent_factory=lambda: agent,
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


def _seed_finding(engine, status="suspected"):
    with Session(engine) as session:
        finding = Finding(
            assessment_id=1,
            canonical_key="test:exposed-document",
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


def test_scan_gate_then_review_and_report(engine, fake_executor, tmp_path, monkeypatch):
    _patch_bonus(monkeypatch)
    _fake_report(tmp_path, monkeypatch)

    with Session(engine) as session:
        prepare_run(session, 1, actor="tester")

    agent = ScriptedAgent(
        [
            [(scan_services, {"target": "127.0.0.1", "rationale": "services first"})],
            [
                (advance_phase, {"phase": "validation", "reason": "scan done"}),
                (finish, {"reason": "coverage adequate"}),
            ],
        ]
    )
    graph = _graph(agent, fake_executor)
    graph.invoke(initial_state(1, "run-1"), graph_config(1))

    snapshot = graph.get_state(graph_config(1))
    assert "gate" in snapshot.next
    gate = snapshot.interrupts[0].value
    assert gate["gate"] == "action"
    assert gate["action"] == "recon_services"
    assert gate["argv"][0] == "nmap"

    with Session(engine) as session:
        assert session.get(Assessment, 1).status == "awaiting_approval"

    _resume(graph)
    snapshot = graph.get_state(graph_config(1))
    assert "review" in snapshot.next
    assert snapshot.interrupts[0].value["gate"] == "review"
    assert fake_executor.calls[0]["action"] == "recon_services"
    assert fake_executor.calls[0]["argv"][0] == "nmap"

    with Session(engine) as session:
        history = control.phase_history(session, 1, "run-1")
        assert [row["to"] for row in history] == ["recon", "validation"]

    _resume(graph)
    assert graph.get_state(graph_config(1)).next == ()
    with Session(engine) as session:
        assessment = session.get(Assessment, 1)
        assert assessment.status == "completed"
        assert assessment.report_path.endswith("report.pdf")


def test_rejected_action_is_never_executed(engine, fake_executor, tmp_path, monkeypatch):
    _patch_bonus(monkeypatch)
    _fake_report(tmp_path, monkeypatch)

    agent = ScriptedAgent(
        [
            [(web_scan, {"scanner": "nikto", "target": "127.0.0.1", "rationale": "x"})],
            [(finish, {"reason": "nothing else to do"})],
        ]
    )
    graph = _graph(agent, fake_executor)
    graph.invoke(initial_state(1, "run-reject"), graph_config(1))

    gate = graph.get_state(graph_config(1)).interrupts[0].value
    assert gate["action"] == "nikto_scan"

    _resume(graph, decision="rejected")
    snapshot = graph.get_state(graph_config(1))
    assert "review" in snapshot.next
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

    agent = ScriptedAgent(
        [
            [
                (scan_services, {"target": "127.0.0.1", "rationale": "services"}),
                (web_scan, {"scanner": "nikto", "target": "127.0.0.1", "rationale": "web"}),
            ],
            [(finish, {"reason": "nothing else to do"})],
        ]
    )
    graph = _graph(agent, fake_executor)
    graph.invoke(initial_state(1, "run-multi"), graph_config(1))

    first = graph.get_state(graph_config(1)).interrupts[0].value
    assert first["action"] == "recon_services"

    _resume(graph, decision="approved")
    second = graph.get_state(graph_config(1)).interrupts[0].value
    assert second["action"] == "nikto_scan"
    assert second["step_id"] != first["step_id"]

    _resume(graph, decision="rejected")
    snapshot = graph.get_state(graph_config(1))
    assert "review" in snapshot.next
    assert [call["action"] for call in fake_executor.calls] == ["recon_services"]

    with Session(engine) as session:
        steps = session.exec(select(Step).order_by(Step.seq)).all()
        assert [step.action for step in steps] == ["recon_services", "nikto_scan"]
        assert steps[0].status == "succeeded"
        assert steps[1].status == "rejected"
        assert steps[1].error == "test"

    _resume(graph)
    with Session(engine) as session:
        assert session.get(Assessment, 1).status == "completed"


def test_probe_evidence_unlocks_a_verdict(
    engine, fake_executor, tmp_path, monkeypatch
):
    _patch_bonus(monkeypatch)
    _fake_report(tmp_path, monkeypatch)
    finding_id = _seed_finding(engine)

    agent = ScriptedAgent(
        [
            [
                (advance_phase, {"phase": "validation", "reason": "findings ready"}),
                (
                    http_probe,
                    {
                        "method": "GET",
                        "url": "http://127.0.0.1:3000/ftp/acquisitions.md",
                        "expected_status": 200,
                        "rationale": "document should require auth",
                        "finding_id": finding_id,
                    },
                ),
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
                (finish, {"reason": "verified the exposure"}),
            ],
        ]
    )
    graph = _graph(agent, fake_executor)
    graph.invoke(initial_state(1, "run-verify"), graph_config(1))

    gate = graph.get_state(graph_config(1)).interrupts[0].value
    assert gate["action"] == "http_probe"
    assert gate["finding_id"] == finding_id

    _resume(graph)
    snapshot = graph.get_state(graph_config(1))
    assert "review" in snapshot.next

    with Session(engine) as session:
        finding = session.get(Finding, finding_id)
        assert finding.status == "confirmed"
        evidence = session.exec(select(Evidence)).one()
        assert evidence.locator["tool"] == "http_probe"
        assert evidence.step_id is not None

    results = dict(agent.results)
    assert results["update_finding_status"]["updated"] is True


def test_verdict_and_probe_require_validation_phase(engine, fake_executor):
    finding_id = _seed_finding(engine)
    token_a = current_assessment_id.set(1)
    token_r = current_run_id.set("run-policy")
    try:
        blocked_probe = http_probe.invoke(
            {
                "method": "GET",
                "url": "http://127.0.0.1:3000/",
                "finding_id": finding_id,
            }
        )
        assert "validation" in blocked_probe["error"]

        blocked_verdict = update_finding_status.invoke(
            {
                "finding_id": finding_id,
                "status": "confirmed",
                "reasoning": "not allowed yet",
            }
        )
        assert "validation" in blocked_verdict["error"]

        moved = advance_phase.invoke({"phase": "validation", "reason": "ready"})
        assert moved["changed"] is True

        no_evidence = update_finding_status.invoke(
            {
                "finding_id": finding_id,
                "status": "confirmed",
                "reasoning": "no probe yet",
            }
        )
        assert "no executed http_probe evidence" in no_evidence["error"]
    finally:
        current_run_id.reset(token_r)
        current_assessment_id.reset(token_a)


def test_scope_duplicate_and_budget_refusals(engine, monkeypatch):
    token_a = current_assessment_id.set(1)
    token_r = current_run_id.set("run-policy")
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
        current_run_id.reset(token_r)
        current_assessment_id.reset(token_a)


def test_phase_and_finish_are_scoped_to_one_run(engine):
    token_a = current_assessment_id.set(1)
    token_r = current_run_id.set("run-control")
    try:
        advance_phase.invoke({"phase": "discovery", "reason": "scan results"})
        advance_phase.invoke({"phase": "validation", "reason": "hypotheses"})
        finish.invoke({"reason": "done"})
    finally:
        current_run_id.reset(token_r)
        current_assessment_id.reset(token_a)

    with Session(engine) as session:
        assert control.current_phase(session, 1, "run-control") == "validation"
        assert control.phase_history(session, 1, "run-control")[-1]["to"] == "validation"
        assert control.run_finished(session, 1, "run-control") is True
        assert control.run_finished(session, 1, "another-run") is False
        assert control.current_phase(session, 1, "another-run") == "recon"
