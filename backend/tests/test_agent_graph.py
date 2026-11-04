import asyncio
from datetime import datetime, timezone

import pytest
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command
from sqlmodel import Session, select

from app import agent
from app.agent import build_graph, graph_config, initial_state, prepare_run
from app.db import init_db, make_engine
from app.models import Approval, Assessment, Audit, Step
from app.planner import Plan, PlanError, PlanStep, deterministic_plan, validate_plan


@pytest.fixture
def engine(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'graph.db'}")
    init_db(engine)
    with Session(engine) as session:
        assessment = Assessment(
            title="Graph lab",
            request="Authorized loopback lab",
            targets=["127.0.0.1"],
            ports=[3000],
        )
        session.add(assessment)
        session.commit()
    return engine


@pytest.fixture
def fake_execute(monkeypatch):
    async def execute(session, assessment_id, action, target=None, rationale="", timeout=None, step=None):
        assert step is not None
        step.status = "succeeded"
        step.exit_code = 0
        step.ended_at = datetime.now(timezone.utc)
        session.commit()
        return step

    monkeypatch.setattr(agent, "execute_action", execute)


@pytest.fixture
def fake_report(tmp_path, monkeypatch):
    def report(session, assessment_id):
        path = tmp_path / "report.pdf"
        path.write_bytes(b"%PDF-1.4 fake")
        assessment = session.get(Assessment, assessment_id)
        assessment.report_path = str(path)
        assessment.report_sha256 = "abc123"
        session.commit()
        return path

    monkeypatch.setattr(agent, "generate_report", report)


def _graph(engine, planner):
    return build_graph(checkpointer=InMemorySaver(), engine=engine, planner=planner)


def _invoke(graph, assessment_id):
    return graph.invoke(initial_state(assessment_id), graph_config(assessment_id))


def _resume(graph, assessment_id, decision):
    return graph.invoke(
        Command(resume={"decision": decision, "actor": "tester", "reason": "test"}),
        graph_config(assessment_id),
    )


def _assessment(engine, assessment_id=1):
    with Session(engine) as session:
        return session.get(Assessment, assessment_id)


def test_full_lifecycle_pauses_at_plan_and_review(engine, fake_execute, fake_report):
    plan = Plan(
        steps=[
            PlanStep(
                action="recon_services",
                target="127.0.0.1",
                rationale="Discovery precedes web probing.",
            )
        ]
    )
    graph = _graph(engine, lambda session, assessment: (plan, "test"))

    with Session(engine) as session:
        prepare_run(session, 1)

    _invoke(graph, 1)
    snapshot = graph.get_state(graph_config(1))
    assert "approve_plan" in snapshot.next
    assert snapshot.interrupts[0].value["gate"] == "plan"
    assert _assessment(engine).status == "awaiting_plan"

    _resume(graph, 1, "approved")
    snapshot = graph.get_state(graph_config(1))
    assert "review" in snapshot.next
    assert snapshot.interrupts[0].value["gate"] == "review"

    with Session(engine) as session:
        steps = session.exec(select(Step)).all()
        approvals = session.exec(select(Approval).order_by(Approval.id)).all()
        assert [step.status for step in steps] == ["succeeded"]
        assert [approval.decision for approval in approvals] == [
            "approved",
            "pending",
        ]

    _resume(graph, 1, "approved")
    assert graph.get_state(graph_config(1)).next == ()
    assessment = _assessment(engine)
    assert assessment.status == "completed"
    assert assessment.report_path.endswith("report.pdf")

    with Session(engine) as session:
        approvals = session.exec(select(Approval).order_by(Approval.id)).all()
        assert [approval.decision for approval in approvals] == [
            "approved",
            "approved",
        ]
        events = session.exec(select(Audit)).all()
        assert any(row.event_type == "plan.approved" for row in events)
        assert any(row.event_type == "review.approved" for row in events)


def test_rejecting_plan_cancels_without_running(engine, fake_execute, fake_report):
    plan = Plan(
        steps=[
            PlanStep(
                action="recon_services",
                target="127.0.0.1",
                rationale="Discovery first.",
            )
        ]
    )
    graph = _graph(engine, lambda session, assessment: (plan, "test"))
    with Session(engine) as session:
        prepare_run(session, 1)

    _invoke(graph, 1)
    _resume(graph, 1, "rejected")

    assert graph.get_state(graph_config(1)).next == ()
    assessment = _assessment(engine)
    assert assessment.status == "cancelled"
    with Session(engine) as session:
        steps = session.exec(select(Step)).all()
        assert [step.status for step in steps] == ["rejected"]


def test_action_gate_requires_second_decision(engine, fake_execute, fake_report):
    plan = Plan(
        steps=[
            PlanStep(
                action="nikto_scan",
                target="127.0.0.1",
                rationale="Active probe needs explicit approval.",
            )
        ]
    )
    graph = _graph(engine, lambda session, assessment: (plan, "test"))
    with Session(engine) as session:
        prepare_run(session, 1)

    _invoke(graph, 1)
    _resume(graph, 1, "approved")

    snapshot = graph.get_state(graph_config(1))
    assert "execute" in snapshot.next
    assert snapshot.interrupts[0].value["gate"] == "action"
    assert _assessment(engine).status == "awaiting_approval"

    _resume(graph, 1, "approved")
    snapshot = graph.get_state(graph_config(1))
    assert "review" in snapshot.next

    with Session(engine) as session:
        steps = session.exec(select(Step)).all()
        assert [step.status for step in steps] == ["succeeded"]
        approvals = session.exec(select(Approval).order_by(Approval.id)).all()
        assert [approval.action for approval in approvals] == [
            "plan_review",
            "nikto_scan",
            "final_review",
        ]


def test_deterministic_plan_skips_completed_actions():
    assessment = Assessment(
        title="Lab",
        targets=["127.0.0.1"],
        ports=[3000],
        exclusions=[],
    )
    plan = deterministic_plan(assessment, set(), [])
    assert [step.action for step in plan.steps] == ["recon_services"]

    plan = deterministic_plan(
        assessment, {("recon_services", "127.0.0.1")}, [3000]
    )
    assert [step.action for step in plan.steps] == ["nikto_scan", "zap_baseline"]

    plan = deterministic_plan(
        assessment,
        {
            ("recon_services", "127.0.0.1"),
            ("nikto_scan", "127.0.0.1"),
            ("zap_baseline", "127.0.0.1"),
        },
        [3000],
    )
    assert plan.steps == []


def test_plan_validation_rejects_scope_and_duplicates():
    assessment = Assessment(title="Lab", targets=["127.0.0.1"], ports=[3000])
    bad_scope = Plan(
        steps=[
            PlanStep(action="recon_services", target="10.0.0.1", rationale="x")
        ]
    )
    with pytest.raises(PlanError):
        validate_plan(assessment, bad_scope, set())

    duplicate = Plan(
        steps=[
            PlanStep(action="recon_services", target="127.0.0.1", rationale="x"),
            PlanStep(action="recon_services", target="127.0.0.1", rationale="y"),
        ]
    )
    with pytest.raises(PlanError):
        validate_plan(assessment, duplicate, set())
