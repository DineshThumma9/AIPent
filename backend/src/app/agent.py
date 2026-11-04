"""LangGraph assessment lifecycle.

START -> intake -> plan -> approve_plan* -> execute -> analyze -+
                                        ^                     |
                                        +---------------------+
                                                              |
                                             review* -> report -> END

`*` is a LangGraph interrupt: the node writes a pending Approval, raises, and
waits for `Command(resume={decision, actor, reason})`. The database is the
evidence of record; the checkpoint only owns control flow.
"""

import asyncio
import sqlite3
from typing import Annotated, Any, TypedDict

from langchain_core.messages import AIMessage, AnyMessage
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.types import Command, interrupt
from sqlalchemy import func
from sqlmodel import Session, select

from app.actions import (
    ScopeError,
    check_scope,
    completed_actions,
    execute_action,
    get_action,
    resolve_argv,
)
from app.config import settings
from app.db import get_engine
from app.log import get_logger
from app.models import (
    Approval,
    Assessment,
    AssessmentStatus,
    Audit,
    Decision,
    Finding,
    Step,
    StepStatus,
    utcnow,
)
from app.planner import PlanStep, build_plan, web_ports
from app.report import build_report_data, generate_report
from app.risk import refresh_risk, summarize

log = get_logger("agent")

MAX_STEPS = settings.max_steps
GRAPH_DB = settings.graph_path


class AgentState(TypedDict, total=False):
    assessment_id: int
    messages: Annotated[list[AnyMessage], add_messages]
    steps: int
    plan: list[dict[str, Any]]
    plan_source: str
    plan_summary: str
    plan_approved: bool
    review_approved: bool
    adaptive_done: bool
    rejected: bool
    finished: bool


def initial_state(assessment_id: int) -> AgentState:
    return {
        "assessment_id": assessment_id,
        "messages": [],
        "steps": 0,
        "plan": [],
        "plan_source": "",
        "plan_summary": "",
        "plan_approved": False,
        "review_approved": False,
        "adaptive_done": False,
        "rejected": False,
        "finished": False,
    }


def graph_config(assessment_id: int) -> dict:
    return {"configurable": {"thread_id": f"assessment-{assessment_id}"}}


def _audit(session: Session, assessment_id: int, event_type: str, payload: dict) -> None:
    session.add(
        Audit(assessment_id=assessment_id, event_type=event_type, payload=payload)
    )


def _read_decision(value: Any) -> tuple[bool, str, str]:
    if isinstance(value, dict):
        approved = str(value.get("decision", "rejected")).lower() == "approved"
        return approved, str(value.get("actor") or "analyst"), str(value.get("reason") or "")
    approved = str(value).lower() == "approved"
    return approved, "analyst", ""


def _pending(
    session: Session,
    assessment_id: int,
    action: str | None = None,
    step_id: int | None = None,
) -> Approval | None:
    query = select(Approval).where(
        Approval.assessment_id == assessment_id,
        Approval.decision == Decision.PENDING.value,
    )
    if action is not None:
        query = query.where(Approval.action == action)
    if step_id is not None:
        query = query.where(Approval.step_id == step_id)
    return session.exec(query.order_by(Approval.id.desc())).first()


def _next_seq(session: Session, assessment_id: int) -> int:
    value = session.exec(
        select(func.max(Step.seq)).where(Step.assessment_id == assessment_id)
    ).one()
    return (value or 0) + 1


def _create_steps(
    session: Session, assessment: Assessment, planned: list[PlanStep]
) -> list[Step]:
    seq = _next_seq(session, assessment.id or 0)
    rows: list[Step] = []
    for offset, item in enumerate(planned):
        step = Step(
            assessment_id=assessment.id or 0,
            seq=seq + offset,
            action=item.action,
            target=item.target,
            rationale=item.rationale,
            status=StepStatus.PLANNED.value,
        )
        session.add(step)
        session.flush()
        step.argv = resolve_argv(item.action, assessment, item.target, step.id or 0)
        rows.append(step)
    session.commit()
    for row in rows:
        session.refresh(row)
    return rows


def prepare_run(session: Session, assessment_id: int, actor: str = "analyst") -> None:
    """Clean stale control rows before a fresh graph invocation."""
    assessment = session.get(Assessment, assessment_id)
    if assessment is None:
        raise LookupError(f"assessment {assessment_id} not found")

    assessment.status = AssessmentStatus.PLANNING.value
    assessment.finished_at = None
    assessment.report_path = None
    assessment.report_sha256 = None

    for step in session.exec(
        select(Step).where(Step.assessment_id == assessment_id)
    ).all():
        if step.status == StepStatus.RUNNING.value:
            step.status = StepStatus.FAILED.value
            step.error = "interrupted by restart"
            step.ended_at = utcnow()
        elif step.status == StepStatus.PLANNED.value:
            step.status = StepStatus.REJECTED.value
            step.error = "superseded by a new run"
            step.ended_at = utcnow()

    for approval in session.exec(
        select(Approval).where(
            Approval.assessment_id == assessment_id,
            Approval.decision == Decision.PENDING.value,
        )
    ).all():
        approval.decision = Decision.REJECTED.value
        approval.outcome = "superseded"
        approval.decided_at = utcnow()

    _audit(session, assessment_id, "run.requested", {"actor": actor})
    session.commit()


def build_graph(checkpointer=None, engine=None, planner=None):
    """Compile the graph. `planner` and `engine` are injectable for tests."""
    engine = engine or get_engine()
    planner_fn = planner or build_plan

    def intake(state: AgentState) -> dict:
        assessment_id = state["assessment_id"]
        with Session(engine, expire_on_commit=False) as session:
            assessment = session.get(Assessment, assessment_id)
            if assessment is None:
                raise LookupError(f"assessment {assessment_id} not found")
            if not assessment.targets:
                raise ScopeError("assessment has no authorised targets")
            for target in assessment.targets:
                if target in assessment.exclusions:
                    raise ScopeError(f"target {target} is also excluded")

            assessment.status = AssessmentStatus.PLANNING.value
            assessment.finished_at = None
            assessment.report_path = None
            assessment.report_sha256 = None
            _audit(
                session,
                assessment_id,
                "agent.started",
                {
                    "targets": assessment.targets,
                    "ports": assessment.ports,
                    "request": assessment.request,
                },
            )
            session.commit()

        return {
            "steps": 0,
            "plan": [],
            "plan_approved": False,
            "review_approved": False,
            "adaptive_done": False,
            "rejected": False,
            "finished": False,
            "messages": [AIMessage(content="Intake accepted; building the plan.")],
        }

    def plan_node(state: AgentState) -> dict:
        assessment_id = state["assessment_id"]
        with Session(engine, expire_on_commit=False) as session:
            assessment = session.get(Assessment, assessment_id)
            if assessment is None:
                raise LookupError(f"assessment {assessment_id} not found")

            plan, source = planner_fn(session, assessment)
            if not plan.steps:
                assessment.status = AssessmentStatus.RUNNING.value
                _audit(
                    session,
                    assessment_id,
                    "plan.empty",
                    {"source": source, "reason": "no remaining catalogued actions"},
                )
                session.commit()
                return {
                    "plan": [],
                    "plan_source": source,
                    "plan_approved": True,
                    "messages": [
                        AIMessage(content="No remaining actions; moving to review.")
                    ],
                }

            steps = _create_steps(session, assessment, plan.steps)
            session.add(
                Approval(
                    assessment_id=assessment_id,
                    action="plan_review",
                    detail={
                        "plan": [item.model_dump() for item in plan.steps],
                        "summary": plan.summary,
                        "source": source,
                    },
                )
            )
            assessment.status = AssessmentStatus.AWAITING_PLAN.value
            _audit(
                session,
                assessment_id,
                "plan.proposed",
                {
                    "source": source,
                    "summary": plan.summary,
                    "steps": [
                        {
                            "step_id": step.id,
                            "action": step.action,
                            "target": step.target,
                            "argv": step.argv,
                        }
                        for step in steps
                    ],
                },
            )
            session.commit()

        return {
            "plan": [item.model_dump() for item in plan.steps],
            "plan_source": source,
            "plan_summary": plan.summary,
            "plan_approved": False,
            "messages": [
                AIMessage(
                    content=(
                        f"Plan proposed with {len(plan.steps)} step(s) "
                        f"from {source}; waiting for analyst approval."
                    )
                )
            ],
        }

    def approve_plan(state: AgentState) -> dict:
        assessment_id = state["assessment_id"]
        payload = {
            "gate": "plan",
            "plan": state.get("plan", []),
            "summary": state.get("plan_summary", ""),
            "source": state.get("plan_source", ""),
        }
        with Session(engine, expire_on_commit=False) as session:
            approval = _pending(session, assessment_id, action="plan_review")
            if approval is not None:
                approval.decision = Decision.PENDING.value
            session.commit()

        # First pass raises here. On resume, `decision` is the resume value.
        decision = interrupt(payload)
        approved, actor, reason = _read_decision(decision)

        with Session(engine, expire_on_commit=False) as session:
            assessment = session.get(Assessment, assessment_id)
            if assessment is None:
                raise LookupError(f"assessment {assessment_id} not found")
            approval = _pending(session, assessment_id, action="plan_review")
            if approval is not None:
                approval.decision = (
                    Decision.APPROVED.value if approved else Decision.REJECTED.value
                )
                approval.actor = actor
                approval.reason = reason or None
                approval.decided_at = utcnow()
                approval.outcome = "plan " + ("accepted" if approved else "rejected")

            if approved:
                assessment.status = AssessmentStatus.RUNNING.value
                _audit(
                    session,
                    assessment_id,
                    "plan.approved",
                    {"actor": actor, "reason": reason},
                )
            else:
                assessment.status = AssessmentStatus.CANCELLED.value
                assessment.finished_at = utcnow()
                for step in session.exec(
                    select(Step).where(
                        Step.assessment_id == assessment_id,
                        Step.status == StepStatus.PLANNED.value,
                    )
                ).all():
                    step.status = StepStatus.REJECTED.value
                    step.error = reason or "plan rejected"
                    step.ended_at = utcnow()
                _audit(
                    session,
                    assessment_id,
                    "plan.rejected",
                    {"actor": actor, "reason": reason},
                )
            session.commit()

        if approved:
            return {
                "plan_approved": True,
                "messages": [AIMessage(content=f"Plan approved by {actor}.")],
            }
        return {
            "plan_approved": False,
            "rejected": True,
            "finished": True,
            "messages": [AIMessage(content=f"Plan rejected by {actor}; run cancelled.")],
        }

    def execute(state: AgentState) -> dict:
        assessment_id = state["assessment_id"]
        if state.get("rejected") or state.get("finished"):
            return {}
        if state.get("steps", 0) >= MAX_STEPS:
            return {"messages": [AIMessage(content="Step cap reached.")]}

        with Session(engine, expire_on_commit=False) as session:
            assessment = session.get(Assessment, assessment_id)
            if assessment is None:
                raise LookupError(f"assessment {assessment_id} not found")

            step = session.exec(
                select(Step)
                .where(
                    Step.assessment_id == assessment_id,
                    Step.status == StepStatus.PLANNED.value,
                )
                .order_by(Step.seq)
            ).first()
            if step is None:
                return {}

            target = step.target or assessment.targets[0]
            check_scope(assessment, target)
            spec = get_action(step.action)

            if spec.gate == "action":
                approval = _pending(
                    session, assessment_id, step_id=step.id
                )
                if approval is None:
                    approval = session.exec(
                        select(Approval)
                        .where(
                            Approval.assessment_id == assessment_id,
                            Approval.step_id == step.id,
                        )
                        .order_by(Approval.id.desc())
                    ).first()

                if approval is None:
                    approval = Approval(
                        assessment_id=assessment_id,
                        step_id=step.id,
                        action=step.action,
                        argv=step.argv,
                        detail={
                            "target": target,
                            "rationale": step.rationale,
                            "gate": "action",
                        },
                    )
                    session.add(approval)
                    session.commit()
                    session.refresh(approval)
                    _audit(
                        session,
                        assessment_id,
                        "approval.requested",
                        {
                            "approval_id": approval.id,
                            "step_id": step.id,
                            "action": step.action,
                            "argv": step.argv,
                        },
                    )

                if approval.decision == Decision.PENDING.value:
                    assessment.status = AssessmentStatus.AWAITING_APPROVAL.value
                    session.commit()
                    decision = interrupt(
                        {
                            "gate": "action",
                            "approval_id": approval.id,
                            "step_id": step.id,
                            "action": step.action,
                            "target": target,
                            "argv": step.argv,
                            "rationale": step.rationale,
                        }
                    )
                    approved, actor, reason = _read_decision(decision)
                    approval.decision = (
                        Decision.APPROVED.value if approved else Decision.REJECTED.value
                    )
                    approval.actor = actor
                    approval.reason = reason or None
                    approval.decided_at = utcnow()
                    approval.outcome = "action " + ("approved" if approved else "rejected")
                    _audit(
                        session,
                        assessment_id,
                        "approval." + ("approved" if approved else "rejected"),
                        {
                            "approval_id": approval.id,
                            "step_id": step.id,
                            "action": step.action,
                            "actor": actor,
                            "reason": reason,
                            "argv": approval.argv,
                        },
                    )

                    if not approved:
                        step.status = StepStatus.REJECTED.value
                        step.error = reason or "rejected by analyst"
                        step.ended_at = utcnow()
                        assessment.status = AssessmentStatus.RUNNING.value
                        session.commit()
                        return {
                            "steps": state.get("steps", 0) + 1,
                            "messages": [
                                AIMessage(
                                    content=f"{step.action} rejected by {actor}."
                                )
                            ],
                        }

                if approval.decision != Decision.APPROVED.value:
                    step.status = StepStatus.REJECTED.value
                    step.error = "approval was not granted"
                    step.ended_at = utcnow()
                    assessment.status = AssessmentStatus.RUNNING.value
                    session.commit()
                    return {
                        "steps": state.get("steps", 0) + 1,
                        "messages": [
                            AIMessage(content=f"{step.action} has no approval.")
                        ],
                    }

                expected = resolve_argv(step.action, assessment, target, step.id or 0)
                if approval.argv != expected:
                    step.status = StepStatus.REJECTED.value
                    step.error = "resolved argv changed after approval"
                    step.ended_at = utcnow()
                    assessment.status = AssessmentStatus.RUNNING.value
                    _audit(
                        session,
                        assessment_id,
                        "approval.argv_mismatch",
                        {
                            "approval_id": approval.id,
                            "approved": approval.argv,
                            "resolved": expected,
                        },
                    )
                    session.commit()
                    return {
                        "steps": state.get("steps", 0) + 1,
                        "messages": [
                            AIMessage(content=f"{step.action} blocked: argv changed.")
                        ],
                    }

            assessment.status = AssessmentStatus.RUNNING.value
            session.commit()

            result = asyncio.run(
                execute_action(
                    session,
                    assessment_id,
                    step.action,
                    target=target,
                    rationale=step.rationale,
                    step=step,
                )
            )
            risk = refresh_risk(session, assessment_id)

        return {
            "steps": state.get("steps", 0) + 1,
            "messages": [
                AIMessage(
                    content=(
                        f"{result.action} on {target}: {result.status}. "
                        f"Risk score {risk['score']}/10."
                    )
                )
            ],
        }

    def analyze(state: AgentState) -> dict:
        assessment_id = state["assessment_id"]
        with Session(engine, expire_on_commit=False) as session:
            summary = refresh_risk(session, assessment_id)
            _audit(
                session,
                assessment_id,
                "analysis.risk",
                {
                    "score": summary["score"],
                    "counts": summary["counts"],
                    "findings": summary["finding_count"],
                },
            )
            session.commit()

            if not state.get("adaptive_done"):
                planned = session.exec(
                    select(func.count(Step.id)).where(
                        Step.assessment_id == assessment_id,
                        Step.status == StepStatus.PLANNED.value,
                    )
                ).one()
                if not planned:
                    assessment = session.get(Assessment, assessment_id)
                    if assessment is None:
                        raise LookupError(f"assessment {assessment_id} not found")
                    ports = web_ports(session, assessment_id)
                    completed = completed_actions(session, assessment_id)
                    target = assessment.targets[0]
                    additions: list[PlanStep] = []
                    if ports:
                        if ("nikto_scan", target) not in completed:
                            additions.append(
                                PlanStep(
                                    action="nikto_scan",
                                    target=target,
                                    rationale=(
                                        f"HTTP service discovered on port {ports[0]}; "
                                        "active probe with a human action gate."
                                    ),
                                )
                            )
                        if ("zap_baseline", target) not in completed:
                            additions.append(
                                PlanStep(
                                    action="zap_baseline",
                                    target=target,
                                    rationale=(
                                        "Passive ZAP baseline adds independent "
                                        "coverage of the discovered HTTP service."
                                    ),
                                )
                            )
                    if additions and state.get("steps", 0) < MAX_STEPS:
                        additions = additions[: MAX_STEPS - state.get("steps", 0)]
                        _create_steps(session, assessment, additions)
                        _audit(
                            session,
                            assessment_id,
                            "plan.appended",
                            {
                                "steps": [
                                    item.model_dump() for item in additions
                                ],
                                "reason": "web service discovered",
                            },
                        )
                        session.commit()
                        return {
                            "adaptive_done": True,
                            "plan": state.get("plan", [])
                            + [item.model_dump() for item in additions],
                            "messages": [
                                AIMessage(
                                    content=(
                                        "Web service found; appended "
                                        f"{len(additions)} probe(s)."
                                    )
                                )
                            ],
                        }

        return {
            "adaptive_done": True,
            "messages": [AIMessage(content="Analysis complete for this round.")],
        }

    def review(state: AgentState) -> dict:
        assessment_id = state["assessment_id"]
        with Session(engine, expire_on_commit=False) as session:
            assessment = session.get(Assessment, assessment_id)
            if assessment is None:
                raise LookupError(f"assessment {assessment_id} not found")
            findings = session.exec(
                select(Finding).where(Finding.assessment_id == assessment_id)
            ).all()
            summary = summarize(findings)
            approval = _pending(session, assessment_id, action="final_review")
            if approval is None:
                approval = Approval(
                    assessment_id=assessment_id,
                    action="final_review",
                    detail={
                        "risk_score": summary["score"],
                        "counts": summary["counts"],
                        "findings": summary["finding_count"],
                    },
                )
                session.add(approval)
                session.commit()
            assessment.status = AssessmentStatus.AWAITING_APPROVAL.value
            session.commit()
            digest = {
                "risk_score": summary["score"],
                "counts": summary["counts"],
                "findings": [
                    {
                        "id": finding.id,
                        "title": finding.title,
                        "severity": finding.severity,
                    }
                    for finding in findings
                ],
            }
            payload = {"gate": "review", "digest": digest}

        decision = interrupt(payload)
        approved, actor, reason = _read_decision(decision)

        with Session(engine, expire_on_commit=False) as session:
            assessment = session.get(Assessment, assessment_id)
            if assessment is None:
                raise LookupError(f"assessment {assessment_id} not found")
            approval = _pending(session, assessment_id, action="final_review")
            if approval is not None:
                approval.decision = (
                    Decision.APPROVED.value if approved else Decision.REJECTED.value
                )
                approval.actor = actor
                approval.reason = reason or None
                approval.decided_at = utcnow()
                approval.outcome = "review " + ("accepted" if approved else "rejected")
            _audit(
                session,
                assessment_id,
                "review." + ("approved" if approved else "rejected"),
                {"actor": actor, "reason": reason},
            )
            if approved:
                assessment.status = AssessmentStatus.RUNNING.value
            else:
                assessment.status = AssessmentStatus.CANCELLED.value
                assessment.finished_at = utcnow()
            session.commit()

        if approved:
            return {
                "review_approved": True,
                "messages": [AIMessage(content=f"Findings review approved by {actor}.")],
            }
        return {
            "review_approved": False,
            "rejected": True,
            "finished": True,
            "messages": [AIMessage(content=f"Review rejected by {actor}; run cancelled.")],
        }

    def report_node(state: AgentState) -> dict:
        assessment_id = state["assessment_id"]
        with Session(engine, expire_on_commit=False) as session:
            assessment = session.get(Assessment, assessment_id)
            if assessment is None:
                raise LookupError(f"assessment {assessment_id} not found")
            assessment.status = AssessmentStatus.REPORTING.value
            session.commit()

            try:
                path = generate_report(session, assessment_id)
                assessment = session.get(Assessment, assessment_id)
                assessment.status = AssessmentStatus.COMPLETED.value
                assessment.finished_at = utcnow()
                session.commit()
                return {
                    "finished": True,
                    "messages": [
                        AIMessage(content=f"Report written to {path}.")
                    ],
                }
            except Exception as exc:  # noqa: BLE001 - report failure ends the run
                log.exception("report failed assessment=%s", assessment_id)
                assessment.status = AssessmentStatus.FAILED.value
                assessment.finished_at = utcnow()
                _audit(
                    session,
                    assessment_id,
                    "report.failed",
                    {"error": str(exc)[:500]},
                )
                session.commit()
                return {
                    "finished": True,
                    "messages": [
                        AIMessage(content=f"Report failed: {str(exc)[:200]}")
                    ],
                }

    def after_plan(state: AgentState) -> str:
        if state.get("rejected") or not state.get("plan"):
            return "review"
        return "approve_plan"

    def after_approve(state: AgentState) -> str:
        return "execute" if state.get("plan_approved") else END

    def after_analyze(state: AgentState) -> str:
        if state.get("rejected") or state.get("finished"):
            return END
        if state.get("steps", 0) >= MAX_STEPS:
            return "review"
        with Session(engine) as session:
            pending = session.exec(
                select(func.count(Step.id)).where(
                    Step.assessment_id == state["assessment_id"],
                    Step.status == StepStatus.PLANNED.value,
                )
            ).one()
        return "execute" if pending else "review"

    def after_review(state: AgentState) -> str:
        return "report" if state.get("review_approved") else END

    graph = StateGraph(AgentState)
    graph.add_node("intake", intake)
    graph.add_node("plan", plan_node)
    graph.add_node("approve_plan", approve_plan)
    graph.add_node("execute", execute)
    graph.add_node("analyze", analyze)
    graph.add_node("review", review)
    graph.add_node("report", report_node)
    graph.add_edge(START, "intake")
    graph.add_edge("intake", "plan")
    graph.add_conditional_edges("plan", after_plan, {"approve_plan": "approve_plan", "review": "review"})
    graph.add_conditional_edges("approve_plan", after_approve, {"execute": "execute", END: END})
    graph.add_edge("execute", "analyze")
    graph.add_conditional_edges("analyze", after_analyze, {"execute": "execute", "review": "review", END: END})
    graph.add_conditional_edges("review", after_review, {"report": "report", END: END})
    graph.add_edge("report", END)
    return graph.compile(checkpointer=checkpointer)


_graph = None


def get_graph():
    """Compiled graph with a SQLite checkpointer for durable threads."""
    global _graph
    if _graph is None:
        GRAPH_DB.parent.mkdir(parents=True, exist_ok=True)
        saver = SqliteSaver(sqlite3.connect(GRAPH_DB, check_same_thread=False))
        saver.setup()
        _graph = build_graph(saver)
    return _graph


def reset_graph() -> None:
    global _graph
    _graph = None


async def run_graph(assessment_id: int) -> dict:
    """Invoke a fresh run off the event loop; the checkpointer is sync."""
    return await asyncio.to_thread(
        get_graph().invoke,
        initial_state(assessment_id),
        graph_config(assessment_id),
    )


async def resume_graph(assessment_id: int, decision: dict) -> dict:
    return await asyncio.to_thread(
        get_graph().invoke,
        Command(resume=decision),
        graph_config(assessment_id),
    )
