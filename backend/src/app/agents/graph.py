"""The single assessment graph.

    START -> intake -> agent -> gate -+-> agent
                                     |
                                     +-> review -> report -> END

The agent node runs the LLM with the full tool set. It decides what to do and
calls ``finish`` when it is done. The gate node is the only place an action is
executed: it pauses for every queued action, executes approved steps and
returns the real observations. There are no per-phase plan functions and no
second graph.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Annotated, Any, TypedDict
from uuid import uuid4

from langchain.agents import create_agent
from langchain_core.messages import AnyMessage, HumanMessage
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.types import interrupt
from sqlalchemy import func
from sqlmodel import Session, select

from app.agents.control import (
    audit,
    current_phase,
    phase_history,
    record_phase,
    run_event_count,
    run_finished,
)
from app.agents.gate import run_gate_step
from app.agents.middleware import middleware_setup
from app.agents.prompts import ASSESSMENT_SYSTEM_PROMPT
from app.agents.tools import ASSESSMENT_TOOLS
from app.core.config import settings
from app.core.db import get_engine
from app.core.log import get_logger
from app.domain.models import (
    Approval,
    Assessment,
    AssessmentStatus,
    Audit,
    Decision,
    Finding,
    Step,
    StepStatus,
    ThinkingLevel,
    utcnow,
)
from app.domain.risk import refresh_risk, summarize
from app.reporting.report import generate_report

log = get_logger("agent.graph")


class AssessmentState(TypedDict, total=False):
    assessment_id: int
    run_id: str
    phase: str
    phase_history: list[dict]
    messages: Annotated[list[AnyMessage], add_messages]
    observations: list[dict]
    plan: list[dict]
    plan_source: str
    steps: int
    turn: int
    finished: bool
    review_approved: bool
    rejected: bool
    report_path: str
    error: str
    last_message: str


def _audit(session: Session, assessment_id: int, event_type: str, payload: dict) -> None:
    audit(session, assessment_id, event_type, payload, actor="system")


def _message_text(message: Any) -> str:
    content = getattr(message, "content", "")
    if isinstance(content, list):
        content = " ".join(
            block.get("text", "")
            for block in content
            if isinstance(block, dict) and block.get("type") == "text"
        )
    return str(content)[:2000]


def _new_messages(history: list[AnyMessage], prompt: HumanMessage, result: dict) -> list:
    """Return only the agent's new messages, not the echoed input history."""
    seen = {
        message.id
        for message in [*history, prompt]
        if getattr(message, "id", None)
    }
    new = []
    for message in result.get("messages", []):
        if isinstance(message, HumanMessage):
            continue
        message_id = getattr(message, "id", None)
        if message_id and message_id in seen:
            continue
        new.append(message)
    return new


def _last_ai_text(messages: list) -> str:
    for message in reversed(messages):
        if getattr(message, "type", "") == "ai" and getattr(message, "content", ""):
            return _message_text(message)
    return ""


def _is_cancelled(assessment_id: int) -> bool:
    with Session(get_engine(), expire_on_commit=False) as session:
        assessment = session.get(Assessment, assessment_id)
        return (
            assessment is not None
            and assessment.status == AssessmentStatus.CANCELLED.value
        )


def _has_planned(assessment_id: int) -> bool:
    with Session(get_engine(), expire_on_commit=False) as session:
        return (
            session.exec(
                select(Step.id)
                .where(
                    Step.assessment_id == assessment_id,
                    Step.status == StepStatus.PLANNED.value,
                )
                .limit(1)
            ).first()
            is not None
        )


def _state_digest(state: AssessmentState) -> str:
    """The facts the agent needs to choose its next tool calls."""
    assessment_id = state["assessment_id"]
    run_id = state["run_id"]
    with Session(get_engine(), expire_on_commit=False) as session:
        assessment = session.get(Assessment, assessment_id)
        if assessment is None:
            raise LookupError(f"assessment {assessment_id} not found")
        findings = session.exec(
            select(Finding)
            .where(Finding.assessment_id == assessment_id)
            .order_by(Finding.updated_at.desc())
            .limit(10)
        ).all()
        steps = session.exec(
            select(Step)
            .where(Step.assessment_id == assessment_id)
            .order_by(Step.seq.desc())
            .limit(8)
        ).all()
        phase = current_phase(session, assessment_id, run_id)
        history = phase_history(session, assessment_id, run_id)
        queued = run_event_count(session, assessment_id, run_id, "action.queued")

    probes = sum(1 for step in steps if step.action == "http_probe")
    payload = {
        "assessment": {
            "id": assessment.id,
            "title": assessment.title,
            "request": assessment.request,
            "targets": assessment.targets,
            "ports": assessment.ports,
            "exclusions": assessment.exclusions,
        },
        "phase": phase,
        "phase_history": history[-6:],
        "budgets": {
            "actions_used": queued,
            "actions_left": max(0, settings.max_steps - queued),
            "probes_used": probes,
            "probes_left": max(0, settings.max_validation_probes - probes),
            "turns_left": max(0, settings.max_agent_turns - state.get("turn", 0)),
        },
        "findings": [
            {
                "id": row.id,
                "status": row.status,
                "severity": row.severity,
                "title": row.title[:80],
                "endpoint": row.endpoint,
            }
            for row in findings
        ],
        "recent_steps": [
            {
                "step_id": row.id,
                "action": row.action,
                "target": row.target,
                "status": row.status,
                "error": row.error,
                "rationale": row.rationale,
            }
            for row in reversed(steps)
        ],
        "last_gate_observations": state.get("observations", [])[-4:],
    }
    body = json.dumps(payload, indent=2, default=str)
    return (
        "ASSESSMENT STATE\n"
        f"{body[:6000]}\n\n"
        "Choose the next tool calls. If the observations answer a hypothesis, "
        "record the verdict. If this phase's objective is complete, call "
        "advance_phase or finish. Never claim an action ran unless it appears "
        "in recent_steps with a terminal status."
    )


def create_assessment_agent():
    provider = settings.llm_provider.lower()
    model_name = settings.llm_model

    if provider == "groq":
        if not settings.groq_api_key:
            raise ValueError(
                "GROQ_API_KEY required for the assessment agent (set it in backend/.env)"
            )
        model = f"groq:{model_name}"
    elif provider == "mistral":
        if not settings.mistral_api_key:
            raise ValueError(
                "MISTRALAI_API_KEY required for the assessment agent (set it in backend/.env)"
            )
        from langchain_mistralai import ChatMistralAI

        model = ChatMistralAI(
            model=model_name,
            mistral_api_key=settings.mistral_api_key,
            timeout=settings.llm_timeout,
            max_tokens=settings.llm_max_tokens,
        )
    else:
        raise ValueError(f"unsupported llm_provider {provider!r}; use groq or mistral")

    return create_agent(
        model=model,
        tools=ASSESSMENT_TOOLS,
        system_prompt=ASSESSMENT_SYSTEM_PROMPT,
        middleware=[
            item
            for item in middleware_setup(ThinkingLevel.MEDIUM)
            if type(item).__name__ != "SummarizationMiddleware"
        ],
    )


def _pending_review(session: Session, assessment_id: int) -> Approval | None:
    return session.exec(
        select(Approval)
        .where(
            Approval.assessment_id == assessment_id,
            Approval.action == "final_review",
            Approval.decision == Decision.PENDING.value,
        )
        .order_by(Approval.id)
    ).first()


def _read_decision(decision: Any) -> tuple[bool, str, str]:
    if isinstance(decision, str):
        return decision.lower() == "approved", "analyst", ""
    payload = decision or {}
    approved = str(payload.get("decision", "rejected")).lower() == "approved"
    return approved, payload.get("actor") or "analyst", payload.get("reason") or ""


def _challenge_delta(assessment_id: int) -> dict | None:
    from app.integrations.juiceshop import latest_delta

    try:
        return latest_delta(assessment_id)
    except Exception as exc:  # noqa: BLE001 - the delta is a bonus, not a gate
        log.debug("challenge delta unavailable: %s", exc)
        return None


def build_assessment_graph(checkpointer=None, agent_factory=None, executor=None):
    """Compile the single loop.

    ``agent_factory`` and ``executor`` are injectable so tests can run the real
    graph, tools and gate without an LLM or live scanners.
    """
    agent = None
    make_agent = agent_factory or create_assessment_agent

    def get_agent():
        nonlocal agent
        if agent is None:
            agent = make_agent()
        return agent

    def intake(state: AssessmentState) -> dict:
        assessment_id = state["assessment_id"]
        run_id = state["run_id"]
        with Session(get_engine(), expire_on_commit=False) as session:
            assessment = session.get(Assessment, assessment_id)
            if assessment is None:
                raise LookupError(f"assessment {assessment_id} not found")
            if not assessment.targets:
                raise ValueError("assessment has no authorised targets")
            for target in assessment.targets:
                if target in assessment.exclusions:
                    raise ValueError(f"target {target} is also excluded")

            assessment.status = AssessmentStatus.PLANNING.value
            assessment.finished_at = None
            assessment.report_path = None
            assessment.report_sha256 = None
            _audit(
                session,
                assessment_id,
                "agent.started",
                {
                    "run_id": run_id,
                    "targets": assessment.targets,
                    "ports": assessment.ports,
                    "request": assessment.request,
                },
            )
            history = phase_history(session, assessment_id, run_id)
            if not history:
                record_phase(
                    session, assessment_id, run_id, "recon", "run start", "recon"
                )
                history = phase_history(session, assessment_id, run_id)
            session.commit()

        return {
            "phase": history[-1]["to"] if history else "recon",
            "phase_history": history,
            "observations": [],
            "plan": [],
            "plan_source": "",
            "steps": 0,
            "turn": 0,
            "finished": False,
            "review_approved": False,
            "rejected": False,
            "last_message": "Intake accepted; the agent is choosing the first action.",
        }

    def agent_node(state: AssessmentState) -> dict:
        from app.agents.context import current_assessment_id, current_run_id

        assessment_id = state["assessment_id"]
        run_id = state["run_id"]
        token_assessment = current_assessment_id.set(assessment_id)
        token_run = current_run_id.set(run_id)
        try:
            if _is_cancelled(assessment_id):
                return {"finished": True, "last_message": "Run cancelled."}

            with Session(get_engine(), expire_on_commit=False) as session:
                assessment = session.get(Assessment, assessment_id)
                if assessment is None:
                    raise LookupError(f"assessment {assessment_id} not found")
                phase_before = current_phase(session, assessment_id, run_id)
                assessment.status = AssessmentStatus.RUNNING.value
                session.commit()

            digest = _state_digest(state)
            history = list(state.get("messages", []))
            prompt = HumanMessage(content=digest)
            payload = {"messages": [*history, prompt]}
            config = {"recursion_limit": settings.agent_recursion_limit}
            result = get_agent().invoke(payload, config=config)
            new_messages = _new_messages(history, prompt, result)
            last_message = _last_ai_text(new_messages)
            if not last_message:
                last_message = _last_ai_text(result.get("messages", []))

            with Session(get_engine(), expire_on_commit=False) as session:
                phase_after = current_phase(session, assessment_id, run_id)
                finished = run_finished(session, assessment_id, run_id)
                history = phase_history(session, assessment_id, run_id)
                _audit(
                    session,
                    assessment_id,
                    "agent.turn",
                    {
                        "run_id": run_id,
                        "phase": phase_after,
                        "from_phase": phase_before,
                        "message": last_message[:500],
                    },
                )
                session.commit()

            return {
                "messages": new_messages,
                "phase": phase_after,
                "phase_history": history,
                "observations": [],
                "finished": finished,
                "turn": state.get("turn", 0) + 1,
                "last_message": last_message,
            }
        finally:
            current_run_id.reset(token_run)
            current_assessment_id.reset(token_assessment)

    def gate_node(state: AssessmentState) -> dict:
        assessment_id = state["assessment_id"]
        if _is_cancelled(assessment_id):
            return {"last_message": "Run cancelled."}

        phase = state.get("phase", "recon")
        result = run_gate_step(assessment_id, phase, interrupt, executor=executor)
        results = [result] if result else []

        with Session(get_engine(), expire_on_commit=False) as session:
            count = session.exec(
                select(func.count(Step.id)).where(
                    Step.assessment_id == assessment_id
                )
            ).one()

        new_plan = [
            {
                "action": row["action"],
                "target": row.get("target") or "",
                "rationale": row.get("rationale") or "",
            }
            for row in results
        ]
        plan = [*state.get("plan", []), *new_plan][-settings.max_steps :]
        return {
            "observations": [*state.get("observations", []), *results][-6:],
            "plan": plan,
            "plan_source": "agent" if plan else state.get("plan_source", ""),
            "steps": count or 0,
        }

    def route_after_gate(state: AssessmentState) -> str:
        assessment_id = state["assessment_id"]
        if _is_cancelled(assessment_id):
            return END
        if _has_planned(assessment_id):
            return "gate"
        if state.get("finished"):
            return "review"
        if state.get("turn", 0) >= settings.max_agent_turns:
            with Session(get_engine(), expire_on_commit=False) as session:
                _audit(
                    session,
                    assessment_id,
                    "agent.budget_exhausted",
                    {
                        "run_id": state["run_id"],
                        "turns": state.get("turn", 0),
                        "reason": "agent did not call finish before the turn cap",
                    },
                )
                session.commit()
            return "review"
        return "agent"

    def review(state: AssessmentState) -> dict:
        assessment_id = state["assessment_id"]
        with Session(get_engine(), expire_on_commit=False) as session:
            assessment = session.get(Assessment, assessment_id)
            if assessment is None:
                raise LookupError(f"assessment {assessment_id} not found")
            findings = session.exec(
                select(Finding).where(Finding.assessment_id == assessment_id)
            ).all()
            summary = summarize(findings)
            refresh_risk(session, assessment_id)

            challenge_delta = _challenge_delta(assessment_id)
            if challenge_delta:
                try:
                    from app.integrations.juiceshop import snapshot_to_artifact

                    snapshot_to_artifact(session, assessment_id, challenge_delta)
                except Exception as exc:  # noqa: BLE001 - bonus feature
                    log.debug("challenge snapshot unavailable: %s", exc)

            history = phase_history(session, assessment_id, state["run_id"])
            approval = _pending_review(session, assessment_id)
            if approval is None:
                approval = Approval(
                    assessment_id=assessment_id,
                    action="final_review",
                    detail={
                        "risk_score": summary["score"],
                        "counts": summary["counts"],
                        "findings": len(findings),
                        "phase": "review",
                        "source": "agent_loop",
                        "phase_history": history,
                        "challenge_delta": challenge_delta,
                    },
                )
                session.add(approval)
            assessment.status = AssessmentStatus.AWAITING_APPROVAL.value
            session.commit()

            digest = {
                "risk_score": summary["score"],
                "counts": summary["counts"],
                "n_findings": len(findings),
                "phases": [row.get("to") for row in history],
                "challenge_delta": challenge_delta,
            }

        decision = interrupt({"gate": "review", "digest": digest, "phase": "review"})
        approved, actor, reason = _read_decision(decision)

        with Session(get_engine(), expire_on_commit=False) as session:
            approval = _pending_review(session, assessment_id)
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
            assessment = session.get(Assessment, assessment_id)
            if assessment is not None:
                if approved:
                    assessment.status = AssessmentStatus.RUNNING.value
                else:
                    assessment.status = AssessmentStatus.CANCELLED.value
                    assessment.finished_at = utcnow()
            session.commit()

        return {
            "review_approved": approved,
            "rejected": not approved,
            "finished": True,
            "last_message": (
                f"Final review {'approved' if approved else 'rejected'} by {actor}."
            ),
        }

    def report(state: AssessmentState) -> dict:
        assessment_id = state["assessment_id"]
        if not state.get("review_approved"):
            with Session(get_engine(), expire_on_commit=False) as session:
                assessment = session.get(Assessment, assessment_id)
                if assessment is not None:
                    assessment.status = AssessmentStatus.CANCELLED.value
                    assessment.finished_at = utcnow()
                    session.commit()
            return {"finished": True}

        with Session(get_engine(), expire_on_commit=False) as session:
            assessment = session.get(Assessment, assessment_id)
            if assessment is None:
                raise LookupError(f"assessment {assessment_id} not found")
            assessment.status = AssessmentStatus.REPORTING.value
            session.commit()
            try:
                path = generate_report(session, assessment_id)
                assessment.status = AssessmentStatus.COMPLETED.value
                assessment.finished_at = utcnow()
                session.commit()
                return {
                    "finished": True,
                    "report_path": str(path),
                    "last_message": f"Report written to {path}.",
                }
            except Exception as exc:  # noqa: BLE001 - status records the failure
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
                    "error": str(exc)[:500],
                    "last_message": f"Report failed: {str(exc)[:200]}",
                }

    graph = StateGraph(AssessmentState)
    graph.add_node("intake", intake)
    graph.add_node("agent", agent_node)
    graph.add_node("gate", gate_node)
    graph.add_node("review", review)
    graph.add_node("report", report)

    graph.add_edge(START, "intake")
    graph.add_edge("intake", "agent")
    graph.add_edge("agent", "gate")
    graph.add_conditional_edges(
        "gate",
        route_after_gate,
        {"gate": "gate", "agent": "agent", "review": "review", END: END},
    )
    graph.add_conditional_edges(
        "review",
        lambda state: "report" if state.get("review_approved") else END,
        {"report": "report", END: END},
    )
    graph.add_edge("report", END)
    return graph.compile(checkpointer=checkpointer)


def initial_state(assessment_id: int, run_id: str | None = None) -> AssessmentState:
    return {
        "assessment_id": assessment_id,
        "run_id": run_id or uuid4().hex[:12],
        "phase": "recon",
        "phase_history": [],
        "messages": [],
        "observations": [],
        "plan": [],
        "plan_source": "",
        "steps": 0,
        "turn": 0,
        "finished": False,
        "review_approved": False,
        "rejected": False,
        "last_message": "",
    }


def graph_config(assessment_id: int) -> dict:
    return {
        "configurable": {"thread_id": f"agent-{assessment_id}"},
        "recursion_limit": settings.max_agent_turns * 2 + 10,
    }


def prepare_run(session: Session, assessment_id: int, actor: str = "analyst") -> None:
    """Clean stale control rows before a fresh loop invocation."""
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

    from app.integrations.juiceshop import capture_baseline

    try:
        capture_baseline(session, assessment_id)
    except Exception as exc:  # noqa: BLE001 - bonus feature
        log.debug("challenge baseline unavailable: %s", exc)

    _audit(
        session,
        assessment_id,
        "run.requested",
        {"actor": actor, "mode": "agent_loop"},
    )
    session.commit()


_graph = None


def get_assessment_graph():
    global _graph
    if _graph is None:
        graph_path = settings.graph_path
        graph_path.parent.mkdir(parents=True, exist_ok=True)
        saver = SqliteSaver(sqlite3.connect(graph_path, check_same_thread=False))
        saver.setup()
        _graph = build_assessment_graph(checkpointer=saver)
    return _graph


def reset_assessment_graph() -> None:
    global _graph
    _graph = None
