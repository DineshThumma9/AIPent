"""The three-role assessment graph.

    START -> intake -> recon -> gate -+-> recon
                                     +-> discovery -> gate -+-> discovery
                                                             +-> validation -> gate
                                                                             +-> review -> report -> END

Each specialist is a real graph node with its own prompt, tool list and local
message history. The action gate is still the only place an action executes and
is shared by all three roles. Routing is owned by Python and driven by typed
handoffs; no role can call another role's tools or jump a stage.

Every node and every database helper is async: the graph runs under
``AsyncSqliteSaver`` and only ``AsyncSession`` is used.
"""
from __future__ import annotations

import asyncio
import json
import os
from typing import Any, Callable, TypedDict
from uuid import uuid4

from langchain.agents import create_agent
from langchain_core.messages import AnyMessage, HumanMessage
from langchain_groq import ChatGroq
from langchain_google_genai import ChatGoogleGenerativeAI as ChatGoogleGenAI
from langchain_huggingface import ChatHuggingFace
from langchain_mistralai import ChatMistralAI
from langchain_ollama import ChatOllama
from langchain_openrouter import ChatOpenRouter
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt
from sqlalchemy import func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from app.agents.control import (
    ROLE_TURN_CAPS,
    audit,
    latest_handoff,
    record_role,
    role_event_count,
    role_history,
)
from app.agents.gate import ACTIVE_STATES, run_gate_step
from app.agents.middleware import middleware_setup
from app.agents.prompts import ROLE_PROMPTS
from app.agents.tools import ROLE_TOOLS
from app.core.config import settings
from app.core.db import get_async_session_ctx
from app.core.log import get_logger
from app.domain.models import (
    Approval,
    Assessment,
    AssessmentStatus,
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

ROLE_ORDER = ("recon", "discovery", "validation")
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
STATUS_RANK = {"suspected": 0, "confirmed": 1, "false_positive": 2}


class AssessmentState(TypedDict, total=False):
    assessment_id: int
    run_id: str
    role: str
    role_history: list[dict]
    role_messages: dict[str, list[AnyMessage]]
    observations: list[dict]
    plan: list[dict]
    plan_source: str
    steps: int
    turns: dict[str, int]
    finished: bool
    review_approved: bool
    rejected: bool
    report_path: str
    error: str
    last_message: str


def _audit(
    session: AsyncSession, assessment_id: int, event_type: str, payload: dict
) -> None:
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
    """Return only the role's new messages, not the echoed input history."""
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


async def _is_cancelled(assessment_id: int) -> bool:
    async with get_async_session_ctx() as session:
        assessment = await session.get(Assessment, assessment_id)
        return (
            assessment is not None
            and assessment.status == AssessmentStatus.CANCELLED.value
        )


async def _has_planned(assessment_id: int) -> bool:
    async with get_async_session_ctx() as session:
        result = await session.execute(
            select(Step.id)
            .where(
                Step.assessment_id == assessment_id,
                Step.status == StepStatus.PLANNED.value,
            )
            .limit(1)
        )
        return result.scalars().first() is not None


def _finding_row(row: Finding) -> dict[str, Any]:
    return {
        "id": row.id,
        "canonical_key": row.canonical_key,
        "title": row.title[:100],
        "severity": row.severity,
        "status": row.status,
        "confidence": row.confidence,
        "endpoint": row.endpoint,
        "asset": row.asset,
        "origin": row.origin,
    }


def _services(rows: list[Finding]) -> list[dict[str, Any]]:
    return [
        _finding_row(row)
        for row in rows
        if (row.canonical_key or "").startswith("nmap:")
        or (row.title or "").lower().startswith("open ")
    ]


def _candidates(rows: list[Finding]) -> list[Finding]:
    return [
        row
        for row in rows
        if not (
            (row.canonical_key or "").startswith("nmap:")
            or (row.title or "").lower().startswith("open ")
        )
    ]


def _rank_candidates(rows: list[Finding]) -> list[Finding]:
    return sorted(
        rows,
        key=lambda row: (
            STATUS_RANK.get(row.status, 9),
            SEVERITY_RANK.get(row.severity, 9),
            -float(row.confidence or 0),
            -(row.updated_at.timestamp() if row.updated_at else 0),
        ),
    )


async def _role_digest(state: AssessmentState, role: str) -> str:
    """Build a bounded, priority-ranked digest for one role."""
    assessment_id = state["assessment_id"]
    run_id = state["run_id"]
    async with get_async_session_ctx() as session:
        assessment = await session.get(Assessment, assessment_id)
        if assessment is None:
            raise LookupError(f"assessment {assessment_id} not found")

        result = await session.execute(
            select(Finding).where(Finding.assessment_id == assessment_id)
        )
        findings = list(result.scalars().all())
        result = await session.execute(
            select(Step)
            .where(Step.assessment_id == assessment_id)
            .order_by(Step.seq.desc())
            .limit(8)
        )
        steps = list(result.scalars().all())
        queued = await role_event_count(
            session, assessment_id, run_id, role, "action.queued"
        )
        last_handoff = await latest_handoff(session, assessment_id, run_id)
        history = await role_history(session, assessment_id, run_id)

    services = _services(findings)
    candidates = _rank_candidates(_candidates(findings))
    probes_used = (
        await session.execute(
            select(func.count(Step.id)).where(
                Step.assessment_id == assessment_id,
                Step.action == "http_probe",
                Step.status.in_(ACTIVE_STATES),
            )
        )
    ).scalar() or 0

    if role == "recon":
        findings_payload = services[:12]
    elif role == "discovery":
        findings_payload = [*services[:8], *[_finding_row(row) for row in candidates[:8]]]
    else:
        findings_payload = [_finding_row(row) for row in candidates[:12]]

    payload = {
        "mission": {
            "id": assessment.id,
            "title": assessment.title,
            "request": assessment.request,
            "targets": assessment.targets,
            "ports": assessment.ports,
            "exclusions": assessment.exclusions,
        },
        "role": role,
        "roles_entered": [row.get("role") for row in history],
        "budgets": {
            "actions_used": queued,
            "actions_left": max(0, settings.max_steps - queued),
            "probes_used": probes_used,
            "probes_left": max(0, settings.max_validation_probes - probes_used),
            "role_turns": state.get("turns", {}).get(role, 0),
            "role_turn_cap": ROLE_TURN_CAPS[role],
        },
        "services": services[:12],
        "findings": findings_payload,
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
        "last_handoff": last_handoff,
    }
    body = json.dumps(payload, indent=2, default=str)
    return (
        f"{role.upper()} STATE\n"
        f"{body[:4500]}\n\n"
        "Use only your role's tools. Read the observations before deciding. "
        "If a tool refuses an action, adapt once and hand off. Never claim an "
        "action ran unless it appears in recent_steps with a terminal status. "
        "A queued action runs only after this turn ends; do not poll for its "
        "result. Call handoff immediately after queueing the action you need."
    )


def _ollama_kwargs() -> dict[str, Any]:
    """Connection options for Ollama, local or cloud.

    ``AIPENT_LLM_BASE_URL`` selects the endpoint (for example
    ``https://ollama.com``). When ``OLLAMA_API_KEY`` is present it is sent as a
    bearer token, which is what the hosted service requires.
    """
    kwargs: dict[str, Any] = {}
    if settings.llm_base_url:
        kwargs["base_url"] = settings.llm_base_url
    client_kwargs: dict[str, Any] = {"timeout": settings.llm_timeout}
    api_key = os.getenv("OLLAMA_API_KEY")
    if api_key:
        client_kwargs["headers"] = {"Authorization": f"Bearer {api_key}"}
    kwargs["client_kwargs"] = client_kwargs
    return kwargs


models = {
    "groq": lambda model_name: ChatGroq(
        model=model_name,
        groq_api_key=settings.groq_api_key,
        timeout=settings.llm_timeout,
        max_tokens=settings.llm_max_tokens,
    ),
    "ollama": lambda model_name: ChatOllama(
        model=model_name or settings.ollama_model,
        num_predict=settings.llm_max_tokens,
        **_ollama_kwargs(),
    ),
    "mistralai": lambda model_name: ChatMistralAI(
        model=model_name,
        mistral_api_key=settings.mistral_api_key,
        timeout=settings.llm_timeout,
        max_tokens=settings.llm_max_tokens,
    ),
    "mistral": lambda model_name: ChatMistralAI(
        model=model_name,
        mistral_api_key=settings.mistral_api_key,
        timeout=settings.llm_timeout,
        max_tokens=settings.llm_max_tokens,
    ),
    "gemini": lambda model_name: ChatGoogleGenAI(
        model=model_name,
    ),
    "openrouter": lambda model_name: ChatOpenRouter(
        model=model_name,
    ),
    "huggingface_model": lambda model_name: ChatHuggingFace(
        model_name=model_name,
    ),
    "huggingface": lambda model_name: ChatHuggingFace(
        model_name=model_name,
    ),
}


def _build_model():
    provider = settings.llm_provider.lower()
    model_name = settings.llm_model
    if provider not in models:
        raise ValueError(f"Provider {provider!r} not available")
    return models[provider](model_name)


def create_role_agent(role: str):
    role = (role or "").strip().lower()
    if role not in ROLE_PROMPTS:
        raise ValueError(f"unknown role {role!r}; expected one of {ROLE_ORDER}")
    return create_agent(
        model=_build_model(),
        tools=ROLE_TOOLS[role],
        system_prompt=ROLE_PROMPTS[role],
        middleware=[
            item
            for item in middleware_setup(ThinkingLevel.MEDIUM)
            if type(item).__name__ != "SummarizationMiddleware"
        ],
    )


async def _pending_review(
    session: AsyncSession, assessment_id: int
) -> Approval | None:
    result = await session.execute(
        select(Approval)
        .where(
            Approval.assessment_id == assessment_id,
            Approval.action == "final_review",
            Approval.decision == Decision.PENDING.value,
        )
        .order_by(Approval.id)
    )
    return result.scalars().first()


def _read_decision(decision: Any) -> tuple[bool, str, str]:
    if isinstance(decision, str):
        return decision.lower() == "approved", "analyst", ""
    payload = decision or {}
    approved = str(payload.get("decision", "rejected")).lower() == "approved"
    return approved, payload.get("actor") or "analyst", payload.get("reason") or ""


async def _challenge_delta(assessment_id: int) -> dict | None:
    from app.integrations.juiceshop import latest_delta

    try:
        return await latest_delta(assessment_id)
    except Exception as exc:  # noqa: BLE001 - the delta is a bonus, not a gate
        log.debug("challenge delta unavailable: %s", exc)
        return None


async def _discovery_eligible(assessment_id: int) -> bool:
    """At least one service finding or a completed recon scan exists."""
    async with get_async_session_ctx() as session:
        result = await session.execute(
            select(Finding.id)
            .where(
                Finding.assessment_id == assessment_id,
                Finding.canonical_key.like("nmap:%"),
            )
            .limit(1)
        )
        if result.scalars().first() is not None:
            return True
        result = await session.execute(
            select(Step.id)
            .where(
                Step.assessment_id == assessment_id,
                Step.action == "recon_services",
                Step.status == StepStatus.SUCCEEDED.value,
            )
            .limit(1)
        )
        return result.scalars().first() is not None


async def _validation_eligible(assessment_id: int) -> bool:
    async with get_async_session_ctx() as session:
        result = await session.execute(
            select(Finding).where(Finding.assessment_id == assessment_id)
        )
        rows = list(result.scalars().all())
    return bool(_candidates(rows))


async def _next_route(state: AssessmentState) -> str:
    assessment_id = state["assessment_id"]
    run_id = state["run_id"]
    role = state.get("role", "recon")

    async with get_async_session_ctx() as session:
        handoff = await latest_handoff(session, assessment_id, run_id, role)

    if handoff:
        recommendation = str(handoff.get("next_recommendation") or "review")
        # When needs_input is true, the role is asking the operator a question
        # about its recommended next step. The operator's approve/reject
        # decision at the gate serves as the answer — we don't override the
        # recommendation just because input was requested.
        if recommendation == "discovery" and await _discovery_eligible(assessment_id):
            return "discovery"
        if recommendation == "validation" and await _validation_eligible(assessment_id):
            return "validation"
        # Safety net: if discovery recommended review but there are unvalidated
        # suspected findings, route to validation so they get tested (e.g. via
        # http_probe) before the run concludes. Don't loop if validation itself
        # just recommended review.
        last_role = handoff.get("role")
        if last_role != "validation" and await _validation_eligible(assessment_id):
            return "validation"
        return "review"

    turns = int(state.get("turns", {}).get(role, 0))
    if turns < ROLE_TURN_CAPS[role]:
        return role

    async with get_async_session_ctx() as session:
        _audit(
            session,
            assessment_id,
            "role.budget_exhausted",
            {
                "run_id": run_id,
                "role": role,
                "turns": turns,
                "reason": "role did not hand off before the turn cap",
            },
        )
        await session.commit()
    return "review"


def build_assessment_graph(
    checkpointer=None,
    agent_factory: Callable[[str], Any] | None = None,
    executor: Callable[..., Any] | None = None,
):
    """Compile the three-role loop.

    ``agent_factory`` and ``executor`` are injectable so tests can run the real
    graph, tools and gate without an LLM or live scanners. The factory takes a
    role name and returns that role's agent.
    """
    agents: dict[str, Any] = {}
    make_agent = agent_factory or create_role_agent

    def get_agent(role: str):
        if role not in agents:
            agents[role] = make_agent(role)
        return agents[role]

    async def intake(state: AssessmentState) -> dict:
        assessment_id = state["assessment_id"]
        run_id = state["run_id"]
        async with get_async_session_ctx() as session:
            assessment = await session.get(Assessment, assessment_id)
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
                    "roles": list(ROLE_ORDER),
                },
            )
            history = await role_history(session, assessment_id, run_id)
            if not history:
                record_role(session, assessment_id, run_id, "recon", "run start")
                history = await role_history(session, assessment_id, run_id)
            await session.commit()

        return {
            "role": "recon",
            "role_history": history,
            "role_messages": {},
            "observations": [],
            "plan": [],
            "plan_source": "",
            "steps": 0,
            "turns": {},
            "finished": False,
            "review_approved": False,
            "rejected": False,
            "last_message": "Intake accepted; recon is choosing the first action.",
        }

    async def role_node(state: AssessmentState, role: str) -> dict:
        from app.agents.context import (
            current_assessment_id,
            current_role,
            current_run_id,
        )

        assessment_id = state["assessment_id"]
        run_id = state["run_id"]
        token_assessment = current_assessment_id.set(assessment_id)
        token_run = current_run_id.set(run_id)
        token_role = current_role.set(role)
        try:
            if await _is_cancelled(assessment_id):
                return {"finished": True, "last_message": "Run cancelled."}

            turns = dict(state.get("turns", {}))
            turn_number = int(turns.get(role, 0))
            async with get_async_session_ctx() as session:
                assessment = await session.get(Assessment, assessment_id)
                if assessment is None:
                    raise LookupError(f"assessment {assessment_id} not found")
                assessment.status = AssessmentStatus.RUNNING.value
                history = await role_history(session, assessment_id, run_id)
                if not history or history[-1].get("role") != role:
                    record_role(
                        session,
                        assessment_id,
                        run_id,
                        role,
                        "role turn",
                        from_role=state.get("role"),
                    )
                    history = await role_history(session, assessment_id, run_id)
                await session.commit()

            digest = await _role_digest(state, role)
            history_messages = list(
                state.get("role_messages", {}).get(role, [])
            )[-6:]
            prompt = HumanMessage(content=digest)
            payload = {"messages": [*history_messages, prompt]}
            config = {"recursion_limit": settings.agent_recursion_limit}
            result = await get_agent(role).ainvoke(payload, config=config)
            new_messages = _new_messages(history_messages, prompt, result)
            last_message = _last_ai_text(new_messages)
            if not last_message:
                last_message = _last_ai_text(result.get("messages", []))

            turns[role] = turn_number + 1

            async with get_async_session_ctx() as session:
                history = await role_history(session, assessment_id, run_id)
                _audit(
                    session,
                    assessment_id,
                    "role.turn",
                    {
                        "run_id": run_id,
                        "role": role,
                        "turn": turns[role],
                        "message": last_message[:500],
                    },
                )
                await session.commit()

            return {
                "role": role,
                "role_history": history,
                "role_messages": {
                    **state.get("role_messages", {}),
                    role: [*history_messages, *new_messages][-6:],
                },
                "observations": [],
                "finished": False,
                "turns": turns,
                "last_message": last_message,
            }
        finally:
            current_role.reset(token_role)
            current_run_id.reset(token_run)
            current_assessment_id.reset(token_assessment)

    async def recon_node(state: AssessmentState) -> dict:
        return await role_node(state, "recon")

    async def discovery_node(state: AssessmentState) -> dict:
        return await role_node(state, "discovery")

    async def validation_node(state: AssessmentState) -> dict:
        return await role_node(state, "validation")

    async def gate_node(state: AssessmentState) -> dict:
        assessment_id = state["assessment_id"]
        if await _is_cancelled(assessment_id):
            return {"last_message": "Run cancelled."}

        role = state.get("role", "recon")
        result = await run_gate_step(assessment_id, role, interrupt, executor=executor)
        results = [result] if result else []

        async with get_async_session_ctx() as session:
            count_result = await session.execute(
                select(func.count(Step.id)).where(
                    Step.assessment_id == assessment_id
                )
            )
            count = count_result.scalar()

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

    async def route_after_role(state: AssessmentState) -> str:
        assessment_id = state["assessment_id"]
        if await _is_cancelled(assessment_id):
            return END
        if await _has_planned(assessment_id):
            return "gate"
        return await _next_route(state)

    async def route_after_gate(state: AssessmentState) -> str:
        assessment_id = state["assessment_id"]
        if await _is_cancelled(assessment_id):
            return END
        if await _has_planned(assessment_id):
            return "gate"
        return await _next_route(state)

    async def review(state: AssessmentState) -> dict:
        assessment_id = state["assessment_id"]
        async with get_async_session_ctx() as session:
            assessment = await session.get(Assessment, assessment_id)
            if assessment is None:
                raise LookupError(f"assessment {assessment_id} not found")
            result = await session.execute(
                select(Finding).where(Finding.assessment_id == assessment_id)
            )
            findings = list(result.scalars().all())
            summary = summarize(findings)
            await refresh_risk(session, assessment_id)

            challenge_delta = await _challenge_delta(assessment_id)
            if challenge_delta:
                try:
                    from app.integrations.juiceshop import snapshot_to_artifact

                    await snapshot_to_artifact(
                        session, assessment_id, challenge_delta
                    )
                except Exception as exc:  # noqa: BLE001 - bonus feature
                    log.debug("challenge snapshot unavailable: %s", exc)

            history = await role_history(session, assessment_id, state["run_id"])
            approval = await _pending_review(session, assessment_id)
            if approval is None:
                approval = Approval(
                    assessment_id=assessment_id,
                    action="final_review",
                    detail={
                        "risk_score": summary["score"],
                        "counts": summary["counts"],
                        "findings": len(findings),
                        "role": "review",
                        "source": "three_role_loop",
                        "role_history": history,
                        "challenge_delta": challenge_delta,
                    },
                )
                session.add(approval)
            assessment.status = AssessmentStatus.AWAITING_APPROVAL.value
            await session.commit()

            digest = {
                "risk_score": summary["score"],
                "counts": summary["counts"],
                "n_findings": len(findings),
                "roles": [row.get("to") for row in history],
                "challenge_delta": challenge_delta,
            }

        decision = interrupt({"gate": "review", "digest": digest, "role": "review"})
        approved, actor, reason = _read_decision(decision)

        async with get_async_session_ctx() as session:
            approval = await _pending_review(session, assessment_id)
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
            assessment = await session.get(Assessment, assessment_id)
            if assessment is not None:
                if approved:
                    assessment.status = AssessmentStatus.RUNNING.value
                else:
                    assessment.status = AssessmentStatus.CANCELLED.value
                    assessment.finished_at = utcnow()
            await session.commit()

        return {
            "review_approved": approved,
            "rejected": not approved,
            "finished": True,
            "last_message": (
                f"Final review {'approved' if approved else 'rejected'} by {actor}."
            ),
        }

    async def report(state: AssessmentState) -> dict:
        assessment_id = state["assessment_id"]

        async with get_async_session_ctx() as session:
            assessment = await session.get(Assessment, assessment_id)
            if assessment is None:
                raise LookupError(f"assessment {assessment_id} not found")
            assessment.status = AssessmentStatus.REPORTING.value
            await session.commit()
            try:
                path = await generate_report(session, assessment_id)
                assessment.status = AssessmentStatus.COMPLETED.value
                assessment.finished_at = utcnow()
                await session.commit()
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
                await session.commit()
                return {
                    "finished": True,
                    "error": str(exc)[:500],
                    "last_message": f"Report failed: {str(exc)[:200]}",
                }

    graph = StateGraph(AssessmentState)
    graph.add_node("intake", intake)
    graph.add_node("recon", recon_node)
    graph.add_node("discovery", discovery_node)
    graph.add_node("validation", validation_node)
    graph.add_node("gate", gate_node)
    graph.add_node("review", review)
    graph.add_node("report", report)

    graph.add_edge(START, "intake")
    graph.add_edge("intake", "recon")
    graph.add_conditional_edges(
        "recon",
        route_after_role,
        {
            "recon": "recon",
            "discovery": "discovery",
            "validation": "validation",
            "gate": "gate",
            "review": "review",
            END: END,
        },
    )
    graph.add_conditional_edges(
        "discovery",
        route_after_role,
        {
            "recon": "recon",
            "discovery": "discovery",
            "validation": "validation",
            "gate": "gate",
            "review": "review",
            END: END,
        },
    )
    graph.add_conditional_edges(
        "validation",
        route_after_role,
        {
            "recon": "recon",
            "discovery": "discovery",
            "validation": "validation",
            "gate": "gate",
            "review": "review",
            END: END,
        },
    )
    graph.add_conditional_edges(
        "gate",
        route_after_gate,
        {
            "recon": "recon",
            "discovery": "discovery",
            "validation": "validation",
            "gate": "gate",
            "review": "review",
            END: END,
        },
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
        "role": "recon",
        "role_history": [],
        "role_messages": {},
        "observations": [],
        "plan": [],
        "plan_source": "",
        "steps": 0,
        "turns": {},
        "finished": False,
        "review_approved": False,
        "rejected": False,
        "last_message": "",
    }


def graph_config(assessment_id: int) -> dict:
    return {
        "configurable": {"thread_id": f"agent-{assessment_id}"},
        "recursion_limit": max(80, settings.agent_recursion_limit * 2),
    }


async def prepare_run(
    session: AsyncSession, assessment_id: int, actor: str = "analyst"
) -> None:
    """Clean stale control rows before a fresh loop invocation."""
    assessment = await session.get(Assessment, assessment_id)
    if assessment is None:
        raise LookupError(f"assessment {assessment_id} not found")

    assessment.status = AssessmentStatus.PLANNING.value
    assessment.finished_at = None
    assessment.report_path = None
    assessment.report_sha256 = None

    result = await session.execute(
        select(Step).where(Step.assessment_id == assessment_id)
    )
    for step in result.scalars().all():
        if step.status == StepStatus.RUNNING.value:
            step.status = StepStatus.FAILED.value
            step.error = "interrupted by restart"
            step.ended_at = utcnow()
        elif step.status == StepStatus.PLANNED.value:
            step.status = StepStatus.REJECTED.value
            step.error = "superseded by a new run"
            step.ended_at = utcnow()

    result = await session.execute(
        select(Approval).where(
            Approval.assessment_id == assessment_id,
            Approval.decision == Decision.PENDING.value,
        )
    )
    for approval in result.scalars().all():
        approval.decision = Decision.REJECTED.value
        approval.outcome = "superseded"
        approval.decided_at = utcnow()

    from app.integrations.juiceshop import capture_baseline

    try:
        await capture_baseline(session, assessment_id)
    except Exception as exc:  # noqa: BLE001 - bonus feature
        log.debug("challenge baseline unavailable: %s", exc)

    _audit(
        session,
        assessment_id,
        "run.requested",
        {"actor": actor, "mode": "three_role_loop"},
    )
    await session.commit()


_graph: Any = None
_graph_conn: Any = None
_graph_lock = asyncio.Lock()


async def get_assessment_graph():
    """Return the compiled graph backed by one AsyncSqliteSaver connection."""
    global _graph, _graph_conn
    if _graph is None:
        async with _graph_lock:
            if _graph is None:
                graph_path = settings.graph_path
                graph_path.parent.mkdir(parents=True, exist_ok=True)
                import aiosqlite

                _graph_conn = await aiosqlite.connect(str(graph_path))
                saver = AsyncSqliteSaver(_graph_conn)
                await saver.setup()
                _graph = build_assessment_graph(checkpointer=saver)
    return _graph
