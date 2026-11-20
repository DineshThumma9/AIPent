"""Supervisor node for V2 agent loop."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING
from langgraph.types import Command

if TYPE_CHECKING:
    from app.agents.state import AssessmentState

from app.agents.contracts import FailureSignal, RouteDecision
from app.agents.mission_brain import (
    build_mission_digest,
    deterministic_safe_route,
    run_supervisor_agent,
    validate_route,
)
from app.agents.nodes.specialist import brief_node
from app.core.db import get_async_session_ctx
from app.core.log import get_logger
from app.persistence import AuditRepo, load_mission_context

logger = get_logger("agent.nodes.supervisor")


def _failure_from_state(state: AssessmentState) -> FailureSignal | None:
    raw = state.get("failure_signal")
    if raw and isinstance(raw, dict):
        try:
            return FailureSignal.model_validate(raw)
        except Exception:
            return None
    return None


async def supervisor_node(state: AssessmentState) -> Command:
    """LLM mission director + Python validate_route guard."""
    assessment_id = state["assessment_id"]
    run_id = state["run_id"]
    failure = _failure_from_state(state)

    async with get_async_session_ctx() as session:
        context = await load_mission_context(session, assessment_id, run_id=run_id)
        digest = await build_mission_digest(
            assessment_id=assessment_id,
            run_id=run_id,
            state=state,
            failure=failure,
            context=context,
        )
        await AuditRepo(session).record_event(
            assessment_id=assessment_id,
            event_type="supervisor.digest",
            payload={
                "run_id": run_id,
                "failure": failure.model_dump() if failure else None,
                "services_count": len(digest.services),
                "candidates_count": len(digest.candidates),
            },
        )
        await session.commit()

    supervisor_exc: Exception | None = None
    supervisor_agent_fn = getattr(sys.modules.get("app.agents.nodes"), "run_supervisor_agent", run_supervisor_agent)
    try:
        proposed = await supervisor_agent_fn(
            digest=digest,
            response_model=RouteDecision,
        )
    except Exception as exc:
        supervisor_exc = exc
        proposed = deterministic_safe_route(state, digest)

    decision, rejection = validate_route(proposed, state, digest)
    logger.info(
        "supervisor_node: routed to role=%s directive=%r (confidence=%.2f)",
        decision.next_role,
        decision.directive,
        decision.confidence,
    )

    async with get_async_session_ctx() as session:
        audit_repo = AuditRepo(session)
        if supervisor_exc is not None:
            await audit_repo.record_event(
                assessment_id=assessment_id,
                event_type="supervisor.unavailable",
                payload={"run_id": run_id, "error": str(supervisor_exc)},
            )
        await audit_repo.record_event(
            assessment_id=assessment_id,
            event_type="supervisor.route_proposed",
            payload={
                "run_id": run_id,
                "proposed_role": proposed.next_role,
                "why": proposed.why,
                "confidence": proposed.confidence,
                "overrides_specialist": proposed.overrides_specialist,
                "directive": proposed.directive,
            },
        )
        if failure:
            await audit_repo.record_event(
                assessment_id=assessment_id,
                event_type="supervisor.recovered",
                payload={
                    "run_id": run_id,
                    "failure_kind": failure.kind,
                    "recovered_role": decision.next_role,
                    "attempts": failure.attempts,
                },
            )
        if rejection:
            await audit_repo.record_event(
                assessment_id=assessment_id,
                event_type="supervisor.route_rejected",
                payload={
                    "run_id": run_id,
                    "proposed_role": proposed.next_role,
                    "rejection_reason": rejection,
                    "fallback_role": decision.next_role,
                },
            )
        await audit_repo.record_event(
            assessment_id=assessment_id,
            event_type="supervisor.route",
            payload={
                "run_id": run_id,
                "accepted_role": decision.next_role,
                "why": decision.why,
                "confidence": decision.confidence,
                "directive": decision.directive,
            },
        )
        if decision.next_role != "review":
            await audit_repo.record_event(
                assessment_id=assessment_id,
                event_type="role.started",
                payload={
                    "run_id": run_id,
                    "role": decision.next_role,
                    "from_role": state.get("role"),
                    "why": decision.why,
                },
            )
        await session.commit()

    if decision.next_role == "review":
        return Command(
            update={
                "role": decision.next_role,
                "supervisor_decision": decision.model_dump(),
                "supervisor_directive": decision.directive,
                "failure_signal": None,
                "last_handoff": None,
                "nudges": 0,
                "no_progress": 0,
                "supervisor_calls": state.get("supervisor_calls", 0) + 1,
                "next_node": decision.next_role,
            },
            goto="review",
        )

    brief_state = dict(state)
    brief_state["role"] = decision.next_role
    brief_state["supervisor_directive"] = decision.directive
    brief_cmd = await brief_node(brief_state)

    update_dict = {
        "role": decision.next_role,
        "supervisor_decision": decision.model_dump(),
        "supervisor_directive": decision.directive,
        "failure_signal": None,
        "last_handoff": None,
        "nudges": 0,
        "no_progress": 0,
        "supervisor_calls": state.get("supervisor_calls", 0) + 1,
        "next_node": decision.next_role,
    }
    if brief_cmd and brief_cmd.update:
        update_dict.update(brief_cmd.update)

    return Command(
        update=update_dict,
        goto="model",
    )
