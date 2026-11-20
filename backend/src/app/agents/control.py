"""Run-scoped role and handoff state (compatibility wrapper for AuditRepo).

The three specialist roles are real graph nodes now. The LLM decides what to do
inside its role; Python records which role ran, what it handed off, and enforces
the role budgets.
"""

from __future__ import annotations

from typing import Any
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.models import Audit
from app.persistence.audit_repo import AuditRepo, ROLES

# The role label is the agent identity used by the skill allowlists.
ROLE_AGENT = {
    "recon": "recon_agent",
    "discovery": "discovery_agent",
    "validation": "validation_agent",
}

ROLE_TURN_CAPS = {
    "recon": 3,
    "discovery": 4,
    "validation": 8,
}


def audit(
    session: AsyncSession,
    assessment_id: int,
    event_type: str,
    payload: dict,
    actor: str = "agent",
) -> None:
    session.add(
        Audit(
            assessment_id=assessment_id,
            actor=actor,
            event_type=event_type,
            payload=payload,
        )
    )


async def _events(
    session: AsyncSession, assessment_id: int, event_type: str
) -> list[Audit]:
    return await AuditRepo(session).get_events(assessment_id, event_type)


def _for_run(events: list[Audit], run_id: str) -> list[dict]:
    return [
        event.payload or {}
        for event in events
        if (event.payload or {}).get("run_id") == run_id
    ]


async def current_role(session: AsyncSession, assessment_id: int, run_id: str) -> str:
    """The last role entered during this run."""
    return await AuditRepo(session).current_role(assessment_id, run_id)


async def role_history(
    session: AsyncSession, assessment_id: int, run_id: str
) -> list[dict]:
    return await AuditRepo(session).role_history(assessment_id, run_id)


def record_role(
    session: AsyncSession,
    assessment_id: int,
    run_id: str,
    role: str,
    reason: str,
    from_role: str | None = None,
) -> dict:
    if role not in ROLES:
        raise ValueError(f"unknown role {role!r}; expected one of {ROLES}")
    payload = {
        "run_id": run_id,
        "from": from_role,
        "to": role,
        "role": role,
        "reason": reason,
    }
    audit(session, assessment_id, "role.started", payload)
    return payload


async def record_turn(
    session: AsyncSession,
    assessment_id: int,
    run_id: str,
    role: str,
    reason: str = "role turn",
    from_role: str | None = None,
) -> int:
    """Record one specialist model invocation and return its turn number."""
    return await AuditRepo(session).record_turn(
        assessment_id=assessment_id,
        run_id=run_id,
        role=role,
        reason=reason,
        from_role=from_role,
    )


def record_handoff(
    session: AsyncSession,
    assessment_id: int,
    run_id: str,
    role: str,
    payload: dict[str, Any],
) -> dict:
    if role not in ROLES:
        raise ValueError(f"unknown role {role!r}; expected one of {ROLES}")
    body = {
        "run_id": run_id,
        "role": role,
        "summary": str(payload.get("summary") or "")[:1000],
        "decisions": payload.get("decisions") or [],
        "finding_ids": payload.get("finding_ids") or [],
        "step_ids": payload.get("step_ids") or [],
        "next_recommendation": payload.get("next_recommendation") or "review",
        "needs_input": bool(payload.get("needs_input")),
        "question": payload.get("question") or None,
        "open_questions": payload.get("open_questions") or [],
    }
    audit(session, assessment_id, "handoff.created", body)
    return body


async def handoff_history(
    session: AsyncSession,
    assessment_id: int,
    run_id: str,
    role: str | None = None,
) -> list[dict]:
    return await AuditRepo(session).handoff_history(assessment_id, run_id, role)


async def latest_handoff(
    session: AsyncSession,
    assessment_id: int,
    run_id: str,
    role: str | None = None,
) -> dict | None:
    return await AuditRepo(session).latest_handoff(assessment_id, run_id, role)


async def role_event_count(
    session: AsyncSession,
    assessment_id: int,
    run_id: str,
    role: str,
    event_type: str,
) -> int:
    return await AuditRepo(session).role_event_count(assessment_id, run_id, role, event_type)
