"""Run-scoped role and handoff state.

The three specialist roles are real graph nodes now. The LLM decides what to do
inside its role; Python records which role ran, what it handed off, and enforces
the role budgets. Keeping this in the database (rather than only in a
checkpoint) means a restart cannot silently lose the handoff trail.

Every event is scoped by ``run_id`` so a previous run cannot leak its handoffs
into a new one.

Write helpers are plain functions because they only append ORM objects to the
session; the caller owns the commit. Read helpers are async because they issue
queries.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from app.domain.models import Audit

ROLES = ("recon", "discovery", "validation")

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
    result = await session.execute(
        select(Audit)
        .where(
            Audit.assessment_id == assessment_id,
            Audit.event_type == event_type,
        )
        .order_by(Audit.id)
    )
    return list(result.scalars().all())


def _for_run(events: list[Audit], run_id: str) -> list[dict]:
    return [
        event.payload or {}
        for event in events
        if (event.payload or {}).get("run_id") == run_id
    ]


async def current_role(session: AsyncSession, assessment_id: int, run_id: str) -> str:
    """The last role entered during this run."""
    for payload in reversed(
        _for_run(await _events(session, assessment_id, "role.started"), run_id)
    ):
        role = str(payload.get("role") or "")
        if role in ROLES:
            return role
    return "recon"


async def role_history(
    session: AsyncSession, assessment_id: int, run_id: str
) -> list[dict]:
    return _for_run(await _events(session, assessment_id, "role.started"), run_id)


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
    if role not in ROLES:
        raise ValueError(f"unknown role {role!r}; expected one of {ROLES}")
    turn = (
        await role_event_count(
            session, assessment_id, run_id, role, "role.turn"
        )
        + 1
    )
    audit(
        session,
        assessment_id,
        "role.turn",
        {
            "run_id": run_id,
            "role": role,
            "reason": reason,
            "from": from_role,
            "turn": turn,
        },
    )
    return turn


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
    rows = _for_run(
        await _events(session, assessment_id, "handoff.created"), run_id
    )
    if role is not None:
        rows = [row for row in rows if row.get("role") == role]
    return rows


async def latest_handoff(
    session: AsyncSession,
    assessment_id: int,
    run_id: str,
    role: str | None = None,
) -> dict | None:
    rows = await handoff_history(session, assessment_id, run_id, role)
    return rows[-1] if rows else None


async def role_event_count(
    session: AsyncSession,
    assessment_id: int,
    run_id: str,
    role: str,
    event_type: str,
) -> int:
    return sum(
        1
        for payload in _for_run(
            await _events(session, assessment_id, event_type), run_id
        )
        if payload.get("role") == role
    )
