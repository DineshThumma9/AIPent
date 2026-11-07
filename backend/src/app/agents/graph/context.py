"""DB-backed routing helpers for the supervisor graph."""

from __future__ import annotations

from typing import Any

from app.core.db import get_async_session_ctx
from app.core.log import get_logger
from app.domain.models import (
    AssessmentStatus,
    Finding,
    Step,
    StepStatus,
)
from app.persistence import AssessmentRepo, FindingRepo, StepRepo

log = get_logger("agent.context")

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
STATUS_RANK = {"suspected": 0, "confirmed": 1, "false_positive": 2}


async def is_cancelled(assessment_id: int) -> bool:
    async with get_async_session_ctx() as session:
        repo = AssessmentRepo(session)
        assessment = await repo.get(assessment_id)
        return (
            assessment is not None
            and assessment.status == AssessmentStatus.CANCELLED.value
        )


async def has_planned(assessment_id: int) -> bool:
    async with get_async_session_ctx() as session:
        repo = StepRepo(session)
        result = await repo.session.execute(
            _planned_select(assessment_id)
        )
        return result.scalars().first() is not None


def _planned_select(assessment_id: int):
    from sqlmodel import select

    return (
        select(Step.id)
        .where(
            Step.assessment_id == assessment_id,
            Step.status == StepStatus.PLANNED.value,
        )
        .limit(1)
    )


def finding_row(row: Finding) -> dict[str, Any]:
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


def services(rows: list[Finding]) -> list[dict[str, Any]]:
    return [
        finding_row(row)
        for row in rows
        if (row.canonical_key or "").startswith("nmap:")
        or (row.title or "").lower().startswith("open ")
    ]


def candidates(rows: list[Finding]) -> list[Finding]:
    return [
        row
        for row in rows
        if not (
            (row.canonical_key or "").startswith("nmap:")
            or (row.title or "").lower().startswith("open ")
        )
    ]


def rank_candidates(rows: list[Finding]) -> list[Finding]:
    return sorted(
        rows,
        key=lambda row: (
            STATUS_RANK.get(row.status, 9),
            SEVERITY_RANK.get(row.severity, 9),
            -float(row.confidence or 0),
            -(row.updated_at.timestamp() if row.updated_at else 0),
        ),
    )


async def discovery_eligible(assessment_id: int) -> bool:
    """At least one service finding or a completed recon scan exists."""
    from sqlmodel import select

    async with get_async_session_ctx() as session:
        finding_repo = FindingRepo(session)
        services_found = await finding_repo.get_services(assessment_id)
        if services_found:
            return True
        result = await session.execute(
            select(Step.id)
            .where(
                Step.assessment_id == assessment_id,
                Step.action.in_(("recon_services", "dirb_scan")),
                Step.status == StepStatus.SUCCEEDED.value,
            )
            .limit(1)
        )
        return result.scalars().first() is not None


async def validation_eligible(assessment_id: int) -> bool:
    async with get_async_session_ctx() as session:
        finding_repo = FindingRepo(session)
        cands = await finding_repo.get_candidates(assessment_id)
    return bool(cands)


async def challenge_delta(assessment_id: int) -> dict | None:
    from app.integrations.juiceshop import latest_delta

    try:
        return await latest_delta(assessment_id)
    except Exception as exc:  # noqa: BLE001 - the delta is a bonus, not a gate
        log.debug("challenge delta unavailable: %s", exc)
        return None


def read_decision(decision: Any) -> tuple[bool, str, str]:
    if isinstance(decision, str):
        return decision.lower() == "approved", "analyst", ""
    payload = decision or {}
    approved = str(payload.get("decision", "rejected")).lower() == "approved"
    return approved, payload.get("actor") or "analyst", payload.get("reason") or ""
