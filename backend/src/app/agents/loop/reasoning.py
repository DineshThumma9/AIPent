"""Evidence board reasoning and hypothesis management.

Folds append-only audit events into an EvidenceBoard with hypotheses, decisions,
and open questions.
"""

from __future__ import annotations

from typing import Any
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.loop.contracts import (
    DecisionRecord,
    EvidenceBoard,
    Hypothesis,
    Observation,
)
from app.domain.models import Audit, utcnow
from app.domain.reasoning import fold_events_into_evidence_board


async def build_evidence_board(session: AsyncSession, assessment_id: int) -> EvidenceBoard:
    """Fold audit events into an EvidenceBoard via AuditRepo."""
    from app.persistence.audit_repo import AuditRepo

    return await AuditRepo(session).get_evidence_board(assessment_id)


async def next_hypothesis_id(session: AsyncSession, assessment_id: int) -> str:
    """Generate the next sequential hypothesis id like H-1, H-2 via AuditRepo."""
    from app.persistence.audit_repo import AuditRepo

    return await AuditRepo(session).next_hypothesis_id(assessment_id)


async def record_hypothesis(
    session: AsyncSession,
    assessment_id: int,
    run_id: str,
    role: str,
    statement: str,
    asset: str,
    endpoint: str | None = None,
    falsifier: str = "",
    evidence_ids: list[int] | None = None,
) -> Observation:
    """Record a hypothesis creation audit event and return an Observation."""
    from app.persistence.audit_repo import AuditRepo

    h_id, _ = await AuditRepo(session).record_hypothesis(
        assessment_id=assessment_id,
        run_id=run_id,
        role=role,
        statement=statement,
        asset=asset,
        endpoint=endpoint,
        falsifier=falsifier,
        evidence_ids=evidence_ids,
    )
    await session.commit()

    return Observation(
        ok=True,
        status="succeeded",
        action="record_hypothesis",
        target=asset,
        summary=f"Recorded {h_id}: {statement}",
        next_hint="Test the falsifier before increasing confidence.",
    )


async def update_hypothesis(
    session: AsyncSession,
    assessment_id: int,
    run_id: str,
    role: str,
    hypothesis_id: str,
    status: str,
    confidence: float,
    evidence_ids: list[int] | None = None,
    note: str | None = None,
) -> Observation:
    """Record a hypothesis update audit event and return an Observation."""
    from app.persistence.audit_repo import AuditRepo

    await AuditRepo(session).update_hypothesis(
        assessment_id=assessment_id,
        run_id=run_id,
        role=role,
        hypothesis_id=hypothesis_id,
        status=status,
        confidence=confidence,
        evidence_ids=evidence_ids,
        note=note,
    )
    await session.commit()

    return Observation(
        ok=True,
        status="succeeded",
        action="update_hypothesis",
        target=hypothesis_id,
        summary=f"Updated {hypothesis_id} to status={status}, confidence={confidence:.2f}",
    )
