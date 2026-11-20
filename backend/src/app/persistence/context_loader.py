"""Preload complete assessment snapshot for agent nodes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.loop.contracts import EvidenceBoard
from app.agents.loop.reasoning import build_evidence_board
from app.domain.models import Assessment, Finding
from app.persistence.finding_repo import FindingRepo
from app.persistence.steering_repo import SteeringRepo


@dataclass(frozen=True)
class MissionContext:
    assessment: Assessment
    services: list[Finding]
    candidates: list[Finding]
    evidence_board: EvidenceBoard
    steering_notes: list[Any]


async def load_mission_context(
    session: AsyncSession,
    assessment_id: int,
    run_id: str | None = None,
) -> MissionContext:
    """Preload complete assessment context snapshot from repositories."""
    assessment = await session.get(Assessment, assessment_id)
    if assessment is None:
        raise LookupError(f"assessment {assessment_id} not found")

    finding_repo = FindingRepo(session)
    services = await finding_repo.get_services(assessment_id)
    candidates = await finding_repo.get_candidates(assessment_id)
    board = await build_evidence_board(session, assessment_id)

    steering_repo = SteeringRepo(session)
    steering_notes = await steering_repo.take_pending(assessment_id, run_id)

    return MissionContext(
        assessment=assessment,
        services=services,
        candidates=candidates,
        evidence_board=board,
        steering_notes=steering_notes,
    )
