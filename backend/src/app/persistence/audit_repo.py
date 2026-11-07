"""Audit event persistence."""

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import col, select

from app.domain.models import Audit, utcnow
from app.persistence.base import BaseRepo


class AuditRepo(BaseRepo):
    """All database access for audit events."""

    async def add(
        self,
        assessment_id: int,
        event_type: str,
        payload: dict[str, Any],
        actor: str = "system",
    ) -> Audit:
        audit = Audit(
            assessment_id=assessment_id,
            actor=actor,
            event_type=event_type,
            payload=payload,
        )
        self.session.add(audit)
        await self.session.flush()
        return audit

    async def get_all_for_assessment(
        self,
        assessment_id: int,
        limit: int = 100,
    ) -> list[Audit]:
        result = await self.session.execute(
            select(Audit)
            .where(Audit.assessment_id == assessment_id)
            .order_by(col(Audit.id).desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def get_for_run(
        self,
        assessment_id: int,
        run_id: str,
    ) -> list[Audit]:
        """Return audit events for a specific run."""
        result = await self.session.execute(
            select(Audit).where(Audit.assessment_id == assessment_id)
        )
        events = list(result.scalars().all())
        return [
            e
            for e in events
            if (e.payload or {}).get("run_id") == run_id
        ]

    async def count_action_queued_for_run(
        self,
        assessment_id: int,
        run_id: str,
    ) -> int:
        result = await self.session.execute(
            select(Audit).where(
                Audit.assessment_id == assessment_id,
                Audit.event_type == "action.queued",
            )
        )
        events = result.scalars().all()
        return sum(
            1 for event in events if (event.payload or {}).get("run_id") == run_id
        )
