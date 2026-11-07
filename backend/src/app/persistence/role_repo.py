"""Role history and handoff persistence."""

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from app.domain.models import Audit, utcnow
from app.persistence.base import BaseRepo


class RoleRepo(BaseRepo):
    """All database access for role history and handoffs."""

    async def record(
        self,
        session: AsyncSession,
        assessment_id: int,
        run_id: str,
        role: str,
        reason: str,
        from_role: str | None = None,
    ) -> None:
        """Record a role turn in the audit trail."""
        session.add(
            Audit(
                assessment_id=assessment_id,
                actor="system",
                event_type="role.turn",
                payload={
                    "run_id": run_id,
                    "role": role,
                    "reason": reason,
                    "from_role": from_role,
                },
            )
        )

    async def latest_handoff(
        self,
        session: AsyncSession,
        assessment_id: int,
        run_id: str,
        role: str | None = None,
    ) -> dict[str, Any] | None:
        """Return the most recent handoff.created audit event."""
        result = await session.execute(
            select(Audit).where(
                Audit.assessment_id == assessment_id,
                Audit.event_type == "handoff.created",
            )
        )
        events = result.scalars().all()
        matching = [
            e
            for e in events
            if (e.payload or {}).get("run_id") == run_id
            and (role is None or (e.payload or {}).get("role") == role)
        ]
        if not matching:
            return None
        # Return the last one by id
        latest = max(matching, key=lambda e: e.id or 0)
        return dict(latest.payload or {})

    async def role_history(
        self,
        session: AsyncSession,
        assessment_id: int,
        run_id: str,
    ) -> list[dict[str, Any]]:
        """Return role.turn audit events for a run, ordered by id."""
        result = await session.execute(
            select(Audit).where(
                Audit.assessment_id == assessment_id,
                Audit.event_type == "role.turn",
            )
        )
        events = result.scalars().all()
        matching = [
            e
            for e in events
            if (e.payload or {}).get("run_id") == run_id
        ]
        matching.sort(key=lambda e: e.id or 0)
        return [dict(e.payload or {}) for e in matching]

    async def role_event_count(
        self,
        session: AsyncSession,
        assessment_id: int,
        run_id: str,
        role: str,
        event_type: str,
    ) -> int:
        result = await session.execute(
            select(Audit).where(
                Audit.assessment_id == assessment_id,
                Audit.event_type == event_type,
            )
        )
        events = result.scalars().all()
        return len(
            [
                e
                for e in events
                if (e.payload or {}).get("run_id") == run_id
                and (e.payload or {}).get("role") == role
            ]
        )
