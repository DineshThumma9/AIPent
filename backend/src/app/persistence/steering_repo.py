"""Persistence repository for operator steering notes."""

from __future__ import annotations

from typing import Sequence
from sqlmodel import select

from app.agents.control import audit
from app.domain.models import SteeringNote, utcnow
from app.persistence.base import BaseRepo


class SteeringRepo(BaseRepo):
    """Manages the queue of operator directives for active and future runs."""

    async def add(
        self,
        assessment_id: int,
        run_id: str | None,
        text: str,
    ) -> SteeringNote:
        """Queue a new steering note and audit steering.queued."""
        note = SteeringNote(
            assessment_id=assessment_id,
            run_id=run_id,
            text=text.strip(),
            status="pending",
            created_at=utcnow(),
        )
        self.session.add(note)
        await self.session.commit()
        await self.session.refresh(note)

        audit(
            self.session,
            assessment_id,
            "steering.queued",
            {
                "note_id": note.id,
                "run_id": run_id,
                "text": note.text,
            },
        )
        await self.session.commit()
        return note

    async def take_pending(
        self,
        assessment_id: int,
        run_id: str | None = None,
    ) -> list[SteeringNote]:
        """Claim pending steering notes for the current run or queued while idle.

        Marks consumed, sets consumed_at, audits steering.consumed, and flushes.
        """
        conditions = [
            SteeringNote.assessment_id == assessment_id,
            SteeringNote.status == "pending",
        ]
        if run_id:
            conditions.append(
                (SteeringNote.run_id == run_id) | (SteeringNote.run_id.is_(None))
            )

        stmt = select(SteeringNote).where(*conditions).order_by(SteeringNote.id)
        result = await self.session.execute(stmt)
        notes = list(result.scalars().all())

        now = utcnow()
        for note in notes:
            note.status = "consumed"
            note.consumed_at = now
            audit(
                self.session,
                assessment_id,
                "steering.consumed",
                {
                    "note_id": note.id,
                    "run_id": run_id,
                    "text": note.text,
                },
            )

        if notes:
            await self.session.commit()
        return notes

    async def expire_for_new_run(self, assessment_id: int) -> None:
        """Expire any remaining pending notes from an old run so they don't surprise a new run."""
        stmt = select(SteeringNote).where(
            SteeringNote.assessment_id == assessment_id,
            SteeringNote.status == "pending",
            SteeringNote.run_id.is_not(None),
        )
        result = await self.session.execute(stmt)
        notes = list(result.scalars().all())
        for note in notes:
            note.status = "expired"
        if notes:
            await self.session.commit()

    async def get_all(self, assessment_id: int) -> Sequence[SteeringNote]:
        """Return all steering notes for an assessment."""
        stmt = (
            select(SteeringNote)
            .where(SteeringNote.assessment_id == assessment_id)
            .order_by(SteeringNote.id)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()
