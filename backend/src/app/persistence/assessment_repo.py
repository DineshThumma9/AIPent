"""Assessment persistence: CRUD and status transitions."""

from datetime import datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from app.domain.models import (
    Assessment,
    AssessmentStatus,
    Audit,
    Decision,
    Step,
    StepStatus,
    utcnow,
)
from app.persistence.base import BaseRepo


class AssessmentRepo(BaseRepo):
    """All database access for assessments."""

    async def create(
        self,
        title: str,
        request: str,
        targets: list[str],
        ports: list[int],
        exclusions: list[str] | None = None,
    ) -> Assessment:
        assessment = Assessment(
            title=title,
            request=request,
            targets=targets,
            ports=ports,
            exclusions=exclusions or [],
            status=AssessmentStatus.DRAFT.value,
        )
        self.session.add(assessment)
        await self.session.flush()
        self.session.add(
            Audit(
                assessment_id=assessment.id,
                event_type="assessment.created",
                payload={"title": title, "targets": targets},
            )
        )
        await self.session.commit()
        await self.session.refresh(assessment)
        return assessment

    async def get(self, assessment_id: int) -> Assessment | None:
        return await self.session.get(Assessment, assessment_id)

    async def set_status(
        self,
        assessment_id: int,
        status: str,
        finished_at: datetime | None = None,
    ) -> Assessment | None:
        assessment = await self.session.get(Assessment, assessment_id)
        if assessment is None:
            return None
        assessment.status = status
        if finished_at is not None:
            assessment.finished_at = finished_at
        await self.session.commit()
        await self.session.refresh(assessment)
        return assessment

    async def prepare_run(
        self,
        assessment_id: int,
        actor: str = "analyst",
    ) -> None:
        """Clean stale control rows before a fresh loop invocation."""
        assessment = await self.session.get(Assessment, assessment_id)
        if assessment is None:
            raise LookupError(f"assessment {assessment_id} not found")

        assessment.status = AssessmentStatus.PLANNING.value
        assessment.finished_at = None
        assessment.report_path = None
        assessment.report_sha256 = None

        result = await self.session.execute(
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

        self.session.add(
            Audit(
                assessment_id=assessment_id,
                actor=actor,
                event_type="run.requested",
                payload={"actor": actor, "mode": "three_role_loop"},
            )
        )
        await self.session.commit()
