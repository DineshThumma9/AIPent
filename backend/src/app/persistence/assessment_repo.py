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
    Message,
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

    async def get_all(self) -> list[Assessment]:
        result = await self.session.execute(
            select(Assessment).order_by(Assessment.id.desc())
        )
        return list(result.scalars().all())

    async def get_messages(self, assessment_id: int) -> list[Message]:
        result = await self.session.execute(
            select(Message)
            .where(Message.assessment_id == assessment_id)
            .order_by(Message.created_at.asc(), Message.id.asc())
        )
        return list(result.scalars().all())

    async def get_message_by_client_id(
        self, assessment_id: int, client_message_id: str
    ) -> Message | None:
        result = await self.session.execute(
            select(Message).where(
                Message.assessment_id == assessment_id,
                Message.client_message_id == client_message_id,
            )
        )
        return result.scalars().first()

    async def add_message(
        self,
        assessment_id: int,
        role: str,
        text: str,
        client_message_id: str | None = None,
    ) -> Message:
        message = Message(
            assessment_id=assessment_id,
            role=role,
            text=text,
            client_message_id=client_message_id,
        )
        self.session.add(message)
        await self.session.commit()
        await self.session.refresh(message)
        return message

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

    async def refresh_risk_score(self, assessment_id: int) -> dict[str, Any]:
        """Recalculate and persist risk score based on findings."""
        from app.domain.models import Finding
        from app.domain.risk import summarize

        assessment = await self.session.get(Assessment, assessment_id)
        result = await self.session.execute(
            select(Finding).where(Finding.assessment_id == assessment_id)
        )
        findings = list(result.scalars().all())
        summary = summarize(findings)
        if assessment is not None:
            assessment.risk_score = summary["score"]
            await self.session.commit()
        return summary
