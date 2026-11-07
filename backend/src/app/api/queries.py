"""Read models shared by the REST detail endpoint and the event stream."""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import col, select

from app.domain.models import Approval, Assessment, Audit, Evidence, Finding, Step
from app.api.schema import AssessmentDetail


async def load_assessment_detail(
    session: AsyncSession, assessment_id: int
) -> AssessmentDetail | None:
    assessment = await session.get(Assessment, assessment_id)
    if assessment is None:
        return None

    result = await session.execute(
        select(Step).where(Step.assessment_id == assessment_id).order_by(Step.seq)
    )
    steps = list(result.scalars().all())

    result = await session.execute(
        select(Finding)
        .where(Finding.assessment_id == assessment_id)
        .order_by(col(Finding.id).desc())
    )
    findings = list(result.scalars().all())

    result = await session.execute(
        select(Evidence)
        .join(Finding, Evidence.finding_id == Finding.id)
        .where(Finding.assessment_id == assessment_id)
        .order_by(Evidence.id)
    )
    evidence = list(result.scalars().all())

    result = await session.execute(
        select(Approval)
        .where(Approval.assessment_id == assessment_id)
        .order_by(col(Approval.id).desc())
    )
    approvals = list(result.scalars().all())

    result = await session.execute(
        select(Audit)
        .where(Audit.assessment_id == assessment_id)
        .order_by(col(Audit.id).desc())
        .limit(100)
    )
    audit = list(result.scalars().all())

    return AssessmentDetail(
        **assessment.model_dump(),
        steps=steps,
        findings=findings,
        evidence=evidence,
        approvals=approvals,
        audit=audit,
    )
