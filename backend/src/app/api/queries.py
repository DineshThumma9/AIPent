"""Read models shared by the REST detail endpoint and the event stream."""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import col, select

from app.domain.models import (
    Approval,
    Assessment,
    AssessmentStatus,
    Audit,
    Decision,
    Evidence,
    Finding,
    Message,
    Step,
)
from app.api.schema import AssessmentDetail, MessageOut
from app.persistence import AuditRepo, AssessmentRepo, FindingRepo, StepRepo


async def load_assessment_detail(
    session: AsyncSession, assessment_id: int
) -> AssessmentDetail | None:
    repo = AssessmentRepo(session)
    assessment = await repo.get(assessment_id)
    if assessment is None:
        return None

    step_repo = StepRepo(session)
    steps = await step_repo.get_all(assessment_id)

    finding_repo = FindingRepo(session)
    findings = await finding_repo.get_all(assessment_id, limit=10000)

    audit_repo = AuditRepo(session)
    evidence = await audit_repo.session.execute(
        select(Evidence)
        .join(Finding, Evidence.finding_id == Finding.id)
        .where(Finding.assessment_id == assessment_id)
        .order_by(Evidence.id)
    )
    evidence = list(evidence.scalars().all())

    approvals = await audit_repo.session.execute(
        select(Approval)
        .where(Approval.assessment_id == assessment_id)
        .order_by(col(Approval.id).desc())
    )
    approvals = list(approvals.scalars().all())

    audit = await audit_repo.get_all_for_assessment(assessment_id, limit=100)

    messages = await audit_repo.session.execute(
        select(Message)
        .where(Message.assessment_id == assessment_id)
        .order_by(Message.created_at)
    )
    messages = [MessageOut.model_validate(m) for m in messages.scalars().all()]

    pending_approval = next(
        (row for row in approvals if row.decision == Decision.PENDING.value),
        None,
    )
    requires_approval = True
    if pending_approval is not None:
        requires_approval = (
            (pending_approval.detail or {}).get("requires_approval", True) is not False
        )
    gate_open = (
        assessment.status == AssessmentStatus.AWAITING_APPROVAL.value
        and requires_approval
    )

    return AssessmentDetail(
        **assessment.model_dump(),
        steps=steps,
        findings=findings,
        evidence=evidence,
        approvals=approvals,
        audit=audit,
        messages=messages,
        gate_open=gate_open,
    )
