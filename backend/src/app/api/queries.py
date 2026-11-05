"""Read models shared by the REST detail endpoint and the event stream."""

from sqlmodel import Session, col, select

from app.domain.models import Approval, Assessment, Audit, Evidence, Finding, Step
from app.api.schema import AssessmentDetail


def load_assessment_detail(
    session: Session, assessment_id: int
) -> AssessmentDetail | None:
    assessment = session.get(Assessment, assessment_id)
    if assessment is None:
        return None

    steps = session.exec(
        select(Step).where(Step.assessment_id == assessment_id).order_by(Step.seq)
    ).all()
    findings = session.exec(
        select(Finding)
        .where(Finding.assessment_id == assessment_id)
        .order_by(col(Finding.id).desc())
    ).all()
    evidence = session.exec(
        select(Evidence)
        .join(Finding, Evidence.finding_id == Finding.id)
        .where(Finding.assessment_id == assessment_id)
        .order_by(Evidence.id)
    ).all()
    approvals = session.exec(
        select(Approval)
        .where(Approval.assessment_id == assessment_id)
        .order_by(col(Approval.id).desc())
    ).all()
    audit = session.exec(
        select(Audit)
        .where(Audit.assessment_id == assessment_id)
        .order_by(col(Audit.id).desc())
        .limit(100)
    ).all()

    return AssessmentDetail(
        **assessment.model_dump(),
        steps=steps,
        findings=findings,
        evidence=evidence,
        approvals=approvals,
        audit=audit,
    )
