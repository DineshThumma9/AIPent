from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, col, select

from app.db import get_session
from app.models import Approval, Assessment, Audit, Finding, Step
from app.scan import ScopeError, run_scan
from app.schema import AssessmentCreate, AssessmentDetail

router = APIRouter()


@router.get("/assessments", response_model=list[Assessment])
def list_assessments(session: Session = Depends(get_session)):
    return session.exec(select(Assessment).order_by(col(Assessment.id).desc())).all()


@router.post("/assessments", response_model=Assessment, status_code=201)
def create_assessment(payload: AssessmentCreate, session: Session = Depends(get_session)):
    assessment = Assessment(**payload.model_dump())
    session.add(assessment)
    session.commit()
    session.refresh(assessment)
    session.add(
        Audit(
            assessment_id=assessment.id,
            event_type="assessment.created",
            payload={"title": assessment.title, "targets": assessment.targets},
        )
    )
    session.commit()
    return assessment


@router.get("/assessments/{assessment_id}", response_model=AssessmentDetail)
def get_assessment(assessment_id: int, session: Session = Depends(get_session)):
    assessment = session.get(Assessment, assessment_id)
    if assessment is None:
        raise HTTPException(404, "assessment not found")

    def rows(model, order=None, limit=None):
        query = select(model).where(model.assessment_id == assessment_id)
        if order is not None:
            query = query.order_by(order)
        if limit is not None:
            query = query.limit(limit)
        return session.exec(query).all()

    return AssessmentDetail(
        **assessment.model_dump(),
        steps=rows(Step, Step.seq),
        findings=rows(Finding, col(Finding.id).desc()),
        approvals=rows(Approval, col(Approval.id).desc()),
        audit=rows(Audit, col(Audit.id).desc(), limit=100),
    )


@router.post("/assessments/{assessment_id}/scan", response_model=Step)
async def scan(assessment_id: int, session: Session = Depends(get_session)):
    try:
        return  run_scan(session, assessment_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ScopeError as exc:
        raise HTTPException(400, str(exc)) from exc
