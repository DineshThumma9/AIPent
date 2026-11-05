from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy.engine import Engine
from sqlmodel import Session, col, select

from app.runtime import runner
from app.core.db import get_engine, get_session
from app.core.events import stream_assessment_events
from app.domain.models import (
    Assessment,
    AssessmentStatus,
    Audit,
    StepStatus,
    utcnow,
)
from app.api.queries import load_assessment_detail
from app.domain.risk import refresh_risk
from app.runtime.scan import ScopeError, run_scan
from app.api.schema import (
    AgentAccepted,
    AgentView,
    AssessmentCreate,
    AssessmentDetail,
    DecisionIn,
)

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
    detail = load_assessment_detail(session, assessment_id)
    if detail is None:
        raise HTTPException(404, "assessment not found")
    return detail


@router.get("/assessments/{assessment_id}/events")
async def assessment_events(
    assessment_id: int,
    request: Request,
    once: bool = Query(False, include_in_schema=False),
    engine: Engine = Depends(get_engine),
):
    """Replay a snapshot, then stream database changes until the client leaves."""
    with Session(engine) as session:
        if session.get(Assessment, assessment_id) is None:
            raise HTTPException(404, "assessment not found")

    return StreamingResponse(
        stream_assessment_events(engine, assessment_id, request, once=once),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/assessments/{assessment_id}/scan", response_model=AssessmentDetail)
async def scan(assessment_id: int, session: Session = Depends(get_session)):
    assessment = session.get(Assessment, assessment_id)
    if assessment is None:
        raise HTTPException(404, f"assessment {assessment_id} not found")

    previous_status = assessment.status
    assessment.status = AssessmentStatus.RUNNING.value
    assessment.finished_at = None
    session.commit()

    try:
        step = await run_scan(session, assessment_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ScopeError as exc:
        assessment.status = previous_status
        session.commit()
        raise HTTPException(400, str(exc)) from exc

    assessment.status = (
        AssessmentStatus.COMPLETED.value
        if step.status == StepStatus.SUCCEEDED.value
        else AssessmentStatus.FAILED.value
    )
    assessment.finished_at = utcnow()
    refresh_risk(session, assessment_id)
    session.commit()

    detail = load_assessment_detail(session, assessment_id)
    if detail is None:
        raise HTTPException(404, "assessment not found")
    return detail


@router.post(
    "/assessments/{assessment_id}/run",
    response_model=AgentAccepted,
    status_code=202,
)
async def run_agent(
    assessment_id: int,
    engine: Engine = Depends(get_engine),
):
    try:
        await runner.start_run(assessment_id, engine)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except runner.AlreadyRunning as exc:
        raise HTTPException(409, str(exc)) from exc
    return AgentAccepted(
        assessment_id=assessment_id,
        message="Agent run accepted; watch the event stream for the action gate.",
    )


@router.post(
    "/assessments/{assessment_id}/resume",
    response_model=AgentAccepted,
    status_code=202,
)
async def resume_agent(
    assessment_id: int,
    payload: DecisionIn,
    engine: Engine = Depends(get_engine),
):
    try:
        await runner.resume_run(assessment_id, engine, payload.model_dump())
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except runner.AlreadyRunning as exc:
        raise HTTPException(409, str(exc)) from exc
    except runner.NotPaused as exc:
        raise HTTPException(409, str(exc)) from exc
    return AgentAccepted(
        assessment_id=assessment_id,
        message=f"Decision {payload.decision} accepted.",
    )


@router.get("/assessments/{assessment_id}/agent", response_model=AgentView)
def agent_state(
    assessment_id: int,
    session: Session = Depends(get_session),
):
    if session.get(Assessment, assessment_id) is None:
        raise HTTPException(404, "assessment not found")
    return runner.get_view(assessment_id, session=session)


@router.get("/assessments/{assessment_id}/report")
def download_report(
    assessment_id: int,
    session: Session = Depends(get_session),
):
    assessment = session.get(Assessment, assessment_id)
    if assessment is None:
        raise HTTPException(404, "assessment not found")
    if not assessment.report_path:
        raise HTTPException(409, "report is not generated yet")
    path = Path(assessment.report_path)
    if not path.exists():
        raise HTTPException(404, "report file is missing")
    media_type = (
        "application/pdf" if path.suffix == ".pdf" else "text/plain; charset=utf-8"
    )
    return FileResponse(path, filename=path.name, media_type=media_type)
