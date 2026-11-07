from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import col, select

from app.api.queries import load_assessment_detail
from app.api.schema import (
    AgentAccepted,
    AgentView,
    AssessmentCreate,
    AssessmentDetail,
    AssessmentRequestUpdate,
    DecisionIn,
    MessageIn,
    MessageOut,
)
from app.core.db import get_session, get_async_session_ctx
from app.core.events import stream_assessment_events
from app.domain.models import (
    Assessment,
    AssessmentStatus,
    Message,
    StepStatus,
    utcnow,
)
from app.domain.risk import refresh_risk
from app.persistence import AssessmentRepo, AuditRepo
from app.runtime import runner
from app.runtime.scan import ScopeError, run_scan

router = APIRouter()


@router.get("/assessments", response_model=list[Assessment])
async def list_assessments(session: AsyncSession = Depends(get_session)):
    repo = AssessmentRepo(session)
    result = await repo.session.execute(
        select(Assessment).order_by(Assessment.id.desc())
    )
    return list(result.scalars().all())


@router.post("/assessments", response_model=Assessment, status_code=201)
async def create_assessment(
    payload: AssessmentCreate, session: AsyncSession = Depends(get_session)
):
    repo = AssessmentRepo(session)
    return await repo.create(
        title=payload.title,
        request=payload.request,
        targets=payload.targets,
        ports=payload.ports,
    )


@router.get("/assessments/{assessment_id}", response_model=AssessmentDetail)
async def get_assessment(
    assessment_id: int, session: AsyncSession = Depends(get_session)
):
    detail = await load_assessment_detail(session, assessment_id)
    if detail is None:
        raise HTTPException(404, "assessment not found")
    return detail


@router.patch("/assessments/{assessment_id}/request", response_model=Assessment)
async def update_assessment_request(
    assessment_id: int,
    payload: AssessmentRequestUpdate,
    session: AsyncSession = Depends(get_session),
):
    repo = AssessmentRepo(session)
    assessment = await repo.get(assessment_id)
    if assessment is None:
        raise HTTPException(404, "assessment not found")

    active = {
        AssessmentStatus.PLANNING.value,
        AssessmentStatus.RUNNING.value,
        AssessmentStatus.AWAITING_APPROVAL.value,
        AssessmentStatus.REPORTING.value,
    }
    if assessment.status in active:
        raise HTTPException(409, "cannot change the objective while a run is active")

    assessment.request = payload.request.strip()
    repo = AuditRepo(session)
    await repo.add(
        assessment_id=assessment_id,
        event_type="assessment.request_updated",
        payload={"request": assessment.request[:500]},
        actor="analyst",
    )
    await repo.session.commit()
    await repo.session.refresh(assessment)
    return assessment


@router.get("/assessments/{assessment_id}/messages", response_model=list[MessageOut])
async def list_messages(
    assessment_id: int,
    session: AsyncSession = Depends(get_session),
):
    assessment = await session.get(Assessment, assessment_id)
    if assessment is None:
        raise HTTPException(404, "assessment not found")
    result = await session.execute(
        select(Message)
        .where(Message.assessment_id == assessment_id)
        .order_by(Message.created_at.asc(), Message.id.asc())
    )
    return list(result.scalars().all())


@router.post("/assessments/{assessment_id}/messages", response_model=MessageOut)
async def create_message(
    assessment_id: int,
    payload: MessageIn,
    session: AsyncSession = Depends(get_session),
):
    assessment = await session.get(Assessment, assessment_id)
    if assessment is None:
        raise HTTPException(404, "assessment not found")

    message = Message(
        assessment_id=assessment_id,
        role=payload.role,
        text=payload.text.strip(),
    )
    session.add(message)
    await session.commit()
    await session.refresh(message)
    return message


@router.get("/assessments/{assessment_id}/events")
async def assessment_events(
    assessment_id: int,
    request: Request,
    once: bool = Query(False, include_in_schema=False),
    
):
    """Replay a snapshot, then stream database changes until the client leaves."""
    async with get_async_session_ctx() as session:
        repo = AssessmentRepo(session)
        if await repo.get(assessment_id) is None:
            raise HTTPException(404, "assessment not found")

    return StreamingResponse(
        stream_assessment_events(assessment_id, request, once=once),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/assessments/{assessment_id}/scan", response_model=AssessmentDetail)
async def scan(assessment_id: int, session: AsyncSession = Depends(get_session)):
    repo = AssessmentRepo(session)
    assessment = await repo.get(assessment_id)
    if assessment is None:
        raise HTTPException(404, f"assessment {assessment_id} not found")

    previous_status = assessment.status
    assessment.status = AssessmentStatus.RUNNING.value
    assessment.finished_at = None
    await repo.session.commit()

    try:
        step = await run_scan(session, assessment_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ScopeError as exc:
        assessment.status = previous_status
        await repo.session.commit()
        raise HTTPException(400, str(exc)) from exc

    assessment.status = (
        AssessmentStatus.COMPLETED.value
        if step.status == StepStatus.SUCCEEDED.value
        else AssessmentStatus.FAILED.value
    )
    assessment.finished_at = utcnow()
    await refresh_risk(session, assessment_id)
    await repo.session.commit()

    detail = await load_assessment_detail(session, assessment_id)
    if detail is None:
        raise HTTPException(404, "assessment not found")
    return detail


@router.post(
    "/assessments/{assessment_id}/run",
    response_model=AgentAccepted,
    status_code=202,
)
async def run_agent(assessment_id: int):
    try:
        await runner.start_run(assessment_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except runner.AlreadyRunning as exc:
        raise HTTPException(409, str(exc)) from exc
    return AgentAccepted(
        assessment_id=assessment_id,
        message="Agent run accepted; watch the event stream for the action gate.",
    )


@router.post(
    "/assessments/{assessment_id}/stop",
    response_model=AgentAccepted,
    status_code=202,
)
async def stop_agent(assessment_id: int):
    try:
        await runner.stop_run(assessment_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    return AgentAccepted(
        assessment_id=assessment_id,
        message="Agent run stopped.",
    )


@router.post(
    "/assessments/{assessment_id}/resume",
    response_model=AgentAccepted,
    status_code=202,
)
async def resume_agent(assessment_id: int, payload: DecisionIn):
    try:
        await runner.resume_run(assessment_id, payload.model_dump())
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
async def agent_state(
    assessment_id: int,
    session: AsyncSession = Depends(get_session),
):
    if await session.get(Assessment, assessment_id) is None:
        raise HTTPException(404, "assessment not found")
    return await runner.get_view(assessment_id, session=session)


@router.get("/assessments/{assessment_id}/report")
async def download_report(
    assessment_id: int,
    session: AsyncSession = Depends(get_session),
):
    assessment = await session.get(Assessment, assessment_id)
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
