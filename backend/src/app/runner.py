"""Background graph runs and the read model the UI polls.

The graph itself is synchronous (SqliteSaver), so invocation happens in a
worker thread. Only one invocation per assessment is allowed; the task registry
is process-local and the checkpoint is durable across restarts.
"""

import asyncio
from typing import Any

from langgraph.types import Command
from sqlalchemy.engine import Engine
from sqlmodel import Session

from app.agent import (
    get_graph,
    graph_config,
    initial_state,
    prepare_run,
)
from app.db import get_engine
from app.log import get_logger
from app.models import Assessment, AssessmentStatus, Audit, utcnow
from app.schema import AgentView

log = get_logger("runner")

_tasks: dict[int, asyncio.Task] = {}


class AlreadyRunning(RuntimeError):
    pass


class NotPaused(RuntimeError):
    pass


def is_running(assessment_id: int) -> bool:
    task = _tasks.get(assessment_id)
    return task is not None and not task.done()


def reset_runner() -> None:
    for task in _tasks.values():
        task.cancel()
    _tasks.clear()


def _values(assessment_id: int) -> tuple[Any, Any]:
    state = get_graph().get_state(graph_config(assessment_id))
    return state, state.values or {}


def get_view(
    assessment_id: int,
    session: Session | None = None,
    running: bool | None = None,
) -> AgentView:
    state, values = _values(assessment_id)
    interrupts = getattr(state, "interrupts", ()) or ()
    pending = interrupts[0].value if interrupts else None
    plan = values.get("plan", []) or []
    messages = values.get("messages", []) or []
    last = messages[-1] if messages else None
    content = getattr(last, "content", None)
    if isinstance(content, list):
        content = " ".join(
            block.get("text", "")
            for block in content
            if isinstance(block, dict) and block.get("type") == "text"
        )

    owns_session = session is None
    if owns_session:
        session = Session(get_engine(), expire_on_commit=False)
    try:
        assessment = session.get(Assessment, assessment_id)
        status = assessment.status if assessment else "missing"
        risk_score = assessment.risk_score if assessment else None
    finally:
        if owns_session:
            session.close()

    return AgentView(
        assessment_id=assessment_id,
        status=status,
        running=is_running(assessment_id) if running is None else running,
        paused=bool(state.next) and pending is not None,
        next=list(state.next),
        plan=plan,
        plan_source=values.get("plan_source", "") or "",
        pending=pending,
        steps=values.get("steps", 0) or 0,
        last_message=content,
        risk_score=risk_score,
    )


async def _invoke(engine: Engine, assessment_id: int, payload: Any) -> None:
    try:
        await asyncio.to_thread(
            get_graph().invoke,
            payload,
            graph_config(assessment_id),
        )
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001 - a run failure is recorded, not fatal
        log.exception("agent run failed assessment=%s", assessment_id)
        with Session(engine, expire_on_commit=False) as session:
            assessment = session.get(Assessment, assessment_id)
            if assessment is not None:
                assessment.status = AssessmentStatus.FAILED.value
                assessment.finished_at = utcnow()
                session.add(
                    Audit(
                        assessment_id=assessment_id,
                        event_type="agent.failed",
                        payload={"error": str(exc)[:500]},
                    )
                )
                session.commit()
    finally:
        _tasks.pop(assessment_id, None)


def _launch(engine: Engine, assessment_id: int, payload: Any) -> None:
    task = asyncio.create_task(_invoke(engine, assessment_id, payload))
    _tasks[assessment_id] = task


async def start_run(
    assessment_id: int,
    engine: Engine,
    actor: str = "analyst",
) -> AgentView:
    if is_running(assessment_id):
        raise AlreadyRunning("an agent run is already active")

    state = get_graph().get_state(graph_config(assessment_id))
    if state.next:
        raise AlreadyRunning("the graph is paused at a gate; resume it instead")

    with Session(engine, expire_on_commit=False) as session:
        if session.get(Assessment, assessment_id) is None:
            raise LookupError(f"assessment {assessment_id} not found")
        prepare_run(session, assessment_id, actor=actor)

    _launch(engine, assessment_id, initial_state(assessment_id))
    return get_view(assessment_id, running=True)


async def resume_run(
    assessment_id: int,
    engine: Engine,
    decision: dict,
) -> AgentView:
    if is_running(assessment_id):
        raise AlreadyRunning("an agent run is already active")

    state = get_graph().get_state(graph_config(assessment_id))
    if not state.next:
        raise NotPaused("the graph is not waiting at a gate")
    if not getattr(state, "interrupts", ()):
        raise NotPaused("the graph has no pending decision")

    _launch(engine, assessment_id, Command(resume=decision))
    return get_view(assessment_id, running=True)
