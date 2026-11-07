"""Background graph runs and the read model — fully async.

The graph runs with ``AsyncSqliteSaver`` so checkpoint reads/writes never
block the event loop. Only one invocation per assessment is allowed; the task
registry is process-local and the checkpoint is durable across restarts.

All run operations are serialised per assessment via an asyncio Lock so that
concurrent HTTP requests (for example a double-clicked Approve button) cannot
interleave and leave the task registry in an inconsistent state.
"""

import asyncio
from typing import Any

from langgraph.types import Command
from sqlalchemy.ext.asyncio import AsyncSession

from app.actions.executor import terminate_process
from app.agents.graph import (
    get_assessment_graph,
    graph_config,
    initial_state,
    prepare_run,
)
from app.api.schema import AgentView
from app.core.config import settings
from app.core.db import get_async_session_ctx
from app.core.log import get_logger
from app.domain.models import Assessment, AssessmentStatus, utcnow
from app.persistence import AssessmentRepo, AuditRepo

log = get_logger("runner")

_tasks: dict[int, asyncio.Task] = {}
_locks: dict[int, asyncio.Lock] = {}


async def _graph_for(assessment_id: int):
    return await get_assessment_graph(), graph_config(assessment_id)


async def _state_for(assessment_id: int):
    graph, config = await _graph_for(assessment_id)
    return await graph.aget_state(config)


class AlreadyRunning(RuntimeError):
    pass


class NotPaused(RuntimeError):
    pass


def _lock_for(assessment_id: int) -> asyncio.Lock:
    """Return (creating if necessary) the per-assessment lock."""
    lock = _locks.get(assessment_id)
    if lock is None:
        lock = asyncio.Lock()
        _locks[assessment_id] = lock
    return lock


def _cleanup_done_tasks() -> None:
    """Remove any done tasks from the registry so they don't block new runs."""
    done = [aid for aid, task in _tasks.items() if task.done()]
    for aid in done:
        _tasks.pop(aid, None)


def is_running(assessment_id: int) -> bool:
    _cleanup_done_tasks()
    task = _tasks.get(assessment_id)
    return task is not None and not task.done()


async def reset_graph_checkpoint(assessment_id: int) -> None:
    """Clear the LangGraph checkpoint for one assessment.

    After a stop/cancel, the graph checkpoint may still hold ``state.next``
    from a paused gate. Deleting the checkpoint rows lets ``start_run`` begin
    a fresh loop instead of erroring with ``the graph is paused at a gate``.
    """
    thread_id = f"agent-{assessment_id}"
    try:
        import aiosqlite

        async with aiosqlite.connect(settings.graph_path) as conn:
            await conn.execute(
                "DELETE FROM checkpoints WHERE thread_id = ?", (thread_id,)
            )
            await conn.execute(
                "DELETE FROM checkpoint_blobs WHERE thread_id = ?",
                (thread_id,),
            )
            await conn.execute(
                "DELETE FROM checkpoint_writes WHERE thread_id = ?",
                (thread_id,),
            )
            await conn.commit()
    except Exception:  # noqa: BLE001 - checkpoint reset is best-effort
        log.debug("checkpoint reset failed for %s", assessment_id)


async def _values(assessment_id: int) -> tuple[Any, Any]:
    state = await _state_for(assessment_id)
    return state, state.values or {}


async def get_view(
    assessment_id: int,
    session: AsyncSession | None = None,
    running: bool | None = None,
) -> AgentView:
    state, values = await _values(assessment_id)
    interrupts = getattr(state, "interrupts", ()) or ()
    pending = interrupts[0].value if interrupts else None
    plan = values.get("plan", []) or []
    content = values.get("last_message")
    if not content:
        messages = values.get("messages", []) or []
        last = messages[-1] if messages else None
        content = getattr(last, "content", None)
        if isinstance(content, list):
            content = " ".join(
                block.get("text", "")
                for block in content
                if isinstance(block, dict) and block.get("type") == "text"
            )

    if session is None:
        async with get_async_session_ctx() as own_session:
            repo = AssessmentRepo(own_session)
            assessment = await repo.get(assessment_id)
            status = assessment.status if assessment else "missing"
            risk_score = assessment.risk_score if assessment else None
    else:
        repo = AssessmentRepo(session)
        assessment = await repo.get(assessment_id)
        status = assessment.status if assessment else "missing"
        risk_score = assessment.risk_score if assessment else None

    return AgentView(
        assessment_id=assessment_id,
        status=status,
        running=is_running(assessment_id) if running is None else running,
        paused=bool(state.next) and pending is not None,
        next=list(state.next),
        plan=plan,
        plan_source=values.get("plan_source", "") or "",
        pending=pending,
        steps=values.get("step_count", 0) or 0,
        last_message=content,
        risk_score=risk_score,
    )


async def _invoke(assessment_id: int, payload: Any) -> None:
    try:
        graph, config = await _graph_for(assessment_id)
        await graph.ainvoke(payload, config=config)
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001 - a run failure is recorded, not fatal
        log.exception("agent run failed assessment=%s", assessment_id)
        async with get_async_session_ctx() as session:
            repo = AssessmentRepo(session)
            audit_repo = AuditRepo(session)
            assessment = await repo.get(assessment_id)
            if assessment is not None:
                assessment.status = AssessmentStatus.FAILED.value
                assessment.finished_at = utcnow()
                await audit_repo.add(
                    assessment_id=assessment_id,
                    event_type="agent.failed",
                    payload={"error": str(exc)[:500]},
                )
                await repo.session.commit()
    finally:
        _tasks.pop(assessment_id, None)


def _launch(assessment_id: int, payload: Any) -> None:
    task = asyncio.create_task(_invoke(assessment_id, payload))
    _tasks[assessment_id] = task


async def start_run(
    assessment_id: int,
    actor: str = "analyst",
) -> AgentView:
    async with _lock_for(assessment_id):
        _cleanup_done_tasks()
        if is_running(assessment_id):
            raise AlreadyRunning("an agent run is already active")

        graph, config = await _graph_for(assessment_id)
        state = await graph.aget_state(config)
        if state.next:
            # If the assessment is cancelled or failed, the old checkpoint state
            # is stale. Reset it and start fresh instead of erroring.
            async with get_async_session_ctx() as session:
                repo = AssessmentRepo(session)
                assessment = await repo.get(assessment_id)
                if assessment is None:
                    raise LookupError(f"assessment {assessment_id} not found")
                if assessment.status in (
                    AssessmentStatus.CANCELLED.value,
                    AssessmentStatus.FAILED.value,
                ):
                    await reset_graph_checkpoint(assessment_id)
                else:
                    raise AlreadyRunning(
                        "the graph is paused at a gate; resume it instead"
                    )

        async with get_async_session_ctx() as session:
            repo = AssessmentRepo(session)
            assessment = await repo.get(assessment_id)
            if assessment is None:
                raise LookupError(f"assessment {assessment_id} not found")
            await prepare_run(session, assessment_id, actor=actor)
            payload = initial_state(assessment_id)

        _launch(assessment_id, payload)
        return await get_view(assessment_id, running=True)


async def resume_run(
    assessment_id: int,
    decision: dict,
) -> AgentView:
    async with _lock_for(assessment_id):
        _cleanup_done_tasks()
        if is_running(assessment_id):
            raise AlreadyRunning("an agent run is already active")

        graph, config = await _graph_for(assessment_id)
        state = await graph.aget_state(config)
        if not state.next:
            raise NotPaused("the graph is not waiting at a gate")
        if not getattr(state, "interrupts", ()):
            raise NotPaused("the graph has no pending decision")

        _launch(assessment_id, Command(resume=decision))
        return await get_view(assessment_id, running=True)


async def stop_run(
    assessment_id: int,
    actor: str = "analyst",
) -> AgentView:
    """Cancel an active agent run and mark the assessment cancelled."""
    async with _lock_for(assessment_id):
        # Terminate any in-flight scanner subprocess so stopping a run
        # actually stops the external tool, not just the Python task.
        terminate_process(assessment_id)

        task = _tasks.get(assessment_id)
        if task is not None and not task.done():
            task.cancel()
        _tasks.pop(assessment_id, None)

        # Clear the graph checkpoint so a fresh start_run can begin a new loop
        # instead of finding a paused gate from the previous run.
        await reset_graph_checkpoint(assessment_id)

        async with get_async_session_ctx() as session:
            repo = AssessmentRepo(session)
            audit_repo = AuditRepo(session)
            assessment = await repo.get(assessment_id)
            if assessment is None:
                raise LookupError(f"assessment {assessment_id} not found")
            assessment.status = AssessmentStatus.CANCELLED.value
            assessment.finished_at = utcnow()
            await audit_repo.add(
                assessment_id=assessment_id,
                actor=actor,
                event_type="agent.stopped",
                payload={"reason": "stopped by operator"},
            )
            await repo.session.commit()

        return await get_view(assessment_id, running=False)
