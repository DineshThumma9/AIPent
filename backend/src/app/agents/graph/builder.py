"""Compile the three-role assessment graph using native LangGraph patterns.

StateGraph handles orchestration; persistence repos own all SQL.
Routing is owned by nodes via Command(update=..., goto=...) — no DB
router functions. The security gate stays (scope, budget, policy, argv,
evidence) because LangGraph does not provide those.

Specialist sub-graphs (recon, discovery, validation) live under
``agents/specialists/`` and are invoked inline by the supervisor node —
they are not graph nodes themselves.
"""

from __future__ import annotations

import asyncio
from typing import Any, Callable

from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from langgraph.graph import END, START, StateGraph

from app.agents.loop.builder import build_assessment_graph_v2
from app.agents.graph.state import AssessmentState, initial_state
from app.core.config import settings
from app.domain.models import (
    Approval,
    AssessmentStatus,
    Decision,
    Step,
    StepStatus,
    utcnow,
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from app.persistence import AssessmentRepo, AuditRepo, SteeringRepo, StepRepo


def build_assessment_graph(
    checkpointer=None,
    executor: Callable[..., Any] | None = None,
):
    """Compile the three-role loop."""
    return build_assessment_graph_v2(checkpointer=checkpointer, executor=executor)


def graph_config(assessment_id: int) -> dict:
    """LangGraph config with thread_id pinned to the assessment."""
    return {
        "configurable": {"thread_id": f"agent-{assessment_id}"},
        "recursion_limit": max(80, settings.agent_recursion_limit * 2),
    }


async def prepare_run(
    session: AsyncSession, assessment_id: int, actor: str = "analyst"
) -> None:
    """Clean stale control rows before a fresh loop invocation."""
    repo = AssessmentRepo(session)
    assessment = await repo.get(assessment_id)
    if assessment is None:
        raise LookupError(f"assessment {assessment_id} not found")

    assessment.status = AssessmentStatus.PLANNING.value
    assessment.finished_at = None
    assessment.report_path = None
    assessment.report_sha256 = None

    step_repo = StepRepo(session)
    steps = await step_repo.get_all(assessment_id)
    for step in steps:
        if step.status == StepStatus.RUNNING.value:
            step.status = StepStatus.FAILED.value
            step.error = "interrupted by restart"
            step.ended_at = utcnow()
        elif step.status == StepStatus.PLANNED.value:
            step.status = StepStatus.REJECTED.value
            step.error = "superseded by a new run"
            step.ended_at = utcnow()

    result = await session.execute(
        select(Approval).where(
            Approval.assessment_id == assessment_id,
            Approval.decision == Decision.PENDING.value,
        )
    )
    for approval in result.scalars().all():
        approval.decision = Decision.REJECTED.value
        approval.outcome = "superseded"
        approval.decided_at = utcnow()

    steering_repo = SteeringRepo(session)
    await steering_repo.expire_for_new_run(assessment_id)

    from app.integrations.juiceshop import capture_baseline

    try:
        await capture_baseline(session, assessment_id)
    except Exception as exc:  # noqa: BLE001 - bonus feature
        from app.core.log import get_logger

        get_logger("agent.graph").debug("challenge baseline unavailable: %s", exc)

    audit_repo = AuditRepo(session)
    await audit_repo.add(
        assessment_id=assessment_id,
        event_type="run.requested",
        payload={"actor": actor, "mode": "three_role_loop"},
        actor=actor,
    )
    await repo.session.commit()


_graphs: dict[str, Any] = {}
_graph_conn: Any = None
_graph_lock = asyncio.Lock()


async def get_assessment_graph():
    """Return the compiled graph backed by one AsyncSqliteSaver connection."""
    global _graphs, _graph_conn
    loop_version = settings.agent_loop
    if loop_version not in _graphs:
        async with _graph_lock:
            if loop_version not in _graphs:
                graph_path = settings.graph_path
                graph_path.parent.mkdir(parents=True, exist_ok=True)
                import aiosqlite

                if _graph_conn is None:
                    _graph_conn = await aiosqlite.connect(str(graph_path))
                saver = AsyncSqliteSaver(_graph_conn)
                await saver.setup()
                if loop_version == "v2":
                    from app.agents.loop.builder import build_assessment_graph_v2

                    _graphs[loop_version] = build_assessment_graph_v2(checkpointer=saver)
                else:
                    _graphs[loop_version] = build_assessment_graph(checkpointer=saver)
    return _graphs[loop_version]
