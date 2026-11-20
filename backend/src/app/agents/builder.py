"""V2 StateGraph builder with native observe-reason-act loop nodes.

Replaces the legacy gate conveyor belt with a closed Specialist loop and
LLM Supervisor Mission Director.
"""

from __future__ import annotations

import asyncio
from typing import Any, Callable
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from langgraph.graph import END, START, StateGraph
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from app.agents.state import AssessmentState, initial_state
from app.agents.nodes import (
    approve_node,
    direct_node,
    intake_node,
    make_execute_node,
    model_node,
    prepare_node,
    report_node,
    report_writer_node,
    review_node,
    supervisor_node,
)
from app.core.config import settings
from app.domain.models import (
    Approval,
    AssessmentStatus,
    Decision,
    Step,
    StepStatus,
    utcnow,
)
from app.persistence import AssessmentRepo, AuditRepo, SteeringRepo, StepRepo


def build_assessment_graph_v2(
    checkpointer=None,
    executor: Callable[..., Any] | None = None,
):
    """Compile the V2 assessment graph."""
    builder = StateGraph(AssessmentState)

    builder.add_node("intake", intake_node)
    builder.add_node("supervisor", supervisor_node)
    builder.add_node("model", model_node)
    builder.add_node("prepare", prepare_node)
    builder.add_node("approve", approve_node)
    builder.add_node("execute", make_execute_node(executor))
    builder.add_node("direct", direct_node)
    builder.add_node("review", review_node)
    builder.add_node("report_writer", report_writer_node)
    builder.add_node("report", report_node)

    builder.add_edge(START, "intake")

    return builder.compile(checkpointer=checkpointer)


def build_assessment_graph(
    checkpointer=None,
    executor: Callable[..., Any] | None = None,
):
    """Compile the assessment graph."""
    return build_assessment_graph_v2(checkpointer=checkpointer, executor=executor)


def graph_config(assessment_id: int, run_id: str | None = None) -> dict:
    """LangGraph config with thread_id pinned to the assessment."""
    tags = [f"assessment:{assessment_id}", f"assessment-{assessment_id}"]
    if run_id:
        tags.append(f"run:{run_id}")
    return {
        "run_name": f"Assessment-{assessment_id}",
        "tags": tags,
        "metadata": {
            "assessment_id": assessment_id,
            "run_id": run_id,
            "agent_loop": settings.agent_loop,
        },
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

    is_juiceshop_target = any(
        "3000" in t or "juice" in t.lower() or (t and t in settings.juiceshop_url)
        for t in assessment.targets
    )
    if is_juiceshop_target:
        try:
            from app.integrations.juiceshop import capture_baseline
            await capture_baseline(session, assessment_id)
        except Exception as exc:  # noqa: BLE001 - bonus feature
            from app.core.log import get_logger

            get_logger("agent.graph").debug("challenge baseline unavailable: %s", exc)

    audit_repo = AuditRepo(session)
    from app.agents.model import role_model_config
    from app.core.log import get_logger

    role_models = role_model_config()
    run_log = get_logger("agent.run")
    run_log.info("run %s model config (provider/model per role):", assessment_id)
    for role, cfg in role_models.items():
        run_log.info("  %-12s %-12s %s", role, cfg["provider"], cfg["model"])

    await audit_repo.add(
        assessment_id=assessment_id,
        event_type="run.requested",
        payload={
            "actor": actor,
            "mode": "three_role_loop",
            "models": role_models,
        },
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
                _graphs[loop_version] = build_assessment_graph_v2(checkpointer=saver)
    return _graphs[loop_version]
