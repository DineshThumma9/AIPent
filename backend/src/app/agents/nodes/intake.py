"""Intake node for V2 agent loop."""

from __future__ import annotations

from typing import TYPE_CHECKING
from langgraph.types import Command

if TYPE_CHECKING:
    from app.agents.state import AssessmentState

from app.core.db import get_async_session_ctx
from app.core.log import get_logger
from app.persistence import AssessmentRepo, AuditRepo

logger = get_logger("agent.nodes.intake")


async def intake_node(state: AssessmentState) -> Command:
    """Initialize state for V2 loop from DB and route to supervisor."""
    assessment_id = state["assessment_id"]
    logger.info("intake_node: initializing assessment=%s run=%s", assessment_id, state.get("run_id"))
    async with get_async_session_ctx() as session:
        assessment = await AssessmentRepo(session).get(assessment_id)
        if assessment is None:
            raise LookupError(f"assessment {assessment_id} not found")

        targets = list(assessment.targets or [])
        ports = list(assessment.ports or [])
        exclusions = list(assessment.exclusions or [])

        from app.agents.model import role_model_config

        await AuditRepo(session).record_event(
            assessment_id=assessment_id,
            event_type="agent.started",
            payload={
                "run_id": state["run_id"],
                "loop": "v2",
                "targets": targets,
                "ports": ports,
                "models": role_model_config(),
            },
        )
        await session.commit()

    return Command(
        update={
            "targets": targets,
            "ports": ports,
            "exclusions": exclusions,
            "messages": [],
            "pending_action": None,
            "approval_decision": None,
            "last_handoff": None,
            "turns": {},
            "nudges": 0,
            "no_progress": 0,
            "finished": False,
            "report_narrative": None,
            "supervisor_decision": None,
            "supervisor_directive": None,
            "failure_signal": None,
            "supervisor_calls": 0,
            "observations": [],
            "next_node": "supervisor",
        },
        goto="supervisor",
    )
