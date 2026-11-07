"""Intake node: validate targets, set status to PLANNING, emit agent.started."""

from app.agents.graph.state import AssessmentState
from app.agents.control import audit, role_history
from app.core.db import get_async_session_ctx
from app.domain.models import AssessmentStatus
from app.persistence import AssessmentRepo


async def intake_node(state: AssessmentState) -> dict:
    assessment_id = state["assessment_id"]
    run_id = state["run_id"]
    async with get_async_session_ctx() as session:
        repo = AssessmentRepo(session)
        assessment = await repo.get(assessment_id)
        if assessment is None:
            raise LookupError(f"assessment {assessment_id} not found")
        if not assessment.targets:
            raise ValueError("assessment has no authorised targets")
        for target in assessment.targets:
            if target in assessment.exclusions:
                raise ValueError(f"target {target} is also excluded")

        assessment.status = AssessmentStatus.PLANNING.value
        assessment.finished_at = None
        assessment.report_path = None
        assessment.report_sha256 = None
        audit(
            session,
            assessment_id,
            "agent.started",
            {
                "run_id": run_id,
                "targets": assessment.targets,
                "ports": assessment.ports,
                "request": assessment.request,
                "roles": ["recon", "discovery", "validation"],
            },
            actor="system",
        )
        history = await role_history(session, assessment_id, run_id)
        await session.commit()

    return {
        "targets": assessment.targets,
        "ports": assessment.ports,
        "exclusions": assessment.exclusions,
        "role": "recon",
        "role_history": history,
        "role_messages": {},
        "observations": [],
        "plan": [],
        "plan_source": "",
        "step_count": 0,
        "turns": {},
        "finished": False,
        "review_approved": False,
        "rejected": False,
        "last_message": "Intake accepted; recon is choosing the first action.",
        "next_node": "recon",
    }
