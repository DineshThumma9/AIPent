"""Report node: generate report, mark completed."""

from __future__ import annotations

from app.agents.graph.state import AssessmentState
from app.core.db import get_async_session_ctx
from app.core.log import get_logger
from app.domain.models import AssessmentStatus, utcnow
from app.persistence import AssessmentRepo, AuditRepo
from app.reporting.report import generate_report

log = get_logger("agent.graph")


async def report_node(state: AssessmentState) -> dict:
    assessment_id = state["assessment_id"]

    async with get_async_session_ctx() as session:
        repo = AssessmentRepo(session)
        assessment = await repo.get(assessment_id)
        if assessment is None:
            raise LookupError(f"assessment {assessment_id} not found")
        assessment.status = AssessmentStatus.REPORTING.value
        await repo.session.commit()
        try:
            path = await generate_report(session, assessment_id)
            assessment.status = AssessmentStatus.COMPLETED.value
            assessment.finished_at = utcnow()
            await repo.session.commit()
            return {
                "finished": True,
                "report_path": str(path),
                "last_message": f"Report written to {path}.",
            }
        except Exception as exc:  # noqa: BLE001 - status records the failure
            log.exception("report failed assessment=%s", assessment_id)
            assessment.status = AssessmentStatus.FAILED.value
            assessment.finished_at = utcnow()
            audit_repo = AuditRepo(session)
            await audit_repo.add(
                assessment_id=assessment_id,
                event_type="report.failed",
                payload={"error": str(exc)[:500]},
            )
            await repo.session.commit()
            return {
                "finished": True,
                "error": str(exc)[:500],
                "last_message": f"Report failed: {str(exc)[:200]}",
            }
