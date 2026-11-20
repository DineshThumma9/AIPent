"""Reporting and human review nodes for V2 agent loop."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING
from langgraph.graph import END
from langgraph.types import Command, interrupt

if TYPE_CHECKING:
    from app.agents.state import AssessmentState

from app.core.db import get_async_session_ctx
from app.core.log import get_logger
from app.domain.models import AssessmentStatus, Decision, utcnow
from app.domain.risk import summarize
from app.persistence import AssessmentRepo, AuditRepo, FindingRepo, StepRepo
from app.reporting.narrative import build_narrative_context, write_narrative_result
from app.reporting.report import generate_report

logger = get_logger("agent.nodes.reporting")


async def review_node(state: AssessmentState) -> Command:
    """Final human delivery review gate."""
    assessment_id = state["assessment_id"]

    async with get_async_session_ctx() as session:
        assessment_repo = AssessmentRepo(session)
        step_repo = StepRepo(session)
        finding_repo = FindingRepo(session)
        audit_repo = AuditRepo(session)

        board = await audit_repo.get_evidence_board(assessment_id)
        findings = await finding_repo.get_all(assessment_id, limit=10000)
        summary = summarize(findings)

        approval = await step_repo.get_pending_approval_by_action(assessment_id, "final_review")
        if approval is None:
            approval = await step_repo.create_approval(
                assessment_id=assessment_id,
                action="final_review",
                argv=[],
                detail={
                    "risk_score": summary["score"],
                    "counts": summary["counts"],
                    "findings": len(findings),
                    "role": "review",
                    "source": "three_role_loop",
                },
            )
        approval_id = approval.id
        await assessment_repo.set_status(assessment_id, AssessmentStatus.AWAITING_APPROVAL.value)

    decision = interrupt({
        "gate": "review",
        "role": "review",
        "approval_id": approval_id,
        "evidence_board": board.model_dump(),
        "message": "Approve the report, or reject to stop without a report.",
    })

    decision_dict = decision if isinstance(decision, dict) else {}
    approved = str(decision_dict.get("decision", "approved")).lower() == "approved"

    async with get_async_session_ctx() as session:
        step_repo = StepRepo(session)
        assessment_repo = AssessmentRepo(session)

        pending = await step_repo.get_pending_approval_by_action(assessment_id, "final_review")
        if pending is not None:
            await step_repo.resolve_approval(
                approval_id=pending.id,
                decision=Decision.APPROVED.value if approved else Decision.REJECTED.value,
                actor=str(decision_dict.get("actor") or "operator"),
                reason=str(decision_dict.get("reason") or "") or None,
                outcome="review " + ("accepted" if approved else "rejected"),
            )

        new_status = AssessmentStatus.RUNNING.value if approved else AssessmentStatus.CANCELLED.value
        await assessment_repo.set_status(assessment_id, new_status)

    if not approved:
        return Command(
            update={"finished": True},
            goto=END,
        )

    return Command(
        goto="report_writer",
    )


async def report_writer_node(state: AssessmentState) -> Command:
    """Report narrative generator node (LLM structured output + Python validation)."""
    assessment_id = state["assessment_id"]
    narrative_data = None
    logger.info("report_writer_node: compiling report narrative for assessment=%s...", assessment_id)
    async with get_async_session_ctx() as session:
        audit_repo = AuditRepo(session)
        try:
            context = await build_narrative_context(session, assessment_id)
            narrative_writer_fn = getattr(
                sys.modules.get("app.agents.nodes"),
                "write_narrative_result",
                write_narrative_result,
            )
            narrative, err = await narrative_writer_fn(context)
            if narrative is not None:
                narrative_data = narrative.model_dump()
                await audit_repo.record_event(
                    assessment_id=assessment_id,
                    event_type="report.narrative_generated",
                    payload={
                        "findings_count": len(narrative.findings),
                        "executive_summary_len": len(narrative.executive_summary),
                    },
                )
            else:
                await audit_repo.record_event(
                    assessment_id=assessment_id,
                    event_type="report.narrative_fallback",
                    payload={
                        "reason": "validation_failed_or_model_error",
                        "error": err or "unknown",
                    },
                )
            await session.commit()
        except Exception as exc:
            logger.exception("report_writer_node unexpected exception: %s", exc)
            await audit_repo.record_event(
                assessment_id=assessment_id,
                event_type="report.narrative_fallback",
                payload={"reason": "exception", "error": str(exc)},
            )
            await session.commit()

    return Command(
        update={"report_narrative": narrative_data},
        goto="report",
    )


async def report_node(state: AssessmentState) -> Command:
    """Compile PDF report and finish run."""
    assessment_id = state["assessment_id"]
    narrative = state.get("report_narrative")
    async with get_async_session_ctx() as session:
        assessment_repo = AssessmentRepo(session)
        await assessment_repo.set_status(
            assessment_id,
            AssessmentStatus.COMPLETED.value,
            finished_at=utcnow(),
        )
        report_path = await generate_report(session, assessment_id, narrative=narrative)
        assessment = await assessment_repo.get(assessment_id)
        if assessment:
            assessment.report_path = str(report_path)
            await session.commit()

    return Command(
        update={
            "report_path": str(report_path),
            "finished": True,
        },
        goto=END,
    )
