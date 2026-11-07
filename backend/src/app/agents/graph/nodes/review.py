"""Review node: interrupt for final review, route to report if approved."""

from __future__ import annotations

from typing import Literal

from langgraph.graph import END
from langgraph.types import Command, interrupt
from sqlmodel import select

from app.agents.graph.context import challenge_delta, read_decision
from app.agents.graph.state import AssessmentState
from app.agents.control import role_history
from app.core.db import get_async_session_ctx
from app.core.log import get_logger
from app.domain.models import (
    Approval,
    AssessmentStatus,
    Decision,
    utcnow,
)
from app.domain.risk import refresh_risk, summarize
from app.persistence import AssessmentRepo, AuditRepo, FindingRepo, StepRepo

log = get_logger("agent.graph")


async def review_node(state: AssessmentState) -> Command[Literal["report", "__end__"]]:
    assessment_id = state["assessment_id"]
    async with get_async_session_ctx() as session:
        repo = AssessmentRepo(session)
        assessment = await repo.get(assessment_id)
        if assessment is None:
            raise LookupError(f"assessment {assessment_id} not found")
        finding_repo = FindingRepo(session)
        findings = await finding_repo.get_all(assessment_id, limit=10000)
        summary = summarize(findings)
        await refresh_risk(session, assessment_id)

        delta = await challenge_delta(assessment_id)
        if delta:
            try:
                from app.integrations.juiceshop import snapshot_to_artifact

                await snapshot_to_artifact(session, assessment_id, delta)
            except Exception as exc:  # noqa: BLE001 - bonus feature
                log.debug("challenge snapshot unavailable: %s", exc)

        history = await role_history(session, assessment_id, state["run_id"])
        step_repo = StepRepo(session)
        result = await session.execute(
            select(Approval)
            .where(
                Approval.assessment_id == assessment_id,
                Approval.action == "final_review",
                Approval.decision == Decision.PENDING.value,
            )
            .order_by(Approval.id)
        )
        approval = result.scalars().first()
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
                    "role_history": history,
                    "challenge_delta": delta,
                },
            )
        assessment.status = AssessmentStatus.AWAITING_APPROVAL.value
        await repo.session.commit()

        digest = {
            "risk_score": summary["score"],
            "counts": summary["counts"],
            "n_findings": len(findings),
            "roles": [row.get("to") for row in history],
            "challenge_delta": delta,
        }

    decision = interrupt({"gate": "review", "digest": digest, "role": "review"})
    approved, actor, reason = read_decision(decision)

    async with get_async_session_ctx() as session:
        repo = AssessmentRepo(session)
        audit_repo = AuditRepo(session)
        result = await session.execute(
            select(Approval)
            .where(
                Approval.assessment_id == assessment_id,
                Approval.action == "final_review",
                Approval.decision == Decision.PENDING.value,
            )
            .order_by(Approval.id)
        )
        approval = result.scalars().first()
        if approval is not None:
            approval.decision = (
                Decision.APPROVED.value if approved else Decision.REJECTED.value
            )
            approval.actor = actor
            approval.reason = reason or None
            approval.decided_at = utcnow()
            approval.outcome = "review " + ("accepted" if approved else "rejected")
        await audit_repo.add(
            assessment_id=assessment_id,
            event_type="review." + ("approved" if approved else "rejected"),
            payload={"actor": actor, "reason": reason},
        )
        assessment = await repo.get(assessment_id)
        if assessment is not None:
            if approved:
                assessment.status = AssessmentStatus.RUNNING.value
            else:
                assessment.status = AssessmentStatus.CANCELLED.value
                assessment.finished_at = utcnow()
        await repo.session.commit()

    if approved:
        return Command(
            update={
                "review_approved": True,
                "rejected": False,
                "finished": True,
                "last_message": f"Final review approved by {actor}.",
                "risk_score": summary["score"],
            },
            goto="report",
        )
    return Command(
        update={
            "review_approved": False,
            "rejected": True,
            "finished": True,
            "last_message": f"Final review rejected by {actor}.",
        },
        goto=END,
    )


async def _challenge_delta(assessment_id: int) -> dict | None:
    """Re-exported via graph/__init__ for tests (monkeypatch target)."""
    import app.agents.graph as _pkg

    if hasattr(_pkg, "_challenge_delta"):
        return await _pkg._challenge_delta(assessment_id)
    return await challenge_delta(assessment_id)
