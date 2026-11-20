"""Initial assessment plan gate.

The supervisor drafts a generic plan from the analyst's request before any
action runs. The operator can edit it in the Web UI or CLI; only then does the
graph proceed to routing. Every specialist and the supervisor receive the
approved plan in their brief/digest.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from langgraph.graph import END
from langgraph.types import Command, interrupt
from sqlmodel import select

if TYPE_CHECKING:
    from app.agents.state import AssessmentState

from app.agents.mission_brain import (
    available_plan_actions,
    generate_initial_plan,
    normalize_plan_steps,
)
from app.core.db import get_async_session_ctx
from app.core.log import get_logger
from app.domain.models import Approval, AssessmentStatus, Decision, SteeringNote, utcnow
from app.persistence import AssessmentRepo, AuditRepo

logger = get_logger("agent.nodes.planning")


def _feedback_from_steering(notes: list[Any] | None) -> str:
    if not notes:
        return ""
    texts = [str(getattr(n, "text", n)).strip() for n in notes]
    return "\n".join(t for t in texts if t)[:2000]


async def plan_node(state: AssessmentState) -> Command:
    """Generate the plan, pause for human review, then publish the approved plan."""
    if state.get("plan_approved"):
        return Command(goto="supervisor")

    assessment_id = state["assessment_id"]
    run_id = state.get("run_id", "")

    async with get_async_session_ctx() as session:
        assessment_repo = AssessmentRepo(session)
        audit_repo = AuditRepo(session)
        assessment = await assessment_repo.get(assessment_id)
        if assessment is None:
            raise LookupError(f"assessment {assessment_id} not found")

        steering_result = await session.execute(
            select(SteeringNote).where(
                SteeringNote.assessment_id == assessment_id,
                SteeringNote.status == "pending",
            )
        )
        steering = list(steering_result.scalars().all())
        feedback = _feedback_from_steering(steering) or state.get("plan_feedback", "")
        objective = assessment.request or "Assess the authorized target within scope."
        targets = list(assessment.targets or [])
        ports = list(assessment.ports or [])

        result = await session.execute(
            select(Approval).where(
                Approval.assessment_id == assessment_id,
                Approval.action == "initial_plan",
                Approval.decision == Decision.PENDING.value,
            )
        )
        pending_row = result.scalars().first()

        if pending_row is None:
            steps, source, notes = await generate_initial_plan(
                objective=objective,
                targets=targets,
                ports=ports,
                exclusions=list(assessment.exclusions or []),
                feedback=feedback,
            )
            pending_row = Approval(
                assessment_id=assessment_id,
                step_id=None,
                action="initial_plan",
                argv=[],
                detail={
                    "gate": "plan",
                    "run_id": run_id,
                    "requires_approval": True,
                    "objective": objective,
                    "targets": targets,
                    "ports": ports,
                    "plan": steps,
                    "source": source,
                    "notes": notes,
                    "available_actions": available_plan_actions(),
                },
                decision=Decision.PENDING.value,
                requested_at=utcnow(),
            )
            session.add(pending_row)
            await session.commit()
            await session.refresh(pending_row)
            await audit_repo.record_event(
                assessment_id=assessment_id,
                event_type="plan.proposed",
                payload={
                    "run_id": run_id,
                    "approval_id": pending_row.id,
                    "plan": steps,
                    "source": source,
                    "notes": notes,
                },
                actor="supervisor",
            )
            await assessment_repo.set_status(
                assessment_id, AssessmentStatus.AWAITING_PLAN.value
            )
            await session.commit()
            logger.info(
                "plan_node: proposed %s steps (source=%s) assessment=%s",
                len(steps),
                source,
                assessment_id,
            )

        proposal = pending_row.detail or {}
        interrupt_payload = {
            "gate": "plan",
            "approval_id": pending_row.id,
            "objective": proposal.get("objective", objective),
            "targets": proposal.get("targets", targets),
            "plan": normalize_plan_steps(proposal.get("plan")),
            "notes": proposal.get("notes", ""),
            "source": proposal.get("source", ""),
            "available_actions": available_plan_actions(),
        }

    logger.info("plan_node: waiting for operator plan review assessment=%s", assessment_id)
    raw_decision = interrupt(interrupt_payload)
    decision = raw_decision if isinstance(raw_decision, dict) else {}
    approved = str(decision.get("decision", "rejected")).lower() == "approved"
    actor = str(decision.get("actor") or "analyst")
    reason = str(decision.get("reason") or "")
    feedback = str(decision.get("feedback") or "")[:2000]
    steps = normalize_plan_steps(decision.get("plan")) or normalize_plan_steps(
        interrupt_payload["plan"]
    )
    steps = [s for s in steps if s.get("enabled") is not False]
    source = "operator-reviewed" if decision.get("plan") else interrupt_payload["source"]

    async with get_async_session_ctx() as session:
        audit_repo = AuditRepo(session)
        assessment_repo = AssessmentRepo(session)
        row = await session.get(Approval, interrupt_payload["approval_id"])
        if row is not None:
            row.decision = Decision.APPROVED.value if approved else Decision.REJECTED.value
            row.actor = actor
            row.reason = reason or ("Approved from the mission desk" if approved else "Rejected from the mission desk")
            row.decided_at = utcnow()
            row.outcome = "plan approved" if approved else "plan rejected"
            row.detail = {
                **(row.detail or {}),
                "plan": steps,
                "source": source,
                "feedback": feedback,
            }
        if approved:
            await assessment_repo.set_status(assessment_id, AssessmentStatus.RUNNING.value)
        else:
            await assessment_repo.set_status(assessment_id, AssessmentStatus.CANCELLED.value)
        await audit_repo.record_event(
            assessment_id=assessment_id,
            event_type="plan.approved" if approved else "plan.rejected",
            payload={
                "run_id": run_id,
                "approval_id": interrupt_payload["approval_id"],
                "actor": actor,
                "reason": reason,
                "feedback": feedback,
                "plan": steps if approved else [],
            },
            actor=actor,
        )
        if feedback:
            await audit_repo.record_event(
                assessment_id=assessment_id,
                event_type="plan.feedback",
                payload={"run_id": run_id, "feedback": feedback, "actor": actor},
                actor=actor,
            )
        await session.commit()

    if not approved:
        return Command(
            update={
                "plan": [],
                "plan_source": "rejected",
                "plan_approved": False,
                "plan_feedback": feedback,
                "finished": True,
                "last_message": f"Plan rejected by {actor}: {reason or 'no reason given'}",
            },
            goto=END,
        )

    logger.info(
        "plan_node: approved %s steps (source=%s) assessment=%s",
        len(steps),
        source,
        assessment_id,
    )
    return Command(
        update={
            "plan": steps,
            "plan_source": source,
            "plan_approved": True,
            "plan_feedback": feedback,
            "last_message": f"Approved plan: {len(steps)} steps. Every role is now briefed with the target and rationale.",
        },
        goto="supervisor",
    )
