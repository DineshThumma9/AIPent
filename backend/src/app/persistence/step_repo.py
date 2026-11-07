"""Step and Approval persistence."""

from typing import Any
from uuid import uuid4

from sqlalchemy import func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from app.actions import (
    ScopeError,
    _artifact_dir,
    check_scope,
    get_action,
    inject_output_path,
    resolve_argv,
)
from app.core.config import settings
from app.domain.models import (
    Approval,
    Assessment,
    Decision,
    Step,
    StepStatus,
    utcnow,
)
from app.persistence.base import BaseRepo
from app.domain.models import Audit
ACTIVE_STATES = (
    StepStatus.PLANNED.value,
    StepStatus.RUNNING.value,
    StepStatus.SUCCEEDED.value,
)


class StepRepo(BaseRepo):
    """All database access for steps and approvals."""

    async def create_step(
        self,
        assessment: Assessment,
        run_id: str,
        role: str,
        action: str,
        target: str,
        rationale: str,
        *,
        argv: list[str] | None = None,
        detail: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a planned Step plus a pending Approval bound to its argv.

        Returns a dict the tool can hand straight to the LLM.
        """
        assessment_id = assessment.id or 0
        spec = get_action(action)

        try:
            check_scope(assessment, target)
        except ScopeError as exc:
            return {"error": str(exc)}

        result = await self.session.execute(
            select(Step).where(
                Step.assessment_id == assessment_id,
                Step.action == action,
                Step.status.in_(ACTIVE_STATES),
            )
        )
        existing = result.scalars().all()
        for row in existing:
            duplicate = row.argv == argv if argv is not None else row.target == target
            if duplicate:
                return {
                    "queued": True,
                    "duplicate_of_step": row.id,
                    "status": row.status,
                    "note": "this action is already queued or executed; not resent",
                }

        # Count queued actions for this run using audit events.
        result = await self.session.execute(
            select(Audit).where(
                Audit.assessment_id == assessment_id,
                Audit.event_type == "action.queued",
            )
        )
        events = result.scalars().all()
        queued_count = sum(
            1 for event in events if (event.payload or {}).get("run_id") == run_id
        )
        if queued_count >= settings.max_steps:
            return {
                "error": (
                    f"action budget exhausted ({settings.max_steps} queued actions "
                    "for this run); hand off and let the analyst review what ran"
                )
            }

        step = Step(
            assessment_id=assessment_id,
            seq=(await self._next_seq(assessment_id)),
            action=action,
            target=target,
            rationale=rationale,
            status=StepStatus.PLANNED.value,
        )
        self.session.add(step)
        await self.session.flush()

        if argv is None:
            argv = resolve_argv(action, assessment, target, step.id or 0)
        elif spec.output == "file":
            output_path = str(_artifact_dir(assessment_id) / f"{step.id}{spec.suffix}")
            argv = inject_output_path(list(argv), output_path, spec)
        step.argv = argv

        approval_detail: dict[str, Any] = {
            "role": role,
            "phase": role,
            "rationale": rationale,
            "tool": spec.tool,
            "plan": [
                {"action": action, "target": target, "rationale": rationale},
            ],
        }
        if detail:
            approval_detail.update(detail)

        approval = Approval(
            assessment_id=assessment_id,
            step_id=step.id,
            action=action,
            argv=argv,
            detail=approval_detail,
        )
        self.session.add(approval)
        await self.session.flush()
        self.session.add(
            Audit(
                assessment_id=assessment_id,
                actor="system",
                event_type="action.queued",
                payload={
                    "run_id": run_id,
                    "role": role,
                    "step_id": step.id,
                    "action": action,
                    "target": target,
                    "argv": argv,
                },
            )
        )
        await self.session.commit()

        return {
            "queued": True,
            "step_id": step.id,
            "approval_id": approval.id,
            "action": action,
            "target": target,
            "argv": argv,
            "gate": "action",
            "note": (
                "Queued, not executed. The gate runs this action after your turn "
                "ends; its result appears in the next observation. Do not poll "
                "query_steps/query_findings waiting for it — call handoff now."
            ),
        }

    async def _next_seq(self, assessment_id: int) -> int:
        result = await self.session.execute(
            select(func.max(Step.seq)).where(Step.assessment_id == assessment_id)
        )
        current = result.scalar()
        return (current or 0) + 1

    async def get_pending(self, assessment_id: int) -> Step | None:
        """Return the oldest planned step, if any."""
        result = await self.session.execute(
            select(Step)
            .where(
                Step.assessment_id == assessment_id,
                Step.status == StepStatus.PLANNED.value,
            )
            .order_by(Step.seq)
        )
        return result.scalars().first()

    async def get_by_id(self, step_id: int) -> Step | None:
        return await self.session.get(Step, step_id)

    async def mark_succeeded(self, step: Step) -> None:
        step.status = StepStatus.SUCCEEDED.value
        step.ended_at = utcnow()
        self.session.add(step)
        await self.session.commit()

    async def mark_failed(self, step: Step, error: str) -> None:
        step.status = StepStatus.FAILED.value
        step.error = error[:500]
        step.ended_at = utcnow()
        self.session.add(step)
        await self.session.commit()

    async def mark_rejected(self, step: Step, error: str) -> None:
        step.status = StepStatus.REJECTED.value
        step.error = error
        step.ended_at = utcnow()
        self.session.add(step)
        await self.session.commit()

    async def count_probes(self, assessment_id: int) -> int:
        result = await self.session.execute(
            select(func.count(Step.id)).where(
                Step.assessment_id == assessment_id,
                Step.action == "http_probe",
                Step.status.in_(ACTIVE_STATES),
            )
        )
        return result.scalar() or 0

    async def count_steps(self, assessment_id: int) -> int:
        result = await self.session.execute(
            select(func.count(Step.id)).where(
                Step.assessment_id == assessment_id
            )
        )
        return result.scalar() or 0

    async def get_all(self, assessment_id: int) -> list[Step]:
        result = await self.session.execute(
            select(Step).where(Step.assessment_id == assessment_id).order_by(Step.seq)
        )
        return list(result.scalars().all())

    async def get_recent(
        self, assessment_id: int, limit: int = 8
    ) -> list[Step]:
        result = await self.session.execute(
            select(Step)
            .where(Step.assessment_id == assessment_id)
            .order_by(Step.seq.desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def update_step_fields(
        self,
        step: Step,
        *,
        rationale: str | None = None,
        target: str | None = None,
    ) -> None:
        if rationale is not None:
            step.rationale = rationale
        if target is not None:
            step.target = target
        self.session.add(step)
        await self.session.commit()
        await self.session.refresh(step)

    async def count_by_action_and_status(
        self, assessment_id: int, action: str, statuses: tuple[str, ...]
    ) -> int:
        result = await self.session.execute(
            select(func.count(Step.id)).where(
                Step.assessment_id == assessment_id,
                Step.action == action,
                Step.status.in_(statuses),
            )
        )
        return result.scalar() or 0

    async def is_duplicate(
        self,
        assessment_id: int,
        action: str,
        target: str | None = None,
        argv: list[str] | None = None,
    ) -> Step | None:
        result = await self.session.execute(
            select(Step).where(
                Step.assessment_id == assessment_id,
                Step.action == action,
                Step.status.in_(ACTIVE_STATES),
            )
        )
        existing = result.scalars().all()
        for row in existing:
            duplicate = row.argv == argv if argv is not None else row.target == target
            if duplicate:
                return row
        return None

    async def get_approval_for_step(self, step_id: int) -> Approval | None:
        result = await self.session.execute(
            select(Approval)
            .where(Approval.step_id == step_id)
            .order_by(Approval.id.desc())
        )
        return result.scalars().first()

    async def create_approval(
        self,
        assessment_id: int,
        action: str,
        argv: list[str],
        detail: dict[str, Any],
        step_id: int | None = None,
    ) -> Approval:
        approval = Approval(
            assessment_id=assessment_id,
            step_id=step_id,
            action=action,
            argv=argv,
            detail=detail,
        )
        self.session.add(approval)
        await self.session.flush()
        await self.session.commit()
        await self.session.refresh(approval)
        return approval

    async def mark_step_running(self, step: Step) -> None:
        step.status = StepStatus.RUNNING.value
        step.error = None
        self.session.add(step)
        await self.session.commit()
        await self.session.refresh(step)
