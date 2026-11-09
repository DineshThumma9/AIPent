"""Step and Approval persistence."""

import json
from typing import Any
from urllib.parse import urlsplit
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
from app.core.policy import policy_for
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


def _step_matches(
    row: Step, target: str, params: dict[str, Any] | None
) -> bool:
    """Whether a queued step is the same action the agent is asking for.

    Most actions are unique per target. HTTP probes are not: one target can
    have many interesting paths, so compare method and path too.
    """
    if row.target != target:
        return False
    if row.action != "curl_request":
        return True
    probe = params or {}
    method = str(probe.get("method", "GET")).upper()
    path = str(probe.get("path") or probe.get("url") or "/")
    if path.startswith("http"):
        path = urlsplit(path).path
    if not path.startswith("/"):
        path = "/" + path
    if len(row.argv) >= 3 and row.argv[0] == "mcp":
        try:
            mcp_args = json.loads(row.argv[2]) if isinstance(row.argv[2], str) else row.argv[2]
            if isinstance(mcp_args, dict):
                if mcp_args.get("method", "GET").upper() != method:
                    return False
                return urlsplit(mcp_args.get("url", "")).path == path
        except Exception:
            return False
    if len(row.argv) < 3 or row.argv[1].upper() != method:
        return False
    return urlsplit(row.argv[2]).path == path


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
        params: dict[str, Any] | None = None,
        detail: dict[str, Any] | None = None,
        auto_approve: bool = False,
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

        # Count actions for this run using audit events, and remember
        # which steps belong to this run so duplicates from an earlier run do
        # not block a legitimate rerun.
        result = await self.session.execute(
            select(Audit).where(
                Audit.assessment_id == assessment_id,
                Audit.event_type.in_(["action.queued", "action.requested"]),
            )
        )
        events = result.scalars().all()
        run_events = [
            event for event in events if (event.payload or {}).get("run_id") == run_id
        ]
        run_step_ids = {
            (event.payload or {}).get("step_id") for event in run_events
        }
        if len(run_events) >= settings.max_steps:
            return {
                "error": (
                    f"action budget exhausted ({settings.max_steps} queued actions "
                    "for this run); hand off and let the analyst review what ran"
                )
            }

        if action == "curl_request":
            probes = sum(
                1
                for event in run_events
                if (event.payload or {}).get("action") == "curl_request"
            )
            if probes >= settings.max_validation_probes:
                return {
                    "error": (
                        "validation probe budget exhausted for this run "
                        f"({settings.max_validation_probes} probes); hand off "
                        "and let the analyst review the evidence"
                    )
                }

        result = await self.session.execute(
            select(Step).where(
                Step.assessment_id == assessment_id,
                Step.action == action,
                Step.status.in_(ACTIVE_STATES),
            )
        )
        existing = result.scalars().all()
        for row in existing:
            if row.id not in run_step_ids:
                continue
            duplicate = (
                row.argv == argv
                if argv is not None
                else _step_matches(row, target, params)
            )
            if duplicate:
                return {
                    "queued": True,
                    "duplicate_of_step": row.id,
                    "status": row.status,
                    "note": "this action is already queued or executed; not resent",
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
            argv = resolve_argv(action, assessment, target, step.id or 0, params=params)
        elif spec.output == "file":
            output_path = str(_artifact_dir(assessment_id) / f"{step.id}{spec.suffix}")
            argv = inject_output_path(list(argv), output_path, spec)
        step.argv = argv

        policy = policy_for(action)
        approval_detail: dict[str, Any] = {
            "role": role,
            "phase": role,
            "rationale": rationale,
            "tool": spec.tool,
            "params": params or {},
            "risk": policy.risk,
            "requires_approval": policy.requires_approval,
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
        event_type = "action.requested" if settings.agent_loop == "v2" else "action.queued"
        self.session.add(
            Audit(
                assessment_id=assessment_id,
                actor="system",
                event_type=event_type,
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
                "ends; its result appears in the next observation. Stop calling "
                "tools and return a short summary."
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
                Step.action == "curl_request",
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
