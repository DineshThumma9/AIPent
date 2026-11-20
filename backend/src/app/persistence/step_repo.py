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


def _curl_path(value: str) -> str:
    """Normalize a path or full URL to path + query for duplicate checks."""
    text = str(value or "/")
    if text.startswith(("http://", "https://")):
        parsed = urlsplit(text)
        text = parsed.path or "/"
        if parsed.query:
            text += "?" + parsed.query
    if not text.startswith("/"):
        text = "/" + text
    return text


def _batch_signature(requests: Any) -> tuple[tuple[str, str], ...]:
    """Order-sensitive signature of a curl batch for duplicate detection."""
    if not isinstance(requests, list):
        return ()
    signature: list[tuple[str, str]] = []
    for item in requests:
        if not isinstance(item, dict):
            return ()
        signature.append(
            (
                str(item.get("method") or "GET").upper(),
                _curl_path(str(item.get("path") or item.get("url") or "/")),
            )
        )
    return tuple(signature)


def _clean_target_host(target: str) -> str:
    from app.actions.catalogue import _clean_host_and_port
    host, _ = _clean_host_and_port(target, 80)
    return host


def _step_matches(
    row: Step, target: str, params: dict[str, Any] | None
) -> bool:
    """Whether a queued step is the same action the agent is asking for.

    Most actions are unique per target. HTTP probes are not: one target can
    have many interesting paths, so compare method and path too.
    """
    if row.target != target and _clean_target_host(row.target) != _clean_target_host(target):
        return False
    if row.action != "curl_request":
        return True
    probe = params or {}
    batch = probe.get("requests")
    if batch:
        desired = _batch_signature(batch)
        if len(row.argv) >= 3 and row.argv[0] == "mcp":
            try:
                mcp_args = json.loads(row.argv[2]) if isinstance(row.argv[2], str) else row.argv[2]
                if isinstance(mcp_args, dict):
                    return _batch_signature(mcp_args.get("batch")) == desired
            except Exception:
                return False
        return False
    method = str(probe.get("method", "GET")).upper()
    path = _curl_path(str(probe.get("path") or probe.get("url") or "/"))
    if len(row.argv) >= 3 and row.argv[0] == "mcp":
        try:
            mcp_args = json.loads(row.argv[2]) if isinstance(row.argv[2], str) else row.argv[2]
            if isinstance(mcp_args, dict):
                if mcp_args.get("method", "GET").upper() != method:
                    return False
                return _curl_path(str(mcp_args.get("url", ""))) == path
        except Exception:
            return False
    if len(row.argv) < 3 or row.argv[1].upper() != method:
        return False
    return _curl_path(row.argv[2]) == path


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

        probe_count = 1
        if action == "curl_request":
            probe_count = len((params or {}).get("requests") or []) or 1
            probes = sum(
                int((event.payload or {}).get("probe_count", 1))
                for event in run_events
                if (event.payload or {}).get("action") == "curl_request"
            )
            if probes + probe_count > settings.max_validation_probes:
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

        # Circuit breaker: prevent repeated failing attempts on identical target/action in the same run
        failed_res = await self.session.execute(
            select(Step).where(
                Step.assessment_id == assessment_id,
                Step.action == action,
                Step.status.in_(["failed", "rejected"]),
            )
        )
        failed_rows = [
            row for row in failed_res.scalars().all()
            if row.id in run_step_ids and (row.argv == argv if argv is not None else _step_matches(row, target, params))
        ]
        if len(failed_rows) >= 2:
            last_err = failed_rows[-1].error or "previously failed"
            return {
                "error": (
                    f"Action {action} on {target} has already failed {len(failed_rows)} times in this run "
                    f"({last_err}). Circuit breaker active: pivot to another endpoint or investigation path."
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
                    "probe_count": probe_count,
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

    async def get_pending_approval_by_action(
        self, assessment_id: int, action: str
    ) -> Approval | None:
        """Find an existing pending approval for this assessment and action."""
        result = await self.session.execute(
            select(Approval)
            .where(
                Approval.assessment_id == assessment_id,
                Approval.action == action,
                Approval.decision == Decision.PENDING.value,
            )
            .order_by(Approval.id)
        )
        return result.scalars().first()

    async def resolve_approval(
        self,
        approval_id: int,
        decision: str,
        actor: str = "operator",
        reason: str | None = None,
        outcome: str | None = None,
    ) -> Approval | None:
        """Resolve a pending approval with decision, actor, reason, and outcome."""
        approval = await self.session.get(Approval, approval_id)
        if approval is not None:
            approval.decision = decision
            approval.actor = actor
            approval.reason = reason
            approval.decided_at = utcnow()
            if outcome is not None:
                approval.outcome = outcome
            self.session.add(approval)
            await self.session.flush()
        return approval

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

    async def create_planned_step(
        self,
        assessment_id: int,
        run_id: str,
        role: str,
        action: str,
        target: str,
        argv: list[str] | None = None,
        risk: str = "medium",
        requires_approval: bool = True,
        rationale: str = "",
        policy_reason: str | None = None,
        detail: dict[str, Any] | None = None,
        hypothesis_id: str | None = None,
        evidence_ids: list[int] | None = None,
        expected_observation: str | None = None,
        would_falsify: str | None = None,
    ) -> tuple[Step, Approval]:
        """Create Step with sequence number and corresponding Approval atomically."""
        seq = await self._next_seq(assessment_id)
        step = Step(
            assessment_id=assessment_id,
            seq=seq,
            action=action,
            target=target,
            argv=list(argv or []),
            rationale=rationale,
            status=StepStatus.PLANNED.value,
        )
        self.session.add(step)
        await self.session.flush()

        approval_detail: dict[str, Any] = {
            "run_id": run_id,
            "role": role,
            "phase": role,
            "rationale": rationale,
            "risk": risk,
            "requires_approval": requires_approval,
            "policy_reason": policy_reason,
            "hypothesis_id": hypothesis_id,
            "evidence_ids": evidence_ids or [],
            "expected_observation": expected_observation,
            "would_falsify": would_falsify,
        }
        if detail:
            approval_detail.update(detail)

        approval = Approval(
            assessment_id=assessment_id,
            step_id=step.id,
            action=action,
            argv=list(argv or []),
            detail=approval_detail,
            decision=Decision.PENDING.value,
        )
        self.session.add(approval)
        await self.session.flush()
        return step, approval

    async def reject_step(
        self,
        step_id: int,
        reason: str = "rejected by analyst",
        error: str | None = None,
        actor: str = "analyst",
    ) -> Step:
        """Mark a planned step and its approval as rejected."""
        step = await self.session.get(Step, step_id)
        if step is None:
            raise LookupError(f"step {step_id} not found")

        err = error or reason
        step.status = StepStatus.REJECTED.value
        step.error = err[:500] if err else "rejected"
        step.ended_at = utcnow()
        self.session.add(step)

        result = await self.session.execute(
            select(Approval).where(Approval.step_id == step_id)
        )
        approval = result.scalars().first()
        if approval:
            approval.decision = Decision.REJECTED.value
            approval.actor = actor
            approval.reason = reason
            approval.decided_at = utcnow()
            approval.outcome = "action rejected"
            self.session.add(approval)

        await self.session.flush()
        return step

    async def complete_step(
        self,
        step_id: int,
        status: str,
        exit_code: int = 0,
        output_path: str = "",
        error: str | None = None,
    ) -> Step:
        """Update step execution completion fields."""
        step = await self.session.get(Step, step_id)
        if step is None:
            raise LookupError(f"step {step_id} not found")

        step.status = status
        step.exit_code = exit_code
        step.output_path = output_path
        if error:
            step.error = error[:500]
        step.ended_at = utcnow()
        self.session.add(step)
        await self.session.flush()
        return step

    async def get_artifact_path(self, step_id: int) -> str | None:
        """Get output_path for a step if it exists."""
        step = await self.session.get(Step, step_id)
        return step.output_path if step else None
