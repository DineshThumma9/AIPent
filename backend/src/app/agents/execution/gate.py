"""One queue/gate primitive for every catalogued action.

The agent never executes anything. It calls a tool that *queues* one action;
this module stores the resolved argv on a Step and binds a pending Approval to
that exact argv. The graph-level gate then pauses for a human, executes only
approved steps through ``actions.execute_action`` and returns the observation
to the agent.

The same path drives nmap, nikto, zap and http_probe. There is no separate plan
gate and no second execution path.
"""

import asyncio
import json
from pathlib import Path
from typing import Any, Callable

from sqlalchemy import func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select
from app.actions import execute_action
from app.core.config import settings
from app.core.db import get_async_session_ctx
from app.core.log import get_logger
from app.core.policy import DEFAULT_ACTION_POLICIES, ActionPolicy
from app.domain.models import (
    Approval,
    Assessment,
    AssessmentStatus,
    Decision,
    Evidence,
    Step,
    StepStatus,
    utcnow,
)
from app.agents.control import audit

log = get_logger("agent.gate")

ACTIVE_STATES = (
    StepStatus.PLANNED.value,
    StepStatus.RUNNING.value,
    StepStatus.SUCCEEDED.value,
)

_policy_cache: dict[str, Any] | None = None


def _policies() -> dict[str, ActionPolicy]:
    global _policy_cache
    if _policy_cache is None:
        from app.core.policy import load_policies_from_json

        _policy_cache = load_policies_from_json(settings.action_policies_json)
    return _policy_cache


def _policy_for(action: str) -> ActionPolicy:
    return _policies().get(action, DEFAULT_ACTION_POLICIES.get(action, ActionPolicy()))


PROBE_HEADERS = (
    "content-type",
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "set-cookie",
    "location",
)


async def _next_seq(session: AsyncSession, assessment_id: int) -> int:
    result = await session.execute(
        select(func.max(Step.seq)).where(Step.assessment_id == assessment_id)
    )
    current = result.scalar()
    return (current or 0) + 1
async def _step_snapshot(assessment_id: int) -> dict[str, Any] | None:
    async with get_async_session_ctx() as session:
        result = await session.execute(
            select(Step)
            .where(
                Step.assessment_id == assessment_id,
                Step.status == StepStatus.PLANNED.value,
            )
            .order_by(Step.seq)
        )
        step = result.scalars().first()
        if step is None:
            return None
        return {
            "step_id": step.id,
            "action": step.action,
            "target": step.target,
            "argv": list(step.argv),
            "rationale": step.rationale,
        }


async def _approval_snapshot(step_id: int) -> dict[str, Any] | None:
    async with get_async_session_ctx() as session:
        result = await session.execute(
            select(Approval)
            .where(Approval.step_id == step_id)
            .order_by(Approval.id.desc())
        )
        approval = result.scalars().first()
        if approval is None:
            return None
        return {
            "id": approval.id,
            "decision": approval.decision,
            "argv": list(approval.argv),
            "detail": dict(approval.detail or {}),
        }


async def _fallback_approval(assessment_id: int, step: dict[str, Any]) -> dict[str, Any]:
    async with get_async_session_ctx() as session:
        row = Approval(
            assessment_id=assessment_id,
            step_id=step["step_id"],
            action=step["action"],
            argv=step["argv"],
            detail={"role": "unknown", "phase": "unknown", "rationale": step["rationale"]},
        )
        session.add(row)
        await session.commit()
        await session.refresh(row)
        return {
            "id": row.id,
            "decision": row.decision,
            "argv": list(row.argv),
            "detail": dict(row.detail or {}),
        }


async def _set_status(assessment_id: int, status: str) -> None:
    async with get_async_session_ctx() as session:
        assessment = await session.get(Assessment, assessment_id)
        if assessment is not None and assessment.status != AssessmentStatus.CANCELLED.value:
            assessment.status = status
            await session.commit()


async def _probe_summary(step: Step) -> dict[str, Any]:
    if not step.output_path:
        return {}
    try:
        payload = json.loads(
            await asyncio.to_thread(
                Path(step.output_path).read_text, encoding="utf-8"
            )
        )
    except Exception as exc:  # noqa: BLE001 - artifact rendering only
        return {"artifact_error": str(exc)[:200]}
    probe = payload.get("probe_result", {})
    headers = probe.get("headers", {}) or {}
    return {
        "status_code": probe.get("status_code"),
        "headers": {
            key: headers.get(key)
            for key in PROBE_HEADERS
            if headers.get(key) is not None
        },
        "body_excerpt": (probe.get("body_preview") or "")[:1200],
        "error": probe.get("error"),
    }


async def _result_row(session: AsyncSession, step: Step, approval: Approval | None) -> dict[str, Any]:
    result = await session.execute(
        select(func.count(Evidence.id)).where(Evidence.step_id == step.id)
    )
    linked = result.scalar()
    detail = (approval.detail or {}) if approval else {}
    row: dict[str, Any] = {
        "step_id": step.id,
        "action": step.action,
        "target": step.target,
        "status": step.status,
        "exit_code": step.exit_code,
        "error": step.error,
        "rationale": step.rationale,
        "finding_id": detail.get("finding_id"),
        "findings_linked": linked or 0,
    }
    if step.action == "http_probe":
        row["http"] = await _probe_summary(step)
    return row


async def _record_probe_evidence(
    session: AsyncSession,
    assessment_id: int,
    step: Step,
    approval: Approval | None,
    row: dict[str, Any],
) -> None:
    finding_id = (approval.detail or {}).get("finding_id") if approval else None
    if (
        step.action != "http_probe"
        or step.status != StepStatus.SUCCEEDED.value
        or not step.output_path
        or not finding_id
    ):
        return

    existing = await session.execute(
        select(Evidence).where(
            Evidence.finding_id == finding_id,
            Evidence.step_id == step.id,
        )
    )
    existing = existing.scalars().first()
    if existing is None:
        http = row.get("http", {})
        if http.get("status_code") is None:
            return
        session.add(
            Evidence(
                finding_id=finding_id,
                step_id=step.id,
                locator={
                    "tool": "http_probe",
                    "method": step.argv[1] if len(step.argv) > 1 else "GET",
                    "url": step.argv[2] if len(step.argv) > 2 else "",
                    "step_id": step.id,
                    "http_status": http.get("status_code"),
                },
                excerpt=(http.get("body_excerpt") or "")[:600],
            )
        )
    audit(
        session,
        assessment_id,
        "verification.probe_executed",
        {
            "step_id": step.id,
            "finding_id": finding_id,
            "http_status": row.get("http", {}).get("status_code"),
            "url": row.get("http", {}).get("url")
            or (step.argv[2] if len(step.argv) > 2 else ""),
        },
    )


async def _decide_and_execute(
    assessment_id: int,
    step_id: int,
    decision: Any,
    executor: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Apply the human decision (or an earlier one) and run the approved step."""
    execute = executor or execute_action
    async with get_async_session_ctx() as session:
        step = await session.get(Step, step_id)
        if step is None:
            return {"step_id": step_id, "status": "missing"}
        result = await session.execute(
            select(Approval)
            .where(
                Approval.assessment_id == assessment_id,
                Approval.step_id == step_id,
            )
            .order_by(Approval.id.desc())
        )
        approval = result.scalars().first()

        if approval is not None and approval.decision == Decision.PENDING.value:
            payload = decision or {}
            approved = str(payload.get("decision", "rejected")).lower() == "approved"
            approval.decision = (
                Decision.APPROVED.value if approved else Decision.REJECTED.value
            )
            approval.actor = payload.get("actor") or "analyst"
            approval.reason = payload.get("reason") or None
            approval.decided_at = utcnow()
            approval.outcome = "action " + ("approved" if approved else "rejected")
            audit(
                session,
                assessment_id,
                "approval." + ("approved" if approved else "rejected"),
                {
                    "approval_id": approval.id,
                    "step_id": step.id,
                    "action": step.action,
                    "actor": approval.actor,
                    "reason": approval.reason,
                    "argv": approval.argv,
                },
            )
            await session.commit()

        if approval is None or approval.decision != Decision.APPROVED.value:
            step.status = StepStatus.REJECTED.value
            step.error = (
                (approval.reason if approval else None) or "rejected by analyst"
            )
            step.ended_at = utcnow()
            await session.commit()
            return await _result_row(session, step, approval)

        assessment = await session.get(Assessment, assessment_id)
        if assessment is None:
            raise LookupError(f"assessment {assessment_id} not found")
        target = step.target or assessment.targets[0]

        # The approved argv must match what is stored on the step. Both were
        # set from the same argv at queue time; Python does not re-generate
        # the command from the catalogue at execution time.
        expected = list(step.argv or [])
        if approval.argv != expected:
            step.status = StepStatus.REJECTED.value
            step.error = "approved argv does not match step argv"
            step.ended_at = utcnow()
            audit(
                session,
                assessment_id,
                "approval.argv_mismatch",
                {
                    "approval_id": approval.id,
                    "step_id": step.id,
                    "approved": approval.argv,
                    "resolved": expected,
                },
            )
            await session.commit()
            return await _result_row(session, step, approval)

        await session.commit()
        executed = await execute(
            session,
            assessment_id,
            step.action,
            target=target,
            rationale=step.rationale,
            step=step,
        )
        await session.refresh(executed)
        row = await _result_row(session, executed, approval)
        await _record_probe_evidence(session, assessment_id, executed, approval, row)
        await session.commit()
        log.info(
            "gate: step=%s action=%s status=%s",
            executed.id,
            executed.action,
            executed.status,
        )
        return row


async def run_gate_step(
    assessment_id: int,
    role: str,
    interrupt_fn: Callable[[dict], Any],
    executor: Callable[..., Any] | None = None,
) -> dict[str, Any] | None:
    """Resolve exactly one planned step.

    The graph self-loops on the gate node for each queued action instead of
    looping here. LangGraph replays a node from the start when it resumes and
    matches resume values to interrupts by their order in that re-execution.
    If one node execution handled several actions, already-executed steps would
    be skipped on replay, shifting the interrupt indices and letting an earlier
    approval leak onto the next action. A single interrupt per node task keeps
    each decision bound to its own step and argv.
    """
    step = await _step_snapshot(assessment_id)
    if step is None:
        await _set_status(assessment_id, AssessmentStatus.RUNNING.value)
        return None

    decision = None
    effective_step_id = step["step_id"]

    approval = await _approval_snapshot(step["step_id"])
    if approval is None:
        approval = await _fallback_approval(assessment_id, step)

    if approval["decision"] == Decision.PENDING.value:
        policy = _policy_for(step["action"])
        if not policy.requires_approval:
            # Agent authority: auto-approve per policy, no human interrupt.
            await _set_status(assessment_id, AssessmentStatus.RUNNING.value)
            decision = {
                "decision": "approved",
                "actor": "system",
                "reason": f"auto-approved by policy ({policy.risk} risk)",
            }
        else:
            await _set_status(assessment_id, AssessmentStatus.AWAITING_APPROVAL.value)
            detail = approval.get("detail") or {}
            decision = interrupt_fn(
                {
                    "gate": "action",
                    "role": detail.get("role", role),
                    # Alias kept for the current dashboard approval card.
                    "phase": detail.get("phase", role),
                    "approval_id": approval["id"],
                    "step_id": step["step_id"],
                    "action": step["action"],
                    "target": step["target"],
                    "argv": step["argv"],
                    "rationale": step["rationale"],
                    "finding_id": detail.get("finding_id"),
                    "risk": policy.risk,
                    "requires_approval": True,
                }
            )

    # When resuming from a human decision, the decision payload carries the
    # step_id of the gate card the analyst saw. Honor it so the binding
    # between the approved card and the executed step is exact.
    if decision and decision.get("step_id"):
        effective_step_id = decision["step_id"]

    return await _decide_and_execute(
        assessment_id, effective_step_id, decision, executor=executor
    )
