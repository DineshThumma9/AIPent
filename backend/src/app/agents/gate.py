"""One queue/gate primitive for every catalogued action.

The agent never executes anything. It calls a tool that *queues* one action;
this module stores the resolved argv on a Step and binds a pending Approval to
that exact argv. The graph-level gate then pauses for a human, executes only
approved steps through ``actions.execute_action`` and returns the observation
to the agent.

The same path drives nmap, nikto, zap and http_probe. There is no separate plan
gate and no second execution path.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Callable

from sqlalchemy import func
from sqlmodel import Session, select

from app.actions import (
    ScopeError,
    check_scope,
    execute_action,
    get_action,
    resolve_argv,
)
from app.core.config import settings
from app.core.db import get_engine
from app.core.log import get_logger
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
from app.agents.control import audit, run_event_count

log = get_logger("agent.gate")

ACTIVE_STATES = (
    StepStatus.PLANNED.value,
    StepStatus.RUNNING.value,
    StepStatus.SUCCEEDED.value,
)

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


def _next_seq(session: Session, assessment_id: int) -> int:
    current = session.exec(
        select(func.max(Step.seq)).where(Step.assessment_id == assessment_id)
    ).one()
    return (current or 0) + 1


def queue_step(
    session: Session,
    assessment: Assessment,
    run_id: str,
    phase: str,
    action: str,
    target: str,
    rationale: str,
    *,
    argv: list[str] | None = None,
    detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a planned Step plus the pending Approval bound to its argv.

    Returns a dict the tool can hand straight to the LLM. Policy refusals are
    returned, not raised, so the agent can adapt in the same turn.
    """
    assessment_id = assessment.id or 0
    spec = get_action(action)

    try:
        check_scope(assessment, target)
    except ScopeError as exc:
        return {"error": str(exc)}

    if run_event_count(session, assessment_id, run_id, "action.queued") >= settings.max_steps:
        return {
            "error": (
                f"action budget exhausted ({settings.max_steps} queued actions "
                "for this run); call finish and let the analyst review what ran"
            )
        }

    existing = session.exec(
        select(Step).where(
            Step.assessment_id == assessment_id,
            Step.action == action,
            Step.status.in_(ACTIVE_STATES),
        )
    ).all()
    for row in existing:
        duplicate = row.argv == argv if argv is not None else row.target == target
        if duplicate:
            return {
                "queued": True,
                "duplicate_of_step": row.id,
                "status": row.status,
                "note": "this action is already queued or executed; not resent",
            }

    step = Step(
        assessment_id=assessment_id,
        seq=_next_seq(session, assessment_id),
        action=action,
        target=target,
        rationale=rationale,
        status=StepStatus.PLANNED.value,
    )
    session.add(step)
    session.flush()

    if argv is None:
        argv = resolve_argv(action, assessment, target, step.id or 0)
    step.argv = argv

    approval_detail: dict[str, Any] = {
        "phase": phase,
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
    session.add(approval)
    session.flush()
    audit(
        session,
        assessment_id,
        "action.queued",
        {
            "run_id": run_id,
            "step_id": step.id,
            "action": action,
            "target": target,
            "argv": argv,
        },
    )
    session.commit()

    return {
        "queued": True,
        "step_id": step.id,
        "approval_id": approval.id,
        "action": action,
        "target": target,
        "argv": argv,
        "gate": "action",
        "note": (
            "Awaiting the human action gate. Nothing has run yet; the result "
            "arrives in the next observation after the gate executes it."
        ),
    }


def _step_snapshot(assessment_id: int) -> dict[str, Any] | None:
    with Session(get_engine(), expire_on_commit=False) as session:
        step = session.exec(
            select(Step)
            .where(
                Step.assessment_id == assessment_id,
                Step.status == StepStatus.PLANNED.value,
            )
            .order_by(Step.seq)
        ).first()
        if step is None:
            return None
        return {
            "step_id": step.id,
            "action": step.action,
            "target": step.target,
            "argv": list(step.argv),
            "rationale": step.rationale,
        }


def _approval_snapshot(step_id: int) -> dict[str, Any] | None:
    with Session(get_engine(), expire_on_commit=False) as session:
        approval = session.exec(
            select(Approval)
            .where(Approval.step_id == step_id)
            .order_by(Approval.id.desc())
        ).first()
        if approval is None:
            return None
        return {
            "id": approval.id,
            "decision": approval.decision,
            "argv": list(approval.argv),
            "detail": dict(approval.detail or {}),
        }


def _fallback_approval(assessment_id: int, step: dict[str, Any]) -> dict[str, Any]:
    with Session(get_engine(), expire_on_commit=False) as session:
        row = Approval(
            assessment_id=assessment_id,
            step_id=step["step_id"],
            action=step["action"],
            argv=step["argv"],
            detail={"phase": "unknown", "rationale": step["rationale"]},
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        return {
            "id": row.id,
            "decision": row.decision,
            "argv": list(row.argv),
            "detail": dict(row.detail or {}),
        }


def _set_status(assessment_id: int, status: str) -> None:
    with Session(get_engine(), expire_on_commit=False) as session:
        assessment = session.get(Assessment, assessment_id)
        if assessment is not None and assessment.status != AssessmentStatus.CANCELLED.value:
            assessment.status = status
            session.commit()


def _probe_summary(step: Step) -> dict[str, Any]:
    if not step.output_path:
        return {}
    try:
        payload = json.loads(Path(step.output_path).read_text(encoding="utf-8"))
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


def _result_row(session: Session, step: Step, approval: Approval | None) -> dict[str, Any]:
    linked = session.exec(
        select(func.count(Evidence.id)).where(Evidence.step_id == step.id)
    ).one()
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
        row["http"] = _probe_summary(step)
    return row


def _record_probe_evidence(
    session: Session,
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

    existing = session.exec(
        select(Evidence).where(
            Evidence.finding_id == finding_id,
            Evidence.step_id == step.id,
        )
    ).first()
    if existing is None:
        http = row.get("http", {})
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


def _decide_and_execute(
    assessment_id: int,
    step_id: int,
    decision: Any,
    executor: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Apply the human decision (or an earlier one) and run the approved step."""
    execute = executor or execute_action
    with Session(get_engine(), expire_on_commit=False) as session:
        step = session.get(Step, step_id)
        if step is None:
            return {"step_id": step_id, "status": "missing"}
        approval = session.exec(
            select(Approval)
            .where(
                Approval.assessment_id == assessment_id,
                Approval.step_id == step_id,
            )
            .order_by(Approval.id.desc())
        ).first()

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
            session.commit()

        if approval is None or approval.decision != Decision.APPROVED.value:
            step.status = StepStatus.REJECTED.value
            step.error = (
                (approval.reason if approval else None) or "rejected by analyst"
            )
            step.ended_at = utcnow()
            session.commit()
            return _result_row(session, step, approval)

        assessment = session.get(Assessment, assessment_id)
        if assessment is None:
            raise LookupError(f"assessment {assessment_id} not found")
        target = step.target or assessment.targets[0]

        expected = (
            list(step.argv)
            if step.action == "http_probe"
            else resolve_argv(step.action, assessment, target, step.id or 0)
        )
        if approval.argv != expected:
            step.status = StepStatus.REJECTED.value
            step.error = "resolved argv changed after approval"
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
            session.commit()
            return _result_row(session, step, approval)

        session.commit()
        executed = asyncio.run(
            execute(
                session,
                assessment_id,
                step.action,
                target=target,
                rationale=step.rationale,
                step=step,
            )
        )
        session.refresh(executed)
        row = _result_row(session, executed, approval)
        _record_probe_evidence(session, assessment_id, executed, approval, row)
        session.commit()
        log.info(
            "gate: step=%s action=%s status=%s",
            executed.id,
            executed.action,
            executed.status,
        )
        return row


def run_gate_step(
    assessment_id: int,
    phase: str,
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
    step = _step_snapshot(assessment_id)
    if step is None:
        _set_status(assessment_id, AssessmentStatus.RUNNING.value)
        return None

    approval = _approval_snapshot(step["step_id"])
    if approval is None:
        approval = _fallback_approval(assessment_id, step)

    decision = None
    if approval["decision"] == Decision.PENDING.value:
        _set_status(assessment_id, AssessmentStatus.AWAITING_APPROVAL.value)
        detail = approval.get("detail") or {}
        decision = interrupt_fn(
            {
                "gate": "action",
                "phase": detail.get("phase", phase),
                "approval_id": approval["id"],
                "step_id": step["step_id"],
                "action": step["action"],
                "target": step["target"],
                "argv": step["argv"],
                "rationale": step["rationale"],
                "finding_id": detail.get("finding_id"),
            }
        )

    return _decide_and_execute(
        assessment_id, step["step_id"], decision, executor=executor
    )
