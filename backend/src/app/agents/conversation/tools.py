"""Tools for the conversation coordinator agent."""

from __future__ import annotations

from contextvars import ContextVar
from typing import Any
from langchain_core.tools import tool
from sqlmodel import select

from app.agents.control import audit
from app.agents.loop.reasoning import build_evidence_board
from app.api.queries import load_assessment_detail
from app.core.db import get_async_session_ctx
from app.domain.models import Approval, Assessment, Finding, Step
from app.persistence import FindingRepo, SteeringRepo

_current_conversation_assessment: ContextVar[int | None] = ContextVar(
    "aipent_conversation_assessment", default=None
)


def set_conversation_assessment_id(assessment_id: int) -> None:
    _current_conversation_assessment.set(assessment_id)


@tool("get_mission_status")
async def get_mission_status() -> dict[str, Any]:
    """Return status, running flag, active role, next node, pending gate, and resource counts."""
    assessment_id = _current_conversation_assessment.get()
    if not assessment_id:
        return {"error": "no assessment selected"}

    async with get_async_session_ctx() as session:
        detail = await load_assessment_detail(session, assessment_id)
        if detail is None:
            return {"error": "assessment not found"}
        from app.runtime import runner

        view = await runner.get_view(assessment_id, session=session)

    return {
        "status": detail.status,
        "running": view.running,
        "paused": view.paused,
        "active_role": view.active_role,
        "next": view.next,
        "gate_open": view.gate_open,
        "findings_count": len(detail.findings),
        "steps_count": len(detail.steps),
        "approvals_count": len(detail.approvals),
    }


@tool("list_findings")
async def list_findings(limit: int = 10) -> list[dict[str, Any]]:
    """Return candidate and confirmed findings discovered during this assessment."""
    assessment_id = _current_conversation_assessment.get()
    if not assessment_id:
        return []

    async with get_async_session_ctx() as session:
        repo = FindingRepo(session)
        findings = await repo.get_all(assessment_id)
        return [
            {
                "id": f.id,
                "title": f.title,
                "status": f.status,
                "severity": f.severity,
                "endpoint": f.endpoint or f.asset,
            }
            for f in findings[:limit]
        ]


@tool("get_evidence")
async def get_evidence(finding_id: int) -> dict[str, Any]:
    """Return supporting evidence and raw scan observations for a finding."""
    assessment_id = _current_conversation_assessment.get()
    if not assessment_id:
        return {"error": "no assessment selected"}

    async with get_async_session_ctx() as session:
        repo = FindingRepo(session)
        finding = await repo.get(finding_id)
        if not finding or finding.assessment_id != assessment_id:
            return {"error": f"finding {finding_id} not found"}
        evidence = await repo.get_evidence_for_finding(finding_id)
        return {
            "finding_id": finding.id,
            "title": finding.title,
            "evidence": [e.model_dump() for e in evidence],
        }


@tool("get_reasoning")
async def get_reasoning() -> dict[str, Any]:
    """Return the current evidence board hypotheses, open questions, and decisions."""
    assessment_id = _current_conversation_assessment.get()
    if not assessment_id:
        return {"error": "no assessment selected"}

    async with get_async_session_ctx() as session:
        board = await build_evidence_board(session, assessment_id)
        return board.model_dump()


@tool("explain_approval")
async def explain_approval(approval_id: int) -> dict[str, Any]:
    """Explain why a specific action requires human approval and its risk parameters."""
    assessment_id = _current_conversation_assessment.get()
    if not assessment_id:
        return {"error": "no assessment selected"}

    async with get_async_session_ctx() as session:
        approval = await session.get(Approval, approval_id)
        if not approval or approval.assessment_id != assessment_id:
            return {"error": f"approval {approval_id} not found"}
        step = await session.get(Step, approval.step_id)
        detail = approval.detail or {}
        return {
            "approval_id": approval.id,
            "decision": approval.decision,
            "action": step.action if step else "unknown",
            "target": step.target if step else "unknown",
            "argv": approval.argv or [],
            "risk": detail.get("risk", "medium"),
            "policy_reason": detail.get("policy_reason", ""),
            "rationale": step.rationale if step else "",
            "hypothesis_id": detail.get("hypothesis_id"),
            "expected_observation": detail.get("expected_observation"),
            "would_falsify": detail.get("would_falsify"),
        }


@tool("update_objective")
async def update_objective(text: str) -> dict[str, Any]:
    """Update the assessment objective. Only permitted when no run is active."""
    assessment_id = _current_conversation_assessment.get()
    if not assessment_id:
        return {"error": "no assessment selected"}

    from app.runtime import runner

    if runner.is_running(assessment_id):
        return {
            "error": "Cannot update objective while a run is active. Please stop the run first."
        }

    async with get_async_session_ctx() as session:
        assessment = await session.get(Assessment, assessment_id)
        if not assessment:
            return {"error": "assessment not found"}
        assessment.request = text.strip()
        await session.commit()

    return {"ok": True, "objective": text.strip()}


@tool("start_run")
async def start_run() -> dict[str, Any]:
    """Start the assessment run. Only call on explicit operator intent."""
    assessment_id = _current_conversation_assessment.get()
    if not assessment_id:
        return {"error": "no assessment selected"}

    from app.runtime import runner

    try:
        view = await runner.start_run(assessment_id, actor="coordinator")
        async with get_async_session_ctx() as session:
            audit(
                session,
                assessment_id,
                "conversation.start_run",
                {"actor": "coordinator"},
            )
            await session.commit()
        return {"ok": True, "status": view.status, "running": view.running}
    except Exception as exc:
        return {"error": str(exc)}


@tool("stop_run")
async def stop_run() -> dict[str, Any]:
    """Stop the active assessment run. Only call on explicit operator intent."""
    assessment_id = _current_conversation_assessment.get()
    if not assessment_id:
        return {"error": "no assessment selected"}

    from app.runtime import runner

    try:
        view = await runner.stop_run(assessment_id, actor="coordinator")
        async with get_async_session_ctx() as session:
            audit(
                session,
                assessment_id,
                "conversation.stop_run",
                {"actor": "coordinator"},
            )
            await session.commit()
        return {"ok": True, "status": view.status, "running": view.running}
    except Exception as exc:
        return {"error": str(exc)}


@tool("add_steering_note")
async def add_steering_note(text: str) -> dict[str, Any]:
    """Queue an operator steering directive for the active assessment run."""
    assessment_id = _current_conversation_assessment.get()
    if not assessment_id:
        return {"error": "no assessment selected"}

    from app.runtime import runner

    run_id: str | None = None
    if runner.is_running(assessment_id):
        try:
            _, values = await runner._values(assessment_id)
            run_id = values.get("run_id")
        except Exception:
            pass

    async with get_async_session_ctx() as session:
        repo = SteeringRepo(session)
        note = await repo.add(assessment_id, run_id, text)
        return {"ok": True, "note_id": note.id, "text": text}


COORDINATOR_TOOLS = [
    get_mission_status,
    list_findings,
    get_evidence,
    get_reasoning,
    explain_approval,
    update_objective,
    start_run,
    stop_run,
    add_steering_note,
]
