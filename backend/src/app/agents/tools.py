"""Role-specific tool sets for the three specialist agents.

Each tool queues one planned action as a Step and returns a result dict the
LLM can reason about. The LLM never supplies raw argv — it names an action and
a target; Python resolves the exact command through the action catalogue.

Tools are grouped by role and each tool has a unique name so the model can
actually choose between them:
- Recon: recon_services
- Discovery: dirb_scan, nikto_scan, zap_baseline
- Validation: http_probe, sqlmap_scan
"""

from __future__ import annotations

from contextvars import ContextVar
from typing import Any, Literal

from langchain_core.tools import tool

from app.core.db import get_async_session_ctx
from app.persistence import AssessmentRepo, FindingRepo, StepRepo

_ACTION_DESCRIPTIONS: dict[str, str] = {
    "recon_services": (
        "Queue an nmap service/version scan against one authorised target. "
        "Use this first to discover open ports and running services. "
        "After it is queued, stop calling tools and summarize."
    ),
    "dirb_scan": (
        "Queue a dirb directory brute-force scan against one authorised web "
        "target. Use only after recon confirms a web service. After it is "
        "queued, stop calling tools and summarize."
    ),
    "nikto_scan": (
        "Queue a nikto web-server scan against one authorised web target. Use "
        "for a known web service. After it is queued, stop calling tools and "
        "summarize."
    ),
    "zap_baseline": (
        "Queue an OWASP ZAP passive baseline scan against one authorised web "
        "target. This action requires human approval. After it is queued, stop "
        "calling tools and summarize."
    ),
    "http_probe": (
        "Queue a safe single HTTP probe (GET, HEAD, or POST) against one "
        "authorised target. Use params to set path, method, headers, expected "
        "status, and finding_id. After it is queued, stop calling tools and "
        "summarize."
    ),
    "sqlmap_scan": (
        "Queue a sqlmap SQL-injection check against one authorised web target. "
        "Requires human approval and strong evidence. After it is queued, stop "
        "calling tools and summarize."
    ),
}


def _queue_step_tool(action: str):
    """Build a uniquely named LangChain tool that queues ``action``."""

    @tool(action, description=_ACTION_DESCRIPTIONS[action])
    async def queue_step(
        target: str,
        rationale: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Queue one planned action and return its step/approval ids."""
        assessment_id = _current_assessment_id.get()
        run_id = _current_run_id.get()
        role = _current_role.get()
        if assessment_id is None or run_id is None or role is None:
            return {"error": "agent tool context is not initialised"}
        turn_state = _turn_state.get()
        if turn_state is None:
            return {"error": "agent tool context is not initialised"}
        if turn_state["queued"]:
            return {
                "error": (
                    "only one action may be queued per specialist turn; "
                    "stop calling tools and summarize what you queued"
                ),
                "action": action,
                "target": target,
            }

        async with get_async_session_ctx() as session:
            repo = AssessmentRepo(session)
            assessment = await repo.get(assessment_id)
            if assessment is None:
                return {
                    "error": f"assessment {assessment_id} not found",
                    "action": action,
                    "target": target,
                }

            step_repo = StepRepo(session)

            detail: dict[str, Any] = {}
            if params and params.get("finding_id") is not None:
                try:
                    detail["finding_id"] = int(params["finding_id"])
                except (TypeError, ValueError):
                    pass

            result = await step_repo.create_step(
                assessment=assessment,
                run_id=run_id,
                role=role,
                action=action,
                target=target,
                rationale=rationale,
                params=params,
                detail=detail or None,
            )

            if result.get("error"):
                return {
                    "error": result["error"],
                    "action": action,
                    "target": target,
                }

            if result.get("duplicate_of_step"):
                turn_state["queued"] = True
                return {
                    "queued": True,
                    "duplicate_of_step": result["duplicate_of_step"],
                    "status": result.get("status"),
                    "action": action,
                    "target": target,
                    "note": result.get("note", "already queued; not resent"),
                }

            turn_state["queued"] = True
            return {
                "queued": True,
                "step_id": result["step_id"],
                "approval_id": result["approval_id"],
                "action": action,
                "target": target,
                "argv": result["argv"],
                "note": (
                    "Queued, not executed. Stop calling tools and return a "
                    "short summary; the gate runs this action after your turn."
                ),
            }

    return queue_step


@tool(
    "update_finding_status",
    description=(
        "Record a validation verdict for one candidate finding. Use only "
        "after an http_probe has executed and its evidence is linked to the "
        "finding. Status must be confirmed, suspected, or false_positive."
    ),
)
async def update_finding_status(
    finding_id: int,
    status: Literal["confirmed", "suspected", "false_positive"],
    reasoning: str,
) -> dict[str, Any]:
    """Update a finding's status after probe evidence has been linked."""
    assessment_id = _current_assessment_id.get()
    if assessment_id is None:
        return {"error": "agent tool context is not initialised"}
    if not reasoning.strip():
        return {"error": "reasoning is required to record a verdict"}

    async with get_async_session_ctx() as session:
        return await FindingRepo(session).update_status(
            finding_id, assessment_id, status, reasoning
        )


# ---------------------------------------------------------------------------
# Role-local context (set by the specialist node before invoking the agent)
# ---------------------------------------------------------------------------

_current_assessment_id: ContextVar[int | None] = ContextVar(
    "aipent_assessment_id", default=None
)
_current_run_id: ContextVar[str | None] = ContextVar("aipent_run_id", default=None)
_current_role: ContextVar[str | None] = ContextVar("aipent_role", default=None)
_turn_state: ContextVar[dict[str, bool] | None] = ContextVar(
    "aipent_turn_state", default=None
)


def set_context(assessment_id: int, run_id: str, role: str) -> None:
    """Set the current assessment/run/role context for tool calls."""
    _current_assessment_id.set(assessment_id)
    _current_run_id.set(run_id)
    _current_role.set(role)
    # A mutable holder so a context copy made by a tool runner still shares
    # the one-action-per-turn flag.
    _turn_state.set({"queued": False})


# ---------------------------------------------------------------------------
# ROLE_TOOLS — each specialist gets only its own tools
# ---------------------------------------------------------------------------

ROLE_TOOLS: dict[str, list] = {
    "recon": [
        _queue_step_tool("recon_services"),
    ],
    "discovery": [
        _queue_step_tool("dirb_scan"),
        _queue_step_tool("nikto_scan"),
        _queue_step_tool("zap_baseline"),
    ],
    "validation": [
        _queue_step_tool("http_probe"),
        _queue_step_tool("sqlmap_scan"),
        update_finding_status,
    ],
}

__all__ = ["ROLE_TOOLS", "set_context", "update_finding_status"]
