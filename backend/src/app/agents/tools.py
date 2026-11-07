"""Role-specific tool sets for the three specialist agents.

Each tool is a LangChain-compatible function. When called, it queues a
planned Step via ``StepRepo`` and returns a result dict the LLM can reason
about. The LLM never supplies raw argv — it names an action and a target;
Python resolves the exact command through the action catalogue.

Tools are grouped by role:
- Recon: scan_services (nmap service discovery)
- Discovery: dirb_scan, nikto_scan, zap_baseline (web scanners)
- Validation: http_probe, sqlmap_scan (probes and vuln testing)
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import tool

from app.actions import get_action, resolve_argv
from app.core.db import get_async_session_ctx
from app.domain.models import StepStatus
from app.persistence import AssessmentRepo, StepRepo


def _queue_step_tool(action: str):
    """Build a LangChain tool that queues a planned Step for ``action``."""

    @tool
    async def _queued_tool(
        target: str,
        rationale: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Queue a planned security action against ``target``.

        Returns a dict with ``step_id``, ``action``, ``target``, ``status``
        and ``note``. The step is not executed until the human gate approves
        it.

        ``params`` are typed scan parameters (for example nmap profile/ports)
        that Python renders into the exact argv. The LLM never supplies raw
        flags.
        """
        assessment_id = _current_assessment_id
        run_id = _current_run_id

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

            # Prevent duplicate active steps for the same action/target.
            existing = await step_repo.is_duplicate(
                assessment_id, action, target=target
            )
            if existing:
                return {
                    "queued": True,
                    "duplicate_of_step": existing.id,
                    "status": existing.status,
                    "action": action,
                    "target": target,
                    "note": (
                        f"{action} against {target} is already queued or "
                        f"executed (step {existing.id})."
                    ),
                }

            result = await step_repo.create_step(
                assessment=assessment,
                run_id=run_id,
                role=_current_role,
                action=action,
                target=target,
                rationale=rationale,
                params=params,
            )

            if result.get("error"):
                return {
                    "error": result["error"],
                    "action": action,
                    "target": target,
                }

            return {
                "queued": True,
                "step_id": result["step_id"],
                "approval_id": result["approval_id"],
                "action": action,
                "target": target,
                "argv": result["argv"],
                "note": (
                    "Queued, not executed. The gate runs this action after "
                    "your turn ends; its result appears in the next "
                    "observation. Do not poll — call handoff now."
                ),
            }

    return _queued_tool


# ---------------------------------------------------------------------------
# Role-local context (set by the specialist node before invoking the agent)
# ---------------------------------------------------------------------------

_current_assessment_id: int | None = None
_current_run_id: str | None = None
_current_role: str | None = None


def set_context(
    assessment_id: int, run_id: str, role: str
) -> None:
    """Set the current assessment/run/role context for tool calls."""
    global _current_assessment_id, _current_run_id, _current_role
    _current_assessment_id = assessment_id
    _current_run_id = run_id
    _current_role = role


# ---------------------------------------------------------------------------
# ROLE_TOOLS — each specialist gets only its own tools
# ---------------------------------------------------------------------------

ROLE_TOOLS: dict[str, list] = {
    "recon": [
        _queue_step_tool("recon_services"),  # nmap service scan
    ],
    "discovery": [
        _queue_step_tool("dirb_scan"),       # directory brute force
        _queue_step_tool("nikto_scan"),      # web server scanner
        _queue_step_tool("zap_baseline"),    # ZAP passive baseline
    ],
    "validation": [
        _queue_step_tool("http_probe"),      # HTTP request probe
        _queue_step_tool("sqlmap_scan"),     # SQL injection tester
    ],
}

__all__ = ["ROLE_TOOLS", "set_context"]
