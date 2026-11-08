"""Role-specific tool sets for the three specialist agents.

Phase 2: Action tools execute directly inside the observe-reason-act loop.
Queueing tools are removed in favor of V2 ToolSpec and bindable_tools.
"""

from __future__ import annotations

from contextvars import ContextVar
from typing import Any, Literal
from langchain_core.tools import tool

from app.agents.loop.tool_specs import ROLE_TOOL_SPECS
from app.core.db import get_async_session_ctx
from app.persistence import FindingRepo

# ---------------------------------------------------------------------------
# Compatibility context (for any legacy callers)
# ---------------------------------------------------------------------------

_current_assessment_id: ContextVar[int | None] = ContextVar(
    "aipent_assessment_id", default=None
)
_current_run_id: ContextVar[str | None] = ContextVar("aipent_run_id", default=None)
_current_role: ContextVar[str | None] = ContextVar("aipent_role", default=None)


def set_context(assessment_id: int, run_id: str, role: str) -> None:
    """Set the current assessment/run/role context for tool calls."""
    _current_assessment_id.set(assessment_id)
    _current_run_id.set(run_id)
    _current_role.set(role)


@tool(
    "update_finding_status",
    description=(
        "Record a validation verdict for one candidate finding. Use only "
        "after a curl_tool has executed and its evidence is linked to the "
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


ROLE_TOOLS = ROLE_TOOL_SPECS

__all__ = ["ROLE_TOOLS", "set_context", "update_finding_status"]
