"""Role-specific tool sets for the three specialist agents.

Phase 2: Action tools execute directly inside the observe-reason-act loop.
Queueing tools are removed in favor of V2 ToolSpec and bindable_tools.
"""

from __future__ import annotations

from app.agents.loop.tool_specs import ROLE_TOOL_SPECS

ROLE_TOOLS = ROLE_TOOL_SPECS

__all__ = ["ROLE_TOOLS", "set_context", "update_finding_status"]
