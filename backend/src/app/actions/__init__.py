"""Closed action catalogue and its single execution path.

Importing this package is the stable public API: ``ACTIONS``, ``execute_action``,
``get_action``, ``resolve_argv``, ``check_scope`` and the artifact location.
"""

from app.actions.catalogue import (
    ACTIONS,
    ARTIFACT_DIR,
    ActionSpec,
    ScopeError,
    UnknownAction,
    _artifact_dir,
    check_scope,
    get_action,
    mcp_command,
    mcp_tool_call,
    resolve_argv,
    transport_target,
)
from app.actions.executor import MCPResult, completed_actions, execute_action

__all__ = [
    "ACTIONS",
    "ARTIFACT_DIR",
    "ActionSpec",
    "MCPResult",
    "ScopeError",
    "UnknownAction",
    "check_scope",
    "completed_actions",
    "execute_action",
    "get_action",
    "mcp_command",
    "mcp_tool_call",
    "resolve_argv",
    "transport_target",
]
