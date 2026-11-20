"""Node package for V2 agent loop.

Exports all graph nodes and execution helpers.
"""

from __future__ import annotations

# Re-exported for monkeypatching compatibility in tests
from app.agents.model import build_role_model
from app.agents.mission_brain import run_supervisor_agent
from app.reporting.narrative import write_narrative_result

from app.agents.nodes.intake import intake_node
from app.agents.nodes.supervisor import _failure_from_state, supervisor_node
from app.agents.nodes.specialist import (
    _last_tool_call,
    approve_node,
    brief_node,
    curl_response_fingerprint,
    handoff_node,
    model_node,
    next_no_progress,
    prepare_node,
)
from app.agents.nodes.execution import direct_node, make_execute_node
from app.agents.nodes.reporting import (
    report_node,
    report_writer_node,
    review_node,
)

__all__ = [
    # Core 10 graph nodes
    "intake_node",
    "supervisor_node",
    "model_node",
    "prepare_node",
    "approve_node",
    "make_execute_node",
    "direct_node",
    "review_node",
    "report_writer_node",
    "report_node",
    # Additional nodes and helpers
    "brief_node",
    "handoff_node",
    "curl_response_fingerprint",
    "next_no_progress",
    "_failure_from_state",
    "_last_tool_call",
    # Monkeypatchable dependencies
    "build_role_model",
    "run_supervisor_agent",
    "write_narrative_result",
]
