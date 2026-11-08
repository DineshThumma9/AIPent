"""V2 StateGraph builder with native observe-reason-act loop nodes.

Replaces the legacy gate conveyor belt with a closed Specialist loop and
LLM Supervisor Mission Director.
"""

from __future__ import annotations

from typing import Any, Callable
from langgraph.graph import END, START, StateGraph

from app.agents.graph.state import AssessmentState
from app.agents.loop.nodes import (
    approve_node,
    brief_node,
    direct_node,
    handoff_node,
    intake_node,
    make_execute_node,
    model_node,
    nudge_node,
    prepare_node,
    report_node,
    report_writer_node,
    review_node,
    supervisor_node,
)


def build_assessment_graph_v2(
    checkpointer=None,
    executor: Callable[..., Any] | None = None,
):
    """Compile the V2 assessment graph."""
    builder = StateGraph(AssessmentState)

    builder.add_node("intake", intake_node)
    builder.add_node("supervisor", supervisor_node)
    builder.add_node("brief", brief_node)
    builder.add_node("model", model_node)
    builder.add_node("prepare", prepare_node)
    builder.add_node("approve", approve_node)
    builder.add_node("execute", make_execute_node(executor))
    builder.add_node("direct", direct_node)
    builder.add_node("handoff", handoff_node)
    builder.add_node("nudge", nudge_node)
    builder.add_node("review", review_node)
    builder.add_node("report_writer", report_writer_node)
    builder.add_node("report", report_node)

    builder.add_edge(START, "intake")

    return builder.compile(checkpointer=checkpointer)
