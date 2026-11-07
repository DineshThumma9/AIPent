"""Native LangGraph assessment graph.

Modular replacement for the monolithic agents/graph.py.
StateGraph handles orchestration; persistence repos own all SQL.
The security gate stays — LangGraph does not provide scope, budget,
policy, argv binding, or evidence recording.
"""

from app.agents.graph.builder import (
    build_assessment_graph,
    get_assessment_graph,
    graph_config,
    prepare_run,
)
from app.agents.graph.context import challenge_delta as _challenge_delta
from app.agents.graph.state import AssessmentState, initial_state
from app.reporting.report import generate_report

__all__ = [
    "AssessmentState",
    "initial_state",
    "build_assessment_graph",
    "get_assessment_graph",
    "graph_config",
    "prepare_run",
    "_challenge_delta",
    "generate_report",
]
