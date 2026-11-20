"""Assessment agent package.

Flat modular structure for V2 observe-reason-act agent loop.
"""

from app.agents.contracts import (
    ActionRequest,
    ActionResult,
    DecisionRecord,
    EvidenceBoard,
    FailureSignal,
    Handoff,
    Hypothesis,
    Observation,
    RouteDecision,
    SteeringNote,
)
from app.agents.state import AssessmentState, initial_state
from app.agents.builder import (
    build_assessment_graph,
    build_assessment_graph_v2,
    get_assessment_graph,
    graph_config,
    prepare_run,
)

__all__ = [
    "ActionRequest",
    "ActionResult",
    "DecisionRecord",
    "EvidenceBoard",
    "FailureSignal",
    "Handoff",
    "Hypothesis",
    "Observation",
    "RouteDecision",
    "SteeringNote",
    "AssessmentState",
    "initial_state",
    "build_assessment_graph",
    "build_assessment_graph_v2",
    "get_assessment_graph",
    "graph_config",
    "prepare_run",
]
