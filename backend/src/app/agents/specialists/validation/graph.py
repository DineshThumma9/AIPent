"""Validation specialist sub-graph.

Self-contained StateGraph: own state, own nodes, own edges.
The supervisor invokes this via ainvoke() with a slice of shared state.
"""

from langgraph.graph import END, START, StateGraph

from app.agents.specialists.validation.agent import agent_node
from app.agents.specialists.validation.state import ValidationState


def build_validation_graph(checkpointer=None):
    """Compile the validation sub-graph."""
    builder = StateGraph(ValidationState)

    builder.add_node("probe", agent_node)
    builder.add_edge(START, "probe")
    builder.add_edge("probe", END)

    return builder.compile(checkpointer=checkpointer)


def validation_graph_config(assessment_id: int) -> dict:
    """LangGraph config for the validation sub-graph."""
    return {
        "configurable": {"thread_id": f"validation-{assessment_id}"},
        "recursion_limit": 20,
    }
