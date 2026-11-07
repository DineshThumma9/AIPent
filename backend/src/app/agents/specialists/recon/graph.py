"""Recon specialist sub-graph.

Self-contained StateGraph: own state, own nodes, own edges.
The supervisor invokes this via ainvoke() with a slice of shared state.
"""

from langgraph.graph import END, START, StateGraph

from app.agents.specialists.recon.agent import agent_node
from app.agents.specialists.recon.state import ReconState


def build_recon_graph(checkpointer=None):
    """Compile the recon sub-graph."""
    builder = StateGraph(ReconState)

    builder.add_node("scan", agent_node)
    builder.add_edge(START, "scan")
    builder.add_edge("scan", END)

    return builder.compile(checkpointer=checkpointer)


def recon_graph_config(assessment_id: int) -> dict:
    """LangGraph config for the recon sub-graph."""
    return {
        "configurable": {"thread_id": f"recon-{assessment_id}"},
        "recursion_limit": 20,
    }
