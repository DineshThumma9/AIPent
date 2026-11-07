"""Discovery specialist sub-graph.

Self-contained StateGraph: own state, own nodes, own edges.
The supervisor invokes this via ainvoke() with a slice of shared state.
"""

from langgraph.graph import END, START, StateGraph

from app.agents.specialists.discovery.agent import agent_node
from app.agents.specialists.discovery.state import DiscoveryState


def build_discovery_graph(checkpointer=None):
    """Compile the discovery sub-graph."""
    builder = StateGraph(DiscoveryState)

    builder.add_node("scan", agent_node)
    builder.add_edge(START, "scan")
    builder.add_edge("scan", END)

    return builder.compile(checkpointer=checkpointer)


def discovery_graph_config(assessment_id: int) -> dict:
    """LangGraph config for the discovery sub-graph."""
    return {
        "configurable": {"thread_id": f"discovery-{assessment_id}"},
        "recursion_limit": 20,
    }
