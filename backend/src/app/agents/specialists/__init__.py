"""Self-contained specialist sub-graphs.

Each agent (recon, discovery, validation) owns:
- its own TypedDict state
- its own compiled StateGraph
- its own nodes

The supervisor graph invokes these sub-graphs via ainvoke(), passing a
slice of shared state and receiving findings/recommendations/step IDs back.
"""

from app.agents.specialists.recon.graph import build_recon_graph
from app.agents.specialists.discovery.graph import build_discovery_graph
from app.agents.specialists.validation.graph import build_validation_graph

__all__ = [
    "build_recon_graph",
    "build_discovery_graph",
    "build_validation_graph",
]
