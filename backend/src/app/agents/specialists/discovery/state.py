"""Discovery specialist state — self-contained, not shared with supervisor."""

from typing import Annotated, Any
from typing_extensions import TypedDict
import operator


class DiscoveryState(TypedDict, total=False):
    # Shared scope slice passed in by supervisor
    assessment_id: int
    run_id: str
    targets: list[str]
    ports: list[int]
    exclusions: list[str]

    # Input from recon handoff
    services: list[dict]          # open services from recon

    # Discovery's own working memory
    candidates: list[dict]        # candidate findings from scanners
    scanners_used: list[str]      # which scanners ran this turn
    steps: list[dict]             # step ids + actions queued this turn

    # Output handed back to supervisor
    recommendations: Annotated[list, operator.add]
    findings: Annotated[list, operator.add]

    # Routing
    next_node: str | None
    finished: bool
