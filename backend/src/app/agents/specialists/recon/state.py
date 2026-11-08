"""Recon specialist state — self-contained, not shared with supervisor."""

from typing import Annotated, Any
from typing_extensions import TypedDict
import operator


class ReconState(TypedDict, total=False):
    # Shared scope slice passed in by supervisor
    assessment_id: int
    run_id: str
    targets: list[str]
    ports: list[int]
    exclusions: list[str]

    # Recon's own working memory
    services: list[dict]          # open services discovered
    tech_guesses: list[str]
    steps: list[dict]             # step ids + actions queued this turn

    # Output handed back to supervisor
    recommendations: Annotated[list, operator.add]
    findings: Annotated[list, operator.add]

    # Routing
    next_node: str | None
    finished: bool
