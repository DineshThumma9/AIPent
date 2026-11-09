"""Validation specialist state — self-contained, not shared with supervisor."""

from typing import Annotated, Any
from typing_extensions import TypedDict
import operator


class ValidationState(TypedDict, total=False):
    # Shared scope slice passed in by supervisor
    assessment_id: int
    run_id: str
    targets: list[str]
    ports: list[int]
    exclusions: list[str]

    # Input from discovery handoff
    candidates: list[dict]        # candidate findings to validate

    # Validation's own working memory
    probes_used: int              # curl_request count this turn
    verdicts: list[dict]          # confirmed / suspected / false_positive
    steps: list[dict]             # step ids + actions queued this turn

    # Output handed back to supervisor
    recommendations: Annotated[list, operator.add]
    findings: Annotated[list, operator.add]

    # Routing
    next_node: str | None
    finished: bool
