"""Shared graph state for the three-role assessment agent.

Mutable working memory lives in state; durable evidence lives in the DB via
persistence repos. Specialist scratchpads prevent state collisions when
parallel execution (Send) is added later.

HOW_TO.md section 4: shared root + namespaced specialist scratchpads.
Append-only lists use reducers so parallel writes merge safely.
Legacy keys (role, role_history, observations, plan, ...) are kept so the
runner view, frontend mission.ts and the audit trail keep working.
"""

from typing import Annotated, Any
from typing_extensions import TypedDict
from langchain_core.messages import AnyMessage
import operator
import uuid


class AssessmentState(TypedDict, total=False):
    # Shared root (scope, budget, audit, final report)
    assessment_id: int
    run_id: str
    targets: list[str]
    ports: list[int]
    exclusions: list[str]
    budget: dict  # actions_used, actions_left, probes_used, probes_left
    risk_score: float | None
    final_report_path: str | None

    # Specialist scratchpads (each owns its namespace)
    recon_state: dict
    discovery_state: dict
    validation_state: dict

    # Append-only shared lists (reducers merge parallel writes safely)
    findings: Annotated[list, operator.add]
    steps: Annotated[list, operator.add]
    recommendations: Annotated[list, operator.add]
    audit_events: Annotated[list, operator.add]

    # Routing control
    next_node: str | None
    interrupt_payload: dict | None

    # Orchestration fields used by intake/gate/review/report and the runner
    # read model. Shared root + scratchpads hold working memory; these track
    # role lifecycle, plan history, and the last gate message.
    role: str
    role_history: list[dict]
    role_messages: dict[str, list[AnyMessage]]
    observations: list[dict]
    plan: list[dict]
    plan_source: str
    step_count: int
    turns: dict[str, int]
    finished: bool
    review_approved: bool
    rejected: bool
    report_path: str
    error: str
    last_message: str
    last_specialist: str | None
    role_history: list[dict]
    role_messages: dict[str, list[AnyMessage]]
    observations: list[dict]
    plan: list[dict]
    plan_source: str
    step_count: int
    turns: dict[str, int]
    finished: bool
    review_approved: bool
    rejected: bool
    report_path: str
    error: str
    last_message: str


ROLE_ORDER = ("recon", "discovery", "validation")


def initial_state(assessment_id: int, run_id: str | None = None) -> AssessmentState:
    """Build the initial graph state for a new assessment run."""
    return {
        "assessment_id": assessment_id,
        "run_id": run_id or uuid.uuid4().hex[:12],
        "targets": [],
        "ports": [],
        "exclusions": [],
        "budget": {
            "actions_used": 0,
            "actions_left": 12,
            "probes_used": 0,
            "probes_left": 10,
        },
        "risk_score": None,
        "final_report_path": None,
        "recon_state": {},
        "discovery_state": {},
        "validation_state": {},
        "findings": [],
        "steps": [],
        "recommendations": [],
        "audit_events": [],
        "next_node": "supervisor",
        "interrupt_payload": None,
        "role": "recon",
        "role_history": [],
        "role_messages": {},
        "observations": [],
        "plan": [],
        "plan_source": "",
        "step_count": 0,
        "turns": {},
        "finished": False,
        "review_approved": False,
        "rejected": False,
        "report_path": "",
        "error": "",
        "last_message": "",
        "last_specialist": None,
    }
