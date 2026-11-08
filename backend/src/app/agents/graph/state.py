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


def keep_last(n: int):
    def reducer(left: list, right: list) -> list:
        return (list(left) + list(right))[-n:]
    return reducer


class AssessmentState(TypedDict, total=False):
    # Existing shared root
    assessment_id: int
    run_id: str
    targets: list[str]
    ports: list[int]
    exclusions: list[str]
    budget: dict  # actions_used, actions_left, probes_used, probes_left
    risk_score: float | None
    final_report_path: str | None

    # Loop control
    role: str                      # recon | discovery | validation | review
    messages: list[AnyMessage]     # replaced at each brief; no reducer
    pending_action: dict | None
    approval_decision: dict | None
    last_handoff: dict | None
    turns: dict[str, int]          # model calls per role
    nudges: int
    no_progress: int
    finished: bool
    last_message: str
    next_node: str | None

    # Supervisor
    supervisor_decision: dict | None
    supervisor_directive: str | None
    failure_signal: dict | None
    supervisor_calls: int

    # Evidence
    observations: Annotated[list[dict], keep_last(80)]
    handoffs: Annotated[list[dict], operator.add]
    decisions: Annotated[list[dict], keep_last(120)]
    steps: Annotated[list[dict], operator.add]

    # Report
    report_narrative: dict | None
    review_approved: bool
    rejected: bool
    report_path: str

    # Legacy keys kept only for the old builder/read model
    recon_state: dict
    discovery_state: dict
    validation_state: dict
    findings: Annotated[list, operator.add]
    recommendations: Annotated[list, operator.add]
    audit_events: Annotated[list, operator.add]
    interrupt_payload: dict | None
    plan: list[dict]
    plan_source: str
    step_count: int
    role_history: list[dict]
    role_messages: dict[str, list[AnyMessage]]
    error: str
    last_specialist: str | None


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
        "role": "recon",
        "messages": [],
        "pending_action": None,
        "approval_decision": None,
        "last_handoff": None,
        "turns": {},
        "nudges": 0,
        "no_progress": 0,
        "finished": False,
        "last_message": "",
        "next_node": "supervisor",
        "supervisor_decision": None,
        "supervisor_directive": None,
        "failure_signal": None,
        "supervisor_calls": 0,
        "observations": [],
        "handoffs": [],
        "decisions": [],
        "steps": [],
        "report_narrative": None,
        "review_approved": False,
        "rejected": False,
        "report_path": "",
        "recon_state": {},
        "discovery_state": {},
        "validation_state": {},
        "findings": [],
        "recommendations": [],
        "audit_events": [],
        "plan": [],
        "plan_source": "",
        "step_count": 0,
        "role_history": [],
        "role_messages": {},
        "error": "",
        "last_specialist": None,
        "interrupt_payload": None,
    }
