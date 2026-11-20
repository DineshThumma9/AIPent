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
    # Scope
    assessment_id: int
    run_id: str
    targets: list[str]
    ports: list[int]
    exclusions: list[str]

    # Operator-reviewed initial plan (shared by every agent)
    plan: list[dict]
    plan_source: str
    plan_approved: bool
    plan_feedback: str
    run_config: dict

    # Loop control
    role: str                      # recon | discovery | validation | review
    messages: list[AnyMessage]     # current turn messages
    recon_messages: list[AnyMessage]
    discovery_messages: list[AnyMessage]
    validation_messages: list[AnyMessage]
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

    # Bounded working history (last 10 only)
    observations: Annotated[list[dict], keep_last(10)]
    steps: Annotated[list[dict], keep_last(10)]

    # Report
    report_narrative: dict | None
    report_path: str


ROLE_ORDER = ("recon", "discovery", "validation")


def initial_state(assessment_id: int, run_id: str | None = None) -> AssessmentState:
    """Build the initial graph state for a new assessment run."""
    return {
        "assessment_id": assessment_id,
        "run_id": run_id or uuid.uuid4().hex[:12],
        "targets": [],
        "ports": [],
        "exclusions": [],
        "plan": [],
        "plan_source": "",
        "plan_approved": False,
        "plan_feedback": "",
        "run_config": {},
        "role": "recon",
        "messages": [],
        "recon_messages": [],
        "discovery_messages": [],
        "validation_messages": [],
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
        "steps": [],
        "report_narrative": None,
        "report_path": "",
    }
