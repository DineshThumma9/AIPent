"""Core contracts for the V2 agent loop.

Pydantic models for actions, observations, handoffs, supervisor route decisions,
evidence board items, and steering notes.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, Field


class ActionRequest(BaseModel):
    """One prepared tool call, before approval/execution."""

    tool_call_id: str
    tool_name: str
    action: str
    target: str
    rationale: str

    # Resolved by Python, not by the model.
    step_id: int
    approval_id: int | None = None
    argv: list[str] = Field(default_factory=list)
    risk: Literal["low", "medium", "high"] = "medium"
    requires_approval: bool = True
    policy_reason: str = ""

    # Structured reasoning supplied through the tool arguments.
    hypothesis_id: str | None = None
    evidence_ids: list[int] = Field(default_factory=list)
    expected_observation: str | None = None
    would_falsify: str | None = None


class Observation(BaseModel):
    """What the agent gets back from one tool call.

    Compact structured feedback. Raw scanner output lives in the artifact and is
    available through read_artifact; the agent needs the summary and ids.
    """

    ok: bool
    status: Literal[
        "succeeded", "failed", "timeout", "blocked", "rejected", "error"
    ]
    action: str
    target: str
    step_id: int | None = None

    summary: str = ""
    findings_created: list[int] = Field(default_factory=list)
    findings_updated: list[int] = Field(default_factory=list)
    evidence_ids: list[int] = Field(default_factory=list)

    artifact: dict[str, Any] | None = None
    # {"path": "...", "sha256": "...", "kind": ".nmap.xml"}

    http: dict[str, Any] | None = None
    # {"status_code": 200, "headers": {...}, "body_excerpt": "..."}

    facts: dict[str, Any] | None = None

    errors: list[str] = Field(default_factory=list)
    duration_ms: int | None = None
    next_hint: str | None = None


class ActionResult(BaseModel):
    """Internal result of app.actions.executor.execute_action."""

    ok: bool
    exit_code: int | None = None
    status: Literal["succeeded", "failed", "timeout", "blocked"] = "failed"
    stdout_excerpt: str = ""
    artifact_path: str | None = None
    artifact_sha256: str | None = None
    error: str | None = None
    duration_ms: int | None = None


class Handoff(BaseModel):
    """Structured end of a specialist turn.

    The supervisor treats this as a recommendation, not a command. It may accept
    it, override it, or send the role back with a directive.
    """

    summary: str = Field(min_length=1, max_length=2000)
    next_role: Literal["recon", "discovery", "validation", "review"]
    why: str = Field(min_length=1, max_length=1000)
    confidence: float = Field(ge=0.0, le=1.0)

    stop_reason: Literal[
        "surface_mapped",
        "hypotheses_tested",
        "no_progress",
        "budget",
        "needs_more_recon",
        "needs_scope_decision",
        "blocked",
    ]
    finding_ids: list[int] = Field(default_factory=list)
    step_ids: list[int] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)


class RouteDecision(BaseModel):
    """The supervisor's proposed next move. Advisory until validate_route accepts it."""

    next_role: Literal["recon", "discovery", "validation", "review"]
    why: str = Field(
        default="Assessing mission state and prioritizing next actions.",
        min_length=1,
        max_length=1500,
        description="Detailed explanation for choosing this next role.",
    )
    priority: Literal["low", "medium", "high"] = "medium"
    confidence: float = Field(
        default=0.75,
        ge=0.0,
        le=1.0,
        description="Confidence score between 0.0 and 1.0.",
    )
    evidence_ids: list[int] = Field(default_factory=list)

    # Set when the supervisor disagrees with the specialist's recommendation.
    overrides_specialist: bool = False
    override_reason: str | None = Field(default=None, max_length=1000)

    # Optional instruction for the next brief. Nudges role without a new graph node.
    directive: str | None = Field(default=None, max_length=1500)

    # True when the supervisor believes the mission is ready for final review.
    report_ready: bool = False


class FailureSignal(BaseModel):
    """Emitted when a role cannot proceed normally."""

    role: Literal["recon", "discovery", "validation"]
    kind: Literal[
        "no_handoff",
        "invalid_handoff",
        "budget_exhausted",
        "no_progress",
        "repeated_action",
        "step_failed",
        "timeout",
        "model_error",
        "approval_rejected",
    ]
    summary: str = Field(min_length=1, max_length=1500)
    attempts: int = Field(default=1, ge=0)
    step_ids: list[int] = Field(default_factory=list)
    evidence_ids: list[int] = Field(default_factory=list)
    observation: dict[str, Any] | None = None


class Hypothesis(BaseModel):
    """Hypothesis recorded on the evidence board."""

    id: str  # "H-1", "H-2"
    statement: str
    asset: str
    endpoint: str | None = None
    status: Literal["open", "supported", "refuted", "inconclusive"] = "open"
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    evidence_ids: list[int] = Field(default_factory=list)
    falsifier: str = ""
    created_by: str  # recon | discovery | validation
    updated_at: datetime


class DecisionRecord(BaseModel):
    """Record of a decision and its expected/falsifying observation."""

    id: str  # "D-1", "D-2"
    role: str
    action: str
    target: str
    hypothesis_id: str | None = None
    evidence_ids: list[int] = Field(default_factory=list)
    observation: str = ""
    expected_observation: str | None = None
    would_falsify: str | None = None
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    outcome: str = ""
    created_at: datetime


class EvidenceBoard(BaseModel):
    """Evidence board folded from audit events."""

    hypotheses: list[Hypothesis] = Field(default_factory=list)
    decisions: list[DecisionRecord] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)
    coverage: dict[str, Any] = Field(default_factory=dict)


class SteeringNote(BaseModel):
    """Operator directive queued for an active run."""

    id: int
    assessment_id: int
    run_id: str | None = None
    text: str
    status: Literal["pending", "consumed", "expired"] = "pending"
    created_at: datetime
    consumed_at: datetime | None = None
