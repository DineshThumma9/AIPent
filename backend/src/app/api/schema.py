"""API request/response models."""

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.agents.loop.contracts import EvidenceBoard


class AssessmentCreate(BaseModel):
    title: str = Field(min_length=1)
    request: str = ""
    targets: list[str] = Field(min_length=1)
    ports: list[Annotated[int, Field(ge=1, le=65535)]] = Field(default_factory=list)


class AssessmentRequestUpdate(BaseModel):
    request: str = Field(min_length=1, max_length=4000)


class StepOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int | None = None
    assessment_id: int
    seq: int
    action: str
    target: str | None = None
    argv: list[str] = Field(default_factory=list)
    rationale: str = ""
    status: str = "planned"
    output_path: str | None = None
    output_sha256: str | None = None
    exit_code: int | None = None
    error: str | None = None
    created_at: datetime
    ended_at: datetime | None = None


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int | None = None
    assessment_id: int
    canonical_key: str
    asset: str
    endpoint: str | None = None
    title: str
    description: str = ""
    severity: str = "info"
    cvss: float | None = None
    cve: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    confidence: float = 0.5
    status: str = "suspected"
    origin: str = "tool"
    impact: str = ""
    remediation: str = ""
    created_at: datetime
    updated_at: datetime


class EvidenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int | None = None
    finding_id: int
    step_id: int | None = None
    locator: dict[str, Any] = Field(default_factory=dict)
    excerpt: str = ""
    created_at: datetime


class ApprovalOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int | None = None
    assessment_id: int
    step_id: int | None = None
    action: str
    argv: list[str] = Field(default_factory=list)
    detail: dict[str, Any] = Field(default_factory=dict)
    decision: str = "pending"
    actor: str | None = None
    reason: str | None = None
    requested_at: datetime
    decided_at: datetime | None = None
    executed_at: datetime | None = None
    outcome: str | None = None


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int | None = None
    assessment_id: int
    ts: datetime
    actor: str = "system"
    event_type: str
    payload: dict[str, Any] = Field(default_factory=dict)


class DecisionIn(BaseModel):
    decision: Literal["approved", "rejected"]
    actor: str = Field(default="analyst", min_length=1, max_length=80)
    reason: str = Field(default="", max_length=500)
    # Bind the decision to the gate card the analyst saw.
    approval_id: int | None = None
    step_id: int | None = None


class MessageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    assessment_id: int
    role: str
    text: str
    client_message_id: str | None = None
    created_at: datetime


class MessageIn(BaseModel):
    role: Literal["operator", "assistant"]
    text: str = Field(min_length=1, max_length=4000)


class ChatIn(BaseModel):
    text: str = Field(min_length=1, max_length=4000)
    client_message_id: str | None = Field(default=None, max_length=80)


class ChatAccepted(BaseModel):
    assessment_id: int
    operator_message_id: int
    accepted: bool = True
    steering: bool = False
    message: str = ""


class PlanStepOut(BaseModel):
    action: str
    target: str
    rationale: str


class AgentView(BaseModel):
    assessment_id: int
    run_id: str | None = None
    status: str
    running: bool
    paused: bool
    next: list[str] = Field(default_factory=list)
    plan: list[PlanStepOut] = Field(default_factory=list)
    plan_source: str = ""
    pending: dict[str, Any] | None = None
    steps: int = 0
    last_message: str | None = None
    risk_score: float | None = None
    gate_open: bool = False
    active_role: str | None = None
    phase: str = ""
    reasoning_summary: str = ""


class AgentAccepted(BaseModel):
    assessment_id: int
    accepted: bool = True
    message: str = ""



class AssessmentDetail(BaseModel):
    """Assessment plus everything the dashboard needs in one round trip."""

    id: int
    title: str
    request: str
    targets: list[str]
    ports: list[int]
    exclusions: list[str]
    status: str
    risk_score: float | None = None
    created_at: datetime
    finished_at: datetime | None = None
    report_path: str | None = None
    report_sha256: str | None = None
    steps: list[StepOut] = Field(default_factory=list)
    findings: list[FindingOut] = Field(default_factory=list)
    evidence: list[EvidenceOut] = Field(default_factory=list)
    approvals: list[ApprovalOut] = Field(default_factory=list)
    audit: list[AuditOut] = Field(default_factory=list)
    messages: list[MessageOut] = Field(default_factory=list)
    gate_open: bool = False
    active_role: str | None = None
    run_id: str | None = None
    reasoning: EvidenceBoard = Field(default_factory=EvidenceBoard)
