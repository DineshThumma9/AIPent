"""API request/response models."""

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlmodel import SQLModel

from app.agents.loop.contracts import EvidenceBoard
from app.domain.models import Approval, Assessment, Audit, Evidence, Finding, Step


class AssessmentCreate(SQLModel):
    title: str = Field(min_length=1)
    request: str = ""
    targets: list[str] = Field(min_length=1)
    ports: list[Annotated[int, Field(ge=1, le=65535)]] = Field(default_factory=list)


class AssessmentRequestUpdate(SQLModel):
    request: str = Field(min_length=1, max_length=4000)


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
    finished_at: datetime | None
    report_path: str | None
    report_sha256: str | None
    steps: list[Step] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    approvals: list[Approval] = Field(default_factory=list)
    audit: list[Audit] = Field(default_factory=list)
    messages: list[MessageOut] = Field(default_factory=list)
    gate_open: bool = False
    active_role: str | None = None
    reasoning: EvidenceBoard = Field(default_factory=EvidenceBoard)
