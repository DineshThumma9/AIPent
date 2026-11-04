"""API request/response models."""

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field
from sqlmodel import SQLModel

from app.models import Approval, Assessment, Audit, Evidence, Finding, Step


class AssessmentCreate(SQLModel):
    title: str = Field(min_length=1)
    request: str = ""
    targets: list[str] = Field(min_length=1)
    ports: list[Annotated[int, Field(ge=1, le=65535)]] = Field(default_factory=list)


class DecisionIn(BaseModel):
    decision: Literal["approved", "rejected"]
    actor: str = Field(default="analyst", min_length=1, max_length=80)
    reason: str = Field(default="", max_length=500)


class PlanStepOut(BaseModel):
    action: str
    target: str
    rationale: str


class AgentView(BaseModel):
    assessment_id: int
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
