"""Persistence schema.

Six tables: one row per fact, no duplicated state. Graph checkpoints live in
LangGraph's own SQLite file; this database is the evidence of record.
"""

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, UniqueConstraint
from sqlmodel import Field, SQLModel


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AssessmentStatus(StrEnum):
    DRAFT = "draft"
    PLANNING = "planning"
    AWAITING_PLAN = "awaiting_plan"
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"


class StepStatus(StrEnum):
    PLANNED = "planned"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMEOUT = "timeout"
    BLOCKED = "blocked"
    REJECTED = "rejected"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(StrEnum):
    CONFIRMED = "confirmed"
    SUSPECTED = "suspected"
    FALSE_POSITIVE = "false_positive"


class Origin(StrEnum):
    TOOL = "tool"
    LLM = "llm"
    IMPORT = "import"


class Decision(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class Assessment(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    title: str
    request: str = ""
    targets: list[str] = Field(default_factory=list, sa_type=JSON)
    ports: list[int] = Field(default_factory=list, sa_type=JSON)
    exclusions: list[str] = Field(default_factory=list, sa_type=JSON)
    status: str = AssessmentStatus.DRAFT.value
    created_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None
    report_path: str | None = None
    report_sha256: str | None = None


class Step(SQLModel, table=True):
    """Planned action and its execution result, in one row."""

    id: int | None = Field(default=None, primary_key=True)
    assessment_id: int = Field(foreign_key="assessment.id", index=True)
    seq: int
    action: str
    argv: list[str] = Field(default_factory=list, sa_type=JSON)
    rationale: str = ""
    status: str = StepStatus.PLANNED.value
    output_path: str | None = None
    output_sha256: str | None = None
    exit_code: int | None = None
    error: str | None = None
    created_at: datetime = Field(default_factory=utcnow)
    ended_at: datetime | None = None


class Finding(SQLModel, table=True):
    """An issue on one asset. Same issue on another asset is another row."""

    __table_args__ = (
        UniqueConstraint("assessment_id", "canonical_key", name="uq_finding_canonical"),
    )

    id: int | None = Field(default=None, primary_key=True)
    assessment_id: int = Field(foreign_key="assessment.id", index=True)
    canonical_key: str = Field(index=True)
    asset: str
    endpoint: str | None = None
    title: str
    description: str = ""
    severity: str = Severity.INFO.value
    cvss: float | None = None
    cve: list[str] = Field(default_factory=list, sa_type=JSON)
    cwe: list[str] = Field(default_factory=list, sa_type=JSON)
    confidence: float = 0.5
    status: str = FindingStatus.SUSPECTED.value
    origin: str = Origin.TOOL.value
    impact: str = ""
    remediation: str = ""
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class Evidence(SQLModel, table=True):
    """Pointer from a finding to a line/URL/param in a stored tool output."""

    id: int | None = Field(default=None, primary_key=True)
    finding_id: int = Field(foreign_key="finding.id", index=True)
    step_id: int | None = Field(default=None, foreign_key="step.id", index=True)
    locator: dict[str, Any] = Field(default_factory=dict, sa_type=JSON)
    excerpt: str = ""
    created_at: datetime = Field(default_factory=utcnow)


class Approval(SQLModel, table=True):
    """Human decision bound to the exact command that will run."""

    id: int | None = Field(default=None, primary_key=True)
    assessment_id: int = Field(foreign_key="assessment.id", index=True)
    step_id: int | None = Field(default=None, foreign_key="step.id", index=True)
    action: str
    argv: list[str] = Field(default_factory=list, sa_type=JSON)
    decision: str = Decision.PENDING.value
    actor: str | None = None
    reason: str | None = None
    requested_at: datetime = Field(default_factory=utcnow)
    decided_at: datetime | None = None
    executed_at: datetime | None = None
    outcome: str | None = None


class Audit(SQLModel, table=True):
    """Append-only trace of every action and decision."""

    id: int | None = Field(default=None, primary_key=True)
    assessment_id: int = Field(foreign_key="assessment.id", index=True)
    ts: datetime = Field(default_factory=utcnow)
    actor: str = "system"
    event_type: str
    payload: dict[str, Any] = Field(default_factory=dict, sa_type=JSON)
