"""API request/response models."""

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, Field
from sqlmodel import SQLModel

from app.models import Approval, Assessment, Audit, Finding, Step


class AssessmentCreate(SQLModel):
    title: str = Field(min_length=1)
    request: str = ""
    targets: list[str] = Field(min_length=1)
    ports: list[Annotated[int, Field(ge=1, le=65535)]] = Field(default_factory=list)


class AssessmentDetail(BaseModel):
    """Assessment plus everything the dashboard needs in one round trip."""

    id: int
    title: str
    request: str
    targets: list[str]
    ports: list[int]
    exclusions: list[str]
    status: str
    created_at: datetime
    finished_at: datetime | None
    report_path: str | None
    report_sha256: str | None
    steps: list[Step] = []
    findings: list[Finding] = []
    approvals: list[Approval] = []
    audit: list[Audit] = []
