"""Shared shapes an adapter returns. Nothing here touches the database."""

from typing import Any

from pydantic import BaseModel, Field

from app.models import FindingStatus, Origin, Severity


class EvidenceDraft(BaseModel):
    locator: dict[str, Any] = Field(default_factory=dict)
    excerpt: str = ""


class FindingDraft(BaseModel):
    canonical_key: str
    title: str
    asset: str
    description: str = ""
    endpoint: str | None = None
    severity: Severity = Severity.INFO
    confidence: float = Field(default=1.0, ge=0, le=1)
    status: FindingStatus = FindingStatus.CONFIRMED
    origin: Origin = Origin.TOOL
    impact: str = ""
    remediation: str = ""
    cvss: float | None = None
    cve: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    evidence: list[EvidenceDraft] = Field(default_factory=list)
