"""Shared shapes an adapter returns. Nothing here touches the database."""

import html
import re
from typing import Any

from pydantic import BaseModel, Field

from app.domain.models import FindingStatus, Origin, Severity


def strip_html(text: str) -> str:
    """Strip HTML tags/entities and collapse whitespace. Used by adapters and report."""
    if not text:
        return ""
    text = re.sub(r"</p\s*>", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"<br\s*/?>", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", "", text)
    text = html.unescape(text)
    text = re.sub(r"[ \t]+", " ", text)
    return text.strip()


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
