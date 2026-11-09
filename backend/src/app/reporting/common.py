"""Shared sanitization and normalization utilities for report generation."""

from __future__ import annotations

import re
from typing import Any

from app.adapters.base import strip_html
from app.domain.models import Finding


def iso_timestamp(value: Any) -> str:
    """Format datetime as ISO string or empty if None."""
    return value.isoformat() if value else ""


def clean_text(text: str | None) -> str:
    """Strip HTML, bracketed scanner test IDs, and dangling path prefixes."""
    if not text:
        return ""
    text = strip_html(text)
    # Strip bracketed test IDs like [007303]
    text = re.sub(r"^\[\d+\]\s*", "", text.strip())
    # Strip leading /: or /path: prefixes if bare
    text = re.sub(r"^/:\s*", "", text)
    return text.strip()


def clean_endpoint(endpoint: str | None) -> str:
    """Normalize endpoints to single http scheme and single port."""
    if not endpoint:
        return ""
    ep = endpoint.strip()
    ep = re.sub(r"^(https?://)+", r"http://", ep)
    ep = re.sub(r":(\d+):\1", r":\1", ep)
    return ep


def clean_finding_title(title: str | None) -> str:
    """Normalize scanner titles (Nikto, Dirb) into professional report headings."""
    cleaned = clean_text(title)
    if not cleaned:
        return ""
    m_interesting = re.match(r"^([^:]+):\s*This might be interesting\.?$", cleaned, re.IGNORECASE)
    if m_interesting:
        return f"Potentially Sensitive File / Path: {m_interesting.group(1).strip()}"
    if "robots.txt" in cleaned.lower() and ("manual" in cleaned.lower() or "entry" in cleaned.lower()):
        return "Robots.txt Discloses Potentially Sensitive Entries"
    return cleaned


def count_severities(findings: list[Finding]) -> dict[str, int]:
    """Aggregate finding severity distribution."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def format_human_timestamp(value: Any) -> str:
    """Format datetime or ISO string as human-readable string (e.g. '2026-11-09 11:55 UTC')."""
    if not value:
        return ""
    if isinstance(value, str):
        try:
            from datetime import datetime
            value = datetime.fromisoformat(value)
        except Exception:
            return value
    if hasattr(value, "strftime"):
        return value.strftime("%Y-%m-%d %H:%M UTC")
    return str(value)


def parse_methodology_blocks(raw: str | None) -> list[dict[str, str]]:
    """Parse methodology text into structured paragraph and list item blocks."""
    if not raw or not raw.strip():
        return []

    text = raw.strip()

    # Convert inline (1), (2), (a), (b) into newline bullet lines
    text = re.sub(r"[\s;]*\(([1-9]|1[0-9]|[a-e])\)\s*", r"\n- ", text)

    # If it contains inline 1. 2. 3. (1-2 digits only) preceded by : or ;
    text = re.sub(r"([:;])\s*([1-9]|1[0-9])\.\s+", r"\1\n- ", text)

    # Separate concluding sentences commonly joined at the end
    concluding_markers = r"(\.\s+)(All actions|All steps|Findings were|In summary|Overall,)"
    text = re.sub(concluding_markers, r".\n\2", text)

    lines = [line.strip() for line in text.split("\n") if line.strip()]
    blocks: list[dict[str, str]] = []
    for line in lines:
        if re.match(r"^(\d{1,2}\.|\-|\*)\s+", line):
            item_text = re.sub(r"^(\d{1,2}\.|\-|\*)\s+", "", line).strip()
            item_text = re.sub(r";$", "", item_text).strip()
            blocks.append({"kind": "item", "text": item_text})
        else:
            blocks.append({"kind": "para", "text": line})
    return blocks

