"""dirb adapter: parse directory and route discovery output."""

from __future__ import annotations

import re
from urllib.parse import urlsplit
from app.adapters.base import EvidenceDraft, FindingDraft
from app.domain.models import FindingStatus, Origin, Severity

_DIR_RE = re.compile(r"==>\s*DIRECTORY:\s*(\S+)", re.IGNORECASE)
_FILE_RE = re.compile(r"\+\s*(\S+)\s*\((?:CODE:\s*(\d+))\s*\|\s*(?:SIZE:\s*(\d+))\)", re.IGNORECASE)

SENSITIVE_KEYWORDS = ("admin", "api", "rest", "swagger", "graphql", "config", "backup", "db", ".git", ".env", "login")


def scan(text: str, host: str, port: int) -> list[FindingDraft]:
    """Parse dirb text output and extract discovered directory and endpoint candidate findings."""
    if not text:
        return []

    drafts: list[FindingDraft] = []
    seen_endpoints: set[str] = set()

    for match in _DIR_RE.finditer(text):
        url = match.group(1).strip()
        path = urlsplit(url).path or url
        if path in seen_endpoints:
            continue
        seen_endpoints.add(path)

        is_sensitive = any(kw in path.lower() for kw in SENSITIVE_KEYWORDS)
        drafts.append(
            FindingDraft(
                canonical_key=f"dirb:{host}:{port}:{path}",
                title=f"Discovered Directory: {path}",
                asset=host,
                endpoint=path,
                severity=Severity.LOW if is_sensitive else Severity.INFO,
                status=FindingStatus.SUSPECTED,
                confidence=0.8,
                origin=Origin.TOOL,
                description=f"Directory enumeration discovered accessible path: {url}",
                evidence=[EvidenceDraft(locator={"tool": "dirb", "path": path}, excerpt=match.group(0))],
            )
        )

    for match in _FILE_RE.finditer(text):
        url = match.group(1).strip()
        code = match.group(2)
        size = match.group(3)
        path = urlsplit(url).path or url
        if path in seen_endpoints:
            continue
        seen_endpoints.add(path)

        is_sensitive = any(kw in path.lower() for kw in SENSITIVE_KEYWORDS)
        drafts.append(
            FindingDraft(
                canonical_key=f"dirb:{host}:{port}:{path}",
                title=f"Discovered Endpoint: {path} (HTTP {code})",
                asset=host,
                endpoint=path,
                severity=Severity.LOW if is_sensitive else Severity.INFO,
                status=FindingStatus.SUSPECTED,
                confidence=0.8,
                origin=Origin.TOOL,
                description=f"Dirb discovered endpoint '{path}' returning HTTP {code} (size {size} bytes).",
                evidence=[EvidenceDraft(locator={"tool": "dirb", "path": path, "code": code, "size": size}, excerpt=match.group(0))],
            )
        )

    return drafts
