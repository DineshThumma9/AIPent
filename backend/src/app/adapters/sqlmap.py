"""sqlmap adapter: parse stdout for verified SQL injection proof."""

from __future__ import annotations

import re
from app.adapters.base import EvidenceDraft, FindingDraft
from app.domain.models import FindingStatus, Origin, Severity

SQLMAP_PROOF = "sqlmap identified the following injection point"
_PARAM_RE = re.compile(r"Parameter:\s*([^\s(]+)\s*\(([^)]+)\)", re.IGNORECASE)
_TYPE_RE = re.compile(r"Type:\s*([^\n\r]+)", re.IGNORECASE)
_URL_RE = re.compile(r"^\s*(?:target\s+)?url:\s*(\S+)", re.IGNORECASE | re.MULTILINE)


def scan(text: str, host: str, port: int) -> list[FindingDraft]:
    """Parse sqlmap output text and extract confirmed injection findings."""
    if not text or SQLMAP_PROOF not in text.lower():
        return []

    param_match = _PARAM_RE.search(text)
    type_match = _TYPE_RE.search(text)

    param = param_match.group(1) if param_match else "unknown"
    method = param_match.group(2) if param_match else "GET"
    inj_type = type_match.group(1).strip() if type_match else "SQL Injection"
    url_match = _URL_RE.search(text)
    endpoint = (
        url_match.group(1).strip("'\"")
        if url_match
        else f"http://{host}:{port}/"
    )

    desc = f"sqlmap confirmed an active SQL injection vulnerability in parameter '{param}' ({method}) via {inj_type}."
    canonical_key = f"sqlmap:{host}:{port}:{param}"

    return [
        FindingDraft(
            canonical_key=canonical_key,
            title=f"SQL Injection via parameter '{param}'",
            asset=host,
            endpoint=endpoint,
            severity=Severity.HIGH,
            status=FindingStatus.CONFIRMED,
            confidence=0.95,
            origin=Origin.TOOL,
            impact="An attacker can bypass authentication, extract or modify database contents, and potentially compromise the host.",
            remediation="Use parameterized queries or prepared statements. Avoid string interpolation or direct concatenation of user input into SQL commands.",
            cwe=["CWE-89"],
            description=desc,
            evidence=[
                EvidenceDraft(
                    locator={"tool": "sqlmap", "param": param, "type": inj_type},
                    excerpt=text[:600],
                )
            ],
        )
    ]
