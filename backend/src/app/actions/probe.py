"""curl_request action: parse stored HTTP request artifacts into findings.

curl_request is executed through the MCP gateway. This module only reads the
stored response artifact; it performs no network calls.
"""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from app.adapters.base import EvidenceDraft, FindingDraft
from app.domain.models import Severity, FindingStatus


def parse(
    text: str,
    host: str,
    port: int,
) -> list[FindingDraft]:
    """Read the stored probe artifact and decide if a new finding is necessary.

    curl_request does not create findings automatically; instead the calling
    skill's evaluate() consumes the stored descriptor. We emit a draft only for
    an explicitly recorded success/failure interesting enough to keep.
    """
    try:
        payload = json.loads(text)
    except (TypeError, json.JSONDecodeError):
        return []

    probe = payload.get("curl_result") or payload.get("probe_result") or {}
    code = probe.get("status_code")
    if code not in (200, 201, 301, 302, 403):
        return []

    # A finding is published only when the probe looks interesting (non-404).
    if code in (404, 410):
        return []

    method = str(probe.get("method") or "GET").upper()
    parts = urlsplit(str(probe.get("url") or ""))
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"

    return [
        FindingDraft(
            canonical_key=f"web:probe:{host}:{port}{path}:{method}",
            asset=host,
            endpoint=probe.get("url", ""),
            title=f"Verification probe ({method}) returned {code}",
            description=probe.get("body_preview", "")[:1000],
            severity=Severity.INFO,
            confidence=0.8,
            status=FindingStatus.SUSPECTED,
            evidence=[
                EvidenceDraft(
                    locator={"tool": "curl_request", "url": probe.get("url"), "http_status": code},
                    excerpt=(probe.get("body_preview") or "")[:600],
                )
            ],
        )
    ]
