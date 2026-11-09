"""curl_tool action: safe non-destructive HTTP request verification.

Added to the closed ACTIONS catalogue so a human action gate binds to the exact
argv (method + url + headers) before the network call happens. This action is
executed locally by httpx in the backend process (no container).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from app.adapters.base import EvidenceDraft, FindingDraft
from app.domain.models import Severity, FindingStatus

SAFE_METHODS = ("GET", "HEAD", "POST")
MAX_TIMEOUT_S = 30
PROBE_MARKER = "curl_tool"


class ProbeResult(BaseModel):
    url: str
    url_probed: str
    method: str
    status_code: int | None
    headers: dict[str, str] = Field(default_factory=dict)
    body_preview: str = ""
    elapsed_ms: float = 0.0
    error: str | None = None


def build_argv(
    assessment: Any,
    target: str,
    output_path: Path,
    method: str = "GET",
    url: str = "",
    headers: dict[str, str] | None = None,
    body: str = "",
    expected_status: int = 200,
    timeout: int = 15,
) -> list[str]:
    """Descriptor stored in step.argv so approval binds to these exact args.

    Format: ["curl_tool", METHOD, URL, headers_json, expected_status, body]
    """
    headers = headers or {}
    if not url.startswith(("http://", "https://")):
        ports = getattr(assessment, "ports", None) or [3000]
        url = f"http://{target}:{ports[0]}{url}"
    return [
        PROBE_MARKER,
        method.upper(),
        url,
        json.dumps(headers, sort_keys=True),
        str(expected_status),
        body,
    ]


async def run_curl(
    method: str,
    url: str,
    headers: dict[str, str],
    body: str = "",
    expected_status: int = 200,
    timeout: int = 15,
) -> ProbeResult:
    """Execute the actual HTTP request (curl) and return the response snapshot.

    The agent cannot mutate the target: DELETE/PUT/PATCH is placed behind the
    executor and stripped before this function is called from a planned step.
    """
    import httpx

    method = method.upper()
    if method not in SAFE_METHODS:
        raise ValueError(f"Unsafe probe method not permitted: {method}")

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        request = client.build_request(method, url, headers=headers, content=body or None)
        try:
            response = await client.send(request)
        except Exception as exc:  # noqa: BLE001 - the artifact records the failure
            return ProbeResult(
                url=url, url_probed=url, method=method,
                status_code=None, error=str(exc)[:300],
            )
        try:
            raw = response.text
            import re
            # Strip verbose inline styles so HTML directory listings and payloads aren't masked
            cleaned = re.sub(r"<style[^>]*>[\s\S]*?</style>", "", raw, flags=re.IGNORECASE)
            body_digest = cleaned[:8000]
        except AttributeError:
            body_digest = ""
        return ProbeResult(
            url=url, url_probed=url,
            method=method,
            status_code=response.status_code,
            headers={k.lower(): v for k, v in response.headers.items()},
            body_preview=body_digest,
            elapsed_ms=response.elapsed.total_seconds() * 1000,
        )


def parse(
    text: str,
    host: str,
    port: int,
) -> list[FindingDraft]:
    """Read the stored probe artifact and decide if a new finding is necessary.

    curl_tool does not create findings automatically; instead the calling
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
                    locator={"tool": "curl_tool", "url": probe.get("url"), "http_status": code},
                    excerpt=(probe.get("body_preview") or "")[:600],
                )
            ],
        )
    ]
