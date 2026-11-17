"""Build Evidence rows from executed step artifacts.

Evidence is what the verdict gate reads. A finding may only be confirmed when
a linked evidence row shows an executed probe with a concrete outcome, so the
locator has to carry the observable result (HTTP status, sqlmap proof marker),
not just a pointer to a log file.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from app.domain.models import Evidence, Step

_STATUS_KEYS = (
    "status_code",
    "http_status",
    "statusCode",
    "httpCode",
    "code",
    "status",
)
_URL_KEYS = ("url", "url_probed", "target_url")
_HTTP_STATUS_RE = re.compile(
    r"(?:HTTP/\d(?:\.\d)?\s+|\bstatus(?:_code)?[\"'\s:=]+)(\d{3})\b",
    re.IGNORECASE,
)
_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
SQLMAP_PROOF = "sqlmap identified the following injection point"


def step_text(step: Step) -> str:
    """Read the artifact of one executed step, or an empty string."""
    if not step.output_path:
        return ""
    path = Path(step.output_path)
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _walk(payload: Any, keys: tuple[str, ...]) -> Any:
    if isinstance(payload, dict):
        for key in keys:
            if key in payload:
                value = payload[key]
                if value not in (None, ""):
                    return value
        for value in payload.values():
            found = _walk(value, keys)
            if found is not None:
                return found
    elif isinstance(payload, list):
        for value in payload:
            found = _walk(value, keys)
            if found is not None:
                return found
    return None


def _as_status(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 100 <= value <= 599 else None
    if isinstance(value, str) and value.strip().isdigit():
        number = int(value.strip())
        return number if 100 <= number <= 599 else None
    return None


def _json_payload(text: str) -> Any:
    stripped = text.strip()
    if not stripped or stripped[0] not in "{[":
        return None
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return None


def http_status(text: str) -> int | None:
    """Extract an HTTP status from a probe artifact."""
    payload = _json_payload(text)
    if payload is not None:
        status = _as_status(_walk(payload, _STATUS_KEYS))
        if status is not None:
            return status
    match = _HTTP_STATUS_RE.search(text)
    return int(match.group(1)) if match else None


def _url_and_method(text: str, step: Step) -> tuple[str | None, str | None]:
    payload = _json_payload(text)
    url = _walk(payload, _URL_KEYS) if payload is not None else None
    method = _walk(payload, ("method",)) if payload is not None else None

    if not url or not method:
        for arg in step.argv or []:
            candidate = str(arg)
            if not candidate.startswith(("{", "[")):
                continue
            parsed = _json_payload(candidate)
            if parsed is None:
                continue
            url = url or _walk(parsed, _URL_KEYS)
            method = method or _walk(parsed, ("method",))

    clean_method = str(method).upper() if method else None
    if clean_method not in _METHODS:
        clean_method = None
    return (str(url) if url else None, clean_method)


def locator_for(step: Step, text: str) -> dict[str, Any]:
    """Build the locator the verdict gate inspects."""
    locator: dict[str, Any] = {"tool": step.action}

    if step.action == "curl_request":
        status = http_status(text)
        if status is not None:
            locator["http_status"] = status
        url, method = _url_and_method(text, step)
        if url:
            locator["url"] = url
        if method:
            locator["method"] = method
    elif step.action == "sqlmap_scan":
        locator["injectable"] = SQLMAP_PROOF in text.lower()

    return locator


async def link_step_evidence(
    session: AsyncSession,
    step: Step,
    finding_id: int,
    text: str | None = None,
) -> Evidence | None:
    """Attach one executed step to a finding, deduplicated by locator + excerpt."""
    body = step_text(step) if text is None else text
    locator = locator_for(step, body)
    excerpt = body.strip()[:800]

    existing = await session.execute(
        select(Evidence).where(
            Evidence.finding_id == finding_id,
            Evidence.step_id == step.id,
        )
    )
    for row in existing.scalars().all():
        if row.locator == locator and row.excerpt == excerpt:
            return None

    evidence = Evidence(
        finding_id=finding_id,
        step_id=step.id,
        locator=locator,
        excerpt=excerpt,
    )
    session.add(evidence)
    await session.flush()
    return evidence
