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


def _status_rank(status: int) -> int:
    """Rank a batch result for evidence: prefer a successful probe, then server errors."""
    if 200 <= status < 300:
        return 0
    if 500 <= status < 600:
        return 1
    if status in (401, 403):
        return 2
    if status in (400, 422):
        return 3
    if status == 404:
        return 4
    return 5


def _batch_candidate(entry: dict[str, Any]) -> dict[str, Any]:
    """Flatten one batch entry into the shape the locator helpers read."""
    result = entry.get("result") if isinstance(entry.get("result"), dict) else {}
    candidate = dict(result)
    request = entry.get("request") or result.get("request")
    if isinstance(request, dict):
        candidate.setdefault("request", request)
    return candidate


def _best_batch_entry(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Pick the most evidentiary entry from a batched curl artifact."""
    best: tuple[int, dict[str, Any]] | None = None
    for entry in payload.get("results") or []:
        if not isinstance(entry, dict):
            continue
        status = http_status(json.dumps(_batch_candidate(entry)))
        if status is None:
            continue
        rank = _status_rank(status)
        if best is None or rank < best[0]:
            best = (rank, entry)
    return best[1] if best is not None else None


def _best_batch_result(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Pick the most evidentiary result from a batched curl artifact."""
    entry = _best_batch_entry(payload)
    return _batch_candidate(entry) if entry is not None else None


def locator_for(step: Step, text: str) -> dict[str, Any]:
    """Build the locator the verdict gate inspects."""
    locator: dict[str, Any] = {"tool": step.action}

    if step.action == "curl_request":
        payload = _json_payload(text)
        if isinstance(payload, dict) and payload.get("batch"):
            chosen = _best_batch_result(payload)
            if chosen is not None:
                text = json.dumps(chosen)
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


def excerpt_for(step: Step, text: str) -> str:
    """Readable evidence text; batches use the result the locator selects."""
    body = text.strip()
    if step.action != "curl_request":
        return body[:800]

    payload = _json_payload(body)
    if not isinstance(payload, dict) or not payload.get("batch"):
        return body[:800]

    entry = _best_batch_entry(payload)
    if entry is None:
        return body[:800]

    result = entry.get("result") if isinstance(entry.get("result"), dict) else {}
    response = (
        result.get("response") if isinstance(result.get("response"), dict) else {}
    )
    content = response.get("body") or result.get("body")
    if isinstance(content, str) and content.strip():
        return content.strip()[:800]
    if content:
        return json.dumps(content)[:800]
    return json.dumps(_batch_candidate(entry))[:800]


async def link_step_evidence(
    session: AsyncSession,
    step: Step,
    finding_id: int,
    text: str | None = None,
) -> Evidence | None:
    """Attach one executed step to a finding, deduplicated by locator + excerpt."""
    body = step_text(step) if text is None else text
    locator = locator_for(step, body)
    excerpt = excerpt_for(step, body)

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
