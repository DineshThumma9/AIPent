"""Guided ZAP workflow over MCP.

Crawl, wait for the crawl, drain passive analysis, then read the JSON report in
bounded chunks. No active scan and no direct ZAP API access.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any

from app.integrations.mcp_client import GatewayClient

# Queue mode returns "Job ID"; direct mode returns "Operation ID".
JOB_ID = re.compile(r"^(?:Job|Operation) ID:\s*(\S+)", re.MULTILINE)
STATUS = re.compile(r"^Status:\s*(.+)$", re.MULTILINE)
COMPLETED = re.compile(r"^Completed:\s*(yes|no)\s*$", re.MULTILINE | re.IGNORECASE)
PROGRESS = re.compile(r"^Progress:\s*(\d+)%", re.MULTILINE)
REPORT_PATH = re.compile(r"^Path:\s*(.+)$", re.MULTILINE)

MAX_POLLS = 80
POLL_SECONDS = 3
CHUNK_CHARS = 100_000
MAX_CHUNKS = 100


class ZapWorkflowError(RuntimeError):
    pass


def _job_id(text: str) -> str:
    match = JOB_ID.search(text)
    if not match:
        raise ZapWorkflowError(f"no Job or Operation ID in response: {text[:500]}")
    return match.group(1)


def _status(text: str) -> str:
    """Normalise the two status shapes this server emits.

    Queue mode has an explicit ``Status:`` line. Direct mode has no status
    field; it reports ``Completed: yes`` and a progress percentage instead.
    """
    match = STATUS.search(text)
    if match:
        return match.group(1).strip()

    completed = COMPLETED.search(text)
    if completed:
        return "SUCCEEDED" if completed.group(1).lower() == "yes" else "RUNNING"

    progress = PROGRESS.search(text)
    if progress and int(progress.group(1)) >= 100:
        return "SUCCEEDED"

    return "UNKNOWN"


async def _wait_for_job(
    gateway: GatewayClient, operation_id: str, label: str
) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    for _ in range(MAX_POLLS):
        text = await gateway.call(
            "zap_crawl_status", {"operationId": operation_id}
        )
        calls.append(
            {
                "tool": "zap_crawl_status",
                "arguments": {"operationId": operation_id},
            }
        )
        status = _status(text)
        if status.lower().startswith("succeeded"):
            return calls
        if status.lower().startswith(("failed", "cancelled", "dead letter")):
            raise ZapWorkflowError(f"{label} {status}: {text[-800:]}")
        await asyncio.sleep(POLL_SECONDS)
    raise ZapWorkflowError(f"{label} did not finish after {MAX_POLLS} polls")


async def _read_report(gateway: GatewayClient, path: str) -> tuple[str, list[dict[str, Any]]]:
    calls: list[dict[str, Any]] = []
    pages: list[str] = []
    offset = 0
    expected: str | None = None

    for _ in range(MAX_CHUNKS):
        arguments: dict[str, Any] = {
            "reportPath": path,
            "offset": offset,
            "maxChars": CHUNK_CHARS,
        }
        if expected:
            arguments["expectedSha256"] = expected
        text = await gateway.call("zap_report_read_chunk", arguments)
        calls.append({"tool": "zap_report_read_chunk", "arguments": arguments})
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ZapWorkflowError(
                f"report chunk was not JSON: {text[:500]}"
            ) from exc

        expected = expected or data.get("artifactSha256")
        pages.append(data.get("content", ""))
        if data.get("endOfFile"):
            return "".join(pages), calls
        next_offset = data.get("nextOffset")
        if next_offset is None:
            raise ZapWorkflowError("report chunk has no nextOffset")
        offset = int(next_offset)

    raise ZapWorkflowError("report exceeded the chunk limit")


async def run_zap_baseline(
    gateway: GatewayClient,
    target_url: str,
    idempotency_key: str,
) -> tuple[str, list[dict[str, Any]]]:
    """Run one HTTP crawl, drain passive analysis, return the JSON report."""
    calls: list[dict[str, Any]] = []

    started = await gateway.call(
        "zap_crawl_start",
        {
            "targetUrl": target_url,
            "strategy": "http",
            "idempotencyKey": idempotency_key,
        },
    )
    calls.append(
        {
            "tool": "zap_crawl_start",
            "arguments": {
                "targetUrl": target_url,
                "strategy": "http",
                "idempotencyKey": idempotency_key,
            },
        }
    )
    operation_id = _job_id(started)
    try:
        calls.extend(await _wait_for_job(gateway, operation_id, "crawl"))
    except Exception:
        # A timed-out crawl keeps running inside ZAP. Stop it before raising so
        # the next attempt is not queued behind a stale spider.
        try:
            await gateway.call("zap_crawl_stop", {"operationId": operation_id})
            calls.append(
                {
                    "tool": "zap_crawl_stop",
                    "arguments": {"operationId": operation_id},
                }
            )
        except Exception:  # noqa: BLE001 - best-effort cleanup
            pass
        raise

    # Passive analysis runs alongside the crawl. Wait for the backlog to drain.
    # dtkmn may return early on its own timeout; call it again if needed.
    for _ in range(3):
        passive = await gateway.call(
            "zap_passive_scan_wait",
            {"timeoutSeconds": 60, "pollIntervalMs": 1000},
        )
        calls.append(
            {
                "tool": "zap_passive_scan_wait",
                "arguments": {"timeoutSeconds": 60, "pollIntervalMs": 1000},
            }
        )
        lowered = passive.lower()
        if "backlog drained" in lowered or "completed: yes" in lowered:
            break
        # "Passive scan wait timed out" means retry; anything else is a
        # provider error worth surfacing rather than hiding.
        if "timed out" not in lowered:
            break

    report = await gateway.call(
        "zap_report_generate", {"baseUrl": target_url, "format": "json"}
    )
    calls.append(
        {
            "tool": "zap_report_generate",
            "arguments": {"baseUrl": target_url, "format": "json"},
        }
    )
    match = REPORT_PATH.search(report)
    if not match:
        raise ZapWorkflowError(f"no report path in response: {report[:500]}")

    body, read_calls = await _read_report(gateway, match.group(1).strip())
    calls.extend(read_calls)
    return body, calls