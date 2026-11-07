"""Server-sent events derived from the database.

The database is the source of truth, so a reconnect only needs a fresh snapshot.
No in-process pub/sub is involved: every poll reads the same rows the REST API
would return.
"""

import asyncio
import time
from datetime import datetime
from enum import StrEnum
from typing import Any

from fastapi import Request
from pydantic import BaseModel, Field

from app.core.db import get_async_session_ctx
from app.core.log import get_logger
from app.domain.models import Approval, Finding, Step, utcnow
from app.api.queries import load_assessment_detail
from app.api.schema import AssessmentDetail

log = get_logger("events")

POLL_SECONDS = 1.0
HEARTBEAT_SECONDS = 15.0


class EventType(StrEnum):
    SNAPSHOT = "snapshot"
    STATUS = "status"
    STEP = "step"
    FINDING = "finding"
    APPROVAL = "approval"
    AUDIT = "audit"
    REPORT = "report"
    MESSAGE = "message"
    ERROR = "error"
    HEARTBEAT = "heartbeat"


class StreamEvent(BaseModel):
    id: int
    type: EventType
    assessment_id: int
    ts: datetime = Field(default_factory=utcnow)
    data: dict[str, Any]


def _step_key(step: Step) -> tuple:
    return (
        step.status,
        step.ended_at,
        step.exit_code,
        step.output_path,
        step.output_sha256,
        step.error,
    )


def _finding_key(finding: Finding, evidence_ids: tuple[int, ...]) -> tuple:
    return (
        finding.updated_at,
        finding.status,
        finding.severity,
        finding.title,
        finding.confidence,
        evidence_ids,
    )


def _approval_key(approval: Approval) -> tuple:
    return (
        approval.decision,
        approval.actor,
        approval.reason,
        approval.decided_at,
        approval.executed_at,
        approval.outcome,
    )


class StreamState:
    """Keeps the last emitted shape of each row and emits only changes."""

    def __init__(self, detail: AssessmentDetail):
        self._seq = 0
        self._steps = {
            step.id: _step_key(step) for step in detail.steps if step.id is not None
        }
        self._findings = {
            finding.id: _finding_key(finding, self._evidence_ids(detail, finding.id))
            for finding in detail.findings
            if finding.id is not None
        }
        self._approvals = {
            approval.id: _approval_key(approval)
            for approval in detail.approvals
            if approval.id is not None
        }
        self._audit_id = max((row.id or 0 for row in detail.audit), default=0)
        self._status = detail.status
        self._report = (detail.report_path, detail.report_sha256)

    @staticmethod
    def _evidence_ids(detail: AssessmentDetail, finding_id: int | None) -> tuple[int, ...]:
        return tuple(
            evidence.id
            for evidence in detail.evidence
            if evidence.finding_id == finding_id and evidence.id is not None
        )

    def event(
        self, assessment_id: int, event_type: EventType, data: dict[str, Any]
    ) -> StreamEvent:
        self._seq += 1
        return StreamEvent(
            id=self._seq,
            type=event_type,
            assessment_id=assessment_id,
            data=data,
        )

    def diff(self, detail: AssessmentDetail) -> list[StreamEvent]:
        events: list[StreamEvent] = []

        def emit(event_type: EventType, data: dict[str, Any]) -> None:
            events.append(self.event(detail.id, event_type, data))

        for step in detail.steps:
            if step.id is None:
                continue
            key = _step_key(step)
            if self._steps.get(step.id) != key:
                self._steps[step.id] = key
                emit(EventType.STEP, {"step": step.model_dump()})

        for finding in detail.findings:
            if finding.id is None:
                continue
            evidence = [
                row for row in detail.evidence if row.finding_id == finding.id
            ]
            key = _finding_key(finding, self._evidence_ids(detail, finding.id))
            if self._findings.get(finding.id) != key:
                self._findings[finding.id] = key
                emit(
                    EventType.FINDING,
                    {
                        "finding": finding.model_dump(),
                        "evidence": [row.model_dump() for row in evidence],
                    },
                )

        for approval in detail.approvals:
            if approval.id is None:
                continue
            key = _approval_key(approval)
            if self._approvals.get(approval.id) != key:
                self._approvals[approval.id] = key
                emit(EventType.APPROVAL, {"approval": approval.model_dump()})

        new_audit = sorted(
            (row for row in detail.audit if (row.id or 0) > self._audit_id),
            key=lambda row: row.id or 0,
        )
        for row in new_audit:
            self._audit_id = max(self._audit_id, row.id or 0)
            emit(EventType.AUDIT, {"event": row.model_dump()})

        # Emitted after the work it describes so the feed reads in causal order.
        if detail.status != self._status:
            self._status = detail.status
            emit(
                EventType.STATUS,
                {"status": detail.status, "finished_at": detail.finished_at},
            )

        report = (detail.report_path, detail.report_sha256)
        if report != self._report:
            self._report = report
            emit(
                EventType.REPORT,
                {
                    "report_path": detail.report_path,
                    "report_sha256": detail.report_sha256,
                    "finished_at": detail.finished_at,
                    "status": detail.status,
                },
            )

        return events


def format_sse(event: StreamEvent) -> str:
    return (
        f"id: {event.id}\n"
        f"event: {event.type.value}\n"
        f"data: {event.model_dump_json()}\n\n"
    )


async def _read_detail(assessment_id: int) -> AssessmentDetail | None:
    async with get_async_session_ctx() as session:
        return await load_assessment_detail(session, assessment_id)


async def stream_assessment_events(
    assessment_id: int,
    request: Request,
    once: bool = False,
):
    detail = await _read_detail(assessment_id)
    if detail is None:
        return

    state = StreamState(detail)
    yield format_sse(state.event(assessment_id, EventType.SNAPSHOT, {"assessment": detail.model_dump()}))

    if once:
        return

    last_heartbeat = time.monotonic()
    log.info("event stream opened assessment=%s", assessment_id)
    try:
        while True:
            if await request.is_disconnected():
                return
            await asyncio.sleep(POLL_SECONDS)

            detail = await _read_detail(assessment_id)
            if detail is None:
                return

            for event in state.diff(detail):
                yield format_sse(event)

            if time.monotonic() - last_heartbeat >= HEARTBEAT_SECONDS:
                last_heartbeat = time.monotonic()
                yield format_sse(
                    state.event(
                        assessment_id,
                        EventType.HEARTBEAT,
                        {"ts": utcnow().isoformat()},
                    )
                )
    except asyncio.CancelledError:
        raise
    except Exception:  # noqa: BLE001 - a broken stream must not take the API down
        log.exception("event stream failed assessment=%s", assessment_id)
    finally:
        log.info("event stream closed assessment=%s", assessment_id)
