"""Tests for Server-Sent Events (SSE) streaming and notification system.

Covers:
- GET /api/assessments/{id}/events?once=true: initial snapshot replay, headers, and 404 on missing.
- StreamState: snapshot construction, diff calculation emitting only new deltas.
- Core notifications: subscribe, notify, unsubscribe.
- DB commit listener: assessment and child (step/finding) commits waking event stream listeners.
"""

from __future__ import annotations

import asyncio
import json
import pytest

from app.api.queries import load_assessment_detail
from app.core import notifications
from app.core.db import get_async_session_ctx
from app.core.events import EventType, StreamState
from app.domain.models import Assessment, Finding, Step


def _create(client, title="SSE Lab"):
    resp = client.post(
        "/api/assessments",
        json={
            "title": title,
            "request": "Stream verification",
            "targets": ["127.0.0.1"],
            "ports": [3000],
        },
    )
    assert resp.status_code == 201
    return resp.json()


def _parse_sse(body: str) -> list[dict]:
    events = []
    for block in body.strip().split("\n\n"):
        data = [
            line.removeprefix("data: ")
            for line in block.splitlines()
            if line.startswith("data: ")
        ]
        if data:
            events.append(json.loads("\n".join(data)))
    return events


def test_stream_replays_snapshot_first(client):
    """Initial connection to /events immediately delivers a full snapshot."""
    assessment = _create(client)
    aid = assessment["id"]

    response = client.get(f"/api/assessments/{aid}/events?once=true")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.headers["cache-control"].startswith("no-cache")

    events = _parse_sse(response.text)
    assert len(events) == 1
    snapshot = events[0]
    assert snapshot["type"] == EventType.SNAPSHOT.value
    assert snapshot["assessment_id"] == aid
    assert snapshot["data"]["assessment"]["id"] == aid
    assert snapshot["data"]["assessment"]["evidence"] == []


def test_stream_missing_assessment_is_404(client):
    """Missing assessment ID returns 404 on event stream."""
    assert client.get("/api/assessments/99999/events?once=true").status_code == 404


def test_stream_state_diff_emits_only_changes(engine):
    """StreamState correctly detects new findings and avoids duplicate emissions."""
    async def run():
        async with get_async_session_ctx() as session:
            assessment = Assessment(
                title="Diff Lab", targets=["127.0.0.1"], ports=[3000]
            )
            session.add(assessment)
            await session.commit()
            await session.refresh(assessment)
            aid = assessment.id

            detail = await load_assessment_detail(session, aid)
            assert detail is not None
            state = StreamState(detail)

            # 1. Snapshot creation
            snapshot = state.event(
                aid,
                EventType.SNAPSHOT,
                {"assessment": detail.model_dump()},
            )
            assert snapshot.assessment_id == aid
            assert snapshot.data["assessment"]["id"] == aid

            # 2. No changes -> diff is empty
            assert state.diff(detail) == []

            # 3. Add a finding -> diff emits finding added event
            finding = Finding(
                assessment_id=aid,
                canonical_key="web:new_port",
                title="New port detected",
                asset="127.0.0.1",
            )
            session.add(finding)
            await session.commit()

            updated_detail = await load_assessment_detail(session, aid)
            assert updated_detail is not None
            diff_events = state.diff(updated_detail)
            assert len(diff_events) >= 1

    asyncio.run(run())


def test_notifications_subscribe_notify_unsubscribe():
    """Notification pub/sub event flag triggers as expected."""
    wake = notifications.subscribe(42)
    assert not wake.is_set()

    notifications.notify(42)
    assert wake.is_set()

    wake.clear()
    notifications.unsubscribe(42, wake)
    notifications.notify(42)
    assert not wake.is_set()


def test_notifications_assessment_commit_wakes_listener(engine):
    """Modifying Assessment in DB notifies listeners on that assessment ID."""
    async def run():
        async with get_async_session_ctx() as session:
            assessment = Assessment(title="Notify Test", targets=["127.0.0.1"], ports=[3000])
            session.add(assessment)
            await session.commit()
            await session.refresh(assessment)
            aid = assessment.id

        wake = notifications.subscribe(aid)
        try:
            assert not wake.is_set()
            async with get_async_session_ctx() as session:
                loaded = await session.get(Assessment, aid)
                assert loaded is not None
                loaded.status = "awaiting_approval"
                await session.commit()

            assert wake.is_set()
        finally:
            notifications.unsubscribe(aid, wake)

    asyncio.run(run())


def test_notifications_child_commit_wakes_listener(engine):
    """Inserting child step or finding notifies listeners on parent assessment ID."""
    async def run():
        async with get_async_session_ctx() as session:
            assessment = Assessment(title="Child Notify Test", targets=["127.0.0.1"], ports=[3000])
            session.add(assessment)
            await session.commit()
            await session.refresh(assessment)
            aid = assessment.id

        wake = notifications.subscribe(aid)
        try:
            assert not wake.is_set()
            async with get_async_session_ctx() as session:
                step = Step(
                    assessment_id=aid,
                    seq=1,
                    role="recon",
                    action="recon_services",
                    target="127.0.0.1",
                )
                session.add(step)
                await session.commit()

            assert wake.is_set()
        finally:
            notifications.unsubscribe(aid, wake)

    asyncio.run(run())
