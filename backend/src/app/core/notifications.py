"""In-process wakeups for the SSE stream.

The database stays the source of truth, but polling alone adds a fixed delay
between a commit and the next stream read. Every ORM commit tags the
assessment rows it touched and wakes the streams watching those assessments.
A short poll remains as a fallback for writes made outside this process.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict

from sqlalchemy import event
from sqlalchemy.orm import Session

_listeners: dict[int, set[asyncio.Event]] = defaultdict(set)


def subscribe(assessment_id: int) -> asyncio.Event:
    """Register a wakeup event for one assessment stream."""
    wake = asyncio.Event()
    _listeners[assessment_id].add(wake)
    return wake


def unsubscribe(assessment_id: int, wake: asyncio.Event) -> None:
    listeners = _listeners.get(assessment_id)
    if not listeners:
        return
    listeners.discard(wake)
    if not listeners:
        _listeners.pop(assessment_id, None)


def notify(assessment_id: int) -> None:
    """Wake every stream currently watching this assessment."""
    for wake in tuple(_listeners.get(assessment_id, ())):
        wake.set()


@event.listens_for(Session, "before_flush")
def _remember_touched_assessments(session: Session, _flush_context, _instances) -> None:
    touched = session.info.setdefault("aipent_notify_assessments", set())
    for row in list(session.new) + list(session.dirty):
        assessment_id = getattr(row, "assessment_id", None)
        if isinstance(assessment_id, int):
            touched.add(assessment_id)


@event.listens_for(Session, "after_commit")
def _notify_committed_assessments(session: Session) -> None:
    for assessment_id in session.info.pop("aipent_notify_assessments", ()):
        notify(assessment_id)


@event.listens_for(Session, "after_rollback")
def _discard_rolled_back_assessments(session: Session) -> None:
    session.info.pop("aipent_notify_assessments", None)
