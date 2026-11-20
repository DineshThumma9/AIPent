"""Tests verifying supervisor visibility of failed/rejected actions to prevent loops."""

from __future__ import annotations

import pytest

from app.agents.mission_brain import (
    MissionDigest,
    build_mission_digest,
    step_digest,
)
from app.core.db import get_async_session_ctx
from app.domain.models import Assessment, Step, StepStatus
from app.persistence.step_repo import StepRepo


def test_step_digest_captures_rejections_and_failures():
    step1 = Step(
        id=101,
        seq=1,
        action="sqlmap_scan",
        target="127.0.0.1",
        status=StepStatus.REJECTED.value,
        error="Dangerous payload rejected by operator",
    )
    step2 = Step(
        id=102,
        seq=2,
        action="nmap_scan",
        target="127.0.0.1",
        status=StepStatus.FAILED.value,
        error="Target host down",
    )
    step3 = Step(
        id=103,
        seq=3,
        action="curl_request",
        target="127.0.0.1",
        status=StepStatus.SUCCEEDED.value,
    )

    observations = [
        {"step_id": 103, "summary": "Found HTTP 200 with JSON response"},
    ]

    digests = step_digest([step1, step2, step3], observations)
    assert len(digests) == 3

    # Reversed order (most recent first)
    d3, d2, d1 = digests
    assert d3["id"] == 103
    assert d3["status"] == "succeeded"
    assert d3["summary"] == "Found HTTP 200 with JSON response"

    assert d2["id"] == 102
    assert d2["status"] == "failed"
    assert d2["error"] == "Target host down"

    assert d1["id"] == 101
    assert d1["status"] == "rejected"
    assert "Dangerous payload" in d1["error"]


@pytest.mark.asyncio
async def test_mission_digest_preserves_rejection_history(engine):
    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Decision Amnesia Target",
            targets=["127.0.0.1"],
            ports=[80],
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        step_repo = StepRepo(session)
        step, approval = await step_repo.create_planned_step(
            assessment_id=assessment.id,
            run_id="run-1",
            role="validation",
            action="sqlmap_scan",
            target="127.0.0.1",
            risk="high",
            requires_approval=True,
        )
        await session.commit()

        # Reject the step
        await step_repo.reject_step(step.id, reason="Rejected by analyst: unsafe during office hours")
        await session.commit()

        state = {
            "turns": {"validation": 1},
            "observations": [],
        }

        digest = await build_mission_digest(
            assessment_id=assessment.id,
            run_id="run-1",
            state=state,
            session=session,
        )

        assert len(digest.recent_steps) == 1
        recorded_step = digest.recent_steps[0]
        assert recorded_step["id"] == step.id
        assert recorded_step["status"] == StepStatus.REJECTED.value
        assert "unsafe during office hours" in (recorded_step["error"] or "")
