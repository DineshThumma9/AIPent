from __future__ import annotations

from datetime import datetime, timezone
import pytest
from app.core.db import get_async_session_ctx
from app.domain.models import Assessment, AssessmentStatus, Audit
from app.agents.loop.contracts import EvidenceBoard, Hypothesis, DecisionRecord
from app.agents.loop.reasoning import (
    fold_events_into_evidence_board,
    build_evidence_board,
    record_hypothesis,
    update_hypothesis,
    next_hypothesis_id,
)
from app.persistence.audit_repo import AuditRepo


def test_fold_events_into_evidence_board_pure():
    """Verify fold_events_into_evidence_board does not touch any database."""
    now = datetime.now(timezone.utc)
    events = [
        Audit(
            id=1,
            assessment_id=1,
            event_type="hypothesis.created",
            payload={
                "run_id": "run-1",
                "hypothesis_id": "H-1",
                "role": "recon",
                "statement": "Port 80 is vulnerable",
                "asset": "127.0.0.1",
                "endpoint": "/test",
                "falsifier": "Returns 404",
                "confidence": 0.5,
                "status": "open",
                "created_by": "recon",
                "updated_at": now.isoformat(),
            },
            ts=now,
        ),
        Audit(
            id=2,
            assessment_id=1,
            event_type="hypothesis.updated",
            payload={
                "run_id": "run-1",
                "hypothesis_id": "H-1",
                "status": "confirmed",
                "confidence": 0.95,
            },
            ts=now,
        ),
        Audit(
            id=3,
            assessment_id=1,
            event_type="decision.recorded",
            payload={
                "id": "D-1",
                "run_id": "run-1",
                "role": "recon",
                "action": "nmap_scan",
                "target": "127.0.0.1",
                "observation": "port 80 open",
                "outcome": "found web server",
                "confidence": 0.9,
            },
            ts=now,
        ),
        Audit(
            id=4,
            assessment_id=1,
            event_type="handoff.created",
            payload={
                "run_id": "run-1",
                "role": "recon",
                "open_questions": ["What tech stack?", "Is WAF present?"],
            },
            ts=now,
        ),
    ]

    board = fold_events_into_evidence_board(events)
    assert isinstance(board, EvidenceBoard)
    assert len(board.hypotheses) == 1
    assert board.hypotheses[0].id == "H-1"
    assert board.hypotheses[0].status == "confirmed"
    assert board.hypotheses[0].confidence == 0.95
    assert len(board.decisions) == 1
    assert board.decisions[0].id == "D-1"
    assert board.open_questions == ["What tech stack?", "Is WAF present?"]


@pytest.mark.asyncio
async def test_audit_repo_hypothesis_and_evidence_board(engine):
    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Hypothesis Test",
            request="Evaluate target security posture",
            targets=["127.0.0.1"],
            status=AssessmentStatus.RUNNING.value,
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        repo = AuditRepo(session)

        # 1. next_hypothesis_id
        h_id = await repo.next_hypothesis_id(assessment.id)
        assert h_id == "H-1"

        # 2. record_hypothesis
        hid, payload = await repo.record_hypothesis(
            assessment_id=assessment.id,
            run_id="run-1",
            role="recon",
            statement="Target exposes Redis without auth",
            asset="127.0.0.1",
            endpoint="6379",
            falsifier="PING requires AUTH",
        )
        assert hid == "H-1"
        assert payload["statement"] == "Target exposes Redis without auth"

        h_id2 = await repo.next_hypothesis_id(assessment.id)
        assert h_id2 == "H-2"

        # 3. update_hypothesis
        up_payload = await repo.update_hypothesis(
            assessment_id=assessment.id,
            run_id="run-1",
            role="discovery",
            hypothesis_id="H-1",
            status="confirmed",
            confidence=0.99,
            note="INFO command succeeded without AUTH",
        )
        assert up_payload["status"] == "confirmed"
        assert up_payload["confidence"] == 0.99

        await session.commit()

        # 4. get_evidence_board
        board = await repo.get_evidence_board(assessment.id)
        assert len(board.hypotheses) == 1
        assert board.hypotheses[0].id == "H-1"
        assert board.hypotheses[0].status == "confirmed"
        assert board.hypotheses[0].confidence == 0.99


@pytest.mark.asyncio
async def test_reasoning_compatibility_wrapper(engine):
    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Reasoning Compatibility Test",
            request="Evaluate target security posture",
            targets=["127.0.0.1"],
            status=AssessmentStatus.RUNNING.value,
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        obs = await record_hypothesis(
            session=session,
            assessment_id=assessment.id,
            run_id="run-compat",
            role="recon",
            statement="Target exposes MySQL on 3306",
            asset="127.0.0.1",
        )
        assert obs.ok is True
        assert "Recorded H-1" in obs.summary

        obs_up = await update_hypothesis(
            session=session,
            assessment_id=assessment.id,
            run_id="run-compat",
            role="validation",
            hypothesis_id="H-1",
            status="refuted",
            confidence=0.1,
        )
        assert obs_up.ok is True
        assert "refuted" in obs_up.summary

        board = await build_evidence_board(session, assessment.id)
        assert len(board.hypotheses) == 1
        assert board.hypotheses[0].status == "refuted"
