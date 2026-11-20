import pytest
from sqlmodel import select
from app.core.db import get_async_session_ctx
from app.persistence.audit_repo import AuditRepo
from app.domain.models import Assessment, Audit

@pytest.mark.asyncio
async def test_audit_repo_records_decision_event(engine):
    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Test Assessment",
            request="Security assessment of 127.0.0.1",
            targets=["127.0.0.1"],
            ports=[80, 443],
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        repo = AuditRepo(session)
        await repo.record_decision(
            assessment_id=assessment.id,
            run_id="run-123",
            role="discovery",
            step_id=42,
            action="dirb_scan",
            target="127.0.0.1",
            observation="Found /api/v1",
            outcome="succeeded",
            confidence=0.8,
        )
        await session.commit()

        res = await session.execute(select(Audit).where(Audit.assessment_id == assessment.id))
        events = res.scalars().all()
        assert len(events) == 1
        assert events[0].event_type == "decision.recorded"
        assert events[0].payload["id"] == "D-42"
        assert events[0].payload["outcome"] == "succeeded"


@pytest.mark.asyncio
async def test_audit_repo_records_generic_event(engine):
    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Test Assessment",
            request="Security assessment of 127.0.0.1",
            targets=["127.0.0.1"],
            ports=[80, 443],
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        repo = AuditRepo(session)
        audit_record = await repo.record_event(
            assessment_id=assessment.id,
            event_type="agent.started",
            payload={"run_id": "run-456", "loop": "v2"},
            actor="system",
        )
        await session.commit()

        assert audit_record.event_type == "agent.started"
        assert audit_record.payload["run_id"] == "run-456"
