import pytest
from sqlmodel import select
from app.core.db import get_async_session_ctx
from app.persistence.audit_repo import AuditRepo
from app.persistence.finding_repo import FindingRepo
from app.persistence.step_repo import StepRepo
from app.persistence.assessment_repo import AssessmentRepo
from app.domain.models import Assessment, Audit, Finding, Evidence, Step, Approval, Message

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


@pytest.mark.asyncio
async def test_repository_read_methods(engine):
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

        # Finding & Evidence
        finding = Finding(
            assessment_id=assessment.id,
            canonical_key="test-sqli-key",
            asset="127.0.0.1",
            title="SQL Injection",
            severity="high",
        )
        session.add(finding)
        await session.commit()
        await session.refresh(finding)

        evidence = Evidence(
            finding_id=finding.id,
            type="http_traffic",
            path="/api/users?id=1'",
        )
        session.add(evidence)

        # Step & Approval
        step = Step(
            assessment_id=assessment.id,
            seq=1,
            target="127.0.0.1",
            action="sqlmap",
            status="pending_approval",
        )
        session.add(step)
        await session.commit()
        await session.refresh(step)

        approval = Approval(
            assessment_id=assessment.id,
            step_id=step.id,
            action="sqlmap",
            target="127.0.0.1",
            status="pending",
        )
        session.add(approval)

        # Message
        message = Message(
            assessment_id=assessment.id,
            role="user",
            text="Start test",
        )
        session.add(message)
        await session.commit()

        # Test FindingRepo.get_all_evidence
        finding_repo = FindingRepo(session)
        evidence_list = await finding_repo.get_all_evidence(assessment.id)
        assert len(evidence_list) == 1
        assert evidence_list[0].finding_id == finding.id

        # Test StepRepo.get_all_approvals
        step_repo = StepRepo(session)
        approvals_list = await step_repo.get_all_approvals(assessment.id)
        assert len(approvals_list) == 1
        assert approvals_list[0].id == approval.id

        # Test AssessmentRepo.get_messages
        assessment_repo = AssessmentRepo(session)
        messages_list = await assessment_repo.get_messages(assessment.id)
        assert len(messages_list) == 1
        assert messages_list[0].text == "Start test"

