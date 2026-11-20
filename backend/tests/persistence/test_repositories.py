"""Tests for repository CRUD and lifecycle operations across domain repositories."""

from __future__ import annotations

import json
from pathlib import Path
import pytest
from sqlmodel import select

from app.adapters.base import FindingDraft
from app.core.db import get_async_session_ctx
from app.domain.models import (
    Assessment,
    AssessmentStatus,
    Audit,
    Decision,
    Evidence,
    Finding,
    FindingStatus,
    Message,
    Severity,
    Step,
    StepStatus,
)
from app.persistence.assessment_repo import AssessmentRepo
from app.persistence.audit_repo import AuditRepo
from app.persistence.finding_repo import FindingRepo
from app.persistence.step_repo import StepRepo


@pytest.mark.asyncio
async def test_step_repo_lifecycle_planned_resolve_and_complete(engine, tmp_path):
    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Step Lifecycle Target",
            request="Evaluate target security posture",
            targets=["127.0.0.1"],
            ports=[80],
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        repo = StepRepo(session)

        # 1. Create planned step with approval
        step, approval = await repo.create_planned_step(
            assessment_id=assessment.id,
            run_id="run-1",
            role="validation",
            action="sqlmap_scan",
            target="127.0.0.1",
            argv=["sqlmap", "-u", "http://127.0.0.1/"],
            risk="high",
            requires_approval=True,
            hypothesis_id="H-1",
        )
        await session.commit()

        assert step.status == StepStatus.PLANNED.value
        assert step.action == "sqlmap_scan"
        assert approval is not None
        assert approval.decision == Decision.PENDING.value
        assert approval.detail["hypothesis_id"] == "H-1"
        assert approval.step_id == step.id

        # 2. Resolve approval
        resolved = await repo.resolve_approval(
            approval_id=approval.id,
            decision=Decision.APPROVED.value,
            actor="analyst",
            reason="Confirmed in scope",
            outcome="proceed",
        )
        await session.commit()

        assert resolved is not None
        assert resolved.decision == Decision.APPROVED.value
        assert resolved.actor == "analyst"
        assert resolved.reason == "Confirmed in scope"
        assert resolved.outcome == "proceed"
        assert resolved.decided_at is not None

        # 3. Complete step
        out_file = tmp_path / "sqlmap.txt"
        out_file.write_text("injection confirmed", encoding="utf-8")

        completed = await repo.complete_step(
            step_id=step.id,
            status=StepStatus.SUCCEEDED.value,
            exit_code=0,
            output_path=str(out_file),
        )
        await session.commit()

        assert completed.status == StepStatus.SUCCEEDED.value
        assert completed.exit_code == 0
        assert completed.output_path == str(out_file)
        assert completed.ended_at is not None

        # 4. Check get_artifact_path & get_by_id
        path = await repo.get_artifact_path(step.id)
        assert path == str(out_file)

        step_by_id = await repo.get_by_id(step.id)
        assert step_by_id is not None
        assert step_by_id.id == step.id


@pytest.mark.asyncio
async def test_step_repo_reject_step(engine):
    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Step Rejection Target",
            request="Evaluate target security posture",
            targets=["127.0.0.1"],
            ports=[80],
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        repo = StepRepo(session)
        step, approval = await repo.create_planned_step(
            assessment_id=assessment.id,
            run_id="run-1",
            role="validation",
            action="sqlmap_scan",
            target="127.0.0.1",
            argv=["sqlmap", "-u", "http://127.0.0.1/"],
            risk="high",
            requires_approval=True,
        )
        await session.commit()

        rejected_step = await repo.reject_step(step.id, reason="Dangerous payload", actor="supervisor")
        await session.commit()

        assert rejected_step.status == StepStatus.REJECTED.value
        assert "Dangerous payload" in (rejected_step.error or "")

        refreshed_approval = await session.get(type(approval), approval.id)
        assert refreshed_approval.decision == Decision.REJECTED.value
        assert refreshed_approval.actor == "supervisor"
        assert refreshed_approval.reason == "Dangerous payload"


@pytest.mark.asyncio
async def test_finding_repo_record_agent_finding_and_extend(engine, tmp_path):
    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Agent Finding Assessment",
            request="Evaluate target security posture",
            targets=["127.0.0.1"],
            ports=[80],
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        # Artifact step for evidence
        art_file = tmp_path / "probe.json"
        art_file.write_text(json.dumps({"curl_result": {"status_code": 200, "url": "http://127.0.0.1/api"}}))

        step_repo = StepRepo(session)
        step, _ = await step_repo.create_planned_step(
            assessment_id=assessment.id,
            run_id="run-1",
            role="discovery",
            action="curl_request",
            target="127.0.0.1",
            argv=["curl", "http://127.0.0.1/api"],
        )
        await step_repo.complete_step(step.id, status=StepStatus.SUCCEEDED.value, output_path=str(art_file))
        await session.commit()

        finding_repo = FindingRepo(session)

        # Record new agent finding
        res1 = await finding_repo.record_agent_finding(
            assessment_id=assessment.id,
            run_id="run-1",
            role="discovery",
            title="Unauthenticated API",
            asset="127.0.0.1",
            endpoint="/api",
            severity="medium",
            description="API returns confidential information without token",
            evidence_step_ids=[step.id],
            cwe=["CWE-200"],
        )
        await session.commit()

        assert res1["ok"] is True
        assert res1["created"] is True
        f_id = res1["finding"].id
        assert res1["finding"].status == FindingStatus.SUSPECTED.value

        # Extend finding with higher severity
        res2 = await finding_repo.record_agent_finding(
            assessment_id=assessment.id,
            run_id="run-1",
            role="validation",
            finding_id=f_id,
            severity="critical",
            evidence_step_ids=[step.id],
        )
        await session.commit()

        assert res2["ok"] is True
        assert res2["created"] is False
        assert res2["finding"].id == f_id
        assert res2["finding"].severity == "critical"

        # Verify candidate queries
        candidates = await finding_repo.get_candidates(assessment_id=assessment.id)
        assert any(c.id == f_id for c in candidates)


@pytest.mark.asyncio
async def test_finding_repo_save_drafts_and_get_services(engine):
    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Drafts Target",
            request="Evaluate target security posture",
            targets=["127.0.0.1"],
            ports=[80, 443],
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        step_repo = StepRepo(session)
        step, _ = await step_repo.create_planned_step(
            assessment_id=assessment.id,
            run_id="run-1",
            role="recon",
            action="nmap_scan",
            target="127.0.0.1",
        )
        await session.commit()

        draft1 = FindingDraft(
            canonical_key="nmap:127.0.0.1:80",
            asset="127.0.0.1",
            title="Open port 80/tcp (http)",
            severity=Severity.INFO,
            status=FindingStatus.CONFIRMED,
        )
        draft2 = FindingDraft(
            canonical_key="web:127.0.0.1:80:missing-header",
            asset="127.0.0.1",
            title="Missing Security Header",
            severity=Severity.LOW,
            status=FindingStatus.SUSPECTED,
        )

        finding_repo = FindingRepo(session)
        added, merged = await finding_repo.save_drafts(assessment.id, step, [draft1, draft2])
        await session.commit()

        assert added == 2
        assert merged == 0

        # Test deduplication on re-save
        added2, merged2 = await finding_repo.save_drafts(assessment.id, step, [draft1])
        await session.commit()
        assert added2 == 0
        assert merged2 == 1

        # Check get_services returns only port/service findings
        services = await finding_repo.get_services(assessment.id)
        assert len(services) == 1
        assert services[0].canonical_key == "nmap:127.0.0.1:80"


@pytest.mark.asyncio
async def test_audit_repo_events_decisions_and_evidence_board(engine):
    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Audit Test Target",
            request="Evaluate target security posture",
            targets=["127.0.0.1"],
            ports=[80],
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        repo = AuditRepo(session)

        # 1. Record generic event
        ev = await repo.record_event(
            assessment_id=assessment.id,
            event_type="custom.event",
            payload={"key": "value"},
            actor="test",
        )
        await session.commit()
        assert ev.event_type == "custom.event"

        # 2. Record decision
        await repo.record_decision(
            assessment_id=assessment.id,
            run_id="run-1",
            role="discovery",
            step_id=10,
            action="dirb_scan",
            target="127.0.0.1",
            observation="Discovered /admin",
            outcome="succeeded",
            confidence=0.9,
            hypothesis_id="H-1",
        )
        await session.commit()

        # 3. Record hypothesis
        await repo.record_event(
            assessment_id=assessment.id,
            event_type="hypothesis.created",
            payload={
                "id": "H-1",
                "statement": "Admin panel is exposed",
                "asset": "127.0.0.1",
                "endpoint": "http://127.0.0.1/admin",
                "status": "open",
                "confidence": 0.8,
                "falsifier": "Returns 404 or requires VPN",
                "created_by": "discovery",
            },
        )
        await session.commit()

        # 4. Check get_evidence_board folds hypotheses and decisions
        board = await repo.get_evidence_board(assessment.id)
        assert len(board.hypotheses) == 1
        assert board.hypotheses[0].id == "H-1"
        assert board.hypotheses[0].statement == "Admin panel is exposed"
        assert len(board.decisions) == 1
        assert board.decisions[0].id == "D-10"
        assert board.decisions[0].action == "dirb_scan"


@pytest.mark.asyncio
async def test_assessment_repo_crud_and_messages(engine):
    async with get_async_session_ctx() as session:
        repo = AssessmentRepo(session)

        created = await repo.create(
            title="Assessment CRUD Test",
            request="Scan network perimeter",
            targets=["192.168.1.1"],
            ports=[80, 443],
            exclusions=["192.168.1.254"],
        )

        assert created.id is not None
        assert created.status == AssessmentStatus.DRAFT.value
        assert created.exclusions == ["192.168.1.254"]

        fetched = await repo.get(created.id)
        assert fetched is not None
        assert fetched.title == "Assessment CRUD Test"

        all_assessments = await repo.get_all()
        assert any(a.id == created.id for a in all_assessments)

        # Add message and verify get_messages
        msg = Message(
            assessment_id=created.id,
            role="user",
            text="Please start scanning",
            client_message_id="client-msg-1",
        )
        session.add(msg)
        await session.commit()

        messages = await repo.get_messages(created.id)
        assert len(messages) == 1
        assert messages[0].text == "Please start scanning"

        by_client_id = await repo.get_message_by_client_id(created.id, "client-msg-1")
        assert by_client_id is not None
        assert by_client_id.id == msg.id
