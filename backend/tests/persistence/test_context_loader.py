"""Tests for mission context snapshot loading from database state."""

from __future__ import annotations

import pytest

from app.adapters.base import FindingDraft
from app.core.db import get_async_session_ctx
from app.domain.models import (
    Assessment,
    FindingStatus,
    Severity,
)
from app.persistence.audit_repo import AuditRepo
from app.persistence.context_loader import MissionContext, load_mission_context
from app.persistence.finding_repo import FindingRepo
from app.persistence.step_repo import StepRepo


@pytest.mark.asyncio
async def test_load_mission_context_complete_snapshot(engine):
    async with get_async_session_ctx() as session:
        # 1. Create assessment
        assessment = Assessment(
            title="Preloader Target Assessment",
            request="Evaluate target security posture",
            targets=["127.0.0.1"],
            ports=[80, 443],
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        # 2. Add steps
        step_repo = StepRepo(session)
        step, _ = await step_repo.create_planned_step(
            assessment_id=assessment.id,
            run_id="run-1",
            role="recon",
            action="nmap_scan",
            target="127.0.0.1",
        )
        await session.commit()

        # 3. Add service finding and candidate finding
        finding_repo = FindingRepo(session)
        draft_service = FindingDraft(
            canonical_key="nmap:127.0.0.1:80",
            asset="127.0.0.1",
            title="Open port 80/tcp (http)",
            severity=Severity.INFO,
            status=FindingStatus.CONFIRMED,
        )
        draft_vuln = FindingDraft(
            canonical_key="web:127.0.0.1:80:sqli",
            asset="127.0.0.1",
            title="SQL Injection Candidate",
            severity=Severity.HIGH,
            status=FindingStatus.SUSPECTED,
        )
        await finding_repo.save_drafts(assessment.id, step, [draft_service, draft_vuln])
        await session.commit()

        # 4. Add audit hypothesis
        audit_repo = AuditRepo(session)
        await audit_repo.record_event(
            assessment_id=assessment.id,
            event_type="hypothesis.created",
            payload={
                "id": "H-1",
                "statement": "Endpoint /login is vulnerable to SQL injection",
                "asset": "127.0.0.1",
                "status": "open",
                "confidence": 0.8,
            },
        )
        await session.commit()

        # 5. Load mission context
        ctx = await load_mission_context(session, assessment.id, run_id="run-1")

        assert isinstance(ctx, MissionContext)
        assert ctx.assessment.id == assessment.id
        assert len(ctx.services) == 1
        assert ctx.services[0].canonical_key == "nmap:127.0.0.1:80"
        assert len(ctx.candidates) == 1
        assert ctx.candidates[0].canonical_key == "web:127.0.0.1:80:sqli"
        assert ctx.evidence_board is not None
        assert len(ctx.evidence_board.hypotheses) == 1
        assert ctx.evidence_board.hypotheses[0].id == "H-1"
        assert len(ctx.recent_steps) == 1
        assert ctx.recent_steps[0].id == step.id


@pytest.mark.asyncio
async def test_load_mission_context_not_found(engine):
    async with get_async_session_ctx() as session:
        with pytest.raises(LookupError, match="assessment 999999 not found"):
            await load_mission_context(session, 999999)
