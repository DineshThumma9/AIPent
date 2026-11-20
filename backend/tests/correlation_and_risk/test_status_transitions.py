"""Tests for finding status transitions: multi-tool confirmation and evidence guards."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from app.adapters.base import EvidenceDraft, FindingDraft
from app.core.db import get_async_session_ctx
from app.domain.models import Assessment, Evidence, Finding, FindingStatus, Severity, Step, StepStatus
from app.persistence.finding_repo import FindingRepo
from app.persistence.step_repo import StepRepo


@pytest.mark.asyncio
async def test_multi_tool_independent_confirmation(engine):
    """1 tool observation = suspected; 2 independent tools observing same key = confirmed."""
    async with get_async_session_ctx() as session:
        assessment = Assessment(title="Multi-Tool Confirmation", targets=["127.0.0.1"], ports=[80])
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        step_repo = StepRepo(session)
        finding_repo = FindingRepo(session)

        # Step 1: Nikto scan observes missing header
        step_nikto, _ = await step_repo.create_planned_step(
            assessment_id=assessment.id,
            run_id="run-1",
            role="discovery",
            action="nikto_scan",
            target="127.0.0.1",
        )
        draft_nikto = FindingDraft(
            canonical_key="web:csp:127.0.0.1:80",
            asset="127.0.0.1",
            title="Missing CSP Header",
            severity=Severity.LOW,
            status=FindingStatus.SUSPECTED,
            evidence=[EvidenceDraft(locator={"tool": "nikto_scan"}, excerpt="missing header")],
        )
        await finding_repo.save_drafts(assessment.id, step_nikto, [draft_nikto])
        await session.commit()

        # Verify initial status is suspected
        findings = await finding_repo.get_all(assessment.id)
        assert len(findings) == 1
        assert findings[0].status == FindingStatus.SUSPECTED.value

        # Step 2: ZAP baseline observes the EXACT same canonical key
        step_zap, _ = await step_repo.create_planned_step(
            assessment_id=assessment.id,
            run_id="run-1",
            role="discovery",
            action="zap_baseline",
            target="127.0.0.1",
        )
        draft_zap = FindingDraft(
            canonical_key="web:csp:127.0.0.1:80",
            asset="127.0.0.1",
            title="CSP Header Not Set",
            severity=Severity.MEDIUM,
            status=FindingStatus.SUSPECTED,
            evidence=[EvidenceDraft(locator={"tool": "zap_baseline"}, excerpt="no csp")],
        )
        await finding_repo.save_drafts(assessment.id, step_zap, [draft_zap])
        await session.commit()

        # Two independent tools (nikto_scan & zap_baseline) confirm the finding
        refreshed = await session.get(Finding, findings[0].id)
        assert refreshed.status == FindingStatus.CONFIRMED.value


@pytest.mark.asyncio
async def test_update_status_evidence_guard_blocks_unproven_confirmation(engine, tmp_path):
    async with get_async_session_ctx() as session:
        assessment = Assessment(title="Status Guard Target", targets=["127.0.0.1"], ports=[80])
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        finding_repo = FindingRepo(session)

        # Finding with no proving evidence
        finding = Finding(
            assessment_id=assessment.id,
            canonical_key="web:unproven:sqli",
            asset="127.0.0.1",
            title="Suspected SQLi",
            status=FindingStatus.SUSPECTED.value,
        )
        session.add(finding)
        await session.commit()
        await session.refresh(finding)

        # Attempt to confirm without proving evidence -> blocked by guard
        res_blocked = await finding_repo.update_status(
            finding_id=finding.id,
            assessment_id=assessment.id,
            status="confirmed",
            reasoning="I believe it is vulnerable",
        )
        assert "error" in res_blocked
        assert "verdict blocked" in res_blocked["error"]

        # Now attach proving evidence (curl_request with http_status)
        step = Step(
            assessment_id=assessment.id,
            seq=1,
            action="curl_request",
            target="127.0.0.1",
            status=StepStatus.SUCCEEDED.value,
        )
        session.add(step)
        await session.commit()
        await session.refresh(step)

        evidence = Evidence(
            finding_id=finding.id,
            step_id=step.id,
            locator={"tool": "curl_request", "http_status": 200},
            excerpt="HTTP/1.1 200 OK with injection proof",
        )
        session.add(evidence)
        await session.commit()

        # Now confirmation succeeds
        res_ok = await finding_repo.update_status(
            finding_id=finding.id,
            assessment_id=assessment.id,
            status="confirmed",
            reasoning="Confirmed with HTTP status and proof string",
        )
        assert res_ok.get("updated") is True
        assert res_ok.get("status") == "confirmed"
