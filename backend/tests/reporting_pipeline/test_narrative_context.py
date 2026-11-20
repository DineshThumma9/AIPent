"""Tests for narrative context compilation from evidence of record."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from app.core.db import get_async_session_ctx
from app.domain.models import Assessment, Evidence, Finding, FindingCve, Step, StepStatus
from app.persistence.step_repo import StepRepo
from app.reporting.narrative import build_narrative_context


@pytest.mark.asyncio
async def test_build_narrative_context_aggregation(engine, tmp_path):
    async with get_async_session_ctx() as session:
        # 1. Create assessment
        assessment = Assessment(
            title="Narrative Context Target",
            request="Evaluate web perimeter",
            targets=["127.0.0.1"],
            ports=[80],
            exclusions=["127.0.0.2"],
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        # 2. Create findings with CVEs
        f1 = Finding(
            assessment_id=assessment.id,
            canonical_key="web:127.0.0.1:80:sqli",
            asset="127.0.0.1",
            endpoint="/api/login",
            title="SQL Injection in Auth",
            severity="critical",
            cvss=9.8,
            cve=["CVE-2023-1234"],
            cwe=["CWE-89"],
            status="confirmed",
            confidence=0.9,
            description="Vulnerable parameter user in /api/login",
            impact="Full DB takeover",
            remediation="Use parameterized queries",
        )
        session.add(f1)
        await session.commit()
        await session.refresh(f1)

        fcve = FindingCve(
            finding_id=f1.id,
            cve_id="CVE-2023-1234",
            source="nvd",
            source_url="https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
        )
        session.add(fcve)

        # 3. Create steps and evidence
        step_repo = StepRepo(session)
        step, approval = await step_repo.create_planned_step(
            assessment_id=assessment.id,
            run_id="run-1",
            role="validation",
            action="curl_request",
            target="127.0.0.1",
        )
        await step_repo.complete_step(step.id, status=StepStatus.SUCCEEDED.value)
        await session.commit()

        ev = Evidence(
            finding_id=f1.id,
            step_id=step.id,
            locator={"tool": "curl_request", "http_status": 200},
            excerpt="A" * 1200,  # Longer than 800 chars to test excerpt capping
        )
        session.add(ev)
        await session.commit()

        # 4. Build narrative context
        ctx = await build_narrative_context(session, assessment.id)

        assert ctx["assessment"]["id"] == assessment.id
        assert ctx["assessment"]["title"] == "Narrative Context Target"
        assert len(ctx["findings"]) == 1
        finding_ctx = ctx["findings"][0]
        assert finding_ctx["id"] == f1.id
        assert finding_ctx["title"] == "SQL Injection in Auth"
        assert finding_ctx["cvss"] == 9.8
        assert finding_ctx["cve"] == ["CVE-2023-1234"]
        assert len(finding_ctx["evidence"]) == 1
        # Excerpt is capped at 800 chars
        assert len(finding_ctx["evidence"][0]["excerpt"]) <= 800
        assert len(finding_ctx["finding_cves"]) == 1
        assert finding_ctx["finding_cves"][0]["cve_id"] == "CVE-2023-1234"


@pytest.mark.asyncio
async def test_build_narrative_context_not_found(engine):
    async with get_async_session_ctx() as session:
        with pytest.raises(LookupError, match="assessment 999999 not found"):
            await build_narrative_context(session, 999999)
