"""Tests for Typst report generation, data compilation, and PDF rendering."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from app.agents.contracts import FindingNarrative, ReportNarrative
from app.core.db import get_async_session_ctx
from app.domain.models import (
    Approval,
    Assessment,
    AssessmentStatus,
    Finding,
    FindingStatus,
    Severity,
    Step,
    utcnow,
)
from app.reporting.report import build_report_data, generate_report


@pytest.fixture
def sample_narrative():
    return ReportNarrative(
        executive_summary="Executive summary: security assessment identified high-risk findings.",
        methodology="Automated and manual penetration testing.",
        risk_overview="Overall risk is High.",
        findings=[
            FindingNarrative(
                finding_id=1,
                technical_analysis="SQL injection detected in product search.",
                impact="Data leakage.",
                remediation="Use prepared statements.",
                confidence_statement="High confidence.",
                observed_vs_inferred="Observed 500 error; inferred injection.",
            )
        ],
        limitations="Scope limited to local test environment.",
        recommendations=["Patch SQL injection."],
        conclusion="Remediate all high severity findings.",
    )


@pytest.mark.asyncio
async def test_build_report_data_structure(engine):
    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Report Data Test",
            request="Evaluate target security posture",
            targets=["127.0.0.1"],
            ports=[80],
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        finding = Finding(
            assessment_id=assessment.id,
            canonical_key="web:test:sqli",
            asset="127.0.0.1",
            title="SQL Injection",
            severity=Severity.HIGH.value,
            status=FindingStatus.CONFIRMED.value,
        )
        session.add(finding)
        await session.commit()

        data = await build_report_data(session, assessment)

        assert "assessment" in data
        assert data["assessment"]["id"] == assessment.id
        assert "risk" in data
        assert "findings" in data
        assert len(data["findings"]) == 1
        assert "steps" in data
        assert "cve_snapshot" in data


@pytest.mark.asyncio
async def test_generate_report_pdf_and_fallback(engine, sample_narrative, tmp_path, monkeypatch):
    monkeypatch.setattr("app.reporting.report.ARTIFACT_DIR", tmp_path)

    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Typst PDF Generation Test",
            request="Evaluate target security posture",
            targets=["127.0.0.1"],
            ports=[80],
            status=AssessmentStatus.RUNNING.value,
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        finding = Finding(
            assessment_id=assessment.id,
            canonical_key="web:test:sqli",
            asset="127.0.0.1",
            endpoint="/search",
            title="SQL Injection",
            severity=Severity.HIGH.value,
            status=FindingStatus.CONFIRMED.value,
            confidence=0.9,
        )
        session.add(finding)

        step = Step(
            assessment_id=assessment.id,
            seq=1,
            action="nmap_scan",
            target="127.0.0.1",
            status="succeeded",
            output_path="/tmp/nmap.xml",
            output_sha256="abc123hash",
        )
        session.add(step)

        approval = Approval(
            assessment_id=assessment.id,
            action="nmap_scan",
            decision="approved",
            actor="analyst",
        )
        session.add(approval)
        await session.commit()
        await session.refresh(finding)

        # 1. Compile with full LLM narrative (update finding_id to match actual ID)
        sample_narrative.findings[0].finding_id = finding.id
        pdf_path = await generate_report(session, assessment.id, narrative=sample_narrative)

        assert pdf_path.exists()
        assert pdf_path.stat().st_size > 0
        assert pdf_path.suffix == ".pdf"
        assert pdf_path.read_bytes()[:5] == b"%PDF-"

        # Check report data and narrative JSON artifacts
        report_data = json.loads((tmp_path / str(assessment.id) / "report-data.json").read_text())
        assert report_data["narrative_source"] == "llm"

        # Assessment finalized
        refreshed_assessment = await session.get(Assessment, assessment.id)
        assert refreshed_assessment.status == AssessmentStatus.COMPLETED.value
        assert refreshed_assessment.report_path == str(pdf_path)

        # 2. Compile with narrative=None (evidence-only fallback)
        pdf_fallback = await generate_report(session, assessment.id, narrative=None)
        assert pdf_fallback.exists()
        assert pdf_fallback.stat().st_size > 0
        report_data_fallback = json.loads((tmp_path / str(assessment.id) / "report-data.json").read_text())
        assert report_data_fallback["narrative_source"] == "evidence-only"
