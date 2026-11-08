"""Tests for Phase 5: report narrative generation, validation, fallback, and Typst compilation."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

from app.agents.graph.state import initial_state
from app.agents.loop.nodes import report_node, report_writer_node
from app.core.config import settings
from app.core.db import get_async_session_ctx, init_db, make_engine, set_engine
from sqlmodel import select
from app.domain.models import (
    Approval,
    Assessment,
    AssessmentStatus,
    Audit,
    Evidence,
    Finding,
    FindingStatus,
    Severity,
    Step,
    utcnow,
)
from app.reporting.narrative import (
    FindingNarrative,
    ReportNarrative,
    build_narrative_context,
    claims_confirmed,
    redact_credentials,
    validate_narrative,
    write_narrative,
    write_narrative_result,
)
from app.reporting.report import build_report_data, generate_report


@pytest.fixture
def sample_context() -> dict:
    return {
        "assessment": {
            "id": 42,
            "title": "Lab Security Assessment",
            "request": "Test lab environment",
            "targets": ["127.0.0.1"],
            "ports": [80, 443],
            "exclusions": [],
            "started_at": "2026-11-08T10:00:00",
            "finished_at": "2026-11-08T11:00:00",
        },
        "risk": {
            "score": 7.5,
            "counts": {"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0},
            "confirmed": 1,
            "suspected": 1,
        },
        "findings": [
            {
                "id": 101,
                "title": "SQL Injection in /api/login",
                "severity": "high",
                "cvss": 7.5,
                "cve": ["CVE-2023-1234"],
                "cwe": ["CWE-89"],
                "status": "confirmed",
                "confidence": 0.9,
                "asset": "127.0.0.1:80",
                "endpoint": "/api/login",
                "description": "SQL injection detected in login query.",
                "impact": "Database extraction.",
                "remediation": "Use parameterized queries.",
                "evidence": [
                    {
                        "id": 1,
                        "tool": "curl_tool",
                        "excerpt": "HTTP 500 syntax error in SQL statement",
                        "locator": {"url": "http://127.0.0.1/api/login"},
                    }
                ],
                "corroborating_tools": ["curl_tool"],
                "narrative": None,
            },
            {
                "id": 102,
                "title": "Possible Information Disclosure",
                "severity": "medium",
                "cvss": None,
                "cve": [],
                "cwe": ["CWE-200"],
                "status": "suspected",
                "confidence": 0.5,
                "asset": "127.0.0.1:80",
                "endpoint": "/debug",
                "description": "Debug endpoint exposed.",
                "impact": "Info leak.",
                "remediation": "Disable debug in production.",
                "evidence": [],
                "corroborating_tools": [],
                "narrative": None,
            },
        ],
        "steps": [
            {
                "seq": 1,
                "action": "recon_services",
                "target": "127.0.0.1",
                "status": "succeeded",
                "error": "",
            },
            {
                "seq": 2,
                "action": "sqlmap_scan",
                "target": "http://127.0.0.1/api/login",
                "status": "rejected",
                "error": "Human rejected action",
            },
        ],
        "approvals": [
            {
                "action": "sqlmap scan",
                "decision": "rejected",
                "actor": "analyst",
                "reason": "Out of test boundary",
            }
        ],
        "reasoning": {
            "open_questions": ["Is authentication bypass possible?"],
            "hypotheses": [
                {
                    "id": "H-1",
                    "statement": "Login endpoint is vulnerable to SQL injection",
                    "status": "supported",
                }
            ],
        },
    }


@pytest.fixture
def valid_narrative() -> ReportNarrative:
    return ReportNarrative(
        executive_summary="The assessment identified 1 confirmed high-severity SQL injection vulnerability.",
        methodology="Conducted automated reconnaissance followed by targeted web vulnerability assessment.",
        risk_overview="Overall risk is High due to vulnerable authentication endpoint.",
        findings=[
            FindingNarrative(
                finding_id=101,
                technical_analysis="The login endpoint is vulnerable to SQL injection as observed with CVE-2023-1234. CVSS 7.5 reflects authentication impact.",
                impact="An unauthorized user can extract confidential database records.",
                remediation="Migrate to parameterized prepared statements.",
                confidence_statement="High confidence based on reproducible SQL error responses.",
                observed_vs_inferred="Observed HTTP 500 SQL syntax error; inferred exploitable injection.",
            ),
            FindingNarrative(
                finding_id=102,
                technical_analysis="The debug endpoint exposes internal application environment details.",
                impact="Minor leakage of configuration parameters.",
                remediation="Ensure debug flags are disabled in production.",
                confidence_statement="Moderate confidence based on response headers.",
                observed_vs_inferred="Observed stack trace; inferred potential leak.",
            ),
        ],
        limitations="sqlmap scan was rejected due to boundary constraints; manual exploitation was not performed.",
        recommendations=[
            "Sanitize all inputs on /api/login",
            "Disable /debug endpoint in production",
        ],
        conclusion="Remediation of the SQL injection should be prioritized immediately.",
    )


# =========================================================================
# Unit Tests: Validation Boundary & Anti-Hallucination
# =========================================================================

def test_validate_narrative_valid(sample_context, valid_narrative):
    """A narrative conforming strictly to context passes validation."""
    validate_narrative(valid_narrative, sample_context)


def test_validate_narrative_unknown_finding_id(sample_context, valid_narrative):
    """Validation fails if narrative contains finding_id not in context."""
    valid_narrative.findings.append(
        FindingNarrative(
            finding_id=999,
            technical_analysis="Fabricated finding analysis.",
            impact="None",
            remediation="None",
            confidence_statement="Low",
            observed_vs_inferred="Fabricated",
        )
    )
    with pytest.raises(ValueError, match="finding_id 999 does not exist"):
        validate_narrative(valid_narrative, sample_context)


def test_validate_narrative_duplicate_finding_id(sample_context, valid_narrative):
    """Validation fails if finding_id appears more than once."""
    valid_narrative.findings.append(valid_narrative.findings[0])
    with pytest.raises(ValueError, match="duplicate finding_id 101"):
        validate_narrative(valid_narrative, sample_context)


def test_validate_narrative_hallucinated_cve_in_finding(sample_context, valid_narrative):
    """Validation fails if a finding narrative mentions an unverified CVE."""
    valid_narrative.findings[0].technical_analysis = (
        "This vulnerability is also related to CVE-2024-99999 remote code execution."
    )
    with pytest.raises(ValueError, match="unauthorized/unverified CVE"):
        validate_narrative(valid_narrative, sample_context)


def test_validate_narrative_hallucinated_cve_in_top_level(sample_context, valid_narrative):
    """Validation fails if top-level executive summary mentions an unverified CVE."""
    valid_narrative.executive_summary = (
        "We discovered a critical issue matching CVE-2024-11111."
    )
    with pytest.raises(ValueError, match="unauthorized/unverified CVE"):
        validate_narrative(valid_narrative, sample_context)


def test_validate_narrative_cvss_fabrication_when_null(sample_context, valid_narrative):
    """Validation fails if narrative invents a CVSS score for a finding where cvss is null."""
    valid_narrative.findings[1].technical_analysis = (
        "The debug endpoint has an estimated CVSS 8.5 score."
    )
    with pytest.raises(ValueError, match="has no CVSS score .* claims CVSS score 8.5"):
        validate_narrative(valid_narrative, sample_context)


def test_validate_narrative_cvss_fabrication_mismatch(sample_context, valid_narrative):
    """Validation fails if narrative claims a CVSS score differing from finding's cvss."""
    valid_narrative.findings[0].technical_analysis = (
        "The login SQL injection is critical with CVSS 9.8."
    )
    with pytest.raises(ValueError, match="has CVSS 7.5, but narrative claims fabricated CVSS score 9.8"):
        validate_narrative(valid_narrative, sample_context)


def test_validate_narrative_suspected_claiming_confirmed(sample_context, valid_narrative):
    """Validation fails if a suspected finding narrative claims it is confirmed."""
    valid_narrative.findings[1].technical_analysis = (
        "We have confirmed this vulnerability by manual inspection."
    )
    with pytest.raises(ValueError, match="has status 'suspected' but narrative claims 'confirmed'"):
        validate_narrative(valid_narrative, sample_context)


def test_claims_confirmed_negation_allowed():
    """Statements explicitly negating confirmation do not trigger the confirmed guard."""
    assert not claims_confirmed("This issue was not confirmed during active testing.")
    assert not claims_confirmed("Vulnerability remains unconfirmed.")
    assert claims_confirmed("We confirmed the presence of the vulnerability.")


def test_redact_credentials():
    """Known lab passwords in credential contexts are safely redacted."""
    raw = 'Found credentials password: admin and secret was "123456" on database.'
    cleaned = redact_credentials(raw)
    assert "admin" not in cleaned
    assert "123456" not in cleaned
    assert "[REDACTED]" in cleaned


# =========================================================================
# Unit Tests: write_narrative and Fallback
# =========================================================================

@pytest.mark.asyncio
async def test_write_narrative_success(sample_context, valid_narrative):
    """write_narrative returns validated narrative when LLM structured output succeeds."""
    mock_model = MagicMock()
    mock_structured = AsyncMock()
    mock_structured.ainvoke.return_value = valid_narrative
    mock_model.with_structured_output.return_value = mock_structured

    narrative, err = await write_narrative_result(sample_context, model=mock_model)
    assert narrative is not None
    assert err is None
    assert narrative.executive_summary == valid_narrative.executive_summary


@pytest.mark.asyncio
async def test_write_narrative_validation_failure_fallback(sample_context, valid_narrative):
    """write_narrative falls back to None on validation failure without crashing."""
    valid_narrative.findings[0].technical_analysis = "Fabricated CVE-2025-0001."
    mock_model = MagicMock()
    mock_structured = AsyncMock()
    mock_structured.ainvoke.return_value = valid_narrative
    mock_model.with_structured_output.return_value = mock_structured

    narrative = await write_narrative(sample_context, model=mock_model)
    assert narrative is None


@pytest.mark.asyncio
async def test_write_narrative_model_exception_fallback(sample_context):
    """write_narrative falls back to None when model raises an exception."""
    mock_model = MagicMock()
    mock_structured = AsyncMock()
    mock_structured.ainvoke.side_effect = RuntimeError("LLM rate limit or timeout")
    mock_model.with_structured_output.return_value = mock_structured

    narrative, err = await write_narrative_result(sample_context, model=mock_model)
    assert narrative is None
    assert "rate limit" in err


# =========================================================================
# Integration Tests: DB Context & Typst Report Compilation
# =========================================================================

@pytest.fixture
def test_db(tmp_path, monkeypatch):
    db_file = tmp_path / "report_test.db"
    engine = make_engine(f"sqlite:///{db_file}")
    import asyncio
    asyncio.run(init_db(engine))
    set_engine(engine)
    monkeypatch.setattr(settings, "agent_loop", "v2")
    return engine


@pytest.mark.asyncio
async def test_build_narrative_context(test_db):
    """build_narrative_context queries DB and creates the compact JSON evidence pack."""
    async with get_async_session_ctx() as test_session:
        assessment = Assessment(
            title="Web Assessment",
            request="Scan targets",
            targets=["127.0.0.1"],
            ports=[80],
            exclusions=[],
            status=AssessmentStatus.RUNNING.value,
        )
        test_session.add(assessment)
        await test_session.commit()
        await test_session.refresh(assessment)

        finding = Finding(
            assessment_id=assessment.id,
            canonical_key="127.0.0.1:80:sqli",
            asset="127.0.0.1:80",
            endpoint="/login",
            title="SQL Injection",
            severity=Severity.HIGH.value,
            cvss=8.0,
            cve=["CVE-2022-0001"],
            cwe=["CWE-89"],
            status=FindingStatus.CONFIRMED.value,
            confidence=0.9,
        )
        test_session.add(finding)
        await test_session.commit()
        await test_session.refresh(finding)

        evidence = Evidence(
            finding_id=finding.id,
            excerpt="Syntax error in query",
            locator={"tool": "curl_tool", "url": "http://127.0.0.1/login"},
        )
        test_session.add(evidence)

        step = Step(
            assessment_id=assessment.id,
            seq=1,
            action="sqlmap_scan",
            target="http://127.0.0.1/login",
            status="rejected",
            error="Manual gate denied",
        )
        test_session.add(step)

        approval = Approval(
            assessment_id=assessment.id,
            action="sqlmap_scan",
            decision="rejected",
            actor="analyst",
            reason="Aggressive tool rejected",
        )
        test_session.add(approval)
        await test_session.commit()

        context = await build_narrative_context(test_session, assessment.id)
        assert context["assessment"]["id"] == assessment.id
        assert len(context["findings"]) == 1
        assert context["findings"][0]["cve"] == ["CVE-2022-0001"]
        assert context["findings"][0]["corroborating_tools"] == ["curl_tool"]
        assert len(context["steps"]) == 1
        assert len(context["approvals"]) == 1
        assert context["approvals"][0]["decision"] == "rejected"


@pytest.mark.asyncio
async def test_generate_report_typst_compile_full_and_fallback(test_db, valid_narrative: ReportNarrative, tmp_path: Path, monkeypatch):
    """Typst compile succeeds with full narrative and with narrative=None (evidence-only)."""
    monkeypatch.setattr("app.reporting.report.ARTIFACT_DIR", tmp_path)

    async with get_async_session_ctx() as test_session:
        assessment = Assessment(
            title="Integration Report Test",
            request="Client compliance audit",
            targets=["127.0.0.1"],
            ports=[80],
            exclusions=[],
            status=AssessmentStatus.RUNNING.value,
            created_at=utcnow(),
            finished_at=utcnow(),
        )
        test_session.add(assessment)
        await test_session.commit()
        await test_session.refresh(assessment)

        finding = Finding(
            id=101,
            assessment_id=assessment.id,
            canonical_key="127.0.0.1:80:sqli",
            asset="127.0.0.1:80",
            endpoint="/api/login",
            title="SQL Injection in /api/login",
            severity=Severity.HIGH.value,
            cvss=7.5,
            cve=["CVE-2023-1234"],
            cwe=["CWE-89"],
            status=FindingStatus.CONFIRMED.value,
            confidence=0.9,
        )
        test_session.add(finding)

        finding2 = Finding(
            id=102,
            assessment_id=assessment.id,
            canonical_key="127.0.0.1:80:debug",
            asset="127.0.0.1:80",
            endpoint="/debug",
            title="Possible Information Disclosure",
            severity=Severity.MEDIUM.value,
            cvss=None,
            cve=[],
            cwe=["CWE-200"],
            status=FindingStatus.SUSPECTED.value,
            confidence=0.5,
        )
        test_session.add(finding2)

        step = Step(
            assessment_id=assessment.id,
            seq=1,
            action="sqlmap_scan",
            target="http://127.0.0.1/api/login",
            status="rejected",
            output_path="/tmp/sqlmap.log",
            output_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        test_session.add(step)

        approval = Approval(
            assessment_id=assessment.id,
            action="sqlmap_scan",
            decision="rejected",
            actor="analyst",
            reason="Out of test boundary",
        )
        test_session.add(approval)
        await test_session.commit()

        # 1. Compile with full LLM narrative
        pdf_full = await generate_report(test_session, assessment.id, narrative=valid_narrative)
        assert pdf_full.exists()
        assert pdf_full.stat().st_size > 0
        assert pdf_full.suffix == ".pdf"

        # Verify report-narrative.json was written
        narrative_json_path = tmp_path / str(assessment.id) / "report-narrative.json"
        assert narrative_json_path.exists()
        saved_narrative = json.loads(narrative_json_path.read_text())
        assert saved_narrative["executive_summary"] == valid_narrative.executive_summary

        # Verify report-data.json content
        report_data = json.loads((tmp_path / str(assessment.id) / "report-data.json").read_text())
        assert report_data["narrative_source"] == "llm"
        assert report_data["findings"][0]["narrative"] is not None

        # 2. Compile with narrative=None (evidence-only fallback)
        pdf_evidence_only = await generate_report(test_session, assessment.id, narrative=None)
        assert pdf_evidence_only.exists()
        assert pdf_evidence_only.stat().st_size > 0
        assert pdf_evidence_only.suffix == ".pdf"

        report_data_fallback = json.loads((tmp_path / str(assessment.id) / "report-data.json").read_text())
        assert report_data_fallback["narrative_source"] == "evidence-only"


@pytest.mark.asyncio
async def test_report_writer_node_audit_events(test_db, valid_narrative: ReportNarrative, monkeypatch):
    """report_writer_node audits report.narrative_generated on success and routes to report."""
    async with get_async_session_ctx() as test_session:
        assessment = Assessment(
            title="Node Audit Test",
            request="Verify node audits",
            targets=["127.0.0.1"],
            ports=[80],
            exclusions=[],
            status=AssessmentStatus.RUNNING.value,
        )
        test_session.add(assessment)
        await test_session.commit()
        await test_session.refresh(assessment)
        assessment_id = assessment.id

    state = initial_state(assessment_id=assessment_id)

    # Patch write_narrative_result to return valid narrative
    async def mock_write_success(ctx, model=None):
        return valid_narrative, None

    monkeypatch.setattr("app.agents.loop.nodes.write_narrative_result", mock_write_success)

    cmd = await report_writer_node(state)
    assert cmd.goto == "report"
    assert cmd.update["report_narrative"] is not None

    async with get_async_session_ctx() as test_session:
        audits = (
            await test_session.execute(
                select(Audit).where(Audit.assessment_id == assessment_id)
            )
        ).scalars().all()
        generated = [a for a in audits if a.event_type == "report.narrative_generated"]
        assert len(generated) == 1
        assert generated[0].payload["findings_count"] == len(valid_narrative.findings)


@pytest.mark.asyncio
async def test_report_writer_node_fallback_audit(test_db, monkeypatch):
    """report_writer_node audits report.narrative_fallback when narrative generation fails."""
    async with get_async_session_ctx() as test_session:
        assessment = Assessment(
            title="Node Fallback Audit Test",
            request="Verify fallback audit",
            targets=["127.0.0.1"],
            ports=[80],
            exclusions=[],
            status=AssessmentStatus.RUNNING.value,
        )
        test_session.add(assessment)
        await test_session.commit()
        await test_session.refresh(assessment)
        assessment_id = assessment.id

    state = initial_state(assessment_id=assessment_id)

    # Patch write_narrative_result to fail validation
    async def mock_write_failure(ctx, model=None):
        return None, "Fabricated CVE detected"

    monkeypatch.setattr("app.agents.loop.nodes.write_narrative_result", mock_write_failure)

    cmd = await report_writer_node(state)
    assert cmd.goto == "report"
    assert cmd.update["report_narrative"] is None

    async with get_async_session_ctx() as test_session:
        audits = (
            await test_session.execute(
                select(Audit).where(Audit.assessment_id == assessment_id)
            )
        ).scalars().all()
        fallback = [a for a in audits if a.event_type == "report.narrative_fallback"]
        assert len(fallback) == 1
        assert "Fabricated CVE" in fallback[0].payload["error"]


@pytest.mark.asyncio
async def test_report_node_execution(test_db, tmp_path: Path, monkeypatch):
    """report_node compiles report, marks assessment completed, and routes to END."""
    monkeypatch.setattr("app.reporting.report.ARTIFACT_DIR", tmp_path)

    async with get_async_session_ctx() as test_session:
        assessment = Assessment(
            title="Report Node Test",
            request="Testing report_node",
            targets=["127.0.0.1"],
            ports=[80],
            exclusions=[],
            status=AssessmentStatus.RUNNING.value,
        )
        test_session.add(assessment)
        await test_session.commit()
        await test_session.refresh(assessment)
        assessment_id = assessment.id

    state = initial_state(assessment_id=assessment_id)
    state["report_narrative"] = None

    cmd = await report_node(state)
    assert cmd.goto == "__end__"
    assert cmd.update["finished"] is True

    async with get_async_session_ctx() as test_session:
        updated = await test_session.get(Assessment, assessment_id)
        assert updated.status == AssessmentStatus.COMPLETED.value
        assert updated.report_path != ""
        assert updated.finished_at is not None

