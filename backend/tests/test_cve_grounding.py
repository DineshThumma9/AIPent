"""Tests for Phase 5.5: CVE Grounding with Vulnify, CveCatalog, FindingCve provenance, and report citations."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from sqlmodel import select

from app.core.config import settings
from app.core.db import get_async_session_ctx, init_db, make_engine, set_engine
from app.domain.models import (
    Assessment,
    AssessmentStatus,
    Finding,
    FindingCve,
    FindingStatus,
    Severity,
    utcnow,
)
from app.intel.cve import CveCandidate, CveCatalog, CveRecord, Reference, get_cve_catalog
from app.persistence.finding_repo import FindingRepo
from app.reporting.narrative import FindingNarrative, ReportNarrative, validate_narrative
from app.reporting.report import build_report_data, generate_report


@pytest.fixture
def fixture_db_path(tmp_path: Path) -> Path:
    """Create a minimal, schema-conformant Vulnify SQLite fixture database."""
    db_file = tmp_path / "vulnify_fixture.db"
    conn = sqlite3.connect(str(db_file))
    cur = conn.cursor()

    cur.executescript("""
    CREATE TABLE cve (
        cve_id TEXT PRIMARY KEY,
        title TEXT,
        summary TEXT,
        published TEXT,
        modified TEXT
    );
    CREATE TABLE cvss (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT NOT NULL,
        version TEXT,
        score REAL,
        severity TEXT
    );
    CREATE TABLE cwe (
        cwe_id TEXT PRIMARY KEY,
        name TEXT,
        description TEXT
    );
    CREATE TABLE cve_cwe (
        cve_id TEXT NOT NULL,
        cwe_id TEXT NOT NULL,
        PRIMARY KEY (cve_id, cwe_id)
    );
    CREATE TABLE kev (
        cve_id TEXT PRIMARY KEY,
        listed INTEGER NOT NULL DEFAULT 0,
        date_added TEXT
    );
    CREATE TABLE intel (
        cve_id TEXT PRIMARY KEY,
        epss_score REAL,
        epss_percentile REAL
    );
    CREATE TABLE reference (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT NOT NULL,
        url TEXT,
        source TEXT,
        title TEXT,
        trust TEXT
    );
    CREATE TABLE cpe_match (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT NOT NULL,
        criteria TEXT NOT NULL,
        match_criteria_id TEXT,
        vulnerable INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE vendor (
        vendor_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE product (
        product_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL DEFAULT '',
        vendor_id INTEGER NOT NULL
    );
    CREATE TABLE affected_product (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT NOT NULL,
        product_id INTEGER NOT NULL
    );

    -- Insert fixture rows
    INSERT INTO cve (cve_id, title, summary, published, modified) VALUES
        ('CVE-2023-1234', 'Login SQL Injection', 'Critical SQL injection in auth component.', '2023-05-01', '2023-06-01'),
        ('CVE-2024-5678', 'Nginx Buffer Overflow', 'Remote buffer overflow in request parser.', '2024-01-15', '2024-02-01');

    INSERT INTO cvss (cve_id, version, score, severity) VALUES
        ('CVE-2023-1234', '3.1', 8.5, 'HIGH'),
        ('CVE-2024-5678', '3.1', 9.8, 'CRITICAL');

    INSERT INTO cwe (cwe_id, name, description) VALUES
        ('CWE-89', 'SQL Injection', 'Improper neutralization of special elements in SQL query.');

    INSERT INTO cve_cwe (cve_id, cwe_id) VALUES
        ('CVE-2023-1234', 'CWE-89');

    INSERT INTO kev (cve_id, listed, date_added) VALUES
        ('CVE-2023-1234', 1, '2023-05-15'),
        ('CVE-2024-5678', 0, NULL);

    INSERT INTO intel (cve_id, epss_score, epss_percentile) VALUES
        ('CVE-2023-1234', 0.941, 0.985),
        ('CVE-2024-5678', 0.120, 0.450);

    INSERT INTO reference (cve_id, url, source, title) VALUES
        ('CVE-2023-1234', 'https://nvd.nist.gov/vuln/detail/CVE-2023-1234', 'nvd', 'NVD Detail'),
        ('CVE-2023-1234', 'https://vendor.example.com/advisories/SEC-01', 'vendor', 'Vendor Advisory'),
        ('CVE-2024-5678', 'https://nvd.nist.gov/vuln/detail/CVE-2024-5678', 'nvd', 'NVD Detail');

    INSERT INTO cpe_match (cve_id, criteria) VALUES
        ('CVE-2024-5678', 'cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*'),
        ('CVE-2024-5678', 'cpe:2.3:a:nginx:nginx:1.24.1:*:*:*:*:*:*:*');

    INSERT INTO vendor (vendor_id, name) VALUES (1, 'nginx');
    INSERT INTO product (product_id, name, vendor_id) VALUES (1, 'nginx', 1);
    INSERT INTO affected_product (cve_id, product_id) VALUES ('CVE-2024-5678', 1);
    """)

    conn.commit()
    conn.close()
    return db_file


@pytest.fixture
def test_db(tmp_path, monkeypatch):
    db_file = tmp_path / "cve_grounding_test.db"
    engine = make_engine(f"sqlite:///{db_file}")
    import asyncio
    asyncio.run(init_db(engine))
    set_engine(engine)
    monkeypatch.setattr(settings, "agent_loop", "v2")
    return engine


# =========================================================================
# Unit Tests: CveCatalog Adapter
# =========================================================================

def test_catalog_hydrate_success(fixture_db_path: Path):
    """CveCatalog.hydrate retrieves CVSS, CWE, KEV flag, EPSS, and upstream references."""
    catalog = CveCatalog(db_path=fixture_db_path)
    assert catalog.is_available is True

    record = catalog.hydrate("CVE-2023-1234")
    assert record is not None
    assert record.cve_id == "CVE-2023-1234"
    assert record.title == "Login SQL Injection"
    assert record.cvss_score == 8.5
    assert record.cvss_severity == "HIGH"
    assert record.cwe == ["CWE-89"]
    assert record.kev is True
    assert record.epss_score == 0.941
    assert len(record.references) >= 2
    assert "https://nvd.nist.gov/vuln/detail/CVE-2023-1234" in [r.url for r in record.references]


def test_catalog_hydrate_unknown_cve(fixture_db_path: Path):
    """CveCatalog.hydrate returns None for an unrecorded CVE."""
    catalog = CveCatalog(db_path=fixture_db_path)
    assert catalog.hydrate("CVE-1999-9999") is None
    assert catalog.hydrate("INVALID-CVE-FORMAT") is None


def test_catalog_candidates(fixture_db_path: Path):
    """CveCatalog.candidates returns conservative candidates with confidence, never confirmation."""
    catalog = CveCatalog(db_path=fixture_db_path)

    # Search with vendor and product
    candidates = catalog.candidates(vendor="nginx", product="nginx", version="1.24.0")
    assert len(candidates) >= 1
    top = candidates[0]
    assert top.cve_id == "CVE-2024-5678"
    assert top.confidence in ("high", "medium")
    assert top.match_reason in ("cpe_exact", "version_range")
    assert top.source_url != ""

    # Search by CPE prefix
    cpe_candidates = catalog.candidates(cpe="cpe:2.3:a:nginx:nginx")
    assert len(cpe_candidates) >= 1
    assert cpe_candidates[0].cve_id == "CVE-2024-5678"


def test_catalog_missing_db_fallback(tmp_path: Path):
    """Missing or incompatible database disables CVE enrichment gracefully without crashing."""
    catalog = CveCatalog(db_path=tmp_path / "non_existent.db")
    assert catalog.is_available is False
    assert catalog.hydrate("CVE-2023-1234") is None
    assert catalog.candidates(vendor="nginx", product="nginx") == []


def test_catalog_references_fallback(fixture_db_path: Path):
    """references() returns upstream reference URLs or deterministic NVD fallback."""
    catalog = CveCatalog(db_path=fixture_db_path)
    refs = catalog.references("CVE-2023-1234")
    assert len(refs) > 0
    assert refs[0].url.startswith("https://")


# =========================================================================
# Integration Tests: FindingRepo Provenance Tracking
# =========================================================================

@pytest.mark.asyncio
async def test_finding_cve_provenance(test_db, fixture_db_path: Path, monkeypatch):
    """Every CVE in a finding has a matching finding_cve row with non-empty source_url."""
    monkeypatch.setattr(settings, "vulnify_db_path", str(fixture_db_path))

    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Provenance Assessment",
            request="Test CVE grounding",
            targets=["127.0.0.1"],
            status=AssessmentStatus.RUNNING.value,
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        repo = FindingRepo(session)
        finding = await repo.create(
            assessment_id=assessment.id,
            canonical_key="127.0.0.1:sqli",
            asset="127.0.0.1",
            title="SQL Injection",
            severity=Severity.HIGH.value,
            cve=["CVE-2023-1234"],
        )

        # Check finding_cve provenance row
        cves = await repo.get_cves_for_finding(finding.id)
        assert len(cves) == 1
        fc = cves[0]
        assert fc.cve_id == "CVE-2023-1234"
        assert fc.source_url != ""
        assert "nvd" in fc.source or "nvd.nist.gov" in fc.source_url or "vendor" in fc.source
        assert fc.catalog_release == settings.vulnify_release


# =========================================================================
# Unit Tests: Direct Tool lookup_cve
# =========================================================================

@pytest.mark.asyncio
async def test_direct_tool_lookup_cve(test_db, fixture_db_path: Path, monkeypatch):
    """Specialists' lookup_cve direct tool returns structured candidate facts."""
    monkeypatch.setattr(settings, "vulnify_db_path", str(fixture_db_path))
    from app.agents.loop.direct_tools import lookup_cve_direct

    async with get_async_session_ctx() as session:
        obs = await lookup_cve_direct(
            session=session,
            assessment_id=1,
            cve_id="CVE-2023-1234",
        )
        assert obs.status == "succeeded"
        assert obs.facts["found"] is True
        assert obs.facts["cvss_score"] == 8.5
        assert obs.facts["kev"] is True

        # Test candidate lookup
        obs_cand = await lookup_cve_direct(
            session=session,
            assessment_id=1,
            vendor="nginx",
            product="nginx",
            version="1.24.0",
        )
        assert obs_cand.status == "succeeded"
        assert len(obs_cand.facts["candidates"]) >= 1
        assert obs_cand.facts["candidates"][0]["cve_id"] == "CVE-2024-5678"


# =========================================================================
# Report Validation & Typst Compilation Tests
# =========================================================================

def test_validate_narrative_provenance_enforcement():
    """validate_narrative rejects findings with CVEs lacking finding_cve provenance."""
    context = {
        "findings": [
            {
                "id": 1,
                "title": "SQL Injection",
                "cve": ["CVE-2023-1234"],
                "finding_cves": [],  # Empty provenance
                "status": "confirmed",
            }
        ]
    }
    narrative = ReportNarrative(
        executive_summary="Summary",
        methodology="Methodology",
        risk_overview="Overview",
        findings=[
            FindingNarrative(
                finding_id=1,
                technical_analysis="Analysis CVE-2023-1234.",
                impact="Impact",
                remediation="Remediation",
                confidence_statement="Confidence",
                observed_vs_inferred="Observed",
            )
        ],
        limitations="Limitations",
        recommendations=["Fix it"],
        conclusion="Conclusion",
    )

    with pytest.raises(ValueError, match="lacks required provenance in finding_cve"):
        validate_narrative(narrative, context)


def test_validate_narrative_reject_vulnify_as_authority():
    """validate_narrative rejects citations attributing authority to vulnify rather than NVD/vendor."""
    context = {
        "findings": [
            {
                "id": 1,
                "title": "SQL Injection",
                "cve": ["CVE-2023-1234"],
                "finding_cves": [
                    {
                        "cve_id": "CVE-2023-1234",
                        "source": "nvd",
                        "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
                    }
                ],
                "status": "confirmed",
            }
        ]
    }
    narrative = ReportNarrative(
        executive_summary="According to Vulnify this host is vulnerable.",
        methodology="Methodology",
        risk_overview="Overview",
        findings=[
            FindingNarrative(
                finding_id=1,
                technical_analysis="Analysis CVE-2023-1234.",
                impact="Impact",
                remediation="Remediation",
                confidence_statement="Confidence",
                observed_vs_inferred="Observed",
            )
        ],
        limitations="Limitations",
        recommendations=["Fix it"],
        conclusion="Conclusion",
    )

    with pytest.raises(ValueError, match="citations must point to NVD or vendor advisories, not vulnify as authority"):
        validate_narrative(narrative, context)


@pytest.mark.asyncio
async def test_report_generation_with_cve_citations(test_db, fixture_db_path: Path, tmp_path: Path, monkeypatch):
    """Typst compile succeeds and embeds verified CVE citations and the CVE snapshot badge."""
    monkeypatch.setattr(settings, "vulnify_db_path", str(fixture_db_path))
    monkeypatch.setattr("app.reporting.report.ARTIFACT_DIR", tmp_path)

    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="CVE Grounded Assessment",
            request="Check grounded CVE citations",
            targets=["127.0.0.1"],
            status=AssessmentStatus.RUNNING.value,
            created_at=utcnow(),
            finished_at=utcnow(),
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        finding = Finding(
            assessment_id=assessment.id,
            canonical_key="127.0.0.1:sqli",
            asset="127.0.0.1",
            endpoint="/login",
            title="SQL Injection",
            severity=Severity.HIGH.value,
            cvss=8.5,
            cve=["CVE-2023-1234"],
            status=FindingStatus.CONFIRMED.value,
        )
        session.add(finding)
        await session.commit()
        await session.refresh(finding)

        # Record provenance
        fc = FindingCve(
            finding_id=finding.id,
            cve_id="CVE-2023-1234",
            source="nvd",
            source_url="https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
            catalog_release=settings.vulnify_release,
            match_reason="cpe_exact",
            confidence="high",
        )
        session.add(fc)
        await session.commit()

        # Build report data
        data = await build_report_data(session, assessment)
        assert "cve_snapshot" in data
        assert "vulnify v2026.11.02" in data["cve_snapshot"]
        assert len(data["findings"][0]["finding_cves"]) == 1
        assert data["findings"][0]["finding_cves"][0]["source_url"] == "https://nvd.nist.gov/vuln/detail/CVE-2023-1234"

        # Generate report and compile Typst PDF
        pdf_path = await generate_report(session, assessment.id, narrative=None)
        assert pdf_path.exists()
        assert pdf_path.stat().st_size > 0
        assert pdf_path.suffix == ".pdf"
