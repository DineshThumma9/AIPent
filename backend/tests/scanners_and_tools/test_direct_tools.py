"""Tests for safe in-process direct tools that execute without external subprocesses or approval gates."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import pytest

from app.agents.direct_tools import (
    hash_identify_direct,
    list_findings,
    list_services,
    lookup_cve_direct,
    read_artifact,
)
from app.core.config import settings
from app.core.db import get_async_session_ctx
from app.domain.models import (
    Assessment,
    Finding,
    FindingStatus,
    Severity,
    Step,
    StepStatus,
)
from app.persistence.step_repo import StepRepo


@pytest.fixture
def cve_db_path(tmp_path: Path) -> Path:
    db_file = tmp_path / "vulnify_direct.db"
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
    CREATE TABLE cpe_match (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT NOT NULL,
        criteria TEXT NOT NULL,
        match_criteria_id TEXT,
        vulnerable INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE reference (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT NOT NULL,
        url TEXT,
        source TEXT,
        title TEXT,
        trust TEXT
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
    """)

    cur.execute(
        "INSERT INTO cve VALUES (?, ?, ?, ?, ?)",
        ("CVE-2023-1234", "Direct Buffer Overflow", "A heap overflow vulnerability", "2023-01-01", "2023-01-02"),
    )
    cur.execute(
        "INSERT INTO cvss (cve_id, version, score, severity) VALUES (?, ?, ?, ?)",
        ("CVE-2023-1234", "3.1", 8.8, "HIGH"),
    )
    cur.execute(
        "INSERT INTO kev (cve_id, listed) VALUES (?, ?)",
        ("CVE-2023-1234", 0),
    )
    cur.execute(
        "INSERT INTO cpe_match (cve_id, criteria) VALUES (?, ?)",
        ("CVE-2023-1234", "cpe:2.3:a:apache:httpd:2.4.49:*:*:*:*:*:*:*"),
    )
    conn.commit()
    conn.close()
    return db_file


@pytest.mark.asyncio
async def test_read_artifact_pagination_and_search(engine, tmp_path):
    async with get_async_session_ctx() as session:
        assessment = Assessment(title="Read Artifact Target", targets=["127.0.0.1"], ports=[80])
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        art_file = tmp_path / "long_output.txt"
        content = "line 1: header\nline 2: secret_token=12345\nline 3: footer\n"
        art_file.write_text(content, encoding="utf-8")

        step_repo = StepRepo(session)
        step, _ = await step_repo.create_planned_step(
            assessment_id=assessment.id,
            run_id="run-1",
            role="discovery",
            action="curl_request",
            target="127.0.0.1",
        )
        await step_repo.complete_step(step.id, status=StepStatus.SUCCEEDED.value, output_path=str(art_file))
        await session.commit()

        # 1. Normal read
        obs = await read_artifact(session, assessment.id, step.id)
        assert obs.ok is True
        assert "secret_token=12345" in obs.summary

        # 2. Search filtering
        obs_search = await read_artifact(session, assessment.id, step.id, search="secret_token")
        assert obs_search.ok is True
        assert "secret_token=12345" in obs_search.summary

        # 2b. Integer search coercion (prevents AttributeError: 'int' object has no attribute 'lower')
        obs_int_search = await read_artifact(session, assessment.id, step.id, search=12345)
        assert obs_int_search.ok is True
        assert "secret_token=12345" in obs_int_search.summary

        # 3. Missing step error
        obs_missing = await read_artifact(session, assessment.id, 99999)
        assert obs_missing.ok is False
        assert "not found" in obs_missing.summary

        # 4. Missing artifact file
        step_no_file, _ = await step_repo.create_planned_step(
            assessment_id=assessment.id,
            run_id="run-1",
            role="discovery",
            action="curl_request",
            target="127.0.0.1",
        )
        await step_repo.complete_step(step_no_file.id, status=StepStatus.SUCCEEDED.value, output_path="/invalid/path.txt")
        await session.commit()

        obs_no_file = await read_artifact(session, assessment.id, step_no_file.id)
        assert obs_no_file.ok is False
        assert "no artifact file" in obs_no_file.summary


@pytest.mark.asyncio
async def test_list_services_and_findings(engine):
    async with get_async_session_ctx() as session:
        assessment = Assessment(title="List Tools Target", targets=["127.0.0.1"], ports=[80, 443])
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        # Service finding
        f_svc = Finding(
            assessment_id=assessment.id,
            canonical_key="nmap:127.0.0.1:80",
            asset="127.0.0.1",
            title="Open port 80/tcp (http)",
            status=FindingStatus.CONFIRMED.value,
            severity=Severity.INFO.value,
        )
        # Vuln finding
        f_vuln = Finding(
            assessment_id=assessment.id,
            canonical_key="web:127.0.0.1:80:xss",
            asset="127.0.0.1",
            endpoint="/search",
            title="Reflected XSS",
            status=FindingStatus.SUSPECTED.value,
            severity=Severity.MEDIUM.value,
        )
        session.add(f_svc)
        session.add(f_vuln)
        await session.commit()

        # Test list_services
        obs_svc = await list_services(session, assessment.id)
        assert obs_svc.ok is True
        assert "Open port 80/tcp (http)" in obs_svc.summary

        # Test list_findings
        obs_findings = await list_findings(session, assessment.id)
        assert obs_findings.ok is True
        assert "Reflected XSS" in obs_findings.summary

        # Test filter by status
        obs_suspected = await list_findings(session, assessment.id, status="suspected")
        assert obs_suspected.ok is True
        assert "Reflected XSS" in obs_suspected.summary


@pytest.mark.asyncio
async def test_lookup_cve_direct(engine, cve_db_path, monkeypatch):
    monkeypatch.setattr(settings, "vulnify_db_path", str(cve_db_path))
    from app.intel.cve import get_cve_catalog
    get_cve_catalog(cve_db_path)

    async with get_async_session_ctx() as session:
        # Lookup by exact CVE ID
        obs_exact = await lookup_cve_direct(session, 1, cve_id="CVE-2023-1234")
        assert obs_exact.status == "succeeded"
        assert obs_exact.facts["found"] is True
        assert obs_exact.facts["cvss_score"] == 8.8

        # Lookup by vendor / product
        obs_cand = await lookup_cve_direct(
            session,
            1,
            vendor="apache",
            product="httpd",
            version="2.4.49",
        )
        assert obs_cand.status == "succeeded"
        assert len(obs_cand.facts["candidates"]) >= 1
        assert obs_cand.facts["candidates"][0]["cve_id"] == "CVE-2023-1234"


@pytest.mark.asyncio
async def test_hash_identify_direct(engine, tmp_path):
    async with get_async_session_ctx() as session:
        assessment = Assessment(title="Hash Target", targets=["127.0.0.1"], ports=[80])
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        hash_file = tmp_path / "shadow.txt"
        hash_file.write_text("root:$1$salt1234$abcdef1234567890123456:1000:1000", encoding="utf-8")

        step_repo = StepRepo(session)
        step, _ = await step_repo.create_planned_step(
            assessment_id=assessment.id,
            run_id="run-1",
            role="discovery",
            action="read_file",
            target="127.0.0.1",
        )
        await step_repo.complete_step(step.id, status=StepStatus.SUCCEEDED.value, output_path=str(hash_file))
        await session.commit()

        # Identify valid hash contained in artifact
        obs = await hash_identify_direct(
            session=session,
            assessment_id=assessment.id,
            hash_value="$1$salt1234$abcdef1234567890123456",
            source_step_id=step.id,
        )
        assert obs.ok is True
        assert obs.facts["candidates"][0]["name"] == "md5crypt"

        # Reject hash not contained in artifact
        obs_reject = await hash_identify_direct(
            session=session,
            assessment_id=assessment.id,
            hash_value="$1$nonexistent$hashvalue",
            source_step_id=step.id,
        )
        assert obs_reject.ok is False
        assert "does not appear in the source step artifact" in obs_reject.summary
