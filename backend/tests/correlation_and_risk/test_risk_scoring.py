"""Tests for risk scoring formula, exposure and impact bands, and assessment risk updates."""

from __future__ import annotations

import pytest

from app.core.db import get_async_session_ctx
from app.domain.models import Assessment, Finding, FindingStatus
from app.domain.risk import (
    SEVERITY_WEIGHT,
    exposure,
    finding_score,
    impact,
    summarize,
)
from app.persistence.assessment_repo import AssessmentRepo


def test_exposure_and_impact_bands():
    # Exposure bands: loopback (0.7), internal (0.85), external (1.0)
    assert exposure("127.0.0.1") == ("loopback", 0.7)
    assert exposure("localhost") == ("loopback", 0.7)
    assert exposure("192.168.1.1") == ("internal", 0.85)
    assert exposure("10.0.0.1") == ("internal", 0.85)
    assert exposure("target.com") == ("external", 1.0)

    # Impact bands: app (1.0), service (0.8), host (0.9)
    assert impact("http://target.com/login") == ("app", 1.0)
    assert impact("https://target.com:8443/api") == ("app", 1.0)
    assert impact("tcp/22") == ("service", 0.8)
    assert impact(None) == ("host", 0.9)


def test_severity_weights():
    assert SEVERITY_WEIGHT["critical"] == 10.0
    assert SEVERITY_WEIGHT["high"] == 7.5
    assert SEVERITY_WEIGHT["medium"] == 5.0
    assert SEVERITY_WEIGHT["low"] == 2.0
    assert SEVERITY_WEIGHT["info"] == 0.0


def test_finding_score_calculation():
    # Critical finding on external app endpoint with confidence=1.0:
    # 10.0 * (0.5 + 0.5 * 1.0) * 1.0 * 1.0 = 10.0
    f_crit = Finding(
        id=1,
        assessment_id=1,
        canonical_key="web:crit:sqli",
        asset="target.com",
        endpoint="http://target.com/sqli",
        title="SQL Injection",
        severity="critical",
        confidence=1.0,
    )
    score_crit = finding_score(f_crit)
    assert score_crit["score"] == 10.0

    # High finding on loopback service with confidence=0.8:
    # 7.5 * (0.5 + 0.5 * 0.8) * 0.7 (loopback) * 0.8 (service) = 7.5 * 0.9 * 0.7 * 0.8 = 3.78
    f_high = Finding(
        id=2,
        assessment_id=1,
        canonical_key="nmap:127.0.0.1:tcp/22",
        asset="127.0.0.1",
        endpoint="tcp/22",
        title="OpenSSH vulnerability",
        severity="high",
        confidence=0.8,
    )
    score_high = finding_score(f_high)
    assert score_high["score"] == 3.78


def test_summarize_findings_summary():
    f1 = Finding(
        id=1,
        assessment_id=1,
        canonical_key="f1",
        asset="target.com",
        endpoint="http://target.com/1",
        title="F1",
        severity="high",
        confidence=1.0,
    )
    f2 = Finding(
        id=2,
        assessment_id=1,
        canonical_key="f2",
        asset="target.com",
        endpoint="http://target.com/2",
        title="F2",
        severity="medium",
        confidence=0.5,
    )
    summary = summarize([f1, f2])
    assert summary["finding_count"] == 2
    assert summary["counts"]["high"] == 1
    assert summary["counts"]["medium"] == 1
    assert summary["score"] == finding_score(f1)["score"]


@pytest.mark.asyncio
async def test_assessment_repo_refresh_risk_score(engine):
    async with get_async_session_ctx() as session:
        repo = AssessmentRepo(session)
        assessment = await repo.create(
            title="Risk Update Target",
            request="Evaluate target security posture",
            targets=["example.com"],
            ports=[80],
        )

        finding = Finding(
            assessment_id=assessment.id,
            canonical_key="web:crit:rce",
            asset="example.com",
            endpoint="http://example.com/upload",
            title="Remote Code Execution",
            severity="critical",
            confidence=1.0,
            status=FindingStatus.CONFIRMED.value,
        )
        session.add(finding)
        await session.commit()

        summary = await repo.refresh_risk_score(assessment.id)
        assert summary["score"] > 0

        refreshed_assessment = await repo.get(assessment.id)
        assert refreshed_assessment.risk_score == summary["score"]
