from __future__ import annotations

import pytest
from app.core.db import get_async_session_ctx
from app.domain.models import Assessment, Finding, FindingStatus, Origin
from app.domain.risk import exposure, finding_score, impact, summarize, refresh_risk
from app.persistence.assessment_repo import AssessmentRepo


def test_pure_risk_calculations():
    # 1. Exposure bands
    assert exposure("127.0.0.1") == ("loopback", 0.7)
    assert exposure("192.168.1.10") == ("internal", 0.85)
    assert exposure("api.target.com") == ("external", 1.0)

    # 2. Impact bands
    assert impact("http://target.com/api") == ("app", 1.0)
    assert impact("tcp/443") == ("service", 0.8)
    assert impact(None) == ("host", 0.9)

    # 3. Finding score & summarize
    f1 = Finding(
        id=1,
        assessment_id=1,
        canonical_key="agent:127.0.0.1:http:f1",
        asset="127.0.0.1",
        endpoint="http://127.0.0.1/admin",
        title="Admin interface exposed",
        severity="high",
        confidence=0.8,
        status=FindingStatus.CONFIRMED.value,
        origin=Origin.LLM.value,
    )
    score1 = finding_score(f1)
    assert score1["severity"] == "high"
    assert score1["score"] > 0

    summary = summarize([f1])
    assert summary["finding_count"] == 1
    assert summary["score"] == score1["score"]
    assert summary["counts"]["high"] == 1


@pytest.mark.asyncio
async def test_assessment_repo_refresh_risk_score(engine):
    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Risk Test Assessment",
            request="Evaluate target security posture",
            targets=["127.0.0.1"],
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        finding = Finding(
            assessment_id=assessment.id,
            canonical_key="agent:127.0.0.1:http:f2",
            asset="127.0.0.1",
            endpoint="http://127.0.0.1/sqli",
            title="SQL Injection",
            severity="critical",
            confidence=0.9,
            status=FindingStatus.CONFIRMED.value,
            origin=Origin.LLM.value,
        )
        session.add(finding)
        await session.commit()

        repo = AssessmentRepo(session)
        summary = await repo.refresh_risk_score(assessment.id)
        assert summary["finding_count"] == 1
        assert summary["score"] > 0

        # Verify assessment risk_score was updated
        updated_assessment = await repo.get(assessment.id)
        assert updated_assessment.risk_score == summary["score"]

        # Verify compatibility wrapper refresh_risk
        compat_summary = await refresh_risk(session, assessment.id)
        assert compat_summary["score"] == summary["score"]
