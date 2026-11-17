"""Agent-discovered findings must be creatable, evidenced, and confirmable."""

import asyncio
import json

import pytest
from sqlmodel import select

from app.agents.loop.direct_tools import record_finding
from app.core.db import get_async_session_ctx, init_db, make_engine, set_engine
from app.domain.models import Assessment, Evidence, Finding, Step, StepStatus
from app.persistence.finding_repo import FindingRepo


@pytest.fixture
def engine(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'findings.db'}")
    asyncio.run(init_db(engine))
    set_engine(engine)
    return engine


def _run_with_session(coro_fn):
    async def runner():
        async with get_async_session_ctx() as session:
            return await coro_fn(session)

    return asyncio.run(runner())


async def _assessment(session, targets=None):
    assessment = Assessment(
        title="Lab", targets=targets or ["127.0.0.1"], ports=[3000]
    )
    session.add(assessment)
    await session.commit()
    await session.refresh(assessment)
    return assessment


async def _step(session, assessment_id, action, text, tmp_path):
    path = tmp_path / f"{action}.artifact"
    path.write_text(text, encoding="utf-8")
    step = Step(
        assessment_id=assessment_id,
        seq=1,
        action=action,
        target="127.0.0.1",
        status=StepStatus.SUCCEEDED.value,
        output_path=str(path),
    )
    session.add(step)
    await session.commit()
    await session.refresh(step)
    return step


def test_record_finding_links_curl_evidence_and_confirms(engine, tmp_path):
    async def body(session):
        assessment = await _assessment(session)
        artifact = json.dumps(
            {
                "curl_result": {
                    "url": "http://127.0.0.1:3000/rest/products/search?q=1",
                    "method": "GET",
                    "status_code": 200,
                    "body_preview": "search results",
                }
            }
        )
        step = await _step(session, assessment.id, "curl_request", artifact, tmp_path)

        obs = await record_finding(
            session,
            assessment.id,
            "run-1",
            "validation",
            title="SQL injection in product search",
            asset="127.0.0.1",
            endpoint="/rest/products/search?q=",
            severity="high",
            evidence_step_ids=[step.id],
            reasoning="Boolean differential changed the response body.",
        )

        assert obs.ok, obs.summary
        finding = await session.get(Finding, obs.findings_created[0])
        assert finding.status == "suspected"
        assert finding.origin == "llm"
        assert finding.severity == "high"

        result = await session.execute(
            select(Evidence).where(Evidence.finding_id == finding.id)
        )
        evidence = result.scalars().all()
        assert len(evidence) == 1
        assert evidence[0].locator["tool"] == "curl_request"
        assert evidence[0].locator["http_status"] == 200

        verdict = await FindingRepo(session).update_status(
            finding.id, assessment.id, "confirmed", "Differential proof."
        )
        assert "error" not in verdict

    _run_with_session(body)


def test_record_finding_dedupes_and_does_not_duplicate_evidence(engine, tmp_path):
    async def body(session):
        assessment = await _assessment(session)
        artifact = json.dumps(
            {"curl_result": {"url": "http://127.0.0.1:3000/x", "method": "GET", "status_code": 200}}
        )
        step = await _step(session, assessment.id, "curl_request", artifact, tmp_path)

        first = await record_finding(
            session,
            assessment.id,
            "run-1",
            "validation",
            title="Missing security header",
            asset="127.0.0.1",
            endpoint="/x",
            evidence_step_ids=[step.id],
        )
        second = await record_finding(
            session,
            assessment.id,
            "run-1",
            "validation",
            title="Missing security header",
            asset="127.0.0.1",
            endpoint="/x",
            evidence_step_ids=[step.id],
        )

        assert first.facts["finding_id"] == second.facts["finding_id"]
        assert second.facts["created"] is False
        assert second.evidence_ids == []

        findings = (await session.execute(select(Finding))).scalars().all()
        evidence = (await session.execute(select(Evidence))).scalars().all()
        assert len(findings) == 1
        assert len(evidence) == 1

    _run_with_session(body)


def test_sqlmap_proof_satisfies_the_verdict_gate(engine, tmp_path):
    async def body(session):
        assessment = await _assessment(session)
        artifact = (
            "sqlmap identified the following injection point(s) with a total of "
            "3 HTTP(s) requests:\n---\nParameter: q (GET)\n"
            "    Type: boolean-based blind\n"
        )
        step = await _step(session, assessment.id, "sqlmap_scan", artifact, tmp_path)

        obs = await record_finding(
            session,
            assessment.id,
            "run-2",
            "validation",
            title="SQL injection in product search",
            asset="127.0.0.1",
            endpoint="/rest/products/search?q=",
            severity="high",
            evidence_step_ids=[step.id],
        )
        assert obs.ok, obs.summary

        finding_id = obs.facts["finding_id"]
        result = await session.execute(
            select(Evidence).where(Evidence.finding_id == finding_id)
        )
        evidence = result.scalars().all()
        assert evidence[0].locator["tool"] == "sqlmap_scan"
        assert evidence[0].locator["injectable"] is True

        verdict = await FindingRepo(session).update_status(
            finding_id, assessment.id, "confirmed", "sqlmap injection point."
        )
        assert "error" not in verdict

    _run_with_session(body)


def test_evidence_without_a_concrete_outcome_cannot_confirm(engine, tmp_path):
    async def body(session):
        assessment = await _assessment(session)
        artifact = json.dumps(
            {"curl_result": {"url": "http://127.0.0.1:3000/x", "method": "GET"}}
        )
        step = await _step(session, assessment.id, "curl_request", artifact, tmp_path)

        obs = await record_finding(
            session,
            assessment.id,
            "run-3",
            "validation",
            title="Suspected SQL injection",
            asset="127.0.0.1",
            endpoint="/x?q=",
            evidence_step_ids=[step.id],
        )
        assert obs.ok, obs.summary

        verdict = await FindingRepo(session).update_status(
            obs.facts["finding_id"], assessment.id, "confirmed", "unsupported"
        )
        assert "error" in verdict

    _run_with_session(body)


def test_record_finding_rejects_out_of_scope_asset(engine, tmp_path):
    async def body(session):
        assessment = await _assessment(session)
        obs = await record_finding(
            session,
            assessment.id,
            "run-4",
            "validation",
            title="Out of scope",
            asset="10.0.0.99",
            endpoint="/x",
        )
        assert obs.ok is False
        assert obs.status == "blocked"

    _run_with_session(body)


def test_record_finding_rejects_unknown_evidence_step(engine, tmp_path):
    async def body(session):
        assessment = await _assessment(session)
        obs = await record_finding(
            session,
            assessment.id,
            "run-5",
            "validation",
            title="Bad evidence link",
            asset="127.0.0.1",
            endpoint="/x",
            evidence_step_ids=[9999],
        )
        assert obs.ok is False

    _run_with_session(body)


def test_record_finding_extends_a_scanner_candidate_by_id(engine, tmp_path):
    async def body(session):
        assessment = await _assessment(session)
        candidate = Finding(
            assessment_id=assessment.id,
            canonical_key="web:probe:127.0.0.1:3000/rest/products/search:GET",
            asset="127.0.0.1",
            endpoint="/rest/products/search?q=",
            title="Verification probe (GET) returned 200",
            severity="medium",
            status="suspected",
            origin="tool",
        )
        session.add(candidate)
        await session.commit()
        await session.refresh(candidate)

        artifact = (
            "sqlmap identified the following injection point(s) with a total of "
            "3 HTTP(s) requests:\n---\nParameter: q (GET)\n"
            "    Type: boolean-based blind\n"
        )
        step = await _step(session, assessment.id, "sqlmap_scan", artifact, tmp_path)

        obs = await record_finding(
            session,
            assessment.id,
            "run-6",
            "validation",
            finding_id=candidate.id,
            evidence_step_ids=[step.id],
        )
        assert obs.ok, obs.summary
        assert obs.facts["finding_id"] == candidate.id
        assert obs.facts["created"] is False

        evidence = (
            await session.execute(
                select(Evidence).where(Evidence.finding_id == candidate.id)
            )
        ).scalars().all()
        assert len(evidence) == 1
        assert evidence[0].locator["tool"] == "sqlmap_scan"
        assert evidence[0].locator["injectable"] is True

        verdict = await FindingRepo(session).update_status(
            candidate.id, assessment.id, "confirmed", "sqlmap injection point."
        )
        assert "error" not in verdict

    _run_with_session(body)


def test_negative_sqlmap_scan_can_mark_false_positive(engine, tmp_path):
    async def body(session):
        assessment = await _assessment(session)
        artifact = (
            "[CRITICAL] all tested parameters do not appear to be injectable. "
            "Try to increase values for '--level'/'--risk' options.\n"
        )
        step = await _step(session, assessment.id, "sqlmap_scan", artifact, tmp_path)

        obs = await record_finding(
            session,
            assessment.id,
            "run-7",
            "validation",
            title="Suspected SQL injection in search",
            asset="127.0.0.1",
            endpoint="/search?q=",
            evidence_step_ids=[step.id],
        )
        assert obs.ok, obs.summary

        repo = FindingRepo(session)
        verdict = await repo.update_status(
            obs.facts["finding_id"],
            assessment.id,
            "false_positive",
            "sqlmap tested the parameter and found no injection point.",
        )
        assert "error" not in verdict

        blocked = await repo.update_status(
            obs.facts["finding_id"],
            assessment.id,
            "confirmed",
            "negative evidence cannot confirm.",
        )
        assert "error" in blocked

    _run_with_session(body)


def test_extending_a_low_finding_keeps_its_severity(engine, tmp_path):
    async def body(session):
        assessment = await _assessment(session)
        artifact = json.dumps(
            {"curl_result": {"url": "http://127.0.0.1:3000/x", "method": "GET", "status_code": 200}}
        )
        step = await _step(session, assessment.id, "curl_request", artifact, tmp_path)
        finding_id = (
            await record_finding(
                session,
                assessment.id,
                "run-8",
                "validation",
                title="Low-risk header issue",
                asset="127.0.0.1",
                endpoint="/x",
                severity="low",
                evidence_step_ids=[step.id],
            )
        ).facts["finding_id"]

        await record_finding(
            session,
            assessment.id,
            "run-8",
            "validation",
            finding_id=finding_id,
            evidence_step_ids=[step.id],
        )
        finding = await session.get(Finding, finding_id)
        assert finding.severity == "low"

        await record_finding(
            session,
            assessment.id,
            "run-8",
            "validation",
            finding_id=finding_id,
            severity="high",
        )
        await session.refresh(finding)
        assert finding.severity == "high"

    _run_with_session(body)
