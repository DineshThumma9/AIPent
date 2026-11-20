"""Tests for database integrity constraints, unique keys, and transaction rollback."""

from __future__ import annotations

import pytest
from sqlalchemy.exc import IntegrityError

from app.core.db import get_async_session_ctx
from app.domain.models import Assessment, Finding, FindingCve
from app.persistence.step_repo import StepRepo


@pytest.mark.asyncio
async def test_non_existent_entity_lookup_error(engine):
    async with get_async_session_ctx() as session:
        step_repo = StepRepo(session)

        with pytest.raises(LookupError, match="step 999999 not found"):
            await step_repo.reject_step(999999, reason="test")

        with pytest.raises(LookupError, match="step 999999 not found"):
            await step_repo.complete_step(999999, status="succeeded")


@pytest.mark.asyncio
async def test_finding_canonical_key_unique_constraint(engine):
    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Constraint Target",
            request="Evaluate target security posture",
            targets=["127.0.0.1"],
            ports=[80],
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        finding1 = Finding(
            assessment_id=assessment.id,
            canonical_key="web:127.0.0.1:80:sqli",
            asset="127.0.0.1",
            title="SQL Injection Finding 1",
        )
        session.add(finding1)
        await session.commit()
        await session.refresh(finding1)
        finding1_id = finding1.id

        # Duplicate (assessment_id, canonical_key)
        finding2 = Finding(
            assessment_id=assessment.id,
            canonical_key="web:127.0.0.1:80:sqli",
            asset="127.0.0.1",
            title="SQL Injection Finding 2",
        )
        session.add(finding2)

        with pytest.raises(IntegrityError):
            await session.commit()

        # Verify rollback restores session sanity
        await session.rollback()

        # Subsequent query succeeds without error
        refreshed = await session.get(Finding, finding1_id)
        assert refreshed is not None
        assert refreshed.title == "SQL Injection Finding 1"


@pytest.mark.asyncio
async def test_finding_cve_unique_constraint(engine):
    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Finding CVE Target",
            request="Evaluate target security posture",
            targets=["127.0.0.1"],
            ports=[80],
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        finding = Finding(
            assessment_id=assessment.id,
            canonical_key="port:127.0.0.1:22",
            asset="127.0.0.1",
            title="OpenSSH Service",
        )
        session.add(finding)
        await session.commit()
        await session.refresh(finding)

        fcve1 = FindingCve(
            finding_id=finding.id,
            cve_id="CVE-2023-38408",
            source="nvd",
        )
        session.add(fcve1)
        await session.commit()

        # Duplicate (finding_id, cve_id)
        fcve2 = FindingCve(
            finding_id=finding.id,
            cve_id="CVE-2023-38408",
            source="nvd",
        )
        session.add(fcve2)

        with pytest.raises(IntegrityError):
            await session.commit()

        await session.rollback()
