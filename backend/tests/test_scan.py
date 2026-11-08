import asyncio
import subprocess

import pytest
from sqlmodel import select

from app.actions import catalogue, executor
from app.core.db import get_async_session_ctx, init_db, make_engine, set_engine
from app.domain.models import Assessment, Audit, Evidence, Finding, Step
from app.runtime import scan


@pytest.fixture
def engine(tmp_path, monkeypatch, nmap_xml):
    engine = make_engine(f"sqlite:///{tmp_path / 'scan.db'}")
    asyncio.run(init_db(engine))
    set_engine(engine)
    monkeypatch.setattr(catalogue, "ARTIFACT_DIR", tmp_path / "artifacts")

    async def fake_run(argv, timeout, assessment_id=None):
        return subprocess.CompletedProcess(argv, 0, nmap_xml, "")

    monkeypatch.setattr(executor, "_run", fake_run)
    return engine


def _run_with_session(coro_fn):
    async def runner():
        async with get_async_session_ctx() as session:
            return await coro_fn(session)

    return asyncio.run(runner())


async def _assessment(session):
    assessment = Assessment(title="Lab", targets=["127.0.0.1"], ports=[3000])
    session.add(assessment)
    await session.commit()
    await session.refresh(assessment)
    return assessment


def test_scan_persists_step_findings_and_evidence(engine):
    async def body(session):
        assessment = await _assessment(session)
        step = await scan.run_scan(session, assessment.id)

        assert step.status == "succeeded"
        assert step.exit_code == 0
        assert step.output_path and step.output_sha256

        result = await session.execute(select(Finding))
        finding = result.scalars().one()
        assert finding.canonical_key == "nmap:127.0.0.1:tcp/3000"
        assert finding.origin == "tool"

        result = await session.execute(select(Evidence))
        evidence = result.scalars().one()
        assert evidence.step_id == step.id
        assert evidence.locator["xpath"].endswith("[@portid='3000']")

        result = await session.execute(select(Audit))
        events = [event.event_type for event in result.scalars().all()]
        assert events == ["step.started", "step.succeeded"]

    _run_with_session(body)


def test_scan_is_idempotent_for_the_same_finding(engine):
    async def body(session):
        assessment = await _assessment(session)
        await scan.run_scan(session, assessment.id)
        await scan.run_scan(session, assessment.id)

        result = await session.execute(select(Finding))
        assert len(result.scalars().all()) == 1
        result = await session.execute(select(Step))
        assert len(result.scalars().all()) == 2

    _run_with_session(body)


def test_out_of_scope_target_never_runs(engine, monkeypatch):
    def explode(*_args, **_kwargs):
        raise AssertionError("subprocess must not run out of scope")

    monkeypatch.setattr(executor.subprocess, "run", explode)

    async def body(session):
        assessment = await _assessment(session)
        with pytest.raises(scan.ScopeError):
            await scan.run_scan(session, assessment.id, target="10.0.0.1")

    _run_with_session(body)
