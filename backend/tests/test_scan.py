import asyncio
import subprocess

import pytest
from sqlmodel import Session, select

from app import actions
from app.actions import executor
from app.runtime import scan
from app.core.db import init_db, make_engine
from app.domain.models import Assessment, Audit, Evidence, Finding, Step


@pytest.fixture
def session(tmp_path, monkeypatch, nmap_xml):
    engine = make_engine(f"sqlite:///{tmp_path / 'scan.db'}")
    init_db(engine)
    monkeypatch.setattr(actions, "ARTIFACT_DIR", tmp_path / "artifacts")

    class Process:
        returncode = 0
        stdout = nmap_xml
        stderr = ""

    monkeypatch.setattr(executor.subprocess, "run", lambda *a, **k: Process())
    with Session(engine, expire_on_commit=False) as session:
        yield session


def _assessment(session):
    assessment = Assessment(title="Lab", targets=["127.0.0.1"], ports=[3000])
    session.add(assessment)
    session.commit()
    session.refresh(assessment)
    return assessment


def test_scan_persists_step_findings_and_evidence(session):
    assessment = _assessment(session)
    step = asyncio.run(scan.run_scan(session, assessment.id))

    assert step.status == "succeeded"
    assert step.exit_code == 0
    assert step.output_path and step.output_sha256

    finding = session.exec(select(Finding)).one()
    assert finding.canonical_key == "nmap:127.0.0.1:tcp/3000"
    assert finding.origin == "tool"

    evidence = session.exec(select(Evidence)).one()
    assert evidence.step_id == step.id
    assert evidence.locator["xpath"].endswith("[@portid='3000']")

    events = [event.event_type for event in session.exec(select(Audit)).all()]
    assert events == ["step.started", "step.succeeded"]


def test_scan_is_idempotent_for_the_same_finding(session):
    assessment = _assessment(session)
    asyncio.run(scan.run_scan(session, assessment.id))
    asyncio.run(scan.run_scan(session, assessment.id))

    assert len(session.exec(select(Finding)).all()) == 1
    assert len(session.exec(select(Step)).all()) == 2


def test_out_of_scope_target_never_runs(session, monkeypatch):
    assessment = _assessment(session)

    def explode(*_args, **_kwargs):
        raise AssertionError("subprocess must not run out of scope")

    monkeypatch.setattr(executor.subprocess, "run", explode)
    with pytest.raises(scan.ScopeError):
        asyncio.run(scan.run_scan(session, assessment.id, target="10.0.0.1"))
