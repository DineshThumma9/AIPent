import asyncio
import json
from pathlib import Path

import pytest
from sqlmodel import Session, select

from app import actions
from app.adapters import nikto, zap
from app.models import Assessment, Evidence, Finding, Step

NIKTO_JSON = json.dumps(
    {
        "host": "127.0.0.1",
        "port": 3000,
        "vulnerabilities": [
            {
                "id": "999957",
                "msg": "The anti-clickjacking X-Frame-Options header is not present.",
                "url": "/",
                "method": "GET",
            },
            {
                "id": "999103",
                "msg": "The X-Content-Type-Options header is not set.",
                "url": "/",
                "method": "GET",
            },
        ],
    }
)

ZAP_JSON = json.dumps(
    {
        "site": [
            {
                "name": "http://127.0.0.1:3000",
                "alerts": [
                    {
                        "pluginid": "10038",
                        "alert": "CSP Header Not Set",
                        "riskcode": "2",
                        "confidence": "3",
                        "desc": "Content Security Policy header is missing.",
                        "solution": "Set a Content-Security-Policy header.",
                        "instances": [
                            {
                                "uri": "http://127.0.0.1:3000/",
                                "method": "GET",
                                "param": "",
                                "evidence": "Content-Security-Policy",
                            }
                        ],
                    }
                ],
            }
        ]
    }
)


def test_nikto_parse_and_drafts():
    items = nikto.parse(NIKTO_JSON)
    drafts = nikto.to_drafts("127.0.0.1", 3000, items)

    assert len(drafts) == 2
    assert drafts[0].canonical_key.startswith("web:")
    assert drafts[0].severity.value == "low"
    assert drafts[0].status.value == "suspected"
    assert drafts[0].evidence[0].locator["id"] == "999957"


def test_zap_parse_and_drafts():
    alerts = zap.parse(ZAP_JSON)
    drafts = zap.to_drafts("127.0.0.1", 3000, alerts)

    assert len(drafts) == 1
    assert drafts[0].title == "CSP Header Not Set"
    assert drafts[0].severity.value == "medium"
    assert drafts[0].confidence == 0.9
    assert drafts[0].remediation.startswith("Set a Content-Security-Policy")
    assert drafts[0].evidence[0].locator["plugin"] == "10038"


def test_zap_argv_reports_relative_to_the_mount(tmp_path):
    argv = zap.argv("127.0.0.1", 3000, str(tmp_path / "3.zap.json"), tmp_path)

    assert f"{tmp_path}:/zap/wrk:rw" in argv
    assert argv[argv.index("-J") + 1] == "3.zap.json"
    assert not any(item.startswith("/zap/wrk/") for item in argv)


@pytest.fixture
def session(engine, tmp_path, monkeypatch):
    monkeypatch.setattr(actions, "ARTIFACT_DIR", tmp_path / "artifacts")
    with Session(engine, expire_on_commit=False) as session:
        assessment = Assessment(title="Lab", targets=["127.0.0.1"], ports=[3000])
        session.add(assessment)
        session.commit()
        session.refresh(assessment)
        yield session, assessment


def test_execute_nikto_writes_artifact_and_evidence(session, monkeypatch):
    session, assessment = session

    def fake_run(argv, **kwargs):
        output = Path(argv[argv.index("-output") + 1])
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(NIKTO_JSON, encoding="utf-8")

        class Process:
            returncode = 0
            stdout = ""
            stderr = ""

        return Process()

    monkeypatch.setattr(actions.subprocess, "run", fake_run)
    step = asyncio.run(
        actions.execute_action(
            session,
            assessment.id,
            "nikto_scan",
            rationale="Active web probe of the approved endpoint",
        )
    )

    assert step.status == "succeeded"
    assert step.output_path and step.output_sha256
    assert Path(step.output_path).read_text() == NIKTO_JSON

    findings = session.exec(select(Finding)).all()
    assert len(findings) == 2
    assert len(session.exec(select(Evidence)).all()) == 2


def test_execute_missing_tool_is_blocked(session, monkeypatch):
    session, assessment = session

    def explode(*_args, **_kwargs):
        raise FileNotFoundError("nikto")

    monkeypatch.setattr(actions.subprocess, "run", explode)
    step = asyncio.run(
        actions.execute_action(session, assessment.id, "nikto_scan")
    )

    assert step.status == "blocked"
    assert "not installed" in (step.error or "")


def test_duplicate_evidence_is_not_written_twice(session, monkeypatch):
    session, assessment = session

    def fake_run(argv, **kwargs):
        output = Path(argv[argv.index("-output") + 1])
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(NIKTO_JSON, encoding="utf-8")

        class Process:
            returncode = 0
            stdout = ""
            stderr = ""

        return Process()

    monkeypatch.setattr(actions.subprocess, "run", fake_run)
    asyncio.run(actions.execute_action(session, assessment.id, "nikto_scan"))
    asyncio.run(actions.execute_action(session, assessment.id, "nikto_scan"))

    assert len(session.exec(select(Finding)).all()) == 2
    assert len(session.exec(select(Evidence)).all()) == 4
