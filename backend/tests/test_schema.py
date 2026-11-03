import logging

import pytest
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from app.db import init_db, make_engine
from app.log import get_logger, setup_logging
from app.models import Assessment, Audit, Evidence, Finding, Step


@pytest.fixture
def engine(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'test.db'}")
    init_db(engine)
    return engine


def test_row_chain_roundtrip(engine):
    with Session(engine) as session:
        assessment = Assessment(title="Lab", targets=["127.0.0.1"], ports=[3000, 8080])
        session.add(assessment)
        session.commit()
        session.refresh(assessment)

        step = Step(
            assessment_id=assessment.id,
            seq=1,
            action="recon_services",
            argv=["nmap", "-sV", "127.0.0.1"],
            rationale="Only local lab target in scope",
        )
        session.add(step)
        session.commit()
        session.refresh(step)

        finding = Finding(
            assessment_id=assessment.id,
            canonical_key="nmap:127.0.0.1:3000:http",
            asset="127.0.0.1",
            endpoint="http://127.0.0.1:3000",
            title="HTTP service exposed",
        )
        session.add(finding)
        session.commit()
        session.refresh(finding)

        session.add(
            Evidence(
                finding_id=finding.id,
                step_id=step.id,
                locator={"line": 12},
                excerpt="3000/tcp open http",
            )
        )
        session.add(
            Audit(
                assessment_id=assessment.id,
                event_type="step.succeeded",
                payload={"step_id": step.id},
            )
        )
        session.commit()

        assert session.exec(select(Step)).one().assessment_id == assessment.id
        assert session.exec(select(Evidence)).one().locator == {"line": 12}
        assert session.exec(select(Audit)).one().payload == {"step_id": step.id}
        assert session.exec(select(Finding)).one().severity == "info"


def test_duplicate_finding_key_is_rejected(engine):
    with Session(engine) as session:
        assessment = Assessment(title="Lab", targets=["127.0.0.1"])
        session.add(assessment)
        session.commit()
        session.refresh(assessment)

        for _ in range(2):
            session.add(
                Finding(
                    assessment_id=assessment.id,
                    canonical_key="same",
                    asset="127.0.0.1",
                    title="dup",
                )
            )
        with pytest.raises(IntegrityError):
            session.commit()


def test_logger_writes_stream_and_file(tmp_path, capsys):
    log_file = tmp_path / "aipent.log"
    setup_logging("DEBUG", log_file, force=True)
    get_logger("test").info("hello from test")

    assert "hello from test" in capsys.readouterr().out
    for handler in logging.getLogger("aipent").handlers:
        handler.flush()
    assert "hello from test" in log_file.read_text()
