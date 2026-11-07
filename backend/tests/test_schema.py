import asyncio
import logging

import pytest
from sqlalchemy.exc import IntegrityError
from sqlmodel import select

from app.core.db import get_async_session_ctx, init_db, make_engine, set_engine
from app.core.log import get_logger, setup_logging
from app.domain.models import Assessment, Audit, Evidence, Finding, Step


@pytest.fixture
def engine(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'test.db'}")
    asyncio.run(init_db(engine))
    set_engine(engine)
    return engine


def _run(fn):
    async def runner():
        async with get_async_session_ctx() as session:
            return await fn(session)

    return asyncio.run(runner())


def test_row_chain_roundtrip(engine):
    async def body(session):
        assessment = Assessment(
            title="Lab", targets=["127.0.0.1"], ports=[3000, 8080]
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        step = Step(
            assessment_id=assessment.id,
            seq=1,
            action="recon_services",
            argv=["nmap", "-sV", "127.0.0.1"],
            rationale="Only local lab target in scope",
        )
        session.add(step)
        await session.commit()
        await session.refresh(step)

        finding = Finding(
            assessment_id=assessment.id,
            canonical_key="nmap:127.0.0.1:3000:http",
            asset="127.0.0.1",
            endpoint="http://127.0.0.1:3000",
            title="HTTP service exposed",
        )
        session.add(finding)
        await session.commit()
        await session.refresh(finding)

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
        await session.commit()

        result = await session.execute(select(Step))
        assert result.scalars().one().assessment_id == assessment.id
        result = await session.execute(select(Evidence))
        assert result.scalars().one().locator == {"line": 12}
        result = await session.execute(select(Audit))
        assert result.scalars().one().payload == {"step_id": step.id}
        result = await session.execute(select(Finding))
        assert result.scalars().one().severity == "info"

    _run(body)


def test_duplicate_finding_key_is_rejected(engine):
    async def body(session):
        assessment = Assessment(title="Lab", targets=["127.0.0.1"])
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

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
            await session.commit()

    _run(body)


def test_logger_writes_stream_and_file(tmp_path, capsys):
    log_file = tmp_path / "aipent.log"
    setup_logging("DEBUG", log_file, force=True)
    get_logger("test").info("hello from test")

    assert "hello from test" in capsys.readouterr().out
    for handler in logging.getLogger("aipent").handlers:
        handler.flush()
    assert "hello from test" in log_file.read_text()
