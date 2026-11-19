"""sqlmap observations must distinguish proof, inconclusive negatives, and clean negatives."""

import asyncio
import json

import pytest

from app.agents.loop.observations import observation_from_step
from app.core.db import get_async_session_ctx, init_db, make_engine, set_engine
from app.domain.models import Assessment, Step, StepStatus


@pytest.fixture
def engine(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'observations.db'}")
    asyncio.run(init_db(engine))
    set_engine(engine)
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


async def _step(session, assessment_id, text, tmp_path):
    path = tmp_path / "sqlmap.txt"
    path.write_text(text, encoding="utf-8")
    step = Step(
        assessment_id=assessment_id,
        seq=1,
        action="sqlmap_scan",
        target="127.0.0.1",
        status=StepStatus.SUCCEEDED.value,
        output_path=str(path),
    )
    session.add(step)
    await session.commit()
    await session.refresh(step)
    return step


def test_sqlmap_negative_with_server_errors_is_inconclusive(engine, tmp_path):
    async def body(session):
        assessment = await _assessment(session)
        step = await _step(
            session,
            assessment.id,
            "[WARNING] GET parameter 'q' does not seem to be injectable\n"
            "[CRITICAL] all tested parameters do not appear to be injectable.\n"
            "[WARNING] HTTP error codes detected during run:\n"
            "500 (Internal Server Error) - 41 times\n",
            tmp_path,
        )

        obs = await observation_from_step(session, step)

        assert "no injection point" in obs.summary
        assert "inconclusive" in obs.next_hint
        assert "not injectable" not in obs.summary

    _run_with_session(body)


def test_sqlmap_clean_negative_does_not_claim_injection(engine, tmp_path):
    async def body(session):
        assessment = await _assessment(session)
        step = await _step(
            session,
            assessment.id,
            "[CRITICAL] all tested parameters do not appear to be injectable.\n",
            tmp_path,
        )

        obs = await observation_from_step(session, step)

        assert "no SQL injection confirmed" in obs.summary
        assert "different parameter" in obs.next_hint

    _run_with_session(body)


def test_sqlmap_proof_marker_is_reported_as_confirmed(engine, tmp_path):
    async def body(session):
        assessment = await _assessment(session)
        step = await _step(
            session,
            assessment.id,
            "sqlmap identified the following injection point(s) with a total of "
            "91 HTTP(s) requests:\n---\nParameter: q (GET)\n"
            "    Type: boolean-based blind\n",
            tmp_path,
        )

        obs = await observation_from_step(session, step)

        assert "confirmed by sqlmap" in obs.summary
        assert "Attach" in obs.next_hint

    _run_with_session(body)


def test_curl_observation_reports_json_row_count(engine, tmp_path):
    async def body(session):
        assessment = await _assessment(session)
        path = tmp_path / "curl.json"
        path.write_text(
            json.dumps(
                {
                    "ok": True,
                    "code": 200,
                    "request": {
                        "url": "http://host.docker.internal:3000/rest/products/search?q=x"
                    },
                    "response": {
                        "status_code": 200,
                        "headers": {"content-type": "application/json"},
                        "body": json.dumps(
                            {"status": "success", "data": [{"id": i} for i in range(46)]}
                        ),
                    },
                }
            ),
            encoding="utf-8",
        )
        step = Step(
            assessment_id=assessment.id,
            seq=1,
            action="curl_request",
            target="127.0.0.1",
            status=StepStatus.SUCCEEDED.value,
            output_path=str(path),
        )
        session.add(step)
        await session.commit()
        await session.refresh(step)

        obs = await observation_from_step(session, step)

        assert obs.facts is not None
        assert obs.facts["json_items"] == 46
        assert "46 items" in obs.summary
        assert "record_finding" in (obs.next_hint or "")

    _run_with_session(body)


def test_local_curl_result_reports_search_hint(engine, tmp_path):
    async def body(session):
        assessment = await _assessment(session)
        path = tmp_path / "curl-local.json"
        path.write_text(
            json.dumps(
                {
                    "curl_result": {
                        "url": "http://127.0.0.1:3000/rest/products/search?q=x",
                        "method": "GET",
                        "status_code": 200,
                        "headers": {"content-type": "application/json"},
                        "body_preview": json.dumps(
                            {"status": "success", "data": [{"id": i} for i in range(46)]}
                        ),
                    }
                }
            ),
            encoding="utf-8",
        )
        step = Step(
            assessment_id=assessment.id,
            seq=1,
            action="curl_request",
            target="127.0.0.1",
            status=StepStatus.SUCCEEDED.value,
            output_path=str(path),
        )
        session.add(step)
        await session.commit()
        await session.refresh(step)

        obs = await observation_from_step(session, step)

        assert obs.facts is not None
        assert obs.facts["json_items"] == 46
        assert "baseline" in (obs.next_hint or "")

    _run_with_session(body)
