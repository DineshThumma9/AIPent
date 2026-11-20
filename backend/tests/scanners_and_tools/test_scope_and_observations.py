"""Tests for target scope parsing, exclusions, root paths, and scanner observation parsing."""

import json
from pathlib import Path
import pytest

from app.actions import catalogue, check_scope, get_action
from app.actions.catalogue import ScopeError
from app.agents.observations import observation_from_step
from app.core.config import BACKEND_DIR, settings
from app.core.db import get_async_session_ctx
from app.domain.models import Assessment, Step, StepStatus


def test_backend_paths_point_at_the_backend_root():
    """A wrong parents[] index silently loads no .env and uses src/data."""
    assert BACKEND_DIR.name == "backend"
    assert settings.data_dir == BACKEND_DIR / "data"
    assert settings.database_url == f"sqlite:///{BACKEND_DIR / 'data' / 'aipent.db'}"
    assert settings.graph_path == BACKEND_DIR / "data" / "graph.sqlite"


def test_scope_normalizes_hosts_and_supports_cidr():
    assessment = Assessment(
        id=1,
        title="Lab",
        targets=["127.0.0.1", "Example.COM.", "10.0.0.0/24"],
        ports=[3000],
    )

    check_scope(assessment, "127.0.0.1")
    check_scope(assessment, "localhost")
    check_scope(assessment, "example.com")
    check_scope(assessment, "10.0.0.42")

    with pytest.raises(ScopeError):
        check_scope(assessment, "example.org")
    with pytest.raises(ScopeError):
        check_scope(assessment, "10.0.1.5")


def test_exclusions_override_inclusive_scope():
    assessment = Assessment(
        id=1,
        title="Lab",
        targets=["10.0.0.0/24", "localhost"],
        exclusions=["10.0.0.9", "127.0.0.1"],
        ports=[3000],
    )

    with pytest.raises(ScopeError):
        check_scope(assessment, "10.0.0.9")
    with pytest.raises(ScopeError):
        check_scope(assessment, "localhost")
    check_scope(assessment, "10.0.0.10")


def test_sqlmap_output_is_stdout():
    assert get_action("sqlmap_scan").output == "stdout"


@pytest.mark.asyncio
async def test_sqlmap_negative_with_server_errors_is_inconclusive(engine, tmp_path):
    async with get_async_session_ctx() as session:
        assessment = Assessment(title="Lab", targets=["127.0.0.1"], ports=[3000])
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        path = tmp_path / "sqlmap.txt"
        path.write_text(
            "[WARNING] GET parameter 'q' does not seem to be injectable\n"
            "[CRITICAL] all tested parameters do not appear to be injectable.\n"
            "[WARNING] HTTP error codes detected during run:\n"
            "500 (Internal Server Error) - 41 times\n",
            encoding="utf-8",
        )
        step = Step(
            assessment_id=assessment.id,
            seq=1,
            action="sqlmap_scan",
            target="127.0.0.1",
            status=StepStatus.SUCCEEDED.value,
            output_path=str(path),
        )
        session.add(step)
        await session.commit()
        await session.refresh(step)

        obs = await observation_from_step(session, step)
        assert "no injection point" in obs.summary
        assert "inconclusive" in obs.next_hint
        assert "not injectable" not in obs.summary


@pytest.mark.asyncio
async def test_sqlmap_clean_negative_does_not_claim_injection(engine, tmp_path):
    async with get_async_session_ctx() as session:
        assessment = Assessment(title="Lab", targets=["127.0.0.1"], ports=[3000])
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        path = tmp_path / "sqlmap_clean.txt"
        path.write_text(
            "[CRITICAL] all tested parameters do not appear to be injectable.\n",
            encoding="utf-8",
        )
        step = Step(
            assessment_id=assessment.id,
            seq=1,
            action="sqlmap_scan",
            target="127.0.0.1",
            status=StepStatus.SUCCEEDED.value,
            output_path=str(path),
        )
        session.add(step)
        await session.commit()
        await session.refresh(step)

        obs = await observation_from_step(session, step)
        assert "no SQL injection confirmed" in obs.summary
        assert "different parameter" in obs.next_hint


@pytest.mark.asyncio
async def test_sqlmap_proof_marker_is_reported_as_confirmed(engine, tmp_path):
    async with get_async_session_ctx() as session:
        assessment = Assessment(title="Lab", targets=["127.0.0.1"], ports=[3000])
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        path = tmp_path / "sqlmap_proof.txt"
        path.write_text(
            "sqlmap identified the following injection point(s) with a total of "
            "91 HTTP(s) requests:\n---\nParameter: q (GET)\n"
            "    Type: boolean-based blind\n",
            encoding="utf-8",
        )
        step = Step(
            assessment_id=assessment.id,
            seq=1,
            action="sqlmap_scan",
            target="127.0.0.1",
            status=StepStatus.SUCCEEDED.value,
            output_path=str(path),
        )
        session.add(step)
        await session.commit()
        await session.refresh(step)

        obs = await observation_from_step(session, step)
        assert "confirmed by sqlmap" in obs.summary
        assert "Attach" in obs.next_hint


@pytest.mark.asyncio
async def test_curl_observation_reports_json_row_count(engine, tmp_path):
    async with get_async_session_ctx() as session:
        assessment = Assessment(title="Lab", targets=["127.0.0.1"], ports=[3000])
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

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
