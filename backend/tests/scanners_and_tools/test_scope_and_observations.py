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


@pytest.mark.asyncio
async def test_curl_observation_extracts_routes_from_javascript(engine, tmp_path):
    async with get_async_session_ctx() as session:
        assessment = Assessment(title="Lab JS", targets=["127.0.0.1"], ports=[3000])
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        js_content = """
        // Application routes
        const loginUrl = "/rest/user/login";
        const captchaEndpoint = "/rest/captcha";
        const feedbackApi = "/api/Feedbacks";
        fetch("/rest/image-captcha/");
        """
        path = tmp_path / "main.js.json"
        path.write_text(
            json.dumps(
                {
                    "ok": True,
                    "code": 200,
                    "request": {"url": "http://127.0.0.1:3000/main.js"},
                    "response": {
                        "status_code": 200,
                        "headers": {"content-type": "application/javascript"},
                        "body": js_content,
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
        routes = obs.facts.get("extracted_routes") or []
        assert "/rest/captcha" in routes
        assert "/api/Feedbacks" in routes
        assert "/rest/user/login" in routes
        assert "/rest/image-captcha/" in routes
        assert "extracted 4 route(s)" in obs.summary
        assert "Probe these discovered routes" in (obs.next_hint or "")


@pytest.mark.asyncio
async def test_curl_observation_extracts_files_from_directory_listing(engine, tmp_path):
    async with get_async_session_ctx() as session:
        assessment = Assessment(title="Lab Dir", targets=["127.0.0.1"], ports=[3000])
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        html_ftp = """
        <!DOCTYPE html><html><head><title>listing directory /ftp</title></head><body>
        <a href=".">.</a>
        <a href="ftp">ftp</a>
        <a href="ftp/acquisitions.md">acquisitions.md</a>
        <a href="ftp/eastere.gg">eastere.gg</a>
        <a href="ftp/package.json.bak">package.json.bak</a>
        </body></html>
        """
        path = tmp_path / "ftp.json"
        path.write_text(
            json.dumps(
                {
                    "ok": True,
                    "code": 200,
                    "request": {"url": "http://127.0.0.1:3000/ftp"},
                    "response": {
                        "status_code": 200,
                        "headers": {"content-type": "text/html"},
                        "body": html_ftp,
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
        files = obs.facts.get("extracted_files") or []
        assert "ftp/acquisitions.md" in files
        assert "ftp/eastere.gg" in files
        assert "ftp/package.json.bak" in files
        assert "." not in files
        assert "extracted 3 file(s)" in obs.summary


@pytest.mark.asyncio
async def test_curl_observation_extracts_keys_and_routes_from_large_json(engine, tmp_path):
    async with get_async_session_ctx() as session:
        assessment = Assessment(title="Lab JSON", targets=["127.0.0.1"], ports=[3000])
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        swagger_json = {
            "swagger": "2.0",
            "info": {"title": "API", "version": "1.0"},
            "paths": {
                "/api/Feedbacks": {"post": {}},
                "/rest/captcha": {"get": {}},
                "/api/Users": {"get": {}},
            },
        }
        path = tmp_path / "swagger.json"
        path.write_text(
            json.dumps(
                {
                    "ok": True,
                    "code": 200,
                    "request": {"url": "http://127.0.0.1:3000/api-docs"},
                    "response": {
                        "status_code": 200,
                        "headers": {"content-type": "application/json"},
                        "body": json.dumps(swagger_json),
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
        keys = obs.facts.get("keys") or []
        routes = obs.facts.get("extracted_routes") or []
        assert "swagger" in keys
        assert "paths" in keys
        assert "/api/Feedbacks" in routes
        assert "/rest/captcha" in routes
        assert "/api/Users" in routes


@pytest.mark.asyncio
async def test_ffuf_scan_observation(engine, tmp_path):
    from app.domain.models import Evidence, Finding, FindingStatus, Origin, Severity

    async with get_async_session_ctx() as session:
        assessment = Assessment(title="Lab FFUF", targets=["127.0.0.1"], ports=[3000])
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        step = Step(
            assessment_id=assessment.id,
            seq=1,
            action="ffuf_scan",
            target="127.0.0.1",
            status=StepStatus.SUCCEEDED.value,
        )
        session.add(step)
        await session.commit()
        await session.refresh(step)

        f1 = Finding(
            assessment_id=assessment.id,
            canonical_key="ffuf:127.0.0.1:3000:/rest/admin",
            title="Discovered Endpoint (FFUF): /rest/admin (HTTP 200)",
            asset="127.0.0.1",
            endpoint="/rest/admin",
            severity=Severity.LOW,
            status=FindingStatus.SUSPECTED,
            origin=Origin.TOOL,
        )
        f2 = Finding(
            assessment_id=assessment.id,
            canonical_key="ffuf:127.0.0.1:3000:/robots.txt",
            title="Discovered Endpoint (FFUF): /robots.txt (HTTP 200)",
            asset="127.0.0.1",
            endpoint="/robots.txt",
            severity=Severity.INFO,
            status=FindingStatus.SUSPECTED,
            origin=Origin.TOOL,
        )
        session.add(f1)
        session.add(f2)
        await session.commit()
        await session.refresh(f1)
        await session.refresh(f2)

        e1 = Evidence(finding_id=f1.id, step_id=step.id, excerpt="admin endpoint")
        e2 = Evidence(finding_id=f2.id, step_id=step.id, excerpt="robots.txt endpoint")
        session.add(e1)
        session.add(e2)
        await session.commit()

        obs = await observation_from_step(session, step)
        assert obs.ok is True
        assert "2 web endpoints discovered by FFUF" in obs.summary
        assert "sensitive: /rest/admin" in obs.summary
        assert obs.facts["discovered_endpoints"] == ["/rest/admin", "/robots.txt"]
        assert obs.facts["sensitive_endpoints"] == ["/rest/admin"]
        assert "sensitive surfaces (/rest/admin)" in (obs.next_hint or "")


