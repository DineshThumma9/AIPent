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


@pytest.mark.asyncio
async def test_curl_auth_success_compact_summary_and_session_save(engine, tmp_path):
    async with get_async_session_ctx() as session:
        assessment = Assessment(title="Lab Auth", targets=["127.0.0.1"], ports=[3000])
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        jwt_token = (
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9."
            "eyJkYXRhIjp7ImlkIjoyNSwidXNlcm5hbWUiOiIiLCJlbWFpbCI6InBlbnRlc3RfdXNlcjEyM0BleGFtcGxlLmNvbSJ9LCJiaWQiOjZ9."
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        )
        login_response = {
            "authentication": {
                "token": jwt_token,
                "bid": 6,
                "umail": "pentest_user123@example.com",
            }
        }
        artifact_path = tmp_path / f"{assessment.id}" / "101.curl.json"
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path.write_text(
            json.dumps(
                {
                    "ok": True,
                    "code": 200,
                    "request": {
                        "url": "http://127.0.0.1:3000/rest/user/login",
                        "method": "POST",
                    },
                    "response": {
                        "status_code": 200,
                        "headers": {"content-type": "application/json"},
                        "body": json.dumps(login_response),
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
            output_path=str(artifact_path),
        )
        session.add(step)
        await session.commit()
        await session.refresh(step)

        obs = await observation_from_step(session, step)
        assert obs.ok is True

        # 1. Compact summary check: must not truncate user info and omits benchmark-specific bid
        assert "Authenticated (JWT token obtained, user=pentest_user123@example.com)" in obs.summary
        assert len(obs.summary) < 150
        assert jwt_token not in obs.summary  # Raw base64 is NOT dumped into summary string
        assert "bid=" not in obs.summary

        # 2. Structured facts["auth"] check (retains benchmark-specific fields like basket_id)
        assert obs.facts is not None
        auth = obs.facts.get("auth")
        assert auth is not None
        assert auth["token"] == jwt_token
        assert auth["basket_id"] == 6
        assert auth["email"] == "pentest_user123@example.com"
        assert auth["authorization_header"] == f"Bearer {jwt_token}"

        # 3. Session file saved to artifacts
        session_file = artifact_path.parent / "session.json"
        assert session_file.exists()
        saved_session = json.loads(session_file.read_text(encoding="utf-8"))
        assert saved_session["token"] == jwt_token
        assert saved_session["basket_id"] == 6

        # 4. next_hint prioritizes auth success with generic guidance
        assert "Authentication succeeded" in obs.next_hint
        assert "Authorization: Bearer" in obs.next_hint
        assert "basket ID" not in obs.next_hint
        assert "/rest/basket/1" not in obs.next_hint


@pytest.mark.asyncio
async def test_curl_auth_failure_does_not_overwrite_session(engine, tmp_path):
    async with get_async_session_ctx() as session:
        assessment = Assessment(title="Lab Auth 401", targets=["127.0.0.1"], ports=[3000])
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        # Step 1: Successful login saves session.json
        jwt_token = "valid-jwt-token-step1"
        sess_dir = tmp_path / f"{assessment.id}"
        sess_dir.mkdir(parents=True, exist_ok=True)
        login_artifact = sess_dir / "101.curl.json"
        login_artifact.write_text(
            json.dumps({
                "ok": True,
                "code": 200,
                "request": {"url": "http://127.0.0.1:3000/rest/user/login", "method": "POST"},
                "response": {
                    "status_code": 200,
                    "headers": {"content-type": "application/json"},
                    "body": json.dumps({"authentication": {"token": jwt_token, "umail": "user@test.com"}}),
                },
            }),
            encoding="utf-8",
        )
        step1 = Step(
            assessment_id=assessment.id,
            seq=1,
            action="curl_request",
            target="127.0.0.1",
            status=StepStatus.SUCCEEDED.value,
            output_path=str(login_artifact),
        )
        session.add(step1)
        await session.commit()
        await session.refresh(step1)
        obs1 = await observation_from_step(session, step1)
        assert obs1.facts["auth"]["token"] == jwt_token

        session_file = sess_dir / "session.json"
        assert session_file.exists()
        assert json.loads(session_file.read_text(encoding="utf-8"))["token"] == jwt_token

        # Step 2: 401 response with an error payload or deleted session cookie
        fail_artifact = sess_dir / "102.curl.json"
        fail_artifact.write_text(
            json.dumps({
                "ok": True,
                "code": 401,
                "request": {"url": "http://127.0.0.1:3000/rest/user/login", "method": "POST"},
                "response": {
                    "status_code": 401,
                    "headers": {"content-type": "application/json", "set-cookie": "session=deleted; Path=/"},
                    "body": json.dumps({"token": "error_payload_token", "message": "Invalid credentials"}),
                },
            }),
            encoding="utf-8",
        )
        step2 = Step(
            assessment_id=assessment.id,
            seq=2,
            action="curl_request",
            target="127.0.0.1",
            status=StepStatus.SUCCEEDED.value,
            output_path=str(fail_artifact),
        )
        session.add(step2)
        await session.commit()
        await session.refresh(step2)
        obs2 = await observation_from_step(session, step2)

        # Assert session.json still retains the step 1 token
        retained = json.loads(session_file.read_text(encoding="utf-8"))
        assert retained["token"] == jwt_token
        assert retained["token"] != "error_payload_token"
        assert obs2.facts["auth"]["token"] == jwt_token


@pytest.mark.asyncio
async def test_filter_self_routes_in_curl_entities(engine, tmp_path):
    async with get_async_session_ctx() as session:
        assessment = Assessment(title="Lab Routes", targets=["127.0.0.1"], ports=[3000])
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        body_with_routes = """
        <html>
            <body>
                <a href="/rest/user/login">Login Again</a>
                <a href="rest/user/login">Relative Login No Slash</a>
                <a href="/login">Short Login</a>
                <a href="/rest/basket/1">View Basket</a>
                <a href="/api/Users">User Directory</a>
            </body>
        </html>
        """
        artifact_path = tmp_path / "102.curl.json"
        artifact_path.write_text(
            json.dumps(
                {
                    "ok": True,
                    "code": 200,
                    "request": {
                        "url": "http://127.0.0.1:3000/rest/user/login",
                        "method": "POST",
                    },
                    "response": {
                        "status_code": 200,
                        "headers": {"content-type": "text/html"},
                        "body": body_with_routes,
                    },
                }
            ),
            encoding="utf-8",
        )

        step = Step(
            assessment_id=assessment.id,
            seq=2,
            action="curl_request",
            target="127.0.0.1",
            status=StepStatus.SUCCEEDED.value,
            output_path=str(artifact_path),
        )
        session.add(step)
        await session.commit()
        await session.refresh(step)

        obs = await observation_from_step(session, step)
        routes = obs.facts.get("extracted_routes") or []
        # The requested URL /rest/user/login must be filtered out as a self-route!
        assert "/rest/user/login" not in routes
        assert "rest/user/login" not in routes
        # Suffix routes like /login must NOT be deleted!
        assert "/login" in routes
        # Genuinely new routes must be preserved
        assert "/rest/basket/1" in routes
        assert "/api/Users" in routes


def test_curl_does_not_auto_inject_auth_token_when_omitted(tmp_path, monkeypatch):
    from app.actions.catalogue import _curl_tool_args
    from app.core.config import settings

    assessment = Assessment(id=999, title="Unauth Test", targets=["127.0.0.1"], ports=[3000])

    # Even if session.json exists for this assessment
    sess_file = tmp_path / "999" / "session.json"
    sess_file.parent.mkdir(parents=True, exist_ok=True)
    sess_file.write_text(json.dumps({"token": "fake-jwt-token"}), encoding="utf-8")
    monkeypatch.setattr(settings, "artifacts_dir", tmp_path)

    # 1. Probing unauthenticated endpoint without Authorization header
    args = _curl_tool_args(
        assessment=assessment,
        target="127.0.0.1:3000",
        p={"url": "/rest/basket/1", "method": "GET"},
        alias="127.0.0.1",
    )
    # Must NOT have Authorization header injected!
    assert "Authorization" not in args.get("headers", {})

    # 2. When Authorization header is provided explicitly, it is preserved/normalized
    args_with_auth = _curl_tool_args(
        assessment=assessment,
        target="127.0.0.1:3000",
        p={"url": "/rest/basket/1", "method": "GET", "headers": {"Authorization": "Bearer test-tok"}},
        alias="127.0.0.1",
    )
    assert args_with_auth.get("headers", {}).get("Authorization") == "Bearer test-tok"

    # 3. Repeated Bearer prefixes are collapsed cleanly to a single Bearer
    args_triple_bearer = _curl_tool_args(
        assessment=assessment,
        target="127.0.0.1:3000",
        p={"url": "/rest/basket/1", "method": "GET", "headers": {"Authorization": "Bearer Bearer Bearer test-tok"}},
        alias="127.0.0.1",
    )
    assert args_triple_bearer.get("headers", {}).get("Authorization") == "Bearer test-tok"

    # 4. Bare JWT (starts with eyJ) is prefixed with Bearer
    args_bare_jwt = _curl_tool_args(
        assessment=assessment,
        target="127.0.0.1:3000",
        p={"url": "/api/users", "method": "GET", "headers": {"Authorization": "eyJhbGciOiJIUzI1NiJ9.eyJpZCI6MX0.sig"}},
        alias="127.0.0.1",
    )
    assert args_bare_jwt.get("headers", {}).get("Authorization") == "Bearer eyJhbGciOiJIUzI1NiJ9.eyJpZCI6MX0.sig"

    # 5. Non-Bearer authorization schemes (Basic, Digest, ApiKey) remain uncorrupted
    args_basic = _curl_tool_args(
        assessment=assessment,
        target="127.0.0.1:3000",
        p={"url": "/admin", "method": "GET", "headers": {"Authorization": "Basic dXNlcjpwYXNz"}},
        alias="127.0.0.1",
    )
    assert args_basic.get("headers", {}).get("Authorization") == "Basic dXNlcjpwYXNz"

    args_digest = _curl_tool_args(
        assessment=assessment,
        target="127.0.0.1:3000",
        p={"url": "/admin", "method": "GET", "headers": {"Authorization": 'Digest username="admin", realm="test"'}},
        alias="127.0.0.1",
    )
    assert args_digest.get("headers", {}).get("Authorization") == 'Digest username="admin", realm="test"'

    args_apikey = _curl_tool_args(
        assessment=assessment,
        target="127.0.0.1:3000",
        p={"url": "/api/v1", "method": "GET", "headers": {"authorization": "ApiKey my-secret-key-123"}},
        alias="127.0.0.1",
    )
    assert args_apikey.get("headers", {}).get("authorization") == "ApiKey my-secret-key-123"


def test_cookie_attribute_strings_not_extracted_as_session_cookie():
    from app.agents.observations import _extract_auth_session

    # Case A: Directive Path=/session must NOT be extracted as a cookie named "Path=/session"
    headers_with_path_session = {
        "content-type": "application/json",
        "set-cookie": "app=123; Path=/session; HttpOnly",
    }
    extracted = _extract_auth_session(
        parsed_body={"status": "ok"},
        headers=headers_with_path_session,
        request_url="http://127.0.0.1:3000/auth/login",
    )
    # "app=123" is not a session cookie, and Path=/session is a directive, not a cookie
    assert extracted is None or "Path=" not in extracted.get("cookie", "")

    # Case B: Legitimate session cookie is extracted as name=value only, attributes dropped
    headers_with_session = {
        "content-type": "application/json",
        "set-cookie": "session_id=abc456; Path=/session; Secure; HttpOnly; SameSite=Lax",
    }
    extracted_valid = _extract_auth_session(
        parsed_body={"status": "ok"},
        headers=headers_with_session,
        request_url="http://127.0.0.1:3000/auth/login",
    )
    assert extracted_valid is not None
    assert extracted_valid.get("cookie") == "session_id=abc456"
    assert "Path=" not in extracted_valid.get("cookie", "")

    # Case C: List of Set-Cookie headers supported
    headers_list = {
        "content-type": "application/json",
        "set-cookie": [
            "theme=dark; Path=/",
            "connect.sid=s%3Axyz999; Path=/; HttpOnly",
        ],
    }
    extracted_list = _extract_auth_session(
        parsed_body={"status": "ok"},
        headers=headers_list,
        request_url="http://127.0.0.1:3000/auth/login",
    )
    assert extracted_list is not None
    assert extracted_list.get("cookie") == "connect.sid=s%3Axyz999"


def test_create_sidecar_manifest_guards_and_batch_curl(tmp_path):
    from app.parsers import create_sidecar_manifest, read_sidecar_manifest

    # 1. Guard against .manifest.json recursion
    manifest_file = tmp_path / "101.curl.json.manifest.json"
    manifest_file.write_text("{}", encoding="utf-8")
    res = create_sidecar_manifest(manifest_file)
    assert res is None

    # 2. Batched curl artifact parsing
    batch_artifact = tmp_path / "103.curl.json"
    batch_data = {
        "batch": True,
        "results": [
            {
                "index": 1,
                "request": {"url": "http://127.0.0.1:3000/api/Users"},
                "result": {
                    "ok": True,
                    "response": {
                        "status_code": 200,
                        "headers": {"content-type": "application/json"},
                        "body": json.dumps({"status": "success", "data": [{"id": 1, "username": "admin"}]}),
                    },
                },
            },
            {
                "index": 2,
                "request": {"url": "http://127.0.0.1:3000/index.html"},
                "result": {
                    "ok": True,
                    "response": {
                        "status_code": 200,
                        "headers": {"content-type": "text/html"},
                        "body": "<html><body><a href='/api/Products'>Products</a></body></html>",
                    },
                },
            },
        ],
    }
    batch_artifact.write_text(json.dumps(batch_data), encoding="utf-8")

    manifest_path = create_sidecar_manifest(batch_artifact)
    assert manifest_path is not None
    assert manifest_path.exists()

    data = read_sidecar_manifest(batch_artifact)
    assert data is not None
    # Must extract routes from responses
    assert "/api/Products" in data["routes"]
    # Must NOT index "batch" or "results" as application JSON keys
    assert "batch" not in data.get("keys", [])
    assert "results" not in data.get("keys", [])
    assert "status" in data.get("keys", [])


@pytest.mark.asyncio
async def test_curl_auth_not_saved_on_error_response_and_preserves_session(engine, tmp_path, monkeypatch):
    from app.core.config import settings
    monkeypatch.setattr(settings, "artifacts_dir", tmp_path)

    async with get_async_session_ctx() as session:
        assessment = Assessment(title="Auth Error Test", targets=["127.0.0.1"], ports=[3000])
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        # Pre-seed valid session.json in assessment artifacts directory
        sess_dir = tmp_path / str(assessment.id)
        sess_dir.mkdir(parents=True, exist_ok=True)
        sess_file = sess_dir / "session.json"
        sess_file.write_text(
            json.dumps({"token": "valid-jwt-token", "email": "analyst@test.com"}),
            encoding="utf-8",
        )

        # Failed login / auth attempt returns HTTP 401 with an error token or cookie
        artifact_path = sess_dir / "104.curl.json"
        artifact_path.write_text(
            json.dumps({
                "ok": True,
                "code": 401,
                "request": {
                    "url": "http://127.0.0.1:3000/rest/user/login",
                    "method": "POST",
                },
                "response": {
                    "status_code": 401,
                    "headers": {
                        "content-type": "application/json",
                        "set-cookie": "token=deleted; Path=/",
                    },
                    "body": json.dumps({"token": "bad-or-error-token", "error": "Invalid email or password."}),
                },
            }),
            encoding="utf-8",
        )

        step = Step(
            assessment_id=assessment.id,
            seq=3,
            action="curl_request",
            target="127.0.0.1",
            status=StepStatus.SUCCEEDED.value,
            output_path=str(artifact_path),
        )
        session.add(step)
        await session.commit()
        await session.refresh(step)

        obs = await observation_from_step(session, step)

        # 1. session.json must NOT be overwritten by the 401 response!
        saved_session = json.loads(sess_file.read_text(encoding="utf-8"))
        assert saved_session["token"] == "valid-jwt-token"
        assert saved_session["token"] != "bad-or-error-token"

        # 2. Existing session must be preserved in facts["auth"]
        assert obs.facts.get("auth") is not None
        assert obs.facts["auth"]["token"] == "valid-jwt-token"

        # 3. Observation summary and next_hint must not claim authentication succeeded
        assert "Authenticated (" not in obs.summary
        assert "Authentication succeeded" not in obs.next_hint
        assert "Credentials rejected" in obs.next_hint


def test_bare_output_path_does_not_dump_session_in_cwd(tmp_path, monkeypatch):
    from app.agents.observations import _load_session_file, _save_session_file
    from app.core.config import settings

    monkeypatch.setattr(settings, "artifacts_dir", tmp_path)
    aid = 777
    bare_filename = "bare_step_output.curl.json"

    # Ensure no ./session.json exists before
    cwd_sess = Path("session.json")
    if cwd_sess.exists():
        cwd_sess.unlink()

    try:
        # Saving with bare filename should resolve via assessment_id to artifacts directory
        saved_path = _save_session_file(aid, bare_filename, {"token": "test-jwt-bare"})
        assert not cwd_sess.exists(), "session.json was dumped into the current working directory!"
        assert saved_path is not None
        assert Path(saved_path) == settings.artifacts_path / str(aid) / "session.json"

        # Loading with bare filename should resolve via assessment_id to artifacts directory
        loaded = _load_session_file(aid, bare_filename)
        assert loaded is not None
        assert loaded.get("token") == "test-jwt-bare"
    finally:
        if cwd_sess.exists():
            cwd_sess.unlink()


@pytest.mark.asyncio
async def test_batch_curl_observation_uses_sidecar_manifest(engine, tmp_path):
    from app.parsers import create_sidecar_manifest

    async with get_async_session_ctx() as session:
        assessment = Assessment(title="Batch Manifest Test", targets=["127.0.0.1"], ports=[3000])
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        batch_artifact = tmp_path / "105.curl.json"
        batch_data = {
            "batch": True,
            "results": [
                {
                    "index": 1,
                    "request": {"url": "http://127.0.0.1:3000/api/Users"},
                    "result": {
                        "ok": True,
                        "response": {
                            "status_code": 200,
                            "headers": {"content-type": "text/html"},
                            "body": "<html><body><a href='/api/FoundFromManifest'>Manifest Route</a></body></html>",
                        },
                    },
                }
            ],
        }
        batch_artifact.write_text(json.dumps(batch_data), encoding="utf-8")
        manifest_path = create_sidecar_manifest(batch_artifact)
        assert manifest_path is not None and manifest_path.exists()

        step = Step(
            assessment_id=assessment.id,
            seq=4,
            action="curl_request",
            target="127.0.0.1",
            status=StepStatus.SUCCEEDED.value,
            output_path=str(batch_artifact),
        )
        session.add(step)
        await session.commit()
        await session.refresh(step)

        obs = await observation_from_step(session, step)
        assert obs.facts.get("batch") is True
        assert "/api/FoundFromManifest" in (obs.facts.get("extracted_routes") or [])


def test_cached_manifest_filters_self_routes_on_read(tmp_path):
    from app.agents.observations import _extract_curl_entities

    art_file = tmp_path / "106.curl.json"
    manifest_file = tmp_path / "106.curl.json.manifest.json"
    art_file.write_text("{}", encoding="utf-8")
    manifest_file.write_text(
        json.dumps({
            "routes": ["/api/users", "/api/products", "http://127.0.0.1:3000/api/users"],
            "files": [],
            "keys": [],
            "forms": [],
        }),
        encoding="utf-8",
    )

    routes, files, keys, forms = _extract_curl_entities(
        request_url="http://127.0.0.1:3000/api/users",
        headers={},
        body="",
        output_path=art_file,
    )
    assert "/api/products" in routes
    assert "/api/users" not in routes
    assert "http://127.0.0.1:3000/api/users" not in routes


@pytest.mark.asyncio
async def test_unauth_homepage_cookie_and_non_auth_token_safeguards(engine, tmp_path):
    async with get_async_session_ctx() as session:
        assessment = Assessment(title="Edge Case Safeguards", targets=["127.0.0.1"], ports=[3000])
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        # 1. Homepage probe setting connect.sid cookie must NOT claim authenticated
        home_art = tmp_path / f"{assessment.id}" / "201.curl.json"
        home_art.parent.mkdir(parents=True, exist_ok=True)
        home_art.write_text(
            json.dumps({
                "ok": True,
                "code": 200,
                "request": {"url": "http://127.0.0.1:3000/", "method": "GET"},
                "response": {
                    "status_code": 200,
                    "headers": {
                        "content-type": "text/html",
                        "set-cookie": "connect.sid=s%3Axyz123; Path=/; HttpOnly",
                    },
                    "body": "<html><body>Welcome to Store</body></html>",
                },
            }),
            encoding="utf-8",
        )

        step1 = Step(
            assessment_id=assessment.id,
            seq=1,
            action="curl_request",
            target="127.0.0.1",
            status=StepStatus.SUCCEEDED.value,
            output_path=str(home_art),
        )
        session.add(step1)
        await session.commit()
        await session.refresh(step1)

        obs1 = await observation_from_step(session, step1)
        assert "Authenticated (" not in obs1.summary
        assert "Authentication succeeded" not in obs1.next_hint
        assert obs1.facts.get("auth") is None

        # 2. Login succeeds and sets JWT session
        jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MX0.abcdef"
        login_art = tmp_path / f"{assessment.id}" / "202.curl.json"
        login_art.write_text(
            json.dumps({
                "ok": True,
                "code": 200,
                "request": {"url": "http://127.0.0.1:3000/rest/user/login", "method": "POST"},
                "response": {
                    "status_code": 200,
                    "headers": {"content-type": "application/json"},
                    "body": json.dumps({"authentication": {"token": jwt_token, "umail": "user@test.com"}}),
                },
            }),
            encoding="utf-8",
        )
        step2 = Step(
            assessment_id=assessment.id,
            seq=2,
            action="curl_request",
            target="127.0.0.1",
            status=StepStatus.SUCCEEDED.value,
            output_path=str(login_art),
        )
        session.add(step2)
        await session.commit()
        await session.refresh(step2)

        obs2 = await observation_from_step(session, step2)
        assert "Authenticated (JWT token obtained" in obs2.summary
        assert obs2.facts["auth"]["token"] == jwt_token

        # 3. Non-auth API endpoint returning a generic token does NOT overwrite active session
        csrf_art = tmp_path / f"{assessment.id}" / "203.curl.json"
        csrf_art.write_text(
            json.dumps({
                "ok": True,
                "code": 200,
                "request": {"url": "http://127.0.0.1:3000/api/Products", "method": "GET"},
                "response": {
                    "status_code": 200,
                    "headers": {"content-type": "application/json"},
                    "body": json.dumps({"status": "success", "token": "csrf-protection-token-xyz"}),
                },
            }),
            encoding="utf-8",
        )
        step3 = Step(
            assessment_id=assessment.id,
            seq=3,
            action="curl_request",
            target="127.0.0.1",
            status=StepStatus.SUCCEEDED.value,
            output_path=str(csrf_art),
        )
        session.add(step3)
        await session.commit()
        await session.refresh(step3)

        obs3 = await observation_from_step(session, step3)
        assert "Authenticated (" not in obs3.summary
        assert obs3.facts["auth"]["token"] == jwt_token  # Unchanged!


@pytest.mark.asyncio
async def test_cookie_only_auth_hint(engine, tmp_path):
    async with get_async_session_ctx() as session:
        assessment = Assessment(title="Cookie Auth", targets=["127.0.0.1"], ports=[3000])
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        login_art = tmp_path / f"{assessment.id}" / "301.curl.json"
        login_art.parent.mkdir(parents=True, exist_ok=True)
        login_art.write_text(
            json.dumps({
                "ok": True,
                "code": 200,
                "request": {"url": "http://127.0.0.1:3000/auth/login", "method": "POST"},
                "response": {
                    "status_code": 200,
                    "headers": {
                        "content-type": "application/json",
                        "set-cookie": "session_id=valid_sess_cookie; Path=/",
                    },
                    "body": json.dumps({"status": "logged_in", "user": {"id": 10, "email": "admin@test.com"}}),
                },
            }),
            encoding="utf-8",
        )
        step = Step(
            assessment_id=assessment.id,
            seq=1,
            action="curl_request",
            target="127.0.0.1",
            status=StepStatus.SUCCEEDED.value,
            output_path=str(login_art),
        )
        session.add(step)
        await session.commit()
        await session.refresh(step)

        obs = await observation_from_step(session, step)
        assert "Authenticated (session cookie obtained" in obs.summary
        assert "Session cookie obtained in facts['auth']['cookie']" in obs.next_hint
        assert "Cookie: session_id=valid_sess_cookie" in obs.next_hint


def test_save_session_file_credential_isolation(tmp_path):
    """Ensure saving a fresh login token clears previous user identifiers to avoid credential mixing."""
    from app.agents.observations import _load_session_file, _save_session_file

    session_path = tmp_path / "artifacts" / "session.json"
    dummy_out = tmp_path / "artifacts" / "resp.json"

    # User 1 logs in (admin with user_id and basket_id)
    user1_auth = {
        "token": "eyJ_user1_jwt",
        "authorization_header": "Bearer eyJ_user1_jwt",
        "user_id": 1,
        "basket_id": 6,
        "email": "admin@juice-sh.op",
    }
    _save_session_file(None, dummy_out, user1_auth)
    loaded1 = _load_session_file(None, dummy_out)
    assert loaded1["user_id"] == 1
    assert loaded1["basket_id"] == 6
    assert loaded1["email"] == "admin@juice-sh.op"
    assert loaded1["token"] == "eyJ_user1_jwt"

    # User 2 logs in with just a token (e.g. low-privilege user)
    user2_auth = {
        "token": "eyJ_user2_jwt",
        "authorization_header": "Bearer eyJ_user2_jwt",
    }
    _save_session_file(None, dummy_out, user2_auth)
    loaded2 = _load_session_file(None, dummy_out)
    assert loaded2["token"] == "eyJ_user2_jwt"
    # User 1's user_id, basket_id, and email MUST NOT carry over to User 2!
    assert "user_id" not in loaded2
    assert "basket_id" not in loaded2
    assert "email" not in loaded2








