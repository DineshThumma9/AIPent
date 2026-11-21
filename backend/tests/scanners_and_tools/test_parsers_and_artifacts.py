"""Tests for parsers (BeautifulSoup DOM, jsluice AST, OpenAPI JSON) and manifest integration."""

import json
from pathlib import Path

import pytest
from app.agents.contracts import Observation
from app.agents.direct_tools import read_artifact
from app.domain.models import Assessment, Step, StepStatus
from app.parsers import (
    create_sidecar_manifest,
    parse_content,
    parse_html,
    parse_js,
    parse_json,
    read_sidecar_manifest,
)
from app.core.db import get_async_session_ctx
from app.persistence.step_repo import StepRepo


def test_html_parser_forms_and_comments():
    html = """
    <!DOCTYPE html>
    <html>
      <head><title>Test App</title></head>
      <body>
        <!-- TODO: internal debug endpoint /rest/debug/status -->
        <form action="/api/Feedbacks" method="POST">
          <input name="captchaId" type="number" />
          <input name="captcha" type="text" />
          <textarea name="comment"></textarea>
          <button type="submit">Send</button>
        </form>
        <form action="login" method="get">
          <input name="email" type="email" />
          <input name="password" type="password" />
        </form>
        <script src="assets/main.bundle.js"></script>
        <a href="downloads/backup.kdbx">Keepass</a>
        <a href="/rest/admin/users">Admin Users</a>
      </body>
    </html>
    """
    res = parse_html(html, base_url="http://127.0.0.1:3000")

    assert "/api/Feedbacks" in res.routes
    assert "/login" in res.routes
    assert "/rest/admin/users" in res.routes
    assert "/rest/debug/status" in res.routes

    assert len(res.forms) == 2
    f1 = res.forms[0]
    assert f1.action == "/api/Feedbacks"
    assert f1.method == "POST"
    inp_names = [i.name for i in f1.inputs]
    assert "captchaId" in inp_names
    assert "captcha" in inp_names
    assert "comment" in inp_names

    f2 = res.forms[1]
    assert f2.action == "/login"
    assert f2.method == "GET"

    assert "assets/main.bundle.js" in res.files
    assert "downloads/backup.kdbx" in res.files


def test_js_parser_ast_with_jsluice():
    js_code = """
    const API_BASE = "/rest/captcha/";
    const feedbackUrl = "/api/Feedbacks";
    function loadProducts() {
        return fetch("/api/Products/search?q=" + query);
    }
    const secretJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummySecret";
    """
    res = parse_js(js_code)

    assert "/rest/captcha/" in res.routes
    assert "/api/Feedbacks" in res.routes
    assert any("/api/Products" in r for r in res.routes)


def test_json_parser_openapi_specification():
    swagger = {
        "swagger": "2.0",
        "paths": {
            "/api/Users": {
                "get": {
                    "parameters": [{"name": "limit", "in": "query", "type": "integer"}]
                },
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "properties": {
                                        "email": {"type": "string"},
                                        "password": {"type": "string"},
                                    }
                                }
                            }
                        }
                    }
                },
            }
        },
    }
    res = parse_json(swagger)
    assert "/api/Users" in res.routes
    assert len(res.forms) == 2
    get_form = next(f for f in res.forms if f.method == "GET")
    post_form = next(f for f in res.forms if f.method == "POST")

    assert get_form.inputs[0].name == "limit"
    post_inputs = [i.name for i in post_form.inputs]
    assert "email" in post_inputs
    assert "password" in post_inputs


def test_sidecar_manifest_lifecycle(tmp_path):
    artifact = tmp_path / "test_artifact.html"
    content = """
    <html>
      <body>
        <form action="/rest/user/login" method="POST">
          <input name="email" type="text"/>
          <input name="password" type="password"/>
        </form>
      </body>
    </html>
    """
    artifact.write_text(content, encoding="utf-8")

    manifest_path = create_sidecar_manifest(artifact, url="http://127.0.0.1:3000")
    assert manifest_path is not None
    assert manifest_path.exists()

    manifest_data = read_sidecar_manifest(artifact)
    assert manifest_data is not None
    assert "/rest/user/login" in manifest_data["routes"]
    assert len(manifest_data["forms"]) == 1
    assert manifest_data["forms"][0]["inputs"][0]["name"] == "email"


@pytest.mark.asyncio
async def test_read_artifact_grep_and_manifest_views(engine, tmp_path):
    async with get_async_session_ctx() as session:
        assessment = Assessment(title="Grep Test", targets=["127.0.0.1"], ports=[3000])
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        art_file = tmp_path / "multi_line.txt"
        content = (
            "line 1: initializing service\n"
            "line 2: database connected at port 5432\n"
            "line 3: token=alpha123 for service auth\n"
            "line 4: processing request\n"
            "line 5: secondary token=beta456 generated\n"
            "line 6: done\n"
        )
        art_file.write_text(content, encoding="utf-8")

        # Create sidecar manifest
        create_sidecar_manifest(art_file, url="http://127.0.0.1:3000")

        step_repo = StepRepo(session)
        step, _ = await step_repo.create_planned_step(
            assessment_id=assessment.id,
            run_id="run-grep",
            role="discovery",
            action="curl_request",
            target="127.0.0.1",
        )
        await step_repo.complete_step(step.id, status=StepStatus.SUCCEEDED.value, output_path=str(art_file))
        await session.commit()

        # 1. Multi-match search
        obs = await read_artifact(session, assessment.id, step.id, search="token")
        assert obs.ok is True
        assert "Found 2 match(es)" in obs.summary
        assert "Match 1 at line 3" in obs.summary
        assert "Match 2 at line 5" in obs.summary
        assert "token=alpha123" in obs.summary
        assert "token=beta456" in obs.summary

        # 2. Manifest view
        obs_manifest = await read_artifact(session, assessment.id, step.id, view="manifest")
        assert obs_manifest.ok is True
        assert "Manifest (manifest)" in obs_manifest.summary
        assert "facts" in obs_manifest.facts or "manifest" in obs_manifest.facts


def test_parse_content_json_with_table_text():
    """Ensure JSON API responses containing table text are parsed as JSON, not HTML."""
    json_payload = json.dumps({
        "status": "success",
        "doc": "<table><tr><td>specs</td></tr></table>",
        "paths": {
            "/api/v2/items": {"get": {}},
        },
    })
    # Sniffed JSON without content-type
    res = parse_content(json_payload, url="http://127.0.0.1:3000/api/docs")
    assert "status" in res.keys
    assert "doc" in res.keys
    assert "/api/v2/items" in res.routes

    # With content-type application/json
    res_ct = parse_content(json_payload, url="http://127.0.0.1:3000/api/docs", content_type="application/json")
    assert "status" in res_ct.keys
    assert "/api/v2/items" in res_ct.routes


def test_sidecar_manifest_unpacks_probe_result(tmp_path):
    """Ensure artifacts with 'probe_result' format are properly unpacked into sidecar manifests."""
    probe_file = tmp_path / "probe_sample.http_probe.json"
    probe_payload = {
        "probe_result": {
            "url": "http://127.0.0.1:3000/test-page",
            "url_probed": "http://127.0.0.1:3000/test-page",
            "method": "GET",
            "status_code": 200,
            "headers": {"content-type": "text/html; charset=UTF-8"},
            "body_preview": "<html><body><a href=\"/api/v1/users\">Users</a><a href=\"/test-page\">Self</a></body></html>",
        },
        "step_id": 5,
    }
    probe_file.write_text(json.dumps(probe_payload), encoding="utf-8")

    manifest_path = create_sidecar_manifest(probe_file)
    assert manifest_path is not None
    assert manifest_path.exists()

    manifest_data = read_sidecar_manifest(probe_file)
    assert manifest_data is not None
    # /api/v1/users must be extracted
    assert "/api/v1/users" in manifest_data["routes"]
    # Self-route /test-page must be filtered out
    assert "/test-page" not in manifest_data["routes"]


def test_filter_self_routes_with_query_params():
    """Ensure filter_self_routes filters relative URLs with query parameters matching request path."""
    from app.parsers.manifest import filter_self_routes

    routes = [
        "/login?redirect=1",
        "login?redirect=1",
        "/login",
        "login",
        "/dashboard",
        "/dashboard?tab=settings",
    ]
    filtered = filter_self_routes(routes, "http://127.0.0.1:3000/login")
    assert "/login?redirect=1" not in filtered
    assert "login?redirect=1" not in filtered
    assert "/login" not in filtered
    assert "login" not in filtered
    assert "/dashboard" in filtered
    assert "/dashboard?tab=settings" in filtered

