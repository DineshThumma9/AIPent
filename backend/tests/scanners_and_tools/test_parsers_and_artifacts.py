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


def test_ffuf_json_parsing_and_manifest(tmp_path):
    """Ensure FFUF JSON output is safely extracted into routes and files without 500 errors or wildcard noise."""
    ffuf_payload = {
        "commandline": "ffuf -u http://127.0.0.1:3000/FUZZ -w common.txt",
        "results": [
            {"url": "http://127.0.0.1:3000/ftp", "status": 200, "length": 11328},
            {"url": "http://127.0.0.1:3000/robots.txt", "status": 200, "length": 28},
            {"url": "http://127.0.0.1:3000/ftp/acquisitions.md", "status": 200, "length": 350},
            {"url": "http://127.0.0.1:3000/assets", "status": 301, "length": 156},
            {"url": "http://127.0.0.1:3000/.env", "status": 200, "length": 42},
            {"url": "http://127.0.0.1:3000/config/.backup", "status": 200, "length": 100},
            {"url": "http://127.0.0.1:3000", "status": 200, "length": 1000},
            {"url": "http://127.0.0.1:3000/administration", "status": 403, "length": 500},
            {"url": "http://127.0.0.1:3000/api", "status": 500, "length": 2408},
            {"url": "http://127.0.0.1:3000/rest", "status": 500, "length": 2410},
            # Wildcard catch-all SPA fallbacks (same length 9984 >= 5 times)
            {"url": "http://127.0.0.1:3000/bogus1", "status": 200, "length": 9984},
            {"url": "http://127.0.0.1:3000/bogus2", "status": 200, "length": 9984},
            {"url": "http://127.0.0.1:3000/bogus3", "status": 200, "length": 9984},
            {"url": "http://127.0.0.1:3000/bogus4", "status": 200, "length": 9984},
            {"url": "http://127.0.0.1:3000/bogus5", "status": 200, "length": 9984},
        ],
        "config": {},
    }

    res = parse_json(ffuf_payload)

    # Valid reachable routes must be extracted
    assert "/ftp" in res.routes
    assert "/assets" in res.routes
    assert "/administration" in res.routes
    assert "/robots.txt" in res.routes
    assert "/ftp/acquisitions.md" in res.routes

    # Files must be separated (including dotfiles like /.env)
    assert "/robots.txt" in res.files
    assert "/ftp/acquisitions.md" in res.files
    assert "/.env" in res.files
    assert "/config/.backup" in res.files
    assert "/ftp" not in res.files

    # Root URLs without trailing path must not produce corrupted route strings
    assert "/http://127.0.0.1:3000" not in res.routes

    # 500 server errors and wildcard SPA fallbacks must NOT be in routes
    assert "/api" not in res.routes
    assert "/rest" not in res.routes
    assert "/bogus1" not in res.routes
    assert "/bogus5" not in res.routes

    # Sidecar manifest creation test
    ffuf_file = tmp_path / "101.ffuf.json"
    ffuf_file.write_text(json.dumps(ffuf_payload), encoding="utf-8")

    manifest_path = create_sidecar_manifest(ffuf_file, url="127.0.0.1:3000")
    assert manifest_path is not None
    assert manifest_path.exists()

    manifest_data = read_sidecar_manifest(ffuf_file)
    assert manifest_data is not None
    assert "/ftp" in manifest_data["routes"]
    assert "/ftp/acquisitions.md" in manifest_data["files"]
    assert "/api" not in manifest_data["routes"]


@pytest.mark.asyncio
async def test_read_artifact_ffuf_routes_and_files_view(engine, tmp_path):
    async with get_async_session_ctx() as session:
        assessment = Assessment(title="FFUF Views", targets=["127.0.0.1"], ports=[3000])
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        ffuf_file = tmp_path / "301.ffuf.json"
        ffuf_file.write_text(
            json.dumps({
                "commandline": "ffuf -u http://127.0.0.1:3000/FUZZ",
                "results": [
                    {"url": "http://127.0.0.1:3000/ftp", "status": 200, "length": 11328},
                    {"url": "http://127.0.0.1:3000/robots.txt", "status": 200, "length": 28},
                    {"url": "http://127.0.0.1:3000/api", "status": 500, "length": 2408},
                ],
            }),
            encoding="utf-8",
        )
        create_sidecar_manifest(ffuf_file, url="127.0.0.1:3000")

        step_repo = StepRepo(session)
        step, _ = await step_repo.create_planned_step(
            assessment_id=assessment.id,
            run_id="run-views",
            role="discovery",
            action="ffuf_scan",
            target="127.0.0.1",
        )
        await step_repo.complete_step(step.id, status=StepStatus.SUCCEEDED.value, output_path=str(ffuf_file))
        await session.commit()

        # Test view="routes"
        obs_routes = await read_artifact(session, assessment.id, step.id, view="routes")
        assert obs_routes.ok is True
        assert "/ftp" in obs_routes.summary
        assert "/robots.txt" in obs_routes.summary
        assert "/api" not in obs_routes.summary

        # Test view="files"
        obs_files = await read_artifact(session, assessment.id, step.id, view="files")
        assert obs_files.ok is True
        assert "/robots.txt" in obs_files.summary
        assert "/ftp" not in obs_files.summary


def test_js_parser_extracts_spa_hash_and_framework_routes():
    """Ensure js_parser extracts Angular/React router tables and preserves /#/ routes."""
    js_code = """
    // Framework route configuration (Angular / React Router style)
    const routes = [
        { path: 'administration', component: AdminComponent },
        { path: 'score-board', component: ScoreBoardComponent },
        { path: 'accounting', redirectTo: '/accounting-login' },
    ];
    function navigate() {
        window.location.href = "/#/tokens";
        fetch("/api/Feedbacks");
    }
    """
    res = parse_js(js_code)
    # Direct and hash versions of router definitions
    assert "/#/administration" in res.routes
    assert "/administration" in res.routes
    assert "/#/score-board" in res.routes
    assert "/score-board" in res.routes
    assert "/#/accounting" in res.routes
    assert "/#/tokens" in res.routes
    assert "/api/Feedbacks" in res.routes


def test_filter_self_routes_preserves_spa_hash_routes():
    """Ensure filter_self_routes does not discard SPA hash routes like /#/administration."""
    from app.parsers.manifest import filter_self_routes

    routes = [
        "/",
        "/#/administration",
        "/#/score-board",
        "#/tokens",
        "/login",
        "/login?ref=1",
    ]
    filtered = filter_self_routes(routes, "http://127.0.0.1:3000/")
    assert "/" not in filtered
    assert "/#/administration" in filtered
    assert "/#/score-board" in filtered
    assert "#/tokens" in filtered
    assert "/login" in filtered


def test_html_parser_extracts_spa_hash_routes():
    """Ensure html_parser extracts SPA hash routes from anchor tags and scripts."""
    html = """
    <!DOCTYPE html>
    <html>
      <head><title>Juice Shop</title></head>
      <body>
        <a href="/#/administration">Admin</a>
        <a href="#/score-board">Scoreboard</a>
        <script src="main.js"></script>
        <script src="runtime.js"></script>
      </body>
    </html>
    """
    res = parse_html(html, base_url="http://127.0.0.1:3000")
    assert "/#/administration" in res.routes
    assert "/administration" in res.routes
    assert "/#/score-board" in res.routes
    assert "main.js" in res.files
    assert "runtime.js" in res.files


def test_html_and_js_parser_preserve_absolute_hash_routes():
    """Ensure absolute URLs with hash routes (e.g. http://host/#/administration) are not dropped."""
    html = """
    <div>
        <a href="http://127.0.0.1:3000/#/administration">Admin Panel</a>
        <p>Endpoint in script: "http://target.local/#/score-board"</p>
    </div>
    """
    res_html = parse_html(html, base_url="http://127.0.0.1:3000")
    assert "/#/administration" in res_html.routes
    assert "/administration" in res_html.routes
    assert "/#/score-board" in res_html.routes
    assert "/score-board" in res_html.routes

    js_code = """
    const adminUrl = "https://example.com/#/administration";
    const boardUrl = "http://target.local/#/tokens";
    """
    res_js = parse_js(js_code)
    assert "/#/administration" in res_js.routes
    assert "/administration" in res_js.routes
    assert "/#/tokens" in res_js.routes


def test_ffuf_argv_filters_out_invalid_filter_size_and_status():
    """Ensure string 'none' or 'null' is never passed as -fs or -fc to ffuf CLI."""
    from app.adapters.ffuf import argv

    # When filter_size or filter_status is "none", they should be omitted
    args_none = argv(target="http://127.0.0.1:3000", port=3000, output_path="/tmp/out.json", filter_size="none", filter_status="none")
    assert "-fs" not in args_none
    assert "-fc" not in args_none
    assert "none" not in args_none

    # When valid values are passed, they should be present
    args_valid = argv(target="http://127.0.0.1:3000", port=3000, output_path="/tmp/out.json", filter_size="5230", filter_status="404,500")
    assert "-fs" in args_valid
    assert "5230" in args_valid
    assert "-fc" in args_valid
    assert "404,500" in args_valid


def test_extract_wildcard_lengths_ignores_small_responses():
    """Small responses (< 100 bytes) like empty body (0) or {} (2) must not be treated as wildcard fallbacks."""
    from app.adapters.ffuf import extract_wildcard_lengths

    results = [
        {"url": "http://127.0.0.1:3000/a", "status": 200, "length": 0},
        {"url": "http://127.0.0.1:3000/b", "status": 200, "length": 0},
        {"url": "http://127.0.0.1:3000/c", "status": 200, "length": 0},
        {"url": "http://127.0.0.1:3000/d", "status": 200, "length": 0},
        {"url": "http://127.0.0.1:3000/e", "status": 200, "length": 0},
        # Real wildcard catch-all pages (> 100 bytes)
        {"url": "http://127.0.0.1:3000/w1", "status": 200, "length": 9999},
        {"url": "http://127.0.0.1:3000/w2", "status": 200, "length": 9999},
        {"url": "http://127.0.0.1:3000/w3", "status": 200, "length": 9999},
        {"url": "http://127.0.0.1:3000/w4", "status": 200, "length": 9999},
        {"url": "http://127.0.0.1:3000/w5", "status": 200, "length": 9999},
    ]
    wildcards = extract_wildcard_lengths(results)
    assert 9999 in wildcards
    assert 0 not in wildcards


def test_nikto_adapter_prevents_url_doubling():
    """Ensure Nikto adapter does not double scheme/host when host is already a full URL."""
    from app.adapters.nikto import NiktoItem, to_drafts

    items = [
        NiktoItem(id="1", msg="CORS header wildcard found", url="/", method="GET"),
        NiktoItem(id="2", msg="robots.txt found", url="/robots.txt", method="GET"),
    ]
    # Pass host with scheme and port
    drafts = to_drafts(host="http://127.0.0.1:3000", port=3000, items=items)
    assert len(drafts) == 2
    for d in drafts:
        assert "http://http://" not in d.endpoint
        assert ":3000:3000" not in d.endpoint
        assert d.asset == "127.0.0.1"
        assert d.canonical_key.startswith("web:")
        assert "http://http://" not in d.canonical_key
    assert drafts[0].endpoint == "http://127.0.0.1:3000/"
    assert drafts[1].endpoint == "http://127.0.0.1:3000/robots.txt"





