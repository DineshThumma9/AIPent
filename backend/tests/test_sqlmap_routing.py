"""sqlmap must be aimable at the endpoint the evidence points to."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from app.actions import catalogue
from app.agents.loop.tool_specs import SqlmapArgs
from app.core.config import settings
from app.domain.models import Assessment


def _assessment() -> Assessment:
    return Assessment(title="Lab", targets=["127.0.0.1"], ports=[3000])


def test_sqlmap_argv_targets_the_exact_endpoint():
    argv = catalogue._sqlmap_argv(
        _assessment(),
        "127.0.0.1",
        Path("/tmp/unused"),
        {"url": "/rest/products/search?q=test", "parameter": "q"},
    )

    assert argv[0] == "sqlmap"
    assert "http://127.0.0.1:3000/rest/products/search?q=test" in argv
    assert argv[argv.index("-p") + 1] == "q"
    assert "--batch" in argv
    assert argv[argv.index("--level") + 1] == "2"
    assert argv[argv.index("--risk") + 1] == "1"
    assert "--dbs" not in argv


def test_sqlmap_argv_adds_a_test_value_for_a_bare_parameter():
    argv = catalogue._sqlmap_argv(
        _assessment(),
        "127.0.0.1",
        Path("/tmp/unused"),
        {"url": "/rest/products/search", "parameter": "q"},
    )

    assert "http://127.0.0.1:3000/rest/products/search?q=1" in argv


def test_sqlmap_argv_post_json_sets_data_and_content_type():
    argv = catalogue._sqlmap_argv(
        _assessment(),
        "127.0.0.1",
        Path("/tmp/unused"),
        {
            "url": "/rest/user/login",
            "method": "POST",
            "parameter": "email",
            "data": '{"email":"a@b.c","password":"x"}',
        },
    )

    assert argv[argv.index("--data") + 1] == '{"email":"a@b.c","password":"x"}'
    assert argv[argv.index("--headers") + 1] == "Content-Type: application/json"
    assert argv[argv.index("-p") + 1] == "email"


def test_sqlmap_rejects_out_of_scope_absolute_url():
    with pytest.raises(catalogue.ScopeError):
        catalogue._sqlmap_argv(
            _assessment(),
            "127.0.0.1",
            Path("/tmp/unused"),
            {"url": "http://evil.example/rest/products/search?q=1"},
        )


def test_sqlmap_rejects_shell_metacharacters_in_parameter():
    with pytest.raises(ValueError):
        catalogue._sqlmap_argv(
            _assessment(),
            "127.0.0.1",
            Path("/tmp/unused"),
            {"url": "/rest/products/search?q=1", "parameter": "q; rm -rf /"},
        )


def test_sqlmap_mcp_descriptor_carries_the_endpoint(monkeypatch):
    monkeypatch.setattr(settings, "mcp_enabled", True)
    monkeypatch.setattr(settings, "mcp_transport", "gateway")
    assessment = _assessment()

    tool, arguments = catalogue.mcp_tool_call(
        "sqlmap_scan",
        assessment,
        "127.0.0.1",
        params={"url": "/rest/products/search?q=test", "parameter": "q"},
    )

    alias = catalogue.transport_target("127.0.0.1")
    assert tool == "sqlmap_scan"
    assert arguments["target_url"] == f"http://{alias}:3000/rest/products/search?q=test"
    assert "-p q" in arguments["params"]
    assert "--dbs" not in arguments["params"]


def test_sqlmap_args_require_an_endpoint():
    with pytest.raises(ValidationError):
        SqlmapArgs(target="127.0.0.1", rationale="test the search parameter")


def test_sqlmap_appends_parameter_when_a_query_string_already_exists():
    argv = catalogue._sqlmap_argv(
        _assessment(),
        "127.0.0.1",
        Path("/tmp/unused"),
        {"url": "/search?category=books", "parameter": "q"},
    )

    assert (
        "http://127.0.0.1:3000/search?category=books&q=1" in argv
    )


def test_sqlmap_does_not_duplicate_a_parameter_already_in_the_url():
    argv = catalogue._sqlmap_argv(
        _assessment(),
        "127.0.0.1",
        Path("/tmp/unused"),
        {"url": "/search?q=test", "parameter": "q"},
    )

    url = argv[argv.index("-u") + 1]
    assert url.count("q=") == 1


def test_sqlmap_preserves_https_for_an_absolute_url():
    assessment = Assessment(
        title="Lab", targets=["example.com"], ports=[8443]
    )
    argv = catalogue._sqlmap_argv(
        assessment,
        "example.com",
        Path("/tmp/unused"),
        {"url": "https://example.com:8443/search?q=1", "parameter": "q"},
    )

    assert argv[argv.index("-u") + 1].startswith(
        "https://example.com:8443/search"
    )


def test_sqlmap_uses_https_when_the_target_port_is_443():
    assessment = Assessment(title="Lab", targets=["example.com"], ports=[443])
    argv = catalogue._sqlmap_argv(
        assessment,
        "example.com",
        Path("/tmp/unused"),
        {"url": "/search?q=1", "parameter": "q"},
    )

    assert argv[argv.index("-u") + 1].startswith(
        "https://example.com:443/search"
    )
