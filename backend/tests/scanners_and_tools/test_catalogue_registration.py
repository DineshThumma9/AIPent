"""Integration tests verifying catalogue registration, argv builders, and mcp_tool_call mappings."""

from __future__ import annotations

import pytest
from app.actions.catalogue import ACTIONS, get_action, mcp_tool_call, resolve_argv
from app.domain.models import Assessment


@pytest.fixture
def assessment():
    return Assessment(id=1, title="Test", targets=["127.0.0.1"], ports=[3000])


def test_catalogue_actions_registered():
    for action_name in ["ffuf_scan", "katana_crawl", "nuclei_scan"]:
        assert action_name in ACTIONS
        spec = get_action(action_name)
        assert spec.name == action_name


def test_mcp_tool_call_mappings(assessment):
    tool, args = mcp_tool_call("ffuf_scan", assessment, "127.0.0.1")
    assert tool == "ffuf_scan"
    assert "FUZZ" in args["target_url"]

    tool, args = mcp_tool_call("katana_crawl", assessment, "127.0.0.1")
    assert tool == "katana_crawl"
    assert "target_url" in args

    tool, args = mcp_tool_call("nuclei_scan", assessment, "127.0.0.1", params={"tags": "cve"})
    assert tool == "nuclei_scan"
    assert "target_url" in args
    assert args.get("tags") == "cve"


def test_resolve_argv_for_new_tools(assessment):
    argv = resolve_argv("ffuf_scan", assessment, "127.0.0.1", 1)
    assert "ffuf" in argv[0]
    assert "-u" in argv

    argv = resolve_argv("katana_crawl", assessment, "127.0.0.1", 1)
    assert "katana" in argv[0]
    assert "-u" in argv

    argv = resolve_argv("nuclei_scan", assessment, "127.0.0.1", 1)
    assert "nuclei" in argv[0]
    assert "-u" in argv
