"""Tests for command-line argument resolution and construction across all catalogued tools."""

from __future__ import annotations

from pathlib import Path
import pytest

from app.actions.catalogue import (
    NMAP_SAFE_SCRIPTS,
    UnknownAction,
    get_action,
    resolve_argv,
)
from app.adapters import hashcat, nikto, nmap, sqlmap, whatweb
from app.core.config import settings
from app.domain.models import Assessment


@pytest.fixture(autouse=True)
def _ensure_local(monkeypatch):
    monkeypatch.setattr(settings, "mcp_enabled", False)
    monkeypatch.setattr(settings, "mcp_transport", "local")


@pytest.fixture
def assessment():
    return Assessment(
        id=42,
        title="Argv Target",
        targets=["127.0.0.1"],
        ports=[3000],
    )


def test_nmap_argv_profiles(assessment):
    # Fast profile
    argv_fast = resolve_argv("nmap_scan", assessment, "127.0.0.1", 1, {"profile": "fast", "ports": "top100"})
    assert "nmap" in argv_fast[0]
    assert "--top-ports" in argv_fast
    assert "100" in argv_fast

    # Service profile
    argv_svc = resolve_argv("nmap_scan", assessment, "127.0.0.1", 1, {"profile": "service", "ports": "top1000"})
    assert "-sV" in argv_svc
    assert "--top-ports" in argv_svc
    assert "1000" in argv_svc

    # Full TCP profile
    argv_full_tcp = resolve_argv("nmap_scan", assessment, "127.0.0.1", 1, {"profile": "full_tcp"})
    assert "-p-" in argv_full_tcp

    # Host discovery profile
    argv_host = resolve_argv("nmap_scan", assessment, "127.0.0.1", 1, {"profile": "host_discovery"})
    assert "-sn" in argv_host


def test_nmap_nse_script_allowlist_enforcement(assessment):
    # Safe scripts are allowed
    argv = resolve_argv("nmap_scan", assessment, "127.0.0.1", 1, {"scripts": ["http-title", "ssl-cert"]})
    assert "--script" in argv
    script_idx = argv.index("--script")
    assert "http-title" in argv[script_idx + 1]
    assert "ssl-cert" in argv[script_idx + 1]

    # Dangerous or unallowlisted scripts MUST be rejected
    with pytest.raises(ValueError, match="not in NMAP_SAFE_SCRIPTS allowlist"):
        resolve_argv("nmap_scan", assessment, "127.0.0.1", 1, {"scripts": ["vuln"]})

    with pytest.raises(ValueError, match="not in NMAP_SAFE_SCRIPTS allowlist"):
        resolve_argv("nmap_scan", assessment, "127.0.0.1", 1, {"scripts": ["exploit"]})


def test_nikto_argv(assessment):
    argv = resolve_argv("nikto_scan", assessment, "127.0.0.1", 2, {"port": 3000})
    assert any("nikto" in arg for arg in argv)
    assert "-h" in argv
    assert "-output" in argv


def test_dirb_argv(assessment):
    argv = resolve_argv("dirb_scan", assessment, "127.0.0.1", 3, {"wordlist": "common.txt"})
    assert any("dirb" in arg for arg in argv)
    assert "http://127.0.0.1:3000/" in argv


def test_sqlmap_argv_get_and_post(assessment):
    # GET scan
    argv_get = resolve_argv(
        "sqlmap_scan",
        assessment,
        "127.0.0.1",
        4,
        {"url": "http://127.0.0.1:3000/api/items?id=1", "parameter": "id", "level": 2, "risk": 1},
    )
    assert any("sqlmap" in arg for arg in argv_get)
    assert "--batch" in argv_get
    assert "-u" in argv_get
    assert "http://127.0.0.1:3000/api/items?id=1" in argv_get
    assert "-p" in argv_get
    assert "id" in argv_get
    assert "--level" in argv_get
    assert "2" in argv_get

    # POST scan with data
    argv_post = resolve_argv(
        "sqlmap_scan",
        assessment,
        "127.0.0.1",
        5,
        {
            "url": "http://127.0.0.1:3000/login",
            "method": "POST",
            "data": "user=admin&pass=secret",
            "parameter": "user",
        },
    )
    assert "--data" in argv_post
    data_idx = argv_post.index("--data")
    assert "user=admin&pass=secret" in argv_post[data_idx + 1]


def test_whatweb_argv(assessment):
    argv = resolve_argv("whatweb", assessment, "127.0.0.1", 6)
    assert any("whatweb" in arg for arg in argv)
    assert "--log-json" in argv


def test_hashcat_argv_has_outfile_format_1_and_bounds(assessment):
    argv = resolve_argv(
        "hashcat_crack",
        assessment,
        "127.0.0.1",
        7,
        {"hash_mode": 0, "hash_value": "5d41402abc4b2a76b9719d911017c592"},
    )
    assert "--outfile-format" in argv
    fmt_idx = argv.index("--outfile-format")
    assert argv[fmt_idx + 1] == "1"
    assert "-m" in argv
    m_idx = argv.index("-m")
    assert argv[m_idx + 1] == "0"


def test_unknown_action_raises(assessment):
    with pytest.raises(UnknownAction):
        resolve_argv("metasploit_exploit", assessment, "127.0.0.1", 99)
