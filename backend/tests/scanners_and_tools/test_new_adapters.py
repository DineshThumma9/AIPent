"""Unit tests for new tool adapters: FFUF, Katana, and Nuclei."""

from __future__ import annotations

import json
import pytest

from app.domain.models import FindingStatus, Origin, Severity


def test_ffuf_argv_builder():
    from app.adapters import ffuf

    args = ffuf.argv("127.0.0.1", 3000, "/tmp/out.json", wordlist="common.txt")
    assert "ffuf" in args[0]
    assert "-u" in args
    assert "http://127.0.0.1:3000/FUZZ" in args
    assert "-w" in args
    assert "-o" in args


def test_ffuf_argv_builder_preserves_custom_fuzz():
    from app.adapters import ffuf

    args = ffuf.argv("127.0.0.1", 3000, "/tmp/out.json", path="/api/v1/FUZZ")
    assert "-u" in args
    assert "http://127.0.0.1:3000/api/v1/FUZZ" in args


def test_ffuf_parser_json():
    from app.adapters import ffuf

    mock_json = json.dumps(
        {
            "results": [
                {
                    "input": {"FUZZ": "admin"},
                    "url": "http://127.0.0.1:3000/admin",
                    "status": 200,
                    "length": 1542,
                    "words": 42,
                    "lines": 12,
                },
                {
                    "input": {"FUZZ": "robots.txt"},
                    "url": "http://127.0.0.1:3000/robots.txt",
                    "status": 200,
                    "length": 250,
                    "words": 10,
                    "lines": 5,
                },
            ]
        }
    )
    findings = ffuf.scan(mock_json, "127.0.0.1", 3000)
    assert len(findings) == 2
    assert findings[0].endpoint == "/admin"
    assert findings[0].severity == Severity.LOW  # sensitive keyword
    assert findings[1].endpoint == "/robots.txt"
    assert findings[1].severity == Severity.INFO
    assert findings[0].status == FindingStatus.SUSPECTED
    assert findings[0].origin == Origin.TOOL


def test_ffuf_parser_empty():
    from app.adapters import ffuf

    assert ffuf.scan("", "127.0.0.1", 3000) == []
    assert ffuf.scan("{}", "127.0.0.1", 3000) == []
