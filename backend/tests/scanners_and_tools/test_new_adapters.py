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
    assert "-ac" in args


def test_ffuf_argv_builder_with_calibration_and_filters():
    from app.adapters import ffuf

    args = ffuf.argv(
        "127.0.0.1",
        3000,
        "/tmp/out.json",
        filter_status="404,500",
        filter_size="1542",
        auto_calibrate=True,
    )
    assert "-ac" in args
    assert "-fc" in args
    assert "404,500" in args
    assert "-fs" in args
    assert "1542" in args


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


def test_ffuf_parser_spa_catchall_filtering():
    from app.adapters import ffuf

    # Simulating an SPA where 6 non-existent paths return HTTP 200 with identical length (5230 bytes)
    mock_results = [
        {"input": {"FUZZ": f"random_{i}"}, "url": f"http://127.0.0.1:3000/random_{i}", "status": 200, "length": 5230}
        for i in range(6)
    ]
    # And one real API endpoint with different length (340 bytes)
    mock_results.append(
        {"input": {"FUZZ": "api/v1/status"}, "url": "http://127.0.0.1:3000/api/v1/status", "status": 200, "length": 340}
    )

    mock_json = json.dumps({"results": mock_results})
    findings = ffuf.scan(mock_json, "127.0.0.1", 3000)

    # The 6 wildcard/SPA responses of length 5230 should be filtered out, leaving only the real endpoint
    assert len(findings) == 1
    assert findings[0].endpoint == "/api/v1/status"



def test_katana_argv_builder():
    from app.adapters import katana

    args = katana.argv("127.0.0.1", 3000, "/tmp/out.txt", depth=2)
    assert "katana" in args[0]
    assert "-u" in args
    assert "http://127.0.0.1:3000" in args
    assert "-d" in args
    assert "2" in args
    assert "-jc" in args


def test_katana_parser_jsonl_and_text():
    from app.adapters import katana

    jsonl_text = "\n".join(
        [
            json.dumps({"request": {"endpoint": "http://127.0.0.1:3000/api/v1/users", "method": "GET"}}),
            json.dumps({"request": {"endpoint": "http://127.0.0.1:3000/assets/main.js", "method": "GET"}}),
            "http://127.0.0.1:3000/rest/admin/settings",
            "",
            "invalid-url-to-skip",
        ]
    )
    findings = katana.scan(jsonl_text, "127.0.0.1", 3000)
    assert len(findings) == 3
    endpoints = {f.endpoint for f in findings}
    assert "/api/v1/users" in endpoints
    assert "/assets/main.js" in endpoints
    assert "/rest/admin/settings" in endpoints

    admin_f = next(f for f in findings if f.endpoint == "/rest/admin/settings")
    assert admin_f.severity == Severity.LOW
    assert admin_f.origin == Origin.TOOL
    assert admin_f.status == FindingStatus.SUSPECTED

    js_f = next(f for f in findings if f.endpoint == "/assets/main.js")
    assert js_f.severity == Severity.INFO


def test_katana_parser_empty():
    from app.adapters import katana

    assert katana.scan("", "127.0.0.1", 3000) == []


def test_nuclei_argv_builder():
    from app.adapters import nuclei

    args = nuclei.argv("127.0.0.1", 3000, "/tmp/out.jsonl", tags="cve,xss", severity="high,critical")
    assert "nuclei" in args[0]
    assert "-u" in args
    assert "http://127.0.0.1:3000" in args
    assert "-tags" in args
    assert "cve,xss" in args
    assert "-severity" in args
    assert "high,critical" in args
    assert "-jsonl" in args


def test_nuclei_parser_jsonl():
    from app.adapters import nuclei

    mock_line = json.dumps(
        {
            "template-id": "cve-2020-5902",
            "info": {
                "name": "F5 BIG-IP TMUI RCE",
                "severity": "critical",
                "description": "Remote code execution vulnerability in F5 BIG-IP.",
                "classification": {
                    "cve-id": ["CVE-2020-5902"],
                    "cwe-id": ["CWE-22", "CWE-78"],
                    "cvss-score": 9.8,
                },
            },
            "matched-at": "http://127.0.0.1:3000/tmui/login.jsp",
            "curl-command": "curl -X GET 'http://127.0.0.1:3000/tmui/login.jsp'",
        }
    )
    findings = nuclei.scan(mock_line, "127.0.0.1", 3000)
    assert len(findings) == 1
    f = findings[0]
    assert f.title == "F5 BIG-IP TMUI RCE"
    assert f.severity == Severity.CRITICAL
    assert f.status == FindingStatus.CONFIRMED
    assert f.cve == ["CVE-2020-5902"]
    assert "CWE-22" in f.cwe
    assert f.endpoint == "/tmui/login.jsp"
    assert "curl -X GET" in f.evidence[0].excerpt


def test_nuclei_parser_empty():
    from app.adapters import nuclei

    assert nuclei.scan("", "127.0.0.1", 3000) == []


