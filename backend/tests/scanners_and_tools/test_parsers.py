"""Tests for adapter parsers converting tool XML/JSON/text outputs to FindingDraft domain models."""

from __future__ import annotations

import json
import pytest

from app.adapters import dirb, nikto, nmap, sqlmap, sslscan, whatweb, zap
from app.domain.models import FindingStatus, Severity


def test_nmap_parser_extracts_open_ports(sample_nmap_xml):
    records = nmap.parse(sample_nmap_xml)
    assert [(r.port, r.state) for r in records] == [(3000, "open"), (8080, "closed")]

    drafts = nmap.to_drafts(records)
    assert len(drafts) == 1
    d = drafts[0]
    assert d.canonical_key == "nmap:127.0.0.1:tcp/3000"
    assert "3000" in d.title
    assert d.status == FindingStatus.CONFIRMED
    assert d.severity == Severity.INFO


def test_nikto_parser_drafts(sample_nikto_json):
    items = nikto.parse(sample_nikto_json)
    drafts = nikto.to_drafts("127.0.0.1", 3000, items)
    assert len(drafts) == 2
    assert all(d.canonical_key.startswith("web:") for d in drafts)
    assert drafts[0].severity == Severity.LOW
    assert drafts[0].status == FindingStatus.SUSPECTED
    assert drafts[0].evidence[0].locator["id"] == "999957"


def test_zap_parser_drafts(sample_zap_json):
    alerts = zap.parse(sample_zap_json)
    drafts = zap.to_drafts("127.0.0.1", 3000, alerts)
    assert len(drafts) == 1
    d = drafts[0]
    assert d.title == "CSP Header Not Set"
    assert d.severity == Severity.MEDIUM
    assert d.confidence == 0.9
    assert d.remediation.startswith("Set a Content-Security-Policy")
    assert d.evidence[0].locator["plugin"] == "10038"


def test_dirb_parser():
    raw_dirb = (
        "----------------- DIRB v2.22 -----------------\n"
        "URL_BASE: http://127.0.0.1:3000/\n"
        "------------------------------------\n"
        "---- Scanning URL: http://127.0.0.1:3000/ ----\n"
        "==> DIRECTORY: http://127.0.0.1:3000/api/\n"
        "+ http://127.0.0.1:3000/robots.txt (CODE:200|SIZE:45)\n"
        "+ http://127.0.0.1:3000/rest/products/search (CODE:200|SIZE:1632)\n"
        "==> DIRECTORY: http://127.0.0.1:3000/admin/\n"
    )
    drafts = dirb.scan(raw_dirb, "127.0.0.1", 3000)
    assert len(drafts) == 4

    endpoints = {d.endpoint for d in drafts}
    assert "/api/" in endpoints
    assert "/robots.txt" in endpoints
    assert "/rest/products/search" in endpoints
    assert "/admin/" in endpoints

    # Sensitive endpoints (/admin/ and /api/) flagged LOW severity, suspected
    admin_draft = next(d for d in drafts if d.endpoint == "/admin/")
    assert admin_draft.severity == Severity.LOW
    assert admin_draft.status == FindingStatus.SUSPECTED

    # Ordinary endpoints flagged INFO
    robots_draft = next(d for d in drafts if d.endpoint == "/robots.txt")
    assert robots_draft.severity == Severity.INFO


def test_sqlmap_parser_positive_and_negative(sample_sqlmap_output):
    # Positive injection
    drafts = sqlmap.scan(sample_sqlmap_output, "127.0.0.1", 3000)
    assert len(drafts) == 1
    d = drafts[0]
    assert d.severity == Severity.HIGH
    assert d.status == FindingStatus.CONFIRMED
    assert "parameter 'q'" in d.title
    assert "boolean-based blind" in d.description
    assert d.cwe == ["CWE-89"]

    # Clean negative
    clean_output = "[WARNING] GET parameter 'q' does not seem to be injectable\n"
    drafts_clean = sqlmap.scan(clean_output, "127.0.0.1", 3000)
    assert drafts_clean == []


def test_whatweb_parser_json_and_jsonl():
    # JSON array
    json_array = json.dumps([
        {
            "target": "http://127.0.0.1:3000/",
            "http_status": 200,
            "plugins": {
                "Apache": {"version": ["2.4.41"]},
                "JQuery": {"version": ["3.5.1"]},
            },
        }
    ])
    drafts = whatweb.scan(json_array, "127.0.0.1", 3000)
    assert len(drafts) == 2
    assert all(d.severity == Severity.INFO for d in drafts)
    assert all(d.canonical_key.startswith("whatweb:127.0.0.1:3000:") for d in drafts)

    # JSONL
    jsonl = (
        '{"target": "http://10.0.0.5:80/", "plugins": {"Nginx": {"version": ["1.18.0"]}}}\n'
        '{"target": "http://10.0.0.5:80/", "plugins": {"PHP": {"version": ["7.4.3"]}}}\n'
    )
    drafts_jsonl = whatweb.scan(jsonl, "10.0.0.5", 80)
    assert len(drafts_jsonl) == 2
    keys = {d.canonical_key for d in drafts_jsonl}
    assert "whatweb:10.0.0.5:80:nginx" in keys
    assert "whatweb:10.0.0.5:80:php" in keys


def test_sslscan_parser():
    sample_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <document title="SSLScan Report" version="2.0.15">
      <ssltest host="example.com" port="443">
        <protocol type="ssl" version="v2" enabled="0" />
        <protocol type="ssl" version="v3" enabled="1" />
        <protocol type="tls" version="v1.0" enabled="1" />
        <protocol type="tls" version="v1.1" enabled="0" />
        <protocol type="tls" version="v1.2" enabled="1" />
        <protocol type="tls" version="v1.3" enabled="1" />
        <certificate>
          <subject>CN=example.com</subject>
          <issuer>CN=Insecure CA</issuer>
          <validity>
            <expired>true</expired>
          </validity>
          <self-signed>true</self-signed>
        </certificate>
      </ssltest>
    </document>
    """
    drafts = sslscan.scan(sample_xml, "example.com", 443)
    titles = {d.title for d in drafts}
    assert "Insecure SSL protocol enabled (SSL V3)" in titles
    assert "Deprecated TLS protocol enabled (TLS V1.0)" in titles
    assert "Expired SSL/TLS certificate on example.com:443" in titles
    assert "Self-signed SSL/TLS certificate on example.com:443" in titles
