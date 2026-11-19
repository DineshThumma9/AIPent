"""Tests for automated finding parsing in sqlmap and dirb adapters."""

from app.actions import catalogue
from app.adapters import dirb, sqlmap
from app.domain.models import FindingStatus, Severity


def test_sqlmap_scan_parser_confirmed():
    text = (
        "sqlmap identified the following injection point(s) with a total of 91 HTTP(s) requests:\n"
        "---\n"
        "Parameter: q (GET)\n"
        "    Type: boolean-based blind\n"
        "    Title: AND boolean-based blind - WHERE or HAVING clause\n"
        "    Payload: q=apple' AND 1=1--\n"
        "---\n"
        "[INFO] the back-end DBMS is SQLite\n"
    )
    drafts = sqlmap.scan(text, "127.0.0.1", 3000)
    assert len(drafts) == 1
    d = drafts[0]
    assert d.severity == Severity.HIGH
    assert d.status == FindingStatus.CONFIRMED
    assert "parameter 'q'" in d.title
    assert "boolean-based blind" in d.description
    assert d.cwe == ["CWE-89"]
    assert len(d.evidence) == 1
    assert d.endpoint == "http://127.0.0.1:3000/"


def test_sqlmap_parser_keeps_tested_url():
    text = (
        "URL: http://127.0.0.1:3000/rest/products/search?q=apple\n"
        "sqlmap identified the following injection point(s) with a total of 91 HTTP(s) requests:\n"
        "---\n"
        "Parameter: q (GET)\n"
        "    Type: boolean-based blind\n"
    )
    drafts = sqlmap.scan(text, "127.0.0.1", 3000)
    assert len(drafts) == 1
    assert drafts[0].endpoint == "http://127.0.0.1:3000/rest/products/search?q=apple"


def test_sqlmap_scan_parser_clean_negative():
    text = "[WARNING] GET parameter 'q' does not seem to be injectable\n"
    drafts = sqlmap.scan(text, "127.0.0.1", 3000)
    assert drafts == []


def test_dirb_scan_parser():
    text = (
        "----------------- DIRB v2.22 -----------------\n"
        "URL_BASE: http://127.0.0.1:3000/\n"
        "------------------------------------\n"
        "---- Scanning URL: http://127.0.0.1:3000/ ----\n"
        "==> DIRECTORY: http://127.0.0.1:3000/api/\n"
        "+ http://127.0.0.1:3000/robots.txt (CODE:200|SIZE:45)\n"
        "+ http://127.0.0.1:3000/rest/products/search (CODE:200|SIZE:1632)\n"
        "==> DIRECTORY: http://127.0.0.1:3000/admin/\n"
    )
    drafts = dirb.scan(text, "127.0.0.1", 3000)
    assert len(drafts) == 4

    endpoints = {d.endpoint for d in drafts}
    assert "/api/" in endpoints
    assert "/robots.txt" in endpoints
    assert "/rest/products/search" in endpoints
    assert "/admin/" in endpoints

    # admin and api should be flagged sensitive (LOW severity instead of INFO)
    admin_draft = next(d for d in drafts if d.endpoint == "/admin/")
    assert admin_draft.severity == Severity.LOW
    assert admin_draft.status == FindingStatus.SUSPECTED


def test_catalogue_specs_use_parsers():
    sqlmap_spec = catalogue.get_action("sqlmap_scan")
    assert sqlmap_spec.parse is not None
    assert sqlmap_spec.parse != (lambda _t, _h, _p: [])

    dirb_spec = catalogue.get_action("dirb_scan")
    assert dirb_spec.parse is not None
    assert dirb_spec.parse != (lambda _t, _h, _p: [])
