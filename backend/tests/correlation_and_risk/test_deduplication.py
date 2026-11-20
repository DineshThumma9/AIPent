"""Tests for cross-tool finding deduplication and canonical key calculation."""

from __future__ import annotations

import pytest

from app.adapters.base import FindingDraft
from app.domain.correlate import canonical_key
from app.domain.models import Severity


def test_canonical_key_rule_matching():
    # Content Security Policy family
    d1 = FindingDraft(
        canonical_key="raw:zap:csp",
        asset="127.0.0.1",
        endpoint="http://127.0.0.1:3000/",
        title="Content Security Policy (CSP) Header Not Set",
        severity=Severity.MEDIUM,
    )
    assert canonical_key(d1) == "web:csp:127.0.0.1:3000"

    # Anti-clickjacking / X-Frame-Options family
    d2 = FindingDraft(
        canonical_key="raw:nikto:clickjacking",
        asset="127.0.0.1",
        endpoint="http://127.0.0.1:3000/",
        title="The anti-clickjacking X-Frame-Options header is not present.",
        severity=Severity.LOW,
    )
    assert canonical_key(d2) == "web:x-frame-options:127.0.0.1:3000"

    # X-Content-Type-Options / MIME family
    d3 = FindingDraft(
        canonical_key="raw:nikto:mime",
        asset="127.0.0.1",
        endpoint="http://127.0.0.1:3000/",
        title="X-Content-Type-Options header is not set",
        severity=Severity.LOW,
    )
    assert canonical_key(d3) == "web:x-content-type-options:127.0.0.1:3000"

    # Strict-Transport-Security / HSTS family
    d4 = FindingDraft(
        canonical_key="raw:zap:hsts",
        asset="example.com",
        endpoint="https://example.com:443/",
        title="Strict-Transport-Security Header Not Set",
        severity=Severity.LOW,
    )
    assert canonical_key(d4) == "web:hsts:example.com:443"

    # Server banner leak family
    d5 = FindingDraft(
        canonical_key="raw:nikto:banner",
        asset="10.0.0.5",
        endpoint="http://10.0.0.5:8080/",
        title="Server leaks version numbers via server header",
        severity=Severity.INFO,
    )
    assert canonical_key(d5) == "web:server-banner:10.0.0.5:8080"


def test_canonical_key_http_slug_fallback():
    # HTTP endpoint without pre-defined rule family falls back to slug
    d = FindingDraft(
        canonical_key="raw:custom:sqli",
        asset="127.0.0.1",
        endpoint="http://127.0.0.1:3000/rest/products/search",
        title="SQL Injection in Search Query Parameter",
        severity=Severity.HIGH,
    )
    key = canonical_key(d)
    assert key.startswith("web:sql-injection-in-search-query-parameter:127.0.0.1:3000")


def test_canonical_key_non_http_fallback():
    # Non-HTTP target (e.g. nmap port finding) keeps its native canonical key
    d = FindingDraft(
        canonical_key="nmap:127.0.0.1:tcp/22",
        asset="127.0.0.1",
        endpoint="tcp/22",
        title="OpenSSH 8.2p1",
        severity=Severity.INFO,
    )
    assert canonical_key(d) == "nmap:127.0.0.1:tcp/22"
