"""Tests for anti-hallucination validation, CVE grounding, and credential redaction."""

from __future__ import annotations

import pytest

from app.agents.contracts import FindingNarrative, ReportNarrative
from app.reporting.narrative import (
    claims_confirmed,
    redact_credentials,
    validate_narrative,
)


@pytest.fixture
def sample_context():
    return {
        "assessment": {
            "id": 1,
            "title": "Lab Target",
            "targets": ["127.0.0.1"],
            "ports": [80],
            "exclusions": [],
            "status": "completed",
        },
        "findings": [
            {
                "id": 101,
                "title": "SQL Injection in Login",
                "severity": "high",
                "cvss": 7.5,
                "cve": ["CVE-2023-1234"],
                "cwe": ["CWE-89"],
                "status": "confirmed",
                "confidence": 0.95,
                "asset": "127.0.0.1:80",
                "endpoint": "/api/login",
            },
            {
                "id": 102,
                "title": "Possible Information Disclosure",
                "severity": "medium",
                "cvss": None,
                "cve": [],
                "cwe": ["CWE-200"],
                "status": "suspected",
                "confidence": 0.5,
                "asset": "127.0.0.1:80",
                "endpoint": "/debug",
            },
        ],
    }


@pytest.fixture
def valid_narrative():
    return ReportNarrative(
        executive_summary="The assessment identified 1 confirmed high-severity SQL injection vulnerability.",
        methodology="Conducted automated reconnaissance followed by targeted testing.",
        risk_overview="Overall risk is High.",
        findings=[
            FindingNarrative(
                finding_id=101,
                technical_analysis="The login endpoint is vulnerable to SQL injection with CVE-2023-1234. CVSS 7.5 reflects impact.",
                impact="Database extraction.",
                remediation="Use parameterized queries.",
                confidence_statement="High confidence based on tests.",
                observed_vs_inferred="Observed syntax error; inferred injection.",
            ),
            FindingNarrative(
                finding_id=102,
                technical_analysis="The debug endpoint exposes internal details.",
                impact="Minor leakage.",
                remediation="Disable debug in production.",
                confidence_statement="Moderate confidence.",
                observed_vs_inferred="Observed stack trace; inferred leak.",
            ),
        ],
        limitations="None.",
        recommendations=["Sanitize inputs on /api/login"],
        conclusion="Remediate SQLi.",
    )


def test_validate_narrative_valid(sample_context, valid_narrative):
    # Should not raise
    validate_narrative(valid_narrative, sample_context)


def test_validate_narrative_unknown_finding_id(sample_context, valid_narrative):
    invalid = valid_narrative.model_copy(deep=True)
    invalid.findings.append(
        FindingNarrative(
            finding_id=999,  # Unknown ID
            technical_analysis="Phantom finding",
            impact="None",
            remediation="None",
            confidence_statement="None",
            observed_vs_inferred="None",
        )
    )
    with pytest.raises(ValueError, match="finding_id 999 does not exist"):
        validate_narrative(invalid, sample_context)


def test_validate_narrative_duplicate_finding_id(sample_context, valid_narrative):
    invalid = valid_narrative.model_copy(deep=True)
    invalid.findings.append(invalid.findings[0])
    with pytest.raises(ValueError, match="duplicate finding_id"):
        validate_narrative(invalid, sample_context)


def test_validate_narrative_hallucinated_cve(sample_context, valid_narrative):
    invalid = valid_narrative.model_copy(deep=True)
    invalid.findings[0].technical_analysis += " Also references CVE-2024-9999."
    with pytest.raises(ValueError, match="unauthorized/unverified CVE"):
        validate_narrative(invalid, sample_context)


def test_validate_narrative_cvss_fabrication(sample_context, valid_narrative):
    # Finding 102 has cvss=None in context; mentioning CVSS score is forbidden
    invalid = valid_narrative.model_copy(deep=True)
    invalid.findings[1].technical_analysis += " CVSS score of 5.5."
    with pytest.raises(ValueError, match="has no CVSS score"):
        validate_narrative(invalid, sample_context)


def test_validate_narrative_suspected_claiming_confirmed(sample_context, valid_narrative):
    # Finding 102 has status='suspected'; narrative claiming it's confirmed is forbidden
    invalid = valid_narrative.model_copy(deep=True)
    invalid.findings[1].technical_analysis += " This vulnerability is confirmed by testing."
    with pytest.raises(ValueError, match="status 'suspected' but narrative claims 'confirmed'"):
        validate_narrative(invalid, sample_context)


def test_claims_confirmed_negation_allowed():
    assert claims_confirmed("Vulnerability is confirmed.") is True
    assert claims_confirmed("Vulnerability is not confirmed.") is False
    assert claims_confirmed("Finding was never confirmed by secondary tool.") is False


def test_redact_credentials():
    text = "The password is 'admin123' and credential was found to be 'letmein'."
    redacted = redact_credentials(text)
    assert "admin123" not in redacted
    assert "letmein" not in redacted
    assert "[REDACTED]" in redacted
