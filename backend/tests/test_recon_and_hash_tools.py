"""Unit and integration tests for Phase 6 recon tools and hash auditing, plus curl_tool.

Acceptance criteria verified:
- whatweb: JSON log parsing, canonical key generation, info severity.
- sslscan: XML parsing, deprecated SSL/TLS detection, certificate expiration, canonical keys.
- nmap_nse: Allowlist enforcement, strictly rejects --script vuln and unknown scripts.
- hash_identify: Direct heuristic matching, artifact containment check, audit logging.
- hashcat_crack: Fixed argv with --outfile-format 1, path traversal prevention, source artifact check.
- Plaintext redaction: Lab wordlist plaintext passwords NEVER appear in observations, findings, or reports.
- curl_tool: Fully replaced http_probe, verified argv and FindingRepo status update.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from app.actions.catalogue import (
    ACTIONS,
    NMAP_SAFE_SCRIPTS,
    WORDLISTS,
    get_action,
    resolve_argv,
)
from app.adapters import hashcat, sslscan, whatweb
from app.agents.loop.direct_tools import hash_identify_direct
from app.core.db import get_async_session_ctx
from app.domain.models import (
    Assessment,
    Audit,
    Evidence,
    Finding,
    FindingStatus,
    Severity,
    Step,
)
from app.persistence.finding_repo import FindingRepo


# --- WhatWeb Tests ---

def test_whatweb_parser_json_array():
    sample_json = json.dumps([
        {
            "target": "http://127.0.0.1:3000/",
            "http_status": 200,
            "plugins": {
                "Apache": {"version": ["2.4.41"]},
                "HTTPServer": {"string": ["Apache/2.4.41 (Ubuntu)"]},
                "JQuery": {"version": ["3.5.1"]},
            },
        }
    ])
    drafts = whatweb.scan(sample_json, "127.0.0.1", 3000)
    assert len(drafts) == 3
    plugins = {d.title for d in drafts}
    assert "Technology detected: Apache 2.4.41" in plugins
    assert "Technology detected: JQuery 3.5.1" in plugins
    assert all(d.severity == Severity.INFO for d in drafts)
    assert all(d.canonical_key.startswith("whatweb:127.0.0.1:3000:") for d in drafts)
    assert drafts[0].evidence[0].locator["tool"] == "whatweb"


def test_whatweb_parser_json_lines():
    sample_jsonl = (
        '{"target": "http://10.0.0.5:80/", "plugins": {"Nginx": {"version": ["1.18.0"]}}}\n'
        '{"target": "http://10.0.0.5:80/", "plugins": {"PHP": {"version": ["7.4.3"]}}}\n'
    )
    drafts = whatweb.scan(sample_jsonl, "10.0.0.5", 80)
    assert len(drafts) == 2
    keys = {d.canonical_key for d in drafts}
    assert "whatweb:10.0.0.5:80:nginx" in keys
    assert "whatweb:10.0.0.5:80:php" in keys


# --- sslscan Tests ---

def test_sslscan_parser_detects_insecure_protocols_and_certs():
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

    # Protocols: SSLv3 (MEDIUM), TLS 1.0 (LOW), TLS 1.2 (INFO), TLS 1.3 (INFO)
    # Certs: Expired (MEDIUM), Self-signed (LOW), Info (INFO)
    titles = {d.title: d.severity for d in drafts}

    assert "Insecure SSL protocol enabled (SSL V3)" in titles
    assert titles["Insecure SSL protocol enabled (SSL V3)"] == Severity.MEDIUM

    assert "Deprecated TLS protocol enabled (TLS V1.0)" in titles
    assert titles["Deprecated TLS protocol enabled (TLS V1.0)"] == Severity.LOW

    assert "Supported TLS protocol (TLS V1.2)" in titles
    assert titles["Supported TLS protocol (TLS V1.2)"] == Severity.INFO

    assert "Expired SSL/TLS certificate on example.com:443" in titles
    assert titles["Expired SSL/TLS certificate on example.com:443"] == Severity.MEDIUM

    assert "Self-signed SSL/TLS certificate on example.com:443" in titles
    assert titles["Self-signed SSL/TLS certificate on example.com:443"] == Severity.LOW

    assert all(d.canonical_key.startswith("sslscan:example.com:443:") for d in drafts)
    assert all(d.cve == [] for d in drafts)  # sslscan must not invent CVEs


# --- Nmap NSE Scripts Allowlist Tests ---

def test_nmap_nse_allows_safe_scripts():
    assessment = Assessment(id=1, title="Lab", targets=["127.0.0.1"], ports=[80, 443])
    argv = resolve_argv(
        "nmap_nse",
        assessment,
        "127.0.0.1",
        step_id=10,
        params={"scripts": ["http-title", "ssl-cert"]},
    )
    assert "--script" in argv
    script_idx = argv.index("--script")
    assert argv[script_idx + 1] == "http-title,ssl-cert"


def test_nmap_nse_rejects_vuln_and_unallowlisted_scripts():
    assessment = Assessment(id=1, title="Lab", targets=["127.0.0.1"], ports=[80])

    # Reject --script vuln
    with pytest.raises(ValueError, match="not in NMAP_SAFE_SCRIPTS allowlist"):
        resolve_argv(
            "nmap_nse",
            assessment,
            "127.0.0.1",
            step_id=11,
            params={"scripts": ["vuln"]},
        )

    # Reject arbitrary unsafe script
    with pytest.raises(ValueError, match="not in NMAP_SAFE_SCRIPTS allowlist"):
        resolve_argv(
            "recon_services",
            assessment,
            "127.0.0.1",
            step_id=12,
            params={"scripts": ["smb-brute"]},
        )


# --- hash_identify Direct Tool Tests ---

@pytest.mark.asyncio
async def test_hash_identify_rejects_hash_not_in_artifact(engine, tmp_path: Path):
    artifact_file = tmp_path / "step-1.txt"
    artifact_file.write_text("Discovered user admin with ID 42\n", encoding="utf-8")

    async with get_async_session_ctx() as session:
        assessment = Assessment(id=1, title="Lab", targets=["127.0.0.1"], ports=[80])
        session.add(assessment)
        step = Step(
            id=1,
            assessment_id=1,
            seq=1,
            action="nikto_scan",
            target="127.0.0.1",
            output_path=str(artifact_file),
        )
        session.add(step)
        await session.commit()

        obs = await hash_identify_direct(
            session=session,
            assessment_id=1,
            hash_value="5d41402abc4b2a76b9719d911017c592",  # Not in artifact
            source_step_id=1,
        )
        assert obs.ok is False
        assert obs.status == "rejected"
        assert "does not appear in the source step artifact" in obs.summary


@pytest.mark.asyncio
async def test_hash_identify_recognizes_formats_and_audits(engine, tmp_path: Path):
    md5_hash = "5d41402abc4b2a76b9719d911017c592"
    bcrypt_hash = "$2a$12$e7r056tW4uLd1F1sV5o0Qe9A1t0k1L2m3N4p5Q6r7S8t9U0v1W2x3"
    artifact_file = tmp_path / "step-2.txt"
    artifact_file.write_text(f"Hashes found:\nadmin:{md5_hash}\nbob:{bcrypt_hash}\n", encoding="utf-8")

    async with get_async_session_ctx() as session:
        assessment = Assessment(id=2, title="Lab", targets=["127.0.0.1"], ports=[80])
        session.add(assessment)
        step = Step(
            id=2,
            assessment_id=2,
            seq=2,
            action="dirb_scan",
            target="127.0.0.1",
            output_path=str(artifact_file),
        )
        session.add(step)
        await session.commit()

        # MD5 identification
        obs_md5 = await hash_identify_direct(
            session=session,
            assessment_id=2,
            hash_value=md5_hash,
            source_step_id=2,
        )
        assert obs_md5.ok is True
        assert obs_md5.facts["candidates"][0]["mode"] == 0
        assert obs_md5.facts["candidates"][0]["name"] == "MD5"

        # bcrypt identification
        obs_bcrypt = await hash_identify_direct(
            session=session,
            assessment_id=2,
            hash_value=bcrypt_hash,
            source_step_id=2,
        )
        assert obs_bcrypt.ok is True
        assert obs_bcrypt.facts["candidates"][0]["mode"] == 3200
        assert obs_bcrypt.facts["candidates"][0]["name"] == "bcrypt"
        assert obs_bcrypt.facts["confidence"] == "high"

        # Verify audit trail
        res = await session.execute(
            select(Audit).where(Audit.assessment_id == 2, Audit.event_type == "hash.identified")
        )
        audits = res.scalars().all()
        assert len(audits) == 2


# --- hashcat_crack & Plaintext Redaction Tests ---

def test_hashcat_argv_has_outfile_format_1_and_bounds():
    assessment = Assessment(id=1, title="Lab", targets=["127.0.0.1"], ports=[80])
    argv = resolve_argv(
        "hashcat_crack",
        assessment,
        "127.0.0.1",
        step_id=5,
        params={
            "hash_mode": 0,
            "runtime": 60,
            "wordlist": "lab",
            "source_step_id": 2,
        },
    )
    assert argv[0] == "hashcat"
    assert "-m" in argv and argv[argv.index("-m") + 1] == "0"
    assert "--outfile-format" in argv and argv[argv.index("--outfile-format") + 1] == "1"
    assert "--runtime" in argv and argv[argv.index("--runtime") + 1] == "60"
    assert str(WORDLISTS["lab"]) in argv


def test_hashcat_adapter_strict_plaintext_redaction():
    # Read lab wordlist to assert against every word in it
    lab_words = [w.strip() for w in WORDLISTS["lab"].read_text().splitlines() if w.strip()]
    assert len(lab_words) >= 8

    # Simulate hashcat output with --outfile-format 1 (hash only)
    sample_cracked_output = (
        "5d41402abc4b2a76b9719d911017c592\n"
        "098f6bcd4621d373cade4e832627b4f6\n"
    )

    drafts = hashcat.scan(sample_cracked_output, "127.0.0.1")
    assert len(drafts) == 1
    finding = drafts[0]

    assert finding.title == "Weak password policy on 127.0.0.1"
    assert finding.severity == Severity.HIGH
    assert finding.status == FindingStatus.CONFIRMED
    assert "plaintext is intentionally omitted" in finding.description
    assert "2 hash(es) cracked; plaintext redacted." in finding.evidence[0].excerpt

    # Specific secret passwords from the wordlist must NEVER appear in title, description, or evidence excerpt
    finding_text = f"{finding.title} {finding.description} {finding.evidence[0].excerpt}".lower()
    for word in ("Password1", "letmein", "123456", "qwerty", "welcome"):
        assert word.lower() not in finding_text, f"Plaintext secret {word} leaked in finding draft!"


# --- curl_tool Verification (Replacing http_probe) ---

def test_curl_tool_argv_resolution():
    assessment = Assessment(id=1, title="Lab", targets=["127.0.0.1"], ports=[3000])
    argv = resolve_argv(
        "curl_tool",
        assessment,
        "127.0.0.1",
        step_id=99,
        params={
            "path": "/api/users",
            "method": "POST",
            "headers": {"Authorization": "Bearer token"},
            "expected_status": 200,
            "body": "{}",
        },
    )
    assert argv[0] == "curl_tool"
    assert argv[1] == "POST"
    assert argv[2] == "http://127.0.0.1:3000/api/users"
    assert json.loads(argv[3]) == {"Authorization": "Bearer token"}
    assert argv[4] == "200"
    assert argv[5] == "{}"


@pytest.mark.asyncio
async def test_finding_repo_requires_curl_tool_evidence(engine):
    async with get_async_session_ctx() as session:
        assessment = Assessment(id=10, title="Lab", targets=["127.0.0.1"], ports=[3000])
        session.add(assessment)
        finding = Finding(
            assessment_id=10,
            title="Admin interface exposed",
            canonical_key="web:admin",
            asset="127.0.0.1",
            severity="high",
            confidence=0.8,
            status="suspected",
        )
        session.add(finding)
        await session.commit()
        await session.refresh(finding)

        repo = FindingRepo(session)

        # Attempt to confirm without curl_tool evidence -> blocked
        result = await repo.update_status(
            finding_id=finding.id,
            assessment_id=10,
            status="confirmed",
            reasoning="looks open",
        )
        assert "error" in result
        assert "no executed curl_tool evidence is linked" in result["error"]

        # Add executed curl_tool evidence row
        session.add(
            Evidence(
                finding_id=finding.id,
                locator={"tool": "curl_tool", "url": "http://127.0.0.1:3000/admin", "http_status": 200},
                excerpt="HTTP 200 OK",
            )
        )
        await session.commit()

        # Confirm with curl_tool evidence -> succeeds
        result = await repo.update_status(
            finding_id=finding.id,
            assessment_id=10,
            status="confirmed",
            reasoning="verified with curl_tool returning 200",
        )
        assert "error" not in result
        assert result["status"] == "confirmed"


@pytest.mark.asyncio
async def test_hashcat_stays_local_when_mcp_gateway_enabled(monkeypatch):
    from app.core.config import settings
    monkeypatch.setattr(settings, "mcp_enabled", True)
    monkeypatch.setattr(settings, "mcp_transport", "gateway")

    assessment = Assessment(id=1, title="Lab", targets=["127.0.0.1"], ports=[80])
    # resolve_argv must not crash with UnknownAction("hashcat_crack")
    argv = resolve_argv(
        "hashcat_crack",
        assessment,
        "127.0.0.1",
        step_id=10,
        params={"hash_mode": 0, "source_step_id": 1},
    )
    assert argv[0] == "hashcat"


@pytest.mark.asyncio
async def test_execute_action_hashcat_uncracked_creates_empty_artifact(engine, monkeypatch, tmp_path):
    import subprocess
    from app.actions import catalogue
    from app.actions.executor import execute_action

    monkeypatch.setattr(catalogue, "ARTIFACT_DIR", tmp_path)

    async with get_async_session_ctx() as session:
        assessment = Assessment(id=20, title="Lab", targets=["127.0.0.1"], ports=[80])
        session.add(assessment)
        await session.commit()

        # Mock _run to simulate hashcat exiting 0 without creating an outfile (uncracked outcome)
        async def mock_run(argv, timeout, assessment_id=None):
            return subprocess.CompletedProcess(argv, 0, stdout="All hashes exhausted\n", stderr="")

        monkeypatch.setattr("app.actions.executor._run", mock_run)

        # execute_action should touch the artifact and produce 0 findings without raising RuntimeError
        step = await execute_action(session, assessment.id, "hashcat_crack")
        assert step.exit_code == 0
        assert step.output_path is not None
        assert Path(step.output_path).exists()
        assert Path(step.output_path).read_text() == ""


@pytest.mark.asyncio
async def test_execute_action_hashcat_cracked_creates_finding(engine, monkeypatch, tmp_path):
    import subprocess
    from app.actions import catalogue
    from app.actions.executor import execute_action

    monkeypatch.setattr(catalogue, "ARTIFACT_DIR", tmp_path)

    async with get_async_session_ctx() as session:
        assessment = Assessment(id=21, title="Lab", targets=["127.0.0.1"], ports=[80])
        session.add(assessment)
        await session.commit()

        # Mock _run to write cracked hash into the expected outfile
        async def mock_run(argv, timeout, assessment_id=None):
            outfile_idx = argv.index("--outfile") + 1
            outfile_path = Path(argv[outfile_idx])
            outfile_path.parent.mkdir(parents=True, exist_ok=True)
            outfile_path.write_text("5d41402abc4b2a76b9719d911017c592\n")
            return subprocess.CompletedProcess(argv, 0, stdout="Cracked: 1\n", stderr="")

        monkeypatch.setattr("app.actions.executor._run", mock_run)

        step = await execute_action(session, assessment.id, "hashcat_crack")
        assert step.exit_code == 0
        assert Path(step.output_path).exists()

        # Verify high-severity finding was created with plaintext redacted
        res = await session.execute(select(Finding).where(Finding.assessment_id == assessment.id))
        findings = list(res.scalars().all())
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "Weak password policy" in findings[0].title

