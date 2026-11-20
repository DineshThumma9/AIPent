"""Tests for linking step evidence, extracting HTTP statuses and proof markers."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from app.actions.evidence import excerpt_for, http_status, link_step_evidence, locator_for
from app.core.db import get_async_session_ctx
from app.domain.models import Assessment, Evidence, Finding, Step, StepStatus


def test_http_status_extraction_from_json():
    # Direct status_code
    payload1 = json.dumps({"status_code": 200, "body": "OK"})
    assert http_status(payload1) == 200

    # Nested curl_result
    payload2 = json.dumps({"curl_result": {"http_status": "403", "url": "http://127.0.0.1/"}})
    assert http_status(payload2) == 403

    # Batch response
    payload3 = json.dumps({"batch": [{"code": 500, "url": "http://127.0.0.1/error"}]})
    assert http_status(payload3) == 500


def test_http_status_extraction_from_raw_text():
    raw_header = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n"
    assert http_status(raw_header) == 404

    raw_status_line = "Response status: 301 Moved Permanently"
    assert http_status(raw_status_line) == 301


def test_locator_for_curl_and_sqlmap():
    step_curl = Step(id=1, action="curl_request", target="127.0.0.1", status="succeeded")
    curl_body = json.dumps({"status_code": 200, "url": "http://127.0.0.1/api", "method": "GET"})
    loc_curl = locator_for(step_curl, curl_body)
    assert loc_curl["tool"] == "curl_request"
    assert loc_curl["http_status"] == 200
    assert loc_curl["url"] == "http://127.0.0.1/api"
    assert loc_curl["method"] == "GET"

    step_sqlmap = Step(id=2, action="sqlmap_scan", target="127.0.0.1", status="succeeded")
    sqlmap_positive = "sqlmap identified the following injection point on parameter id"
    loc_sqlmap_pos = locator_for(step_sqlmap, sqlmap_positive)
    assert loc_sqlmap_pos["tool"] == "sqlmap_scan"
    assert loc_sqlmap_pos["injectable"] is True

    sqlmap_negative = "all tested parameters do not appear to be injectable"
    loc_sqlmap_neg = locator_for(step_sqlmap, sqlmap_negative)
    assert loc_sqlmap_neg["injectable"] is False


@pytest.mark.asyncio
async def test_link_step_evidence_deduplication(engine, tmp_path):
    async with get_async_session_ctx() as session:
        assessment = Assessment(title="Evidence Linking", targets=["127.0.0.1"], ports=[80])
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        finding = Finding(
            assessment_id=assessment.id,
            canonical_key="web:test:sqli",
            asset="127.0.0.1",
            title="SQLi Test",
        )
        session.add(finding)
        await session.commit()
        await session.refresh(finding)

        art_file = tmp_path / "step_out.json"
        body = json.dumps({"status_code": 200, "url": "http://127.0.0.1/sqli"})
        art_file.write_text(body, encoding="utf-8")

        step = Step(
            assessment_id=assessment.id,
            seq=1,
            action="curl_request",
            target="127.0.0.1",
            status=StepStatus.SUCCEEDED.value,
            output_path=str(art_file),
        )
        session.add(step)
        await session.commit()
        await session.refresh(step)

        # 1. First linking creates Evidence row
        ev1 = await link_step_evidence(session, step, finding.id, text=body)
        assert ev1 is not None
        assert ev1.locator["http_status"] == 200

        # 2. Second linking with identical locator and excerpt returns None (deduplicated)
        ev2 = await link_step_evidence(session, step, finding.id, text=body)
        assert ev2 is None
