"""Comprehensive REST API tests.

Covers:
- POST /api/assessments (creation, schema validation, 422 on empty scope)
- GET /api/assessments (listing)
- GET /api/assessments/{id} (detailed view, 404 handling)
- PATCH /api/assessments/{id}/request (updating objective, audit event, 409 if running)
- POST /api/assessments/{id}/messages & GET /api/assessments/{id}/messages
- POST /api/assessments/{id}/chat (operator chat message, client_message_id idempotency)
- POST /api/assessments/{id}/decisions & POST /api/assessments/{id}/resume
- POST /api/assessments/{id}/run, POST /api/assessments/{id}/stop, GET /api/assessments/{id}/agent
- GET /api/assessments/{id}/report (download PDF, 409 when pending, 404 when missing)
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch
import pytest
from app.core.db import get_async_session_ctx
from app.domain.models import Assessment, AssessmentStatus


def _create_assessment(client, title="API Test Assessment", targets=None, ports=None):
    return client.post(
        "/api/assessments",
        json={
            "title": title,
            "request": "Assess security boundary",
            "targets": targets or ["127.0.0.1"],
            "ports": ports or [80, 443],
        },
    )


def test_create_list_and_detail_assessment(client):
    """Test standard assessment CRUD operations."""
    resp = _create_assessment(client, title="Vulnerability Audit")
    assert resp.status_code == 201
    created = resp.json()
    assert created["id"] is not None
    assert created["title"] == "Vulnerability Audit"
    assert created["status"] == "draft"

    # List assessments
    list_resp = client.get("/api/assessments")
    assert list_resp.status_code == 200
    items = list_resp.json()
    assert any(item["id"] == created["id"] for item in items)

    # Detail assessment
    detail_resp = client.get(f"/api/assessments/{created['id']}")
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["id"] == created["id"]
    assert detail["steps"] == []
    assert detail["findings"] == []
    assert detail["evidence"] == []
    assert len(detail["audit"]) >= 1
    assert detail["audit"][0]["event_type"] == "assessment.created"


def test_rejects_empty_scope_and_missing_is_404(client):
    """Empty targets returns 422 Unprocessable Entity, nonexistent ID returns 404."""
    bad_resp = client.post("/api/assessments", json={"title": "Empty Scope", "targets": []})
    assert bad_resp.status_code == 422

    missing_resp = client.get("/api/assessments/999999")
    assert missing_resp.status_code == 404


def test_patch_assessment_request_objective(client):
    """Test modifying the assessment request / objective."""
    created = _create_assessment(client).json()
    aid = created["id"]

    # 1. Successful patch when in draft status
    patch_resp = client.patch(
        f"/api/assessments/{aid}/request",
        json={"request": "Updated objective: focus on API authentication"},
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["request"] == "Updated objective: focus on API authentication"

    # Verify audit event was logged
    detail = client.get(f"/api/assessments/{aid}").json()
    audit_types = [a["event_type"] for a in detail["audit"]]
    assert "assessment.request_updated" in audit_types

    # 2. Rejection (409) when assessment is in an active running status
    client.post(f"/api/assessments/{aid}/scan")  # marks completed, let's artificially set running
    import asyncio
    async def set_running():
        async with get_async_session_ctx() as session:
            a = await session.get(Assessment, aid)
            a.status = AssessmentStatus.RUNNING.value
            await session.commit()
    asyncio.run(set_running())

    patch_blocked = client.patch(
        f"/api/assessments/{aid}/request",
        json={"request": "Cannot change while running"},
    )
    assert patch_blocked.status_code == 409
    assert "cannot change the objective" in patch_blocked.json()["detail"]


def test_messages_crud_and_chat_idempotency(client):
    """Test operator message log and asynchronous /chat endpoint."""
    created = _create_assessment(client).json()
    aid = created["id"]

    # 1. Message CRUD
    msg_post = client.post(
        f"/api/assessments/{aid}/messages",
        json={"role": "operator", "text": "Status inquiry"},
    )
    assert msg_post.status_code == 200
    msg = msg_post.json()
    assert msg["text"] == "Status inquiry"

    msgs_get = client.get(f"/api/assessments/{aid}/messages")
    assert msgs_get.status_code == 200
    assert len(msgs_get.json()) >= 1

    # 2. Chat endpoint with enqueue mock
    with patch("app.agents.conversation.enqueue", new_callable=AsyncMock) as mock_enqueue:
        chat_resp1 = client.post(
            f"/api/assessments/{aid}/chat",
            json={"text": "Summarize open ports", "client_message_id": "client-uuid-101"},
        )
        assert chat_resp1.status_code == 202
        data1 = chat_resp1.json()
        assert data1["accepted"] is True
        assert data1["operator_message_id"] > 0
        mock_enqueue.assert_called_once()

        # Idempotent replay with same client_message_id
        chat_resp2 = client.post(
            f"/api/assessments/{aid}/chat",
            json={"text": "Summarize open ports", "client_message_id": "client-uuid-101"},
        )
        assert chat_resp2.status_code == 202
        data2 = chat_resp2.json()
        assert data2["message"] == "duplicate message ignored"
        assert data2["operator_message_id"] == data1["operator_message_id"]


def test_agent_run_stop_and_decisions_endpoints(client):
    """Test run, stop, resume, and decisions endpoints."""
    created = _create_assessment(client).json()
    aid = created["id"]

    # Test /run
    with patch("app.api.routes.runner.start_run", new_callable=AsyncMock) as mock_start:
        run_resp = client.post(f"/api/assessments/{aid}/run")
        assert run_resp.status_code == 202
        assert "Agent run accepted" in run_resp.json()["message"]
        mock_start.assert_called_once_with(aid)

    # Test /stop
    with patch("app.api.routes.runner.stop_run", new_callable=AsyncMock) as mock_stop:
        stop_resp = client.post(f"/api/assessments/{aid}/stop")
        assert stop_resp.status_code == 202
        assert "Agent run stopped" in stop_resp.json()["message"]
        mock_stop.assert_called_once_with(aid)

    # Test /resume and /decisions
    with patch("app.api.routes.runner.resume_run", new_callable=AsyncMock) as mock_resume:
        resume_resp = client.post(
            f"/api/assessments/{aid}/resume",
            json={"decision": "approved", "rationale": "Analyst approval"},
        )
        assert resume_resp.status_code == 202
        assert "Decision approved accepted" in resume_resp.json()["message"]

        # Alias /decisions endpoint
        decisions_resp = client.post(
            f"/api/assessments/{aid}/decisions",
            json={"decision": "rejected", "rationale": "Analyst rejection"},
        )
        assert decisions_resp.status_code == 202
        assert "Decision rejected accepted" in decisions_resp.json()["message"]

    # Test /agent state view
    with patch("app.api.routes.runner.get_view", new_callable=AsyncMock) as mock_view:
        from app.api.schema import AgentView
        mock_view.return_value = AgentView(
            assessment_id=aid,
            status="running",
            running=True,
            paused=False,
            active_role="recon",
        )
        agent_resp = client.get(f"/api/assessments/{aid}/agent")
        assert agent_resp.status_code == 200
        assert agent_resp.json()["active_role"] == "recon"


def test_report_download_endpoint(client, tmp_path):
    """Test GET /api/assessments/{id}/report error handling and binary response."""
    created = _create_assessment(client).json()
    aid = created["id"]

    # 1. Report not generated yet -> 409 Conflict
    r1 = client.get(f"/api/assessments/{aid}/report")
    assert r1.status_code == 409
    assert "report is not generated yet" in r1.json()["detail"]

    # 2. Report path points to nonexistent file -> 404
    import asyncio
    async def set_report_path(path_str):
        async with get_async_session_ctx() as session:
            a = await session.get(Assessment, aid)
            a.report_path = path_str
            await session.commit()

    asyncio.run(set_report_path("/tmp/nonexistent_report_123.pdf"))
    r2 = client.get(f"/api/assessments/{aid}/report")
    assert r2.status_code == 404
    assert "report file is missing" in r2.json()["detail"]

    # 3. Valid PDF report generated -> 200 FileResponse with application/pdf
    real_pdf = tmp_path / "final_report.pdf"
    real_pdf.write_bytes(b"%PDF-1.4 test report binary content")
    asyncio.run(set_report_path(str(real_pdf)))

    r3 = client.get(f"/api/assessments/{aid}/report")
    assert r3.status_code == 200
    assert r3.headers["content-type"] == "application/pdf"
    assert r3.content.startswith(b"%PDF-")
