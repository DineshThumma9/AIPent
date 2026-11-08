"""Tests for Phase 4: conversation coordinator agent, steering queue, and chat endpoint."""

from __future__ import annotations

import asyncio
import pytest
from httpx import ASGITransport, AsyncClient
from langchain_core.messages import AIMessage, HumanMessage
from sqlmodel import select

from app.agents.conversation import answer, enqueue
from app.agents.conversation.tools import (
    add_steering_note,
    explain_approval,
    get_mission_status,
    get_reasoning,
    list_findings,
    set_conversation_assessment_id,
    update_objective,
)
from app.agents.graph.state import AssessmentState, initial_state
from app.agents.loop.nodes import brief_node, model_node
from app.core.config import settings
from app.core.db import get_async_session_ctx, init_db, make_engine, set_engine
from app.domain.models import (
    Approval,
    Assessment,
    AssessmentStatus,
    Audit,
    Decision,
    Finding,
    Message,
    Step,
    SteeringNote,
    utcnow,
)
from app.main import app
from app.persistence import SteeringRepo


@pytest.fixture
def engine(tmp_path, monkeypatch):
    test_db = tmp_path / "coordinator_test.db"
    test_engine = make_engine(f"sqlite:///{test_db}")
    asyncio.run(init_db(test_engine))
    set_engine(test_engine)
    monkeypatch.setattr(settings, "agent_loop", "v2")
    return test_engine


async def _create_test_assessment() -> int:
    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Coordinator Assessment",
            request="Initial objective: map perimeter",
            targets=["127.0.0.1"],
            ports=[80, 443],
            exclusions=[],
            status=AssessmentStatus.DRAFT.value,
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)
        return assessment.id


@pytest.mark.asyncio
async def test_steering_repo_lifecycle(engine):
    assessment_id = await _create_test_assessment()

    async with get_async_session_ctx() as session:
        repo = SteeringRepo(session)

        # 1. Add note while idle
        note1 = await repo.add(assessment_id, None, "Focus on port 443 first")
        assert note1.id is not None
        assert note1.status == "pending"

        # 2. Add note during run-1
        note2 = await repo.add(assessment_id, "run-1", "Skip /docs endpoint")
        assert note2.status == "pending"

        # 3. Take pending for run-1 -> consumes both
        claimed = await repo.take_pending(assessment_id, "run-1")
        assert len(claimed) == 2
        assert all(n.status == "consumed" for n in claimed)
        assert all(n.consumed_at is not None for n in claimed)

        # 4. No more pending
        claimed_empty = await repo.take_pending(assessment_id, "run-1")
        assert len(claimed_empty) == 0

        # 5. Add note for run-1, then expire it for a new run
        note3 = await repo.add(assessment_id, "run-1", "Old run directive")
        assert note3.status == "pending"

        await repo.expire_for_new_run(assessment_id)
        all_notes = await repo.get_all(assessment_id)
        expired_note = next(n for n in all_notes if n.id == note3.id)
        assert expired_note.status == "expired"


@pytest.mark.asyncio
async def test_coordinator_tools(engine):
    assessment_id = await _create_test_assessment()
    set_conversation_assessment_id(assessment_id)

    async with get_async_session_ctx() as session:
        # Add a finding and an approval for testing
        finding = Finding(
            assessment_id=assessment_id,
            canonical_key="xss:http://127.0.0.1/search",
            title="Reflected XSS in search",
            category="xss",
            severity="high",
            status="candidate",
            asset="127.0.0.1",
            endpoint="http://127.0.0.1/search",
        )
        session.add(finding)

        step = Step(
            assessment_id=assessment_id,
            seq=1,
            role="discovery",
            action="nikto_scan",
            target="127.0.0.1",
            argv=["nikto", "-h", "http://127.0.0.1"],
            rationale="Test web server configuration",
        )
        session.add(step)
        await session.commit()
        await session.refresh(step)

        approval = Approval(
            assessment_id=assessment_id,
            step_id=step.id,
            action="nikto_scan",
            decision=Decision.PENDING.value,
            argv=["nikto", "-h", "http://127.0.0.1"],
            detail={"risk": "medium", "policy_reason": "Automated scan on target"},
        )
        session.add(approval)
        await session.commit()
        await session.refresh(approval)
        approval_id = approval.id

    # Test get_mission_status
    status_res = await get_mission_status.ainvoke({})
    assert "status" in status_res
    assert status_res["findings_count"] >= 1

    # Test list_findings
    findings_res = await list_findings.ainvoke({"limit": 5})
    assert len(findings_res) >= 1
    assert findings_res[0]["title"] == "Reflected XSS in search"

    # Test explain_approval
    explain_res = await explain_approval.ainvoke({"approval_id": approval_id})
    assert explain_res["approval_id"] == approval_id
    assert explain_res["action"] == "nikto_scan"
    assert explain_res["risk"] == "medium"

    # Test update_objective while idle
    update_res = await update_objective.ainvoke(
        {"text": "New objective: test API only"}
    )
    assert update_res["ok"] is True
    assert update_res["objective"] == "New objective: test API only"

    # Test add_steering_note
    note_res = await add_steering_note.ainvoke(
        {"text": "Steer specialist towards /v2/api"}
    )
    assert note_res["ok"] is True
    assert note_res["text"] == "Steer specialist towards /v2/api"


@pytest.mark.asyncio
async def test_chat_endpoint_and_idempotency(engine):
    assessment_id = await _create_test_assessment()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # First chat post
        resp1 = await client.post(
            f"/api/assessments/{assessment_id}/chat",
            json={
                "text": "What is the status of the run?",
                "client_message_id": "client-uuid-1",
            },
        )
        assert resp1.status_code == 202
        data1 = resp1.json()
        assert data1["accepted"] is True
        assert data1["operator_message_id"] > 0

        # Duplicate post with same client_message_id
        resp2 = await client.post(
            f"/api/assessments/{assessment_id}/chat",
            json={
                "text": "What is the status of the run?",
                "client_message_id": "client-uuid-1",
            },
        )
        assert resp2.status_code == 202
        data2 = resp2.json()
        assert data2["message"] == "duplicate message ignored"
        assert data2["operator_message_id"] == data1["operator_message_id"]

    # Verify only one operator message was persisted
    async with get_async_session_ctx() as session:
        res = await session.execute(
            select(Message).where(
                Message.assessment_id == assessment_id,
                Message.client_message_id == "client-uuid-1",
            )
        )
        messages = res.scalars().all()
        assert len(messages) == 1


@pytest.mark.asyncio
async def test_coordinator_answer_and_worker(engine):
    assessment_id = await _create_test_assessment()

    # Create a mock agent that returns a clear answer
    class MockCoordinatorAgent:
        async def ainvoke(self, inputs):
            return {
                "messages": [
                    AIMessage(
                        content="Recon is currently running. Port 80 and 443 are in scope."
                    )
                ]
            }

    # Test direct answer
    reply = await answer(
        assessment_id=assessment_id,
        text="Give me an update",
        coordinator_agent=MockCoordinatorAgent(),
    )
    assert "Recon is currently running" in reply

    # Test enqueue and worker execution
    async with get_async_session_ctx() as session:
        op_msg = Message(
            assessment_id=assessment_id,
            role="operator",
            text="Any findings?",
        )
        session.add(op_msg)
        await session.commit()
        await session.refresh(op_msg)

    # Mock coordinator for worker
    from unittest.mock import patch

    with patch(
        "app.agents.conversation.service.build_coordinator_agent",
        return_value=MockCoordinatorAgent(),
    ):
        await enqueue(assessment_id, op_msg.id, op_msg.text)
        # Give worker a brief moment to drain queue
        await asyncio.sleep(0.3)

    # Check assistant reply was stored
    async with get_async_session_ctx() as session:
        res = await session.execute(
            select(Message).where(
                Message.assessment_id == assessment_id,
                Message.role == "assistant",
            )
        )
        assistant_msgs = res.scalars().all()
        assert len(assistant_msgs) >= 1
        assert "Recon is currently running" in assistant_msgs[-1].text


@pytest.mark.asyncio
async def test_brief_and_model_nodes_consume_steering(engine):
    assessment_id = await _create_test_assessment()

    # 1. Queue a steering note
    async with get_async_session_ctx() as session:
        repo = SteeringRepo(session)
        await repo.add(assessment_id, "run-1", "Priority directive: focus on admin portal")

    # 2. Run brief_node
    state = initial_state(assessment_id)
    state["role"] = "recon"
    state["run_id"] = "run-1"

    cmd = await brief_node(state)
    assert cmd.goto == "model"
    brief_text = cmd.update["messages"][0].content
    assert "OPERATOR STEERING" in brief_text
    assert "Priority directive: focus on admin portal" in brief_text

    # Note is now consumed
    async with get_async_session_ctx() as session:
        repo = SteeringRepo(session)
        pending = await repo.take_pending(assessment_id, "run-1")
        assert len(pending) == 0

    # 3. Queue another note mid-turn
    async with get_async_session_ctx() as session:
        repo = SteeringRepo(session)
        await repo.add(assessment_id, "run-1", "Mid-turn directive: test rate limits")

    # Mock role model to verify injected messages
    class MockRoleModel:
        def __init__(self):
            self.captured_messages = []

        def bind_tools(self, tools):
            return self

        async def ainvoke(self, messages):
            self.captured_messages = list(messages)
            return AIMessage(
                content="",
                tool_calls=[
                    {
                        "id": "call_1",
                        "name": "handoff",
                        "args": {
                            "summary": "Done",
                            "next_role": "discovery",
                            "why": "Testing",
                            "confidence": 0.8,
                            "stop_reason": "goal_achieved",
                        },
                    }
                ],
            )

    mock_model = MockRoleModel()
    from unittest.mock import patch

    with patch(
        "app.agents.loop.nodes.build_role_model",
        return_value=mock_model,
    ):
        await model_node(state)

    # Verify steering directive was injected into model messages
    injected = any(
        "Mid-turn directive: test rate limits" in getattr(m, "content", "")
        for m in mock_model.captured_messages
    )
    assert injected is True
