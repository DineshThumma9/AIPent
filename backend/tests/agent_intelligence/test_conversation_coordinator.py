"""Tests for conversation coordinator agent, tools, steering, and assistant workers."""

from __future__ import annotations

import asyncio
from unittest.mock import patch
import pytest
from langchain_core.messages import AIMessage
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
from app.core.db import get_async_session_ctx
from app.domain.models import (
    Approval,
    Assessment,
    AssessmentStatus,
    Decision,
    Finding,
    Message,
    Step,
)


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
async def test_coordinator_tools(engine):
    assessment_id = await _create_test_assessment()
    set_conversation_assessment_id(assessment_id)

    async with get_async_session_ctx() as session:
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
        finding_id = finding.id

    status_res = await get_mission_status.ainvoke({})
    assert "status" in status_res
    assert status_res["findings_count"] >= 1

    findings_res = await list_findings.ainvoke({"limit": 5})
    assert len(findings_res) >= 1
    assert any(f["id"] == finding_id for f in findings_res)

    evidence_res = await get_mission_status.ainvoke({})
    assert evidence_res["findings_count"] >= 1

    reasoning_res = await get_reasoning.ainvoke({})
    assert "hypotheses" in reasoning_res
    assert "decisions" in reasoning_res

    approval_res = await explain_approval.ainvoke({"approval_id": approval_id})
    assert approval_res["action"] == "nikto_scan"
    assert approval_res["risk"] == "medium"

    obj_res = await update_objective.ainvoke({"text": "Focus exclusively on SQLi"})
    assert obj_res["ok"] is True

    note_res = await add_steering_note.ainvoke({"text": "Steer specialist towards /v2/api"})
    assert note_res["ok"] is True
    assert note_res["text"] == "Steer specialist towards /v2/api"


@pytest.mark.asyncio
async def test_coordinator_tools_with_explicit_assessment_id(engine):
    assessment_id = await _create_test_assessment()
    set_conversation_assessment_id(None)

    async with get_async_session_ctx() as session:
        finding = Finding(
            assessment_id=assessment_id,
            canonical_key="xss:http://127.0.0.1/explicit",
            title="Explicit Parameter Finding",
            category="xss",
            severity="medium",
            status="candidate",
            asset="127.0.0.1",
            endpoint="http://127.0.0.1/explicit",
        )
        session.add(finding)
        await session.commit()

    status_res = await get_mission_status.ainvoke({"assessment_id": assessment_id})
    assert "status" in status_res
    assert status_res["findings_count"] >= 1

    findings_res = await list_findings.ainvoke({"assessment_id": assessment_id, "limit": 5})
    assert len(findings_res) >= 1
    assert any(f["title"] == "Explicit Parameter Finding" for f in findings_res)

    note_res = await add_steering_note.ainvoke({
        "assessment_id": assessment_id,
        "text": "Steer using explicit assessment_id",
    })
    assert note_res["ok"] is True
    assert note_res["text"] == "Steer using explicit assessment_id"


@pytest.mark.asyncio
async def test_coordinator_answer_and_worker(engine):
    assessment_id = await _create_test_assessment()

    class MockCoordinatorAgent:
        async def ainvoke(self, inputs):
            return {
                "messages": [
                    AIMessage(
                        content="Recon is currently running. Port 80 and 443 are in scope."
                    )
                ]
            }

    reply = await answer(
        assessment_id=assessment_id,
        text="Give me an update",
        coordinator_agent=MockCoordinatorAgent(),
    )
    assert "Recon is currently running" in reply

    async with get_async_session_ctx() as session:
        op_msg = Message(
            assessment_id=assessment_id,
            role="operator",
            text="Any findings?",
        )
        session.add(op_msg)
        await session.commit()
        await session.refresh(op_msg)

    with patch(
        "app.agents.conversation.service.build_coordinator_agent",
        return_value=MockCoordinatorAgent(),
    ):
        await enqueue(assessment_id, op_msg.id, op_msg.text)
        await asyncio.sleep(0.3)

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
