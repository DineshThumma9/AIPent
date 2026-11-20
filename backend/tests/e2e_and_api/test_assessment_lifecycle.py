"""End-to-end integration tests for full assessment lifecycle.

Covers:
- Full multi-turn assessment: Create -> Recon -> Discovery -> Validation -> Review -> PDF generation
- prepare_run lifecycle: role model auditing and target baseline capture
- Specialist turn single-action guard: rejecting extraneous tool calls
- Operator steering directive injection into brief and specialist execution
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, AnyMessage, HumanMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command
from sqlmodel import select

from app.actions import catalogue
from app.agents.builder import build_assessment_graph_v2, prepare_run
from app.agents.mission_brain import deterministic_safe_route
from app.agents.nodes import brief_node, model_node
from app.agents.state import initial_state
from app.core.config import settings
from app.core.db import get_async_session_ctx
from app.domain.models import (
    Approval,
    Assessment,
    AssessmentStatus,
    Audit,
    Decision,
    Evidence,
    Finding,
    Severity,
    Step,
    StepStatus,
)
from app.persistence import FindingRepo, SteeringRepo
from app.persistence.audit_repo import audit
from app.reporting.report import generate_report


class MultiTurnScriptedModel(BaseChatModel):
    """Scripted model that returns responses in order across roles."""

    responses: list[AIMessage]
    recorded_inputs: list[list[AnyMessage]] = []

    def bind_tools(self, tools: Any, **kwargs: Any) -> Any:
        return self

    async def _agenerate(
        self,
        messages: list[AnyMessage],
        stop: list[str] | None = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> ChatResult:
        self.recorded_inputs.append(list(messages))
        idx = len(self.recorded_inputs) - 1
        if idx < len(self.responses):
            resp = self.responses[idx]
        else:
            resp = AIMessage(content="completed")
        return ChatResult(generations=[ChatGeneration(message=resp)])

    def _generate(
        self,
        messages: list[AnyMessage],
        stop: list[str] | None = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> ChatResult:
        self.recorded_inputs.append(list(messages))
        idx = len(self.recorded_inputs) - 1
        if idx < len(self.responses):
            resp = self.responses[idx]
        else:
            resp = AIMessage(content="completed")
        return ChatResult(generations=[ChatGeneration(message=resp)])

    @property
    def _llm_type(self) -> str:
        return "multi-turn-scripted-model"


@pytest.mark.asyncio
async def test_full_multi_role_assessment_lifecycle(engine, monkeypatch, tmp_path):
    """Test full multi-role observe-reason-act loop:

    Recon -> Discovery -> Validation -> Review with human approval gate and PDF report.
    """
    monkeypatch.setattr(catalogue, "ARTIFACT_DIR", tmp_path / "artifacts")
    monkeypatch.setattr(settings, "artifacts_dir", tmp_path / "artifacts")
    monkeypatch.setattr(settings, "agent_loop", "v2")

    # 1. Create Assessment
    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Full Lifecycle E2E Assessment",
            request="Execute comprehensive security evaluation",
            targets=["127.0.0.1"],
            ports=[3000],
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)
        aid = assessment.id

    # 2. Mock Executor that simulates scanners producing findings and evidence
    created_finding_ids: list[int] = []

    async def mock_executor(session, a_id, action, target=None, rationale="", step=None):
        step.status = StepStatus.SUCCEEDED.value
        step.output_path = f"/tmp/{step.id}.{action}.txt"
        step.output_sha256 = f"sha256_{step.id}"

        if action == "recon_services":
            f = Finding(
                assessment_id=a_id,
                canonical_key=f"nmap:{target}:tcp/3000",
                title="Open port 3000/tcp (http Express)",
                asset=target or "127.0.0.1",
                endpoint="tcp/3000",
                severity=Severity.LOW.value,
                status="info",
            )
            session.add(f)
            await session.flush()
            created_finding_ids.append(f.id)
            ev = Evidence(
                assessment_id=a_id,
                step_id=step.id,
                finding_id=f.id,
                category="recon",
                locator={"tool": "nmap", "port": 3000},
                excerpt="3000/tcp open http Express",
            )
            session.add(ev)

        elif action == "zap_baseline":
            f = Finding(
                assessment_id=a_id,
                canonical_key=f"zap:{target}:missing_csrf",
                title="Missing Anti-CSRF Tokens",
                asset=target or "127.0.0.1",
                endpoint="tcp/3000/login",
                severity=Severity.MEDIUM.value,
                status="suspected",
            )
            session.add(f)
            await session.flush()
            created_finding_ids.append(f.id)
            ev = Evidence(
                assessment_id=a_id,
                step_id=step.id,
                finding_id=f.id,
                category="vulnerability",
                locator={"tool": "zap_baseline", "alert": "Missing Anti-CSRF Tokens"},
                excerpt="Anti-CSRF Tokens missing on login form",
            )
            session.add(ev)

        elif action == "curl_request":
            target_finding_id = created_finding_ids[-1]
            ev = Evidence(
                assessment_id=a_id,
                step_id=step.id,
                finding_id=target_finding_id,
                category="probe",
                locator={"tool": "curl_request", "http_status": 200, "finding_id": target_finding_id},
                excerpt="HTTP 200 OK without CSRF protection",
            )
            session.add(ev)

        audit(session, a_id, "step.succeeded", {"step_id": step.id, "action": action})
        await session.commit()
        return step

    # 3. Define LLM responses for each role
    scripted_model = MultiTurnScriptedModel(
        responses=[
            # Recon turn 1: recon_services
            AIMessage(
                content="Scanning services.",
                tool_calls=[{
                    "id": "recon_call_1",
                    "name": "recon_services",
                    "args": {"target": "127.0.0.1", "rationale": "Discover listening ports.", "profile": "fast", "ports": "3000"},
                }],
            ),
            # Recon turn 2: handoff to discovery
            AIMessage(
                content="Port 3000 HTTP mapped. Handing off to discovery.",
                tool_calls=[{
                    "id": "recon_handoff",
                    "name": "handoff",
                    "args": {
                        "summary": "Port 3000 HTTP open.",
                        "next_role": "discovery",
                        "why": "Web service present, need discovery.",
                        "confidence": 0.85,
                        "stop_reason": "surface_mapped",
                        "finding_ids": [1],
                        "step_ids": [1],
                        "open_questions": [],
                    },
                }],
            ),
            # Discovery turn 3: zap_baseline
            AIMessage(
                content="Starting web baseline scan.",
                tool_calls=[{
                    "id": "zap_call_1",
                    "name": "zap_baseline",
                    "args": {"target": "127.0.0.1", "rationale": "Identify web application candidates."},
                }],
            ),
            # Discovery turn 4: handoff to validation
            AIMessage(
                content="Discovered candidate vulnerabilities. Handing off to validation.",
                tool_calls=[{
                    "id": "discovery_handoff",
                    "name": "handoff",
                    "args": {
                        "summary": "Discovered candidate CSRF finding.",
                        "next_role": "validation",
                        "why": "Candidates ready for probing.",
                        "confidence": 0.80,
                        "stop_reason": "hypotheses_tested",
                        "finding_ids": [2],
                        "step_ids": [2],
                        "open_questions": [],
                    },
                }],
            ),
            # Validation turn 5: curl_request
            AIMessage(
                content="Validating candidate finding #2 with safe probe.",
                tool_calls=[{
                    "id": "curl_call_1",
                    "name": "curl_request",
                    "args": {
                        "target": "127.0.0.1",
                        "rationale": "Verify login endpoint response.",
                        "path": "/login",
                        "method": "GET",
                        "finding_id": 2,
                    },
                }],
            ),
            # Validation turn 6: update_finding_status
            AIMessage(
                content="Probe confirmed CSRF vulnerability.",
                tool_calls=[{
                    "id": "update_status_1",
                    "name": "update_finding_status",
                    "args": {
                        "finding_id": 2,
                        "status": "confirmed",
                        "reasoning": "Endpoint responded HTTP 200 without Anti-CSRF token headers.",
                    },
                }],
            ),
            # Validation turn 7: handoff to review
            AIMessage(
                content="Validation complete. Handing off to review.",
                tool_calls=[{
                    "id": "validation_handoff",
                    "name": "handoff",
                    "args": {
                        "summary": "Finding #2 confirmed via active probe.",
                        "next_role": "review",
                        "why": "All candidates evaluated.",
                        "confidence": 0.95,
                        "stop_reason": "hypotheses_tested",
                        "finding_ids": [2],
                        "step_ids": [3],
                        "open_questions": [],
                    },
                }],
            ),
        ]
    )

    monkeypatch.setattr("app.agents.nodes.build_role_model", lambda role: scripted_model)

    async def mock_supervisor(digest, **kwargs):
        last_h = digest.recent_handoffs[-1] if digest.recent_handoffs else None
        return deterministic_safe_route(
            {"turns": digest.budget.get("turns", {}), "last_handoff": last_h},
            digest,
        )

    monkeypatch.setattr("app.agents.nodes.run_supervisor_agent", mock_supervisor)

    # 4. Build graph and execute steps
    checkpointer = MemorySaver()
    graph = build_assessment_graph_v2(checkpointer=checkpointer, executor=mock_executor)
    config = {"configurable": {"thread_id": f"agent-{aid}"}}

    init = initial_state(aid, run_id="e2e-run-1")

    # Step 1: The supervisor proposes an editable plan -> PAUSES at plan gate
    await graph.ainvoke(init, config=config)

    state = await graph.aget_state(config)
    assert state.next == ("plan",)
    proposed = state.tasks[0].interrupts[0].value
    assert proposed["gate"] == "plan"
    assert proposed["plan"]

    # Approve the plan (with a sample operator edit) so orchestration can start.
    edited_plan = [
        {**step, "rationale": f"{step['rationale']} (operator reviewed)"}
        for step in proposed["plan"]
    ]
    await graph.ainvoke(
        Command(
            resume={
                "decision": "approved",
                "actor": "analyst",
                "reason": "Approved initial plan",
                "plan": edited_plan,
                "feedback": "Stay within the authorized lab target.",
            }
        ),
        config=config,
    )

    # Recon runs and hands off to Discovery; Discovery requests zap_baseline -> PAUSES at approve gate
    state = await graph.aget_state(config)
    assert state.next == ("approve",)
    pending_interrupt = state.tasks[0].interrupts[0].value
    assert pending_interrupt["gate"] == "action"
    assert pending_interrupt["action"] == "zap_baseline"

    # Resume with approval for zap_baseline
    await graph.ainvoke(
        Command(resume={"decision": "approved", "actor": "analyst", "reason": "Approved zap baseline"}),
        config=config,
    )

    # Step 2: Discovery completes, hands off to Validation; Validation requests curl_request -> PAUSES at approve gate
    state = await graph.aget_state(config)
    assert state.next == ("approve",)
    pending_curl = state.tasks[0].interrupts[0].value
    assert pending_curl["action"] == "curl_request"

    # Resume with approval for curl_request
    await graph.ainvoke(
        Command(resume={"decision": "approved", "actor": "analyst", "reason": "Approved curl probe"}),
        config=config,
    )

    # Step 3: Graph runs probe, updates finding to confirmed, and reaches review gate
    state = await graph.aget_state(config)
    assert state.next == ("review",)

    # 5. Verify database state & generate PDF report
    async with get_async_session_ctx() as session:
        f_repo = FindingRepo(session)
        findings = await f_repo.get_all(aid)
        assert len(findings) >= 2

        # Verify Finding #2 confirmed
        f2 = await f_repo.get(2)
        assert f2 is not None
        assert f2.status == "confirmed"

        # Generate final report
        report_path = await generate_report(session, aid)
        assert Path(report_path).exists()
        assert Path(report_path).stat().st_size > 0
        content = Path(report_path).read_bytes()
        assert content.startswith(b"%PDF-")


@pytest.mark.asyncio
async def test_prepare_run_auditing_and_juiceshop_baseline(engine, monkeypatch):
    """Test prepare_run audits all role models and checks targets for JuiceShop."""
    from app.integrations import juiceshop

    baseline_captured = []

    async def mock_capture(session, assessment_id):
        baseline_captured.append(assessment_id)
        return {"baseline": "ok"}

    monkeypatch.setattr(juiceshop, "capture_baseline", mock_capture)

    # Case A: Generic target -> does not capture juiceshop baseline
    async with get_async_session_ctx() as session:
        a_generic = Assessment(
            title="Generic Target",
            request="Evaluate standard server",
            targets=["192.168.1.100"],
            ports=[80],
        )
        session.add(a_generic)
        await session.commit()
        await session.refresh(a_generic)

        await prepare_run(session, a_generic.id)
        assert a_generic.id not in baseline_captured

    # Case B: JuiceShop target -> captures baseline
    async with get_async_session_ctx() as session:
        a_juice = Assessment(
            title="JuiceShop Target",
            request="Evaluate juice-shop target",
            targets=["http://localhost:3000"],
            ports=[3000],
        )
        session.add(a_juice)
        await session.commit()
        await session.refresh(a_juice)

        await prepare_run(session, a_juice.id)
        assert a_juice.id in baseline_captured

        # Case C: Check run.requested audit event contains role models
        res = await session.execute(
            select(Audit).where(Audit.assessment_id == a_juice.id, Audit.event_type == "run.requested")
        )
        audit_ev = res.scalars().first()
        assert audit_ev is not None
        assert "models" in audit_ev.payload
        assert set(audit_ev.payload["models"]) >= {"recon", "discovery", "validation", "supervisor"}
        # Run-start visibility: budgets, per-role tools and thinking levels.
        config = audit_ev.payload["config"]
        assert "max_agent_turns" in config["budgets"]
        assert "curl_request" in config["tools"]["validation"]
        assert set(config["thinking"]) >= {"supervisor", "recon", "discovery", "validation"}


@pytest.mark.asyncio
async def test_specialist_action_concurrency_guard(engine, monkeypatch):
    """Verify specialist attempting multiple actions in a single turn executes only the first."""
    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Concurrency Guard Assessment",
            request="Test single action constraint",
            targets=["127.0.0.1"],
            ports=[3000],
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)
        aid = assessment.id

    class ScriptedTwoActionsModel(BaseChatModel):
        def bind_tools(self, tools, **kwargs):
            return self

        def _generate(self, messages, stop=None, run_manager=None, **kwargs):
            return ChatResult(
                generations=[
                    ChatGeneration(
                        message=AIMessage(
                            content="Running multiple scans",
                            tool_calls=[
                                {
                                    "id": "call_1",
                                    "name": "recon_services",
                                    "args": {"target": "127.0.0.1", "rationale": "scan 1"},
                                },
                                {
                                    "id": "call_2",
                                    "name": "recon_services",
                                    "args": {"target": "127.0.0.1", "rationale": "scan 2"},
                                },
                            ],
                        )
                    )
                ]
            )

        @property
        def _llm_type(self):
            return "scripted-two-actions"

    monkeypatch.setattr("app.agents.nodes.build_role_model", lambda role: ScriptedTwoActionsModel())

    state = {
        "assessment_id": aid,
        "run_id": "test_run_guard",
        "role": "recon",
        "turns": {"recon": 0},
        "nudges": 0,
        "no_progress": 0,
        "messages": [HumanMessage(content="Start recon")],
    }

    cmd = await model_node(state)
    assert cmd.goto == "prepare"
    extra_msg = cmd.update["messages"][-1]
    assert "Only one action tool call is executed per turn" in extra_msg.content
    assert extra_msg.tool_call_id == "call_2"


@pytest.mark.asyncio
async def test_steering_directive_injection_in_lifecycle(engine):
    """Test that steering notes queued by the operator are consumed by brief_node and model_node."""
    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Steering Assessment",
            request="Test operator steering",
            targets=["127.0.0.1"],
            ports=[80],
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)
        aid = assessment.id

        repo = SteeringRepo(session)
        await repo.add(aid, "run-steer-1", "Focus specifically on port 80 admin paths")

    state = initial_state(aid)
    state["role"] = "recon"
    state["run_id"] = "run-steer-1"

    cmd = await brief_node(state)
    assert cmd.goto == "model"
    brief_content = cmd.update["messages"][0].content
    assert "OPERATOR STEERING" in brief_content
    assert "Focus specifically on port 80 admin paths" in brief_content

    # Verify steering note marked consumed
    async with get_async_session_ctx() as session:
        repo = SteeringRepo(session)
        pending = await repo.take_pending(aid, "run-steer-1")
        assert len(pending) == 0
