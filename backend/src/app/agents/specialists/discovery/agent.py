"""Discovery specialist agent — LLM agent with discovery tools (nikto, zap).

The agent decides whether to run nikto_scan, zap_baseline, or both, and
against which open web services. It returns a typed handoff.
"""

from __future__ import annotations

from typing import Any, Literal

from langchain_core.messages import HumanMessage
from langgraph.types import Command

from app.agents.control import audit, record_role, role_history
from app.agents.graph.state import AssessmentState
from app.agents.model import build_role_agent
from app.agents.prompts import DISCOVERY_PROMPT
from app.agents.tools import set_context
from app.core.db import get_async_session_ctx
from app.persistence import AssessmentRepo, StepRepo


async def agent_node(state: dict) -> Command[Literal["__end__"]]:
    """Run the discovery LLM agent. It queues web scan steps via its tools."""
    assessment_id = state["assessment_id"]
    run_id = state["run_id"]
    role = "discovery"

    set_context(assessment_id, run_id, role)

    async with get_async_session_ctx() as session:
        repo = AssessmentRepo(session)
        assessment = await repo.get(assessment_id)
        if assessment is None:
            raise LookupError(f"assessment {assessment_id} not found")

        history = await role_history(session, assessment_id, run_id)
        if not history or history[-1].get("role") != role:
            record_role(
                session, assessment_id, run_id, role, "role turn",
                from_role=state.get("role"),
            )
            history = await role_history(session, assessment_id, run_id)
        await session.commit()

    agent = build_role_agent(role)
    targets = state.get("targets", [])
    services = state.get("recon_state", {}).get("services", [])

    services_summary = "\n".join(
        f"- {s.get('endpoint', 'unknown')} on {s.get('asset', 'unknown')}"
        for s in services[:12]
    ) or "No services reported by recon."

    digest = (
        f"You are the Discovery specialist for assessment {assessment_id}.\n"
        f"Authorised targets: {targets}\n"
        f"Open services from recon:\n{services_summary}\n"
        f"Run ID: {run_id}\n"
        f"Mission: Turn service facts into candidate vulnerabilities.\n"
        f"Use nikto_scan or zap_baseline against open web services. "
        f"Do not use sqlmap or http_probe — those belong to Validation.\n"
        f"When finished, call handoff with your recommendation."
    )

    result = await agent.ainvoke(
        {"messages": [HumanMessage(content=digest)]},
        config={"recursion_limit": 10},
    )

    messages = result.get("messages", [])
    last_text = ""
    for message in reversed(messages):
        content = getattr(message, "content", "")
        if content and getattr(message, "type", "") == "ai":
            last_text = str(content)[:2000]
            break

    async with get_async_session_ctx() as session:
        step_repo = StepRepo(session)
        steps = await step_repo.get_all(assessment_id)
        discovery_steps = [
            s for s in steps
            if s.action in ("nikto_scan", "zap_baseline")
        ]

    # Emit handoff.created audit event
    async with get_async_session_ctx() as session:
        audit(
            session,
            assessment_id,
            "handoff.created",
            {
                "run_id": run_id,
                "role": role,
                "summary": f"Discovery queued {len(discovery_steps)} step(s); ready for validation.",
                "decisions": [
                    {"action": s.action, "target": s.target, "status": s.status}
                    for s in discovery_steps
                ],
                "finding_ids": [],
                "step_ids": [s.id for s in discovery_steps],
                "next_recommendation": "validation",
                "needs_input": False,
                "question": None,
                "open_questions": [],
            },
            actor="system",
        )
        await session.commit()

    return Command(
        update={
            "last_specialist": "discovery",
            "role": "discovery",
            "role_history": history,
            "last_message": last_text or "Discovery completed.",
            "recommendations": [
                {
                    "source_agent": "discovery",
                    "recommended_agent": "validation",
                    "reason": "web scan steps queued; validate candidate findings",
                    "priority": "high",
                    "task": "validate discovery candidates",
                    "confidence": 0.85,
                }
            ],
            "steps": [
                *state.get("steps", []),
                *[
                    {
                        "step_id": s.id,
                        "action": s.action,
                        "target": s.target,
                        "status": s.status,
                    }
                    for s in discovery_steps
                ],
            ],
            "finished": True,
        },
        goto="__end__",
    )
