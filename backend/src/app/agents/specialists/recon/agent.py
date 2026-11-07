"""Recon specialist agent — LLM agent with recon tools (nmap, dirb).

The agent decides whether to run scan_services, dirb_scan, or both, and
against which targets. It returns a typed handoff with recommendations.
"""

from __future__ import annotations

from typing import Any, Literal, TYPE_CHECKING

from langchain_core.messages import HumanMessage
from langgraph.errors import GraphRecursionError
from langgraph.types import Command

from app.agents.control import audit, record_role, role_history
from app.agents.model import build_role_agent
from app.agents.prompts import RECON_PROMPT
from app.agents.tools import set_context
from app.core.db import get_async_session_ctx
from app.persistence import AssessmentRepo, StepRepo

if TYPE_CHECKING:
    from app.agents.graph.state import AssessmentState


async def agent_node(state: AssessmentState) -> Command[Literal["__end__"]]:
    """Run the recon LLM agent. It queues recon steps via its tools."""
    assessment_id = state["assessment_id"]
    run_id = state["run_id"]
    role = "recon"

    # Set context so tools know which assessment/run/role they operate in.
    set_context(assessment_id, run_id, role)

    async with get_async_session_ctx() as session:
        repo = AssessmentRepo(session)
        assessment = await repo.get(assessment_id)
        if assessment is None:
            raise LookupError(f"assessment {assessment_id} not found")

        # Record role turn.
        history = await role_history(session, assessment_id, run_id)
        if not history or history[-1].get("role") != role:
            record_role(
                session, assessment_id, run_id, role, "role turn",
                from_role=state.get("role"),
            )
            history = await role_history(session, assessment_id, run_id)
        await session.commit()

    # Build the LLM agent with recon's tools and prompt.
    agent = build_role_agent(role)
    targets = state.get("targets", [])
    ports = state.get("ports", [])

    digest = (
        f"You are the Recon specialist for assessment {assessment_id}.\n"
        f"Authorised targets: {targets}\n"
        f"Authorised ports: {ports}\n"
        f"Run ID: {run_id}\n"
        f"Mission: Map live services and technology facts on the authorised targets.\n"
        f"Use scan_services as your first action against each target. "
        f"If you find open web services, you may also use dirb_scan.\n"
        f"When finished, call handoff with your recommendation."
    )

    try:
        result = await agent.ainvoke(
            {"messages": [HumanMessage(content=digest)]},
            config={"recursion_limit": 50},
        )
    except GraphRecursionError as exc:
        log.warning(
            "Recon agent hit recursion limit (%s); proceeding with whatever steps were queued",
            exc,
        )
        result = {"messages": []}

    messages = result.get("messages", [])
    last_text = ""
    for message in reversed(messages):
        content = getattr(message, "content", "")
        if content and getattr(message, "type", "") == "ai":
            last_text = str(content)[:2000]
            break

    # The agent's tool calls have already queued steps via StepRepo.
    # Read back what was queued this run for this role.
    async with get_async_session_ctx() as session:
        step_repo = StepRepo(session)
        steps = await step_repo.get_all(assessment_id)
        recon_steps = [
            s for s in steps
            if s.action == "recon_services"
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
                "summary": f"Recon queued {len(recon_steps)} step(s); ready for discovery.",
                "decisions": [
                    {"action": s.action, "target": s.target, "status": s.status}
                    for s in recon_steps
                ],
                "finding_ids": [],
                "step_ids": [s.id for s in recon_steps],
                "next_recommendation": "discovery",
                "needs_input": False,
                "question": None,
                "open_questions": [],
            },
            actor="system",
        )
        await session.commit()

    return Command(
        update={
            "last_specialist": "recon",
            "role": "recon",
            "role_history": history,
            "last_message": last_text or "Recon completed.",
            "recommendations": [
                {
                    "source_agent": "recon",
                    "recommended_agent": "discovery",
                    "reason": "recon scan queued; run discovery against open web services",
                    "priority": "high",
                    "task": "discover candidate findings from recon services",
                    "confidence": 0.9,
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
                    for s in recon_steps
                ],
            ],
            "finished": True,
        },
        goto="__end__",
    )
