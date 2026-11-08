"""Discovery specialist agent — LLM agent with web scanners (dirb, nikto, zap).

The agent decides whether to run dirb_scan, nikto_scan, or zap_baseline, and
against which open web services. It returns a typed handoff.
"""

from __future__ import annotations

from typing import Any, Literal, TYPE_CHECKING

from langchain_core.messages import HumanMessage
from langgraph.errors import GraphRecursionError
from langgraph.types import Command

from app.agents.control import audit, record_turn
from app.agents.model import build_role_agent
from app.agents.prompts import DISCOVERY_PROMPT
from app.agents.tools import set_context
from app.core.config import settings
from app.core.db import get_async_session_ctx
from app.core.log import get_logger
from app.persistence import AssessmentRepo, FindingRepo, StepRepo

log = get_logger("agent.discovery")

if TYPE_CHECKING:
    from app.agents.graph.state import AssessmentState


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

        await record_turn(
            session,
            assessment_id,
            run_id,
            role,
            reason="discovery agent invocation",
            from_role=state.get("role"),
        )
        await session.commit()

    agent = build_role_agent(role)
    targets = state.get("targets", [])

    # Read services from DB (nmap findings created by the gate after recon's step executed)
    # instead of the empty recon_state scratchpad. By the time discovery runs,
    # the gate has already executed recon's nmap step and created Finding rows.
    async with get_async_session_ctx() as session:
        finding_repo = FindingRepo(session)
        service_findings = await finding_repo.get_services(assessment_id)
        services = [
            {
                "id": f.id,
                "canonical_key": f.canonical_key,
                "title": f.title[:100] if f.title else "",
                "severity": f.severity,
                "status": f.status,
                "confidence": f.confidence,
                "endpoint": f.endpoint,
                "asset": f.asset,
                "origin": f.origin,
            }
            for f in service_findings
        ]

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
        f"Use dirb_scan, nikto_scan, or zap_baseline against open web services. "
        f"Choose the scanner that fits; do not run all three blindly.\n"
        f"After queueing, stop calling tools and reply with a short summary. "
        f"The gate runs the scan after your turn.\n"
        f"Do not use sqlmap or curl_tool — those belong to Validation."
    )

    try:
        result = await agent.ainvoke(
            {"messages": [HumanMessage(content=digest)]},
            config={"recursion_limit": settings.agent_recursion_limit},
        )
    except GraphRecursionError as exc:
        log.warning(
            "Discovery agent hit recursion limit (%s); proceeding with whatever steps were queued",
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

    async with get_async_session_ctx() as session:
        step_repo = StepRepo(session)
        steps = await step_repo.get_all(assessment_id)
        discovery_steps = [
            s for s in steps
            if s.action in ("dirb_scan", "nikto_scan", "zap_baseline")
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
