"""Validation specialist agent — LLM agent with validation tools (http_probe, sqlmap).

The agent decides which candidate findings to validate with http_probe,
and whether sqlmap_scan is warranted. It returns verdicts and a handoff.
"""

from __future__ import annotations

from typing import Any, Literal, TYPE_CHECKING

from langchain_core.messages import HumanMessage
from langgraph.errors import GraphRecursionError
from langgraph.types import Command

from app.agents.control import audit, record_role, role_history
from app.agents.model import build_role_agent
from app.agents.prompts import VALIDATION_PROMPT
from app.agents.tools import set_context
from app.core.db import get_async_session_ctx
from app.core.log import get_logger
from app.persistence import AssessmentRepo, StepRepo

log = get_logger("agent.validation")

if TYPE_CHECKING:
    from app.agents.graph.state import AssessmentState


async def agent_node(state: dict) -> Command[Literal["__end__"]]:
    """Run the validation LLM agent. It queues probe steps via its tools."""
    assessment_id = state["assessment_id"]
    run_id = state["run_id"]
    role = "validation"

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
    candidates = state.get("discovery_state", {}).get("candidates", [])

    candidates_summary = "\n".join(
        f"- {c.get('canonical_key', c.get('title', 'unknown'))} "
        f"(status={c.get('status', 'unknown')}, severity={c.get('severity', 'unknown')})"
        for c in candidates[:12]
    ) or "No candidates reported by discovery."

    digest = (
        f"You are the Validation specialist for assessment {assessment_id}.\n"
        f"Authorised targets: {targets}\n"
        f"Candidate findings from discovery:\n{candidates_summary}\n"
        f"Run ID: {run_id}\n"
        f"Mission: Test candidate findings with safe, controlled probes.\n"
        f"Use http_probe to verify candidates. Only use sqlmap_scan if you "
        f"have strong evidence of SQL injection — it requires human approval.\n"
        f"Never run destructive sqlmap options (--dump, --os-shell, etc.).\n"
        f"Record your verdict for each candidate: confirmed, suspected, or false_positive.\n"
        f"When finished, call handoff with your recommendation."
    )

    try:
        result = await agent.ainvoke(
            {"messages": [HumanMessage(content=digest)]},
            config={"recursion_limit": 50},
        )
    except GraphRecursionError as exc:
        log.warning(
            "Validation agent hit recursion limit (%s); proceeding with whatever steps were queued",
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
        validation_steps = [
            s for s in steps
            if s.action in ("http_probe", "sqlmap_scan")
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
                "summary": f"Validation queued {len(validation_steps)} step(s); ready for review.",
                "decisions": [
                    {"action": s.action, "target": s.target, "status": s.status}
                    for s in validation_steps
                ],
                "finding_ids": [],
                "step_ids": [s.id for s in validation_steps],
                "next_recommendation": "review",
                "needs_input": False,
                "question": None,
                "open_questions": [],
            },
            actor="system",
        )
        await session.commit()

    return Command(
        update={
            "last_specialist": "validation",
            "role": "validation",
            "role_history": history,
            "last_message": last_text or "Validation completed.",
            "recommendations": [
                {
                    "source_agent": "validation",
                    "recommended_agent": "review",
                    "reason": "probe steps queued; review results before concluding",
                    "priority": "high",
                    "task": "review probe outcomes",
                    "confidence": 0.8,
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
                    for s in validation_steps
                ],
            ],
            "finished": True,
        },
        goto="__end__",
    )
