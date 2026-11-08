"""Validation specialist agent — LLM agent with validation tools (curl_tool, sqlmap).

The agent decides which candidate findings to validate with curl_tool,
and whether sqlmap_scan is warranted. It returns verdicts and a handoff.
"""

from __future__ import annotations

from typing import Any, Literal, TYPE_CHECKING

from langchain_core.messages import HumanMessage
from langgraph.errors import GraphRecursionError
from langgraph.types import Command

from app.agents.control import audit, record_turn
from app.agents.model import build_role_agent
from app.agents.prompts import VALIDATION_PROMPT
from app.agents.tools import set_context
from app.core.config import settings
from app.core.db import get_async_session_ctx
from app.core.log import get_logger
from app.persistence import AssessmentRepo, FindingRepo, StepRepo

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

        await record_turn(
            session,
            assessment_id,
            run_id,
            role,
            reason="validation agent invocation",
            from_role=state.get("role"),
        )
        await session.commit()

    agent = build_role_agent(role)
    targets = state.get("targets", [])

    # Candidates are findings created by Discovery. Read them from the DB
    # instead of relying on a scratchpad key that is not populated.
    async with get_async_session_ctx() as session:
        finding_repo = FindingRepo(session)
        candidates = [
            row
            for row in await finding_repo.get_candidates(assessment_id)
            if row.status != "false_positive"
        ]

    candidates_summary = "\n".join(
        f"- id={c.id} {c.canonical_key or c.title} "
        f"(asset={c.asset}, endpoint={c.endpoint or 'n/a'}, "
        f"status={c.status}, severity={c.severity})"
        for c in candidates[:12]
    ) or "No candidate findings."

    digest = (
        f"You are the Validation specialist for assessment {assessment_id}.\n"
        f"Authorised targets: {targets}\n"
        f"Candidate findings from discovery:\n{candidates_summary}\n"
        f"Run ID: {run_id}\n"
        f"Mission: Test candidate findings with safe, controlled probes.\n"
        f"Use curl_tool for candidates. Pass the candidate endpoint as "
        f"params.path and the candidate id as params.finding_id. "
        f"Only use sqlmap_scan if you have strong evidence of SQL injection — "
        f"it requires human approval.\n"
        f"Never run destructive sqlmap options (--dump, --os-shell, etc.).\n"
        f"If there are no candidates, do not queue any action; say there is "
        f"nothing to validate.\n"
        f"After queueing, stop calling tools and reply with a short summary. "
        f"The gate runs the probe after your turn; do not claim a verdict "
        f"before it runs."
    )

    try:
        result = await agent.ainvoke(
            {"messages": [HumanMessage(content=digest)]},
            config={"recursion_limit": settings.agent_recursion_limit},
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
            if s.action in ("curl_tool", "sqlmap_scan", "hashcat_crack")
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
