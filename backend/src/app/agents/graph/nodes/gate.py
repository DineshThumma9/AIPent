"""Gate node: slim wrapper around the security gate.

The gate is NOT orchestration — it is security enforcement (scope, budget,
duplicate, policy, argv binding, evidence). LangGraph gives us interrupt() +
Command(resume=...); the gate gives us the rules for when interrupt is
required and what runs after approval.
"""

from __future__ import annotations

from typing import Callable, Literal

from langgraph.graph import END
from langgraph.types import Command, interrupt

from app.agents.execution.gate import run_gate_step
from app.agents.graph.context import has_planned, is_cancelled
from app.agents.graph.state import AssessmentState
from app.core.db import get_async_session_ctx
from app.core.config import settings
from app.persistence import StepRepo


def make_gate_node(executor: Callable[..., object] | None = None):
    """Build gate node with injected executor (tests use fake_executor)."""

    async def gate_node(state: AssessmentState) -> Command[Literal["gate", "supervisor", "review"]]:
        assessment_id = state["assessment_id"]
        if await is_cancelled(assessment_id):
            return Command(update={"last_message": "Run cancelled."}, goto="supervisor")

        role = state.get("role", "recon")
        result = await run_gate_step(assessment_id, role, interrupt, executor=executor)
        results = [result] if result else []

        async with get_async_session_ctx() as session:
            count = await StepRepo(session).count_steps(assessment_id)

        new_plan = [
            {
                "action": row["action"],
                "target": row.get("target") or "",
                "rationale": row.get("rationale") or "",
            }
            for row in results
        ]
        plan = [*state.get("plan", []), *new_plan][-settings.max_steps :]

        update = {
            "observations": [*state.get("observations", []), *results][-6:],
            "plan": plan,
            "plan_source": "agent" if plan else state.get("plan_source", ""),
            "step_count": count or 0,
            "steps": results[-6:] if results else [],
        }
        if await has_planned(assessment_id):
            return Command(update=update, goto="gate")
        return Command(update=update, goto="supervisor")

    return gate_node
