"""Supervisor node: owns the routing decision over specialist sub-graphs.

Specialists are self-contained LangGraph sub-graphs under ``agents/specialists/``.
The supervisor:
1. Routes to the gate when there are planned (unexecuted) steps.
2. Processes a just-finished specialist's recommendation and invokes the next
   specialist sub-graph inline (or routes to review).
3. Otherwise invokes recon, merges findings/recommendations/steps into shared
   state, and re-enters itself so the gate can execute the queued step.

The supervisor never touches a target directly — it only schedules specialists
and decides what to do with their output. Every specialist invocation is
audited with ``role.started`` and bounded by per-role turn caps.
"""

from __future__ import annotations

from typing import Literal

from langgraph.types import Command

from app.agents.control import ROLE_TURN_CAPS, audit
from app.agents.graph.context import discovery_eligible, has_planned, validation_eligible
from app.agents.graph.state import AssessmentState
from app.core.db import get_async_session_ctx

from app.agents.specialists import (
    build_discovery_graph,
    build_recon_graph,
    build_validation_graph,
)
from app.agents.specialists.discovery.graph import discovery_graph_config
from app.agents.specialists.recon.graph import recon_graph_config
from app.agents.specialists.validation.graph import validation_graph_config


# Compiled once per process, shared across invocations.
_recon_graph = build_recon_graph()
_discovery_graph = build_discovery_graph()
_validation_graph = build_validation_graph()


def _latest_recommendation(state: AssessmentState) -> dict | None:
    """Return the most recent non-trivial recommendation, if any."""
    for rec in reversed(state.get("recommendations", []) or []):
        if rec.get("recommended_agent") not in (None, "none"):
            return rec
    return None


async def _emit_role_started(
    session,
    assessment_id: int,
    run_id: str,
    role: str,
    reason: str,
    from_role: str | None = None,
) -> None:
    """Audit that a specialist role is starting a turn."""
    audit(
        session,
        assessment_id,
        "role.started",
        {
            "run_id": run_id,
            "from": from_role,
            "to": role,
            "role": role,
            "reason": reason,
        },
        actor="system",
    )


async def _invoke_specialist(state: AssessmentState, specialist: str) -> dict:
    """Run a specialist sub-graph with a slice of shared state."""
    assessment_id = state["assessment_id"]
    slice_ = {
        "assessment_id": assessment_id,
        "run_id": state["run_id"],
        "targets": state.get("targets", []),
        "ports": state.get("ports", []),
        "exclusions": state.get("exclusions", []),
    }

    if specialist == "recon":
        return await _recon_graph.ainvoke(
            slice_, config=recon_graph_config(assessment_id)
        )
    if specialist == "discovery":
        slice_["services"] = state.get("recon_state", {}).get("services", [])
        return await _discovery_graph.ainvoke(
            slice_, config=discovery_graph_config(assessment_id)
        )
    if specialist == "validation":
        slice_["candidates"] = state.get("discovery_state", {}).get("candidates", [])
        return await _validation_graph.ainvoke(
            slice_, config=validation_graph_config(assessment_id)
        )
    raise ValueError(f"unknown specialist {specialist!r}")


async def supervisor_node(state: AssessmentState) -> Command:
    assessment_id = state["assessment_id"]
    run_id = state["run_id"]
    current_role = state.get("role", "recon")

    # 1. Planned steps waiting → gate (human approval before anything runs).
    if await has_planned(assessment_id):
        return Command(update={"next_node": "gate"}, goto="gate")

    # 2. A specialist just finished — act on its recommendation.
    last_specialist = state.get("last_specialist")
    if last_specialist:
        rec = _latest_recommendation(state)
        target = rec.get("recommended_agent") if rec else None

        if target == "discovery" and await discovery_eligible(assessment_id):
            turns = int(state.get("turns", {}).get("discovery", 0))
            cap = ROLE_TURN_CAPS["discovery"]
            if turns >= cap:
                async with get_async_session_ctx() as session:
                    await audit(
                        session,
                        assessment_id,
                        "role.budget_exhausted",
                        {
                            "run_id": run_id,
                            "role": "discovery",
                            "turns": turns,
                            "cap": cap,
                            "reason": "discovery turn cap reached",
                        },
                        actor="system",
                    )
                    await session.commit()
                return Command(
                    update={"last_specialist": None, "next_node": "review"},
                    goto="review",
                )
            async with get_async_session_ctx() as session:
                await _emit_role_started(
                    session, assessment_id, run_id, "discovery",
                    reason="discovery candidates queued by recon",
                    from_role=current_role,
                )
                await session.commit()
            result = await _invoke_specialist(state, "discovery")
            return Command(
                update={
                    "last_specialist": "discovery",
                    "role": "discovery",
                    "recommendations": [
                        *state.get("recommendations", []),
                        *result.get("recommendations", []),
                    ],
                    "steps": [*state.get("steps", []), *result.get("steps_queued", [])],
                    "discovery_state": {
                        **state.get("discovery_state", {}),
                        "candidates": result.get("candidates", []),
                        "scanners_used": result.get("scanners_used", []),
                    },
                    "next_node": "supervisor",
                },
                goto="supervisor",
            )

        if target == "validation" and await validation_eligible(assessment_id):
            turns = int(state.get("turns", {}).get("validation", 0))
            cap = ROLE_TURN_CAPS["validation"]
            if turns >= cap:
                async with get_async_session_ctx() as session:
                    await audit(
                        session,
                        assessment_id,
                        "role.budget_exhausted",
                        {
                            "run_id": run_id,
                            "role": "validation",
                            "turns": turns,
                            "cap": cap,
                            "reason": "validation turn cap reached",
                        },
                        actor="system",
                    )
                    await session.commit()
                return Command(
                    update={"last_specialist": None, "next_node": "review"},
                    goto="review",
                )
            async with get_async_session_ctx() as session:
                await _emit_role_started(
                    session, assessment_id, run_id, "validation",
                    reason="validation candidates queued by discovery",
                    from_role=current_role,
                )
                await session.commit()
            result = await _invoke_specialist(state, "validation")
            return Command(
                update={
                    "last_specialist": "validation",
                    "role": "validation",
                    "recommendations": [
                        *state.get("recommendations", []),
                        *result.get("recommendations", []),
                    ],
                    "steps": [*state.get("steps", []), *result.get("steps_queued", [])],
                    "validation_state": {
                        **state.get("validation_state", {}),
                        "verdicts": result.get("verdicts", []),
                        "probes_used": result.get("probes_used", 0),
                    },
                    "next_node": "supervisor",
                },
                goto="supervisor",
            )

        # Review or no actionable recommendation.
        return Command(
            update={"last_specialist": None, "next_node": "review"},
            goto="review",
        )

    # 3. No specialist has run in this pass — start with recon.
    turns = int(state.get("turns", {}).get("recon", 0))
    cap = ROLE_TURN_CAPS["recon"]
    if turns >= cap:
        async with get_async_session_ctx() as session:
            await audit(
                session,
                assessment_id,
                "role.budget_exhausted",
                {
                    "run_id": run_id,
                    "role": "recon",
                    "turns": turns,
                    "cap": cap,
                    "reason": "recon turn cap reached",
                },
                actor="system",
            )
            await session.commit()
        return Command(
            update={"next_node": "review"},
            goto="review",
        )

    async with get_async_session_ctx() as session:
        await _emit_role_started(
            session, assessment_id, run_id, "recon",
            reason="run start",
            from_role=None,
        )
        await session.commit()

    result = await _invoke_specialist(state, "recon")

    services = result.get("services", [])
    return Command(
        update={
            "last_specialist": "recon",
            "role": "recon",
            "recommendations": [
                *state.get("recommendations", []),
                *result.get("recommendations", []),
            ],
            "steps": [*state.get("steps", []), *result.get("steps_queued", [])],
            "recon_state": {
                **state.get("recon_state", {}),
                "services": services,
            },
            "next_node": "supervisor",
        },
        goto="supervisor",
    )
