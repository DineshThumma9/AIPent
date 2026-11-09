"""MissionBrain: shared digest, supervisor agent execution, and deterministic route guard.

The supervisor proposes a RouteDecision based on the mission digest.
Python's validate_route guard accepts, rejects, or replaces it.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from app.agents.control import audit
if TYPE_CHECKING:
    from app.agents.graph.state import AssessmentState
from app.agents.loop.contracts import FailureSignal, RouteDecision
from app.agents.loop.reasoning import build_evidence_board
from app.agents.loop.tool_specs import SUPERVISOR_TOOL_SPECS, ToolSpec
from app.core.config import settings
from app.core.db import get_async_session_ctx
from app.domain.models import Assessment, Audit, Finding, Step
from app.persistence.finding_repo import FindingRepo

ROLE_TURN_CAPS = {
    "recon": 10,
    "discovery": 20,
    "validation": 25,
    "review": 2,
}


class MissionDigest(BaseModel):
    """Bounded snapshot of the current mission state."""

    assessment_id: int
    run_id: str
    status: str = "running"
    targets: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    exclusions: list[str] = Field(default_factory=list)
    services: list[dict[str, Any]] = Field(default_factory=list)
    candidates: list[dict[str, Any]] = Field(default_factory=list)
    hypotheses: list[dict[str, Any]] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)
    recent_handoffs: list[dict[str, Any]] = Field(default_factory=list)
    recent_steps: list[dict[str, Any]] = Field(default_factory=list)
    budget: dict[str, Any] = Field(default_factory=dict)
    failure: dict[str, Any] | None = None
    last_route: dict[str, Any] | None = None
    last_route_error: str | None = None

    @property
    def has_discovery_surface(self) -> bool:
        return len(self.services) > 0

    @property
    def has_validation_candidates(self) -> bool:
        return len(self.candidates) > 0


def _role_has_budget(role: str, state: AssessmentState) -> bool:
    cap = min(ROLE_TURN_CAPS.get(role, 8), settings.max_agent_turns)
    turns = state.get("turns", {}).get(role, 0)
    return turns < cap


def _retry_allowed(state: AssessmentState, digest: MissionDigest) -> bool:
    return state.get("nudges", 0) < settings.max_role_retries


async def build_mission_digest(
    assessment_id: int,
    run_id: str,
    state: AssessmentState,
    failure: FailureSignal | None = None,
) -> MissionDigest:
    """Construct a bounded MissionDigest from DB and State."""
    async with get_async_session_ctx() as session:
        assessment = await session.get(Assessment, assessment_id)
        targets = assessment.targets if assessment else []
        ports = assessment.ports if assessment else []
        exclusions = assessment.exclusions if assessment else []

        finding_repo = FindingRepo(session)
        service_rows = await finding_repo.get_services(assessment_id)
        candidate_rows = await finding_repo.get_candidates(assessment_id)
        board = await build_evidence_board(session, assessment_id)

        step_res = await session.execute(
            select(Step)
            .where(Step.assessment_id == assessment_id)
            .order_by(Step.id.desc())
            .limit(8)
        )
        obs_map = {
            o.get("step_id"): o
            for o in state.get("observations", [])
            if isinstance(o, dict) and o.get("step_id") is not None
        }
        recent_steps = []
        for s in reversed(list(step_res.scalars().all())):
            entry: dict[str, Any] = {
                "id": s.id,
                "action": s.action,
                "target": s.target,
                "status": s.status,
                "error": s.error,
            }
            obs = obs_map.get(s.id)
            if obs:
                if obs.get("summary"):
                    entry["summary"] = obs["summary"][:300]
                facts = obs.get("facts") or {}
                if "status_code" in facts and facts["status_code"] is not None:
                    entry["status_code"] = facts["status_code"]
            recent_steps.append(entry)

    handoffs = state.get("handoffs", [])
    if state.get("last_handoff"):
        handoffs = list(handoffs) + [state["last_handoff"]]

    return MissionDigest(
        assessment_id=assessment_id,
        run_id=run_id,
        status="running",
        targets=targets,
        ports=ports,
        exclusions=exclusions,
        services=[{"id": s.id, "title": s.title, "endpoint": s.endpoint or s.asset} for s in service_rows[:20]],
        candidates=[{"id": c.id, "title": c.title, "severity": c.severity, "endpoint": c.endpoint} for c in candidate_rows[:20]],
        hypotheses=[h.model_dump() for h in board.hypotheses[:10]],
        open_questions=board.open_questions[:10],
        recent_handoffs=handoffs[-5:],
        recent_steps=recent_steps,
        budget={
            "turns": state.get("turns", {}),
            "supervisor_calls": state.get("supervisor_calls", 0),
        },
        failure=failure.model_dump() if failure else None,
        last_route=state.get("supervisor_decision"),
    )


def deterministic_safe_route(
    state: AssessmentState,
    digest: MissionDigest,
) -> RouteDecision:
    """Safe fallback route when supervisor model is unavailable or proposal is invalid."""
    turns = state.get("turns", {})
    last_handoff = state.get("last_handoff")

    # If specialist recommended a valid next role with budget
    if last_handoff and isinstance(last_handoff, dict):
        rec = last_handoff.get("next_role")
        if rec in ("recon", "discovery", "validation") and _role_has_budget(rec, state):
            return RouteDecision(
                next_role=rec,
                why=f"Follow specialist handoff to {rec}.",
                priority="medium",
                confidence=float(last_handoff.get("confidence", 0.7)),
            )
        elif rec == "review":
            return RouteDecision(
                next_role="review",
                why=last_handoff.get("why") or "Specialist recommended review.",
                priority="medium",
                confidence=float(last_handoff.get("confidence", 0.8)),
                report_ready=True,
            )

    # Progression order: recon -> discovery -> validation -> review
    if turns.get("recon", 0) == 0 and _role_has_budget("recon", state):
        return RouteDecision(
            next_role="recon",
            why="Initial assessment entry: perform reconnaissance.",
            priority="high",
            confidence=0.9,
        )

    if _role_has_budget("discovery", state) and (digest.has_discovery_surface or turns.get("discovery", 0) == 0):
        return RouteDecision(
            next_role="discovery",
            why="Proceed to vulnerability discovery.",
            priority="medium",
            confidence=0.8,
        )

    if _role_has_budget("validation", state) and (digest.has_validation_candidates or turns.get("validation", 0) == 0):
        return RouteDecision(
            next_role="validation",
            why="Candidate findings discovered; validate candidates.",
            priority="medium",
            confidence=0.75,
        )

    return RouteDecision(
        next_role="review",
        why="Mission progression complete or budgets exhausted.",
        priority="low",
        confidence=0.95,
        report_ready=True,
    )


def validate_route(
    proposed: RouteDecision,
    state: AssessmentState,
    digest: MissionDigest,
) -> tuple[RouteDecision, str | None]:
    """Validate a proposed RouteDecision against determinism and safety constraints."""
    if proposed.next_role not in {"recon", "discovery", "validation", "review"}:
        return deterministic_safe_route(state, digest), "unknown_role"

    if proposed.overrides_specialist and not (proposed.override_reason or "").strip():
        return deterministic_safe_route(state, digest), "missing_override_reason"

    if proposed.next_role != "review" and not _role_has_budget(proposed.next_role, state):
        return deterministic_safe_route(state, digest), "role_budget_exhausted"

    has_run_turns = state.get("turns", {}).get(proposed.next_role, 0) > 0
    if proposed.next_role == state.get("role") and has_run_turns and not (proposed.directive or "").strip():
        return deterministic_safe_route(state, digest), "same_role_without_directive"

    if proposed.next_role == state.get("role") and has_run_turns and not _retry_allowed(state, digest):
        return deterministic_safe_route(state, digest), "retry_limit_reached"

    if state.get("supervisor_calls", 0) >= settings.supervisor_calls_per_run:
        return deterministic_safe_route(state, digest), "supervisor_call_cap"

    if proposed.report_ready and proposed.next_role != "review":
        return deterministic_safe_route(state, digest), "report_ready_without_review"

    return proposed, None


async def run_supervisor_agent(
    digest: MissionDigest,
    tools: list[Any] | None = None,
    response_model: type[RouteDecision] = RouteDecision,
    max_tool_calls: int = 4,
    chat_model: Any | None = None,
) -> RouteDecision:
    """Invoke the supervisor LLM mission director or return safe route."""
    model = chat_model
    if model is None:
        try:
            from app.agents.model import _build_model
            model = _build_model()
        except Exception:
            return deterministic_safe_route({"turns": digest.budget.get("turns", {})}, digest)

    prompt = (
        "You are the AIPENT Lead Penetration Tester and Mission Supervisor directing a multi-role security assessment.\n"
        "Your team consists of three specialist roles:\n"
        "- 'recon': Target discovery, port scanning, and service version identification.\n"
        "- 'discovery': Web path fuzzing, endpoint enumeration, technology fingerprinting, and identifying candidate vulnerabilities.\n"
        "- 'validation': Non-destructive verification of candidate findings, auth bypass testing, and discriminating exploit probes (e.g., using curl_request, sqlmap_scan).\n"
        "- 'review': Final phase to assemble verified findings when testing is complete or budgets are reached.\n\n"
        "MISSION STRATEGY & DECISION RULES:\n"
        "1. If no ports/services are mapped, route to 'recon'.\n"
        "2. If services are known but attack surface/endpoints are unexplored, route to 'discovery'.\n"
        "3. If candidate vulnerabilities or unauthenticated endpoints exist, route to 'validation' to verify or falsify them.\n"
        "4. If all discovered candidates have been validated or budgets are spent, route to 'review' with report_ready=True.\n"
        "5. If a specialist failed, timed out, or repeated an action (see failure and recent_steps), you MUST intervene: "
        "steer them away from the failing endpoint/tool and direct an alternative path.\n\n"
        "TACTICAL DIRECTIVE REQUIREMENT:\n"
        "Whenever next_role is NOT 'review', you MUST provide a concrete, tactical 'directive' field instructing the specialist:\n"
        "- Specify the exact target endpoint or URL to test.\n"
        "- Specify the exact tool (curl_request, dirb_scan, sqlmap_scan, etc.), HTTP method, headers, or test payload.\n"
        "- Specify the hypothesis to test and what response (e.g. HTTP status, response body, reflection) confirms or refutes it.\n"
        "- Emphasize what dead ends or past mistakes to avoid.\n\n"
        f"MISSION DIGEST:\n{digest.model_dump_json(indent=2)}\n\n"
        "Call RouteDecision with your next_role, detailed rationale, confidence score, and tactical directive."
    )

    # 1. Try native tool binding for RouteDecision
    try:
        model_with_tool = model.bind_tools([RouteDecision])
        ai_msg = await model_with_tool.ainvoke(prompt)
        tool_calls = getattr(ai_msg, "tool_calls", []) or []
        for call in tool_calls:
            if call.get("name") == "RouteDecision":
                return RouteDecision.model_validate(call.get("args") or {})
    except Exception:
        pass

    # 2. Try structured output
    try:
        structured = model.with_structured_output(response_model)
        result = await structured.ainvoke(prompt)
        if isinstance(result, RouteDecision):
            return result
        if isinstance(result, dict):
            return RouteDecision.model_validate(result)
    except Exception:
        pass

    return deterministic_safe_route({"turns": digest.budget.get("turns", {})}, digest)


def supervisor_tools(assessment_id: int, run_id: str) -> list[ToolSpec]:
    """Return read-only supervisor tools."""
    return list(SUPERVISOR_TOOL_SPECS)
