"""MissionBrain: shared digest, supervisor agent execution, and deterministic route guard.

The supervisor proposes a RouteDecision based on the mission digest.
Python's validate_route guard accepts, rejects, or replaces it.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any
from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.control import audit
from app.agents.prompts import ROLE_PROMPTS
if TYPE_CHECKING:
    from app.agents.graph.state import AssessmentState
from app.agents.loop.contracts import FailureSignal, RouteDecision
from app.agents.loop.tool_specs import bindable_tools
from app.core.config import settings
from app.core.db import get_async_session_ctx
from app.core.log import get_logger
from app.domain.models import Assessment, Audit, Finding, Step
from app.persistence import MissionContext, load_mission_context
from app.persistence.finding_repo import FindingRepo

log = get_logger("agent.mission")

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


def step_digest(
    steps: list[Step],
    observations: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Pure domain function mapping steps to recent step digests."""
    obs_map = {
        o.get("step_id"): o
        for o in (observations or [])
        if isinstance(o, dict) and o.get("step_id") is not None
    }
    recent_steps = []
    for s in reversed(steps):
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
    return recent_steps


async def build_mission_digest(
    assessment_id: int,
    run_id: str,
    state: AssessmentState,
    failure: FailureSignal | None = None,
    context: MissionContext | None = None,
    session: AsyncSession | None = None,
) -> MissionDigest:
    """Construct a bounded MissionDigest from Context or Session and State."""
    if context is None:
        if session is not None:
            context = await load_mission_context(session, assessment_id, run_id=run_id)
        else:
            async with get_async_session_ctx() as sess:
                context = await load_mission_context(sess, assessment_id, run_id=run_id)

    assessment = context.assessment
    targets = assessment.targets if assessment else []
    ports = assessment.ports if assessment else []
    exclusions = assessment.exclusions if assessment else []

    service_rows = context.services
    candidate_rows = context.candidates
    board = context.evidence_board

    recent_steps = step_digest(context.recent_steps, state.get("observations", []))
    recent_handoffs = [state["last_handoff"]] if state.get("last_handoff") else []

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
        recent_handoffs=recent_handoffs,
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
        if (
            rec == "validation"
            and not digest.has_validation_candidates
            and _role_has_budget("discovery", state)
        ):
            # Never validate thin air: map endpoints into candidate findings first.
            rec = "discovery"
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

    if _role_has_budget("validation", state) and digest.has_validation_candidates:
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

    if proposed.next_role == "validation" and not digest.has_validation_candidates:
        return deterministic_safe_route(state, digest), "validation_without_candidates"

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


def _supervisor_tool_payload(
    name: str, args: dict[str, Any], digest: MissionDigest
) -> dict[str, Any]:
    """Serve supervisor tool calls from the already-built digest."""
    limit = int(args.get("limit") or 0)
    if name == "get_mission_digest":
        return digest.model_dump(mode="json")
    if name == "list_services":
        return {"services": digest.services[: limit or 50]}
    if name == "list_findings":
        return {
            "findings": [
                f.model_dump(mode="json") if hasattr(f, "model_dump") else f
                for f in digest.candidates[: limit or 50]
            ]
        }
    if name == "get_steps":
        return {"steps": digest.recent_steps[-limit:] if limit else digest.recent_steps}
    if name == "get_handoffs":
        return {
            "handoffs": digest.recent_handoffs[-limit:] if limit else digest.recent_handoffs
        }
    if name == "get_budget":
        return digest.budget
    return {"error": f"unknown supervisor tool {name}"}


def _extract_route_decision(raw_obj: Any) -> RouteDecision | None:
    """Robustly extract RouteDecision from a Pydantic object, dict, or AIMessage/text."""
    if isinstance(raw_obj, RouteDecision):
        return raw_obj
    if isinstance(raw_obj, dict):
        if isinstance(raw_obj.get("parsed"), RouteDecision):
            return raw_obj["parsed"]
        if raw_obj.get("parsed"):
            try:
                return RouteDecision.model_validate(raw_obj["parsed"])
            except Exception:
                pass
        if "next_role" in raw_obj:
            try:
                return RouteDecision.model_validate(raw_obj)
            except Exception:
                pass
        if "raw" in raw_obj:
            raw_obj = raw_obj["raw"]

    tool_calls = getattr(raw_obj, "tool_calls", None) or []
    for tc in tool_calls:
        args = tc.get("args") if isinstance(tc, dict) else getattr(tc, "args", None)
        if args and isinstance(args, dict) and args.get("next_role"):
            try:
                return RouteDecision.model_validate(args)
            except Exception:
                pass

    candidates: list[str] = []
    content = getattr(raw_obj, "content", None) or (raw_obj if isinstance(raw_obj, str) else None)
    if content and isinstance(content, str):
        candidates.append(content)

    additional_kwargs = getattr(raw_obj, "additional_kwargs", {}) or {}
    for k in ("reasoning", "reasoning_content"):
        if additional_kwargs.get(k):
            candidates.append(str(additional_kwargs[k]))

    for text in candidates:
        m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if m:
            try:
                return RouteDecision.model_validate(json.loads(m.group(1)))
            except Exception:
                pass
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return RouteDecision.model_validate(json.loads(text[start : end + 1]))
            except Exception:
                pass

    return None


async def run_supervisor_agent(
    digest: MissionDigest,
    response_model: type[RouteDecision] = RouteDecision,
    max_tool_calls: int = 4,
    chat_model: Any | None = None,
) -> RouteDecision:
    """Invoke the supervisor LLM mission director or return safe route."""
    model = chat_model
    if model is None:
        try:
            from app.agents.model import build_role_model
            model = build_role_model("supervisor")
        except Exception as exc:
            log.warning("supervisor model build failed: %s", exc)
            return deterministic_safe_route({"turns": digest.budget.get("turns", {})}, digest)


    user_content = (
        f"MISSION DIGEST:\n{digest.model_dump_json(indent=2)}\n\n"
        "Analyze the mission digest and provide your RouteDecision by calling the RouteDecision tool with next_role, why, confidence score, and tactical directive. "
        "Populate all required arguments directly inside the tool call."
    )
    messages = [
        SystemMessage(content=ROLE_PROMPTS.get("supervisor")),
        HumanMessage(content=user_content),
    ]

    call_config = {
        "run_name": "supervisor-route-decision",
        "tags": ["supervisor", f"assessment:{digest.assessment_id}", f"run:{digest.run_id}"],
        "metadata": {"assessment_id": digest.assessment_id, "run_id": digest.run_id},
    }

    # 1. Let the supervisor read mission state through its tools.
    conversation = list(messages)
    try:
        tool_model = model.bind_tools(bindable_tools("supervisor"))
        for _ in range(max(0, max_tool_calls)):
            ai = await tool_model.ainvoke(conversation, config=call_config)
            decision = _extract_route_decision(ai)
            if decision:
                return decision

            tool_calls = list(getattr(ai, "tool_calls", []) or [])
            if not tool_calls:
                break
            conversation.append(ai)
            for call in tool_calls:
                cname = call.get("name") or "unknown"
                if cname == "RouteDecision":
                    continue
                conversation.append(
                    ToolMessage(
                        tool_call_id=call.get("id") or "",
                        name=cname,
                        content=json.dumps(
                            _supervisor_tool_payload(
                                cname,
                                call.get("args") or {},
                                digest,
                            ),
                            default=str,
                        ),
                    )
                )
    except Exception as exc:
        log.warning("supervisor tool loop failed: %s", exc)
        # Clean up any trailing assistant message that has unresolved tool calls
        if conversation and getattr(conversation[-1], "tool_calls", None):
            conversation.pop()

    # 2. RouteDecision is the response format (first attempt with include_raw=True).
    try:
        structured = model.with_structured_output(response_model, include_raw=True)
        result = await structured.ainvoke(conversation, config=call_config)
        decision = _extract_route_decision(result)
        if decision:
            return decision
    except Exception as exc:
        log.warning("supervisor structured route with include_raw failed: %s", exc)
        try:
            structured = model.with_structured_output(response_model)
            result = await structured.ainvoke(conversation, config=call_config)
            decision = _extract_route_decision(result)
            if decision:
                return decision
        except Exception as exc2:
            log.warning("supervisor structured route failed: %s", exc2)

    # Fallback to direct model invocation and text extraction if structured tool-calling failed
    try:
        raw_ai = await model.ainvoke(conversation, config=call_config)
        decision = _extract_route_decision(raw_ai)
        if decision:
            log.info("recovered RouteDecision via direct text fallback (role=%s)", decision.next_role)
            return decision
    except Exception as exc:
        log.warning("supervisor direct invoke fallback failed: %s", exc)

    log.warning("supervisor unavailable; using deterministic route")
    fallback = deterministic_safe_route(
        {"turns": digest.budget.get("turns", {})}, digest
    )
    fallback.why = f"Supervisor model unavailable; deterministic fallback. {fallback.why}"
    return fallback

