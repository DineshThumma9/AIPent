"""MissionBrain: shared digest, supervisor agent execution, and deterministic route guard.

The supervisor proposes a RouteDecision based on the mission digest.
Python's validate_route guard accepts, rejects, or replaces it.
"""

from __future__ import annotations

import json
import re
import time
from typing import TYPE_CHECKING, Any
from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.persistence.audit_repo import audit
from app.agents.prompts import PLAN_PROMPT, ROLE_PROMPTS
if TYPE_CHECKING:
    from app.agents.state import AssessmentState
from app.agents.contracts import FailureSignal, PlanProposal, PlanStep, RouteDecision
from app.agents.tool_specs import ROLE_TOOLS
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
    objective: str = ""
    plan: list[dict[str, Any]] = Field(default_factory=list)
    plan_source: str = ""
    feedback: str = ""
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
        objective=(assessment.request if assessment else "") or "",
        plan=[s for s in state.get("plan", []) if s.get("enabled") is not False],
        plan_source=state.get("plan_source", "") or "",
        feedback=state.get("plan_feedback", "") or "",
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


PLAN_ROLES = ("recon", "discovery", "validation", "review")


def available_plan_actions() -> dict[str, list[str]]:
    """Action names each role may use, as advertised to the planner and UI."""
    actions: dict[str, list[str]] = {}
    for role in PLAN_ROLES:
        names: list[str] = []
        for spec in ROLE_TOOLS.get(role, []):
            for value in (getattr(spec, "name", None), getattr(spec, "action", None)):
                if value and value not in names:
                    names.append(value)
        if role == "review":
            names.append("final_review")
        actions[role] = names
    return actions


def normalize_plan_steps(raw: Any) -> list[dict[str, Any]]:
    """Coerce a model/operator plan into bounded, serialisable step dicts."""
    if isinstance(raw, dict):
        raw = raw.get("steps") or raw.get("plan") or []
    if not isinstance(raw, list):
        return []

    allowed = available_plan_actions()
    steps: list[dict[str, Any]] = []
    for item in raw[:16]:
        if isinstance(item, PlanStep):
            item = item.model_dump()
        if not isinstance(item, dict):
            continue
        role = str(item.get("role") or "recon").strip().lower()
        if role not in PLAN_ROLES:
            role = "recon"
        action = str(item.get("action") or "").strip()
        target = str(item.get("target") or "").strip()
        rationale = str(item.get("rationale") or "").strip()[:1000]

        if not action and rationale:
            action = "curl_request" if role in ("discovery", "validation") else "nmap_scan"
        if not target and rationale:
            target = "in-scope target"

        if not action or not target:
            continue
        steps.append(
            {
                "role": role,
                "action": action[:80],
                "target": target[:300],
                "rationale": rationale,
                "enabled": item.get("enabled") is not False,
                "valid_action": action in allowed.get(role, []),
            }
        )
    return steps


def _template_plan(
    objective: str, targets: list[str], ports: list[int]
) -> list[dict[str, Any]]:
    """Deterministic methodology fallback when the planner model is unavailable."""
    host = (targets or ["127.0.0.1"])[0]
    port = ports[0] if ports else None
    where = f"{host}:{port}" if port else host
    text = (objective or "").lower()

    steps: list[dict[str, Any]] = [
        {
            "role": "recon",
            "action": "recon_services",
            "target": host,
            "rationale": f"Confirm the authorized surface on {where} and identify service/version banners before probing anything else.",
        },
        {
            "role": "recon" if "whatweb" in available_plan_actions()["recon"] else "discovery",
            "action": "whatweb" if "whatweb" in available_plan_actions()["recon"] else "curl_request",
            "target": host,
            "rationale": f"Fingerprint the technology behind {where} so later probes match the actual stack.",
        },
        {
            "role": "discovery",
            "action": "ffuf_scan",
            "target": host,
            "rationale": f"Enumerate common paths and routes on {where} using high-speed FFUF; use only discovered endpoints in later steps.",
        },
    ]

    if any(word in text for word in ("access control", "idor", "forged", "authorization", "auth bypass", "broken access")):
        steps.append(
            {
                "role": "discovery",
                "action": "curl_request",
                "target": host,
                "rationale": "Probe discovered authenticated surfaces and record identifiers/parameters that could be varied between users.",
            }
        )
        steps.append(
            {
                "role": "validation",
                "action": "curl_request",
                "target": host,
                "rationale": "Verify suspected access-control behavior across two contexts; treat a CAPTCHA/auth precondition failure as inconclusive, not proof.",
            }
        )
    elif any(word in text for word in ("sql", "sqli", "injection")):
        steps.append(
            {
                "role": "discovery",
                "action": "curl_request",
                "target": host,
                "rationale": "Locate parameters that reflect or alter server-side behavior on already discovered endpoints.",
            }
        )
        steps.append(
            {
                "role": "validation",
                "action": "sqlmap_scan",
                "target": host,
                "rationale": "Run one bounded sqlmap probe on an exact discovered endpoint/parameter; do not conclude 'not injectable' without it.",
            }
        )
    else:
        steps.append(
            {
                "role": "discovery",
                "action": "curl_request",
                "target": host,
                "rationale": "Probe the most relevant discovered endpoints and record observations with evidence for correlation.",
            }
        )
        steps.append(
            {
                "role": "validation",
                "action": "curl_request",
                "target": host,
                "rationale": "Confirm or refute the hypothesis with a discriminating non-destructive probe on an observed endpoint.",
            }
        )

    steps.append(
        {
            "role": "review",
            "action": "final_review",
            "target": host,
            "rationale": "Assemble verified evidence, separate observed facts from inferences, and prepare the final report.",
        }
    )
    return normalize_plan_steps(steps)


async def generate_initial_plan(
    objective: str,
    targets: list[str],
    ports: list[int] | None = None,
    exclusions: list[str] | None = None,
    feedback: str | None = None,
    chat_model: Any | None = None,
) -> tuple[list[dict[str, Any]], str, str]:
    """Produce the initial, generic plan for analyst review.

    Returns ``(steps, source, notes)``. The model is advisory; Python always
    normalises the actions so operators cannot be handed invalid tools.
    """
    ports = ports or []
    exclusions = exclusions or []
    fallback = _template_plan(objective, targets, ports)
    actions = available_plan_actions()
    actions_text = "\n".join(
        f"  {role}: {', '.join(names)}" for role, names in actions.items()
    )
    user_content = (
        f"OBJECTIVE:\n{objective or 'Assess the authorized target within scope.'}\n\n"
        f"TARGETS: {targets or ['127.0.0.1']}\n"
        f"PORTS: {ports or ['tool default']}\n"
        f"EXCLUSIONS: {exclusions or ['none']}\n"
        f"OPERATOR FEEDBACK: {feedback or 'none'}\n\n"
        f"AVAILABLE ACTIONS (role: exact action names):\n{actions_text}\n"
    )

    model = chat_model
    if model is None:
        try:
            from app.agents.model import build_role_model

            model = build_role_model("supervisor")
        except Exception as exc:  # noqa: BLE001 - degrade to deterministic plan
            log.warning("planner model build failed: %s", exc)
            return fallback, "template", "Planner model unavailable; used the standard methodology template."

    try:
        structured = model.with_structured_output(PlanProposal)
        proposal = await structured.ainvoke(
            [SystemMessage(content=PLAN_PROMPT), HumanMessage(content=user_content)],
            config={"run_name": "supervisor-initial-plan", "tags": ["planning"]},
        )
        if isinstance(proposal, dict):
            proposal = PlanProposal.model_validate(proposal)
        steps = normalize_plan_steps(getattr(proposal, "steps", []))
        if steps:
            notes = str(getattr(proposal, "notes", "") or "")
            if feedback:
                notes = f"Operator feedback: {feedback}. {notes}".strip()
            return steps, "llm", notes[:1000]
    except Exception as exc:  # noqa: BLE001 - degrade to deterministic plan
        log.warning("initial plan generation failed: %s", exc)

    notes = "Generated from the standard methodology template."
    if feedback:
        notes = f"Operator feedback: {feedback}. {notes}"
    return fallback, "template", notes[:1000]


async def run_supervisor_agent(
    digest: MissionDigest,
    response_model: type[RouteDecision] = RouteDecision,
    chat_model: Any | None = None,
) -> RouteDecision:
    """Ask the supervisor for one RouteDecision.

    The mission digest is the supervisor's whole context: services, candidates,
    hypotheses, recent steps, handoffs, and budget are already in it. A tool
    loop would only re-read that same prompt, so the supervisor gets one
    structured call and no execution tools.
    """
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
        "Analyze the mission digest and return a RouteDecision with next_role, "
        "why, confidence score, and a tactical directive. Populate every field "
        "directly in the response."
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

    started = time.perf_counter()
    try:
        structured = model.with_structured_output(response_model)
        result = await structured.ainvoke(messages, config=call_config)
        decision = _extract_route_decision(result)
        if decision:
            log.info(
                "supervisor_decision role=%s elapsed=%.1fs",
                decision.next_role,
                time.perf_counter() - started,
            )
            return decision
    except Exception as exc:
        log.warning("supervisor structured route failed: %s", exc)

    # Some providers return the decision as text instead of a structured call.
    try:
        raw_ai = await model.ainvoke(messages, config=call_config)
        decision = _extract_route_decision(raw_ai)
        if decision:
            log.info(
                "recovered RouteDecision via direct text fallback (role=%s, elapsed=%.1fs)",
                decision.next_role,
                time.perf_counter() - started,
            )
            return decision
    except Exception as exc:
        log.warning("supervisor direct invoke fallback failed: %s", exc)

    log.warning("supervisor unavailable; using deterministic route")
    fallback = deterministic_safe_route(
        {"turns": digest.budget.get("turns", {})}, digest
    )
    fallback.why = f"Supervisor model unavailable; deterministic fallback. {fallback.why}"
    return fallback

