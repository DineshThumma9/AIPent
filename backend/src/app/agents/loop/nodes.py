"""Graph nodes for the V2 agent loop.

Implements intake, supervisor, brief, model, prepare, approve, execute,
direct, handoff, nudge, review, report_writer, and report.
All inter-node transitions use Command(update=..., goto=...).
"""

from __future__ import annotations

import json
from typing import Any, Callable
from langchain_core.messages import AIMessage, AnyMessage, HumanMessage, ToolMessage
from langgraph.graph import END
from langgraph.types import Command, interrupt
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from app.actions.catalogue import check_scope
from app.actions.executor import execute_action
from app.agents.control import audit
from app.agents.graph.state import AssessmentState
from app.agents.loop.brief import render_brief
from app.agents.loop.contracts import (
    ActionRequest,
    FailureSignal,
    Handoff,
    Observation,
    RouteDecision,
)
from app.agents.loop.direct_tools import run_direct
from app.agents.loop.mission_brain import (
    ROLE_TURN_CAPS,
    build_mission_digest,
    deterministic_safe_route,
    run_supervisor_agent,
    supervisor_tools,
    validate_route,
)
from app.agents.loop.observations import (
    error_observation,
    observation_from_step,
    rejection_observation,
)
from app.agents.loop.reasoning import build_evidence_board
from app.agents.loop.tool_specs import bindable_tools, is_direct_tool, lookup_tool
from app.agents.model import build_role_model
from app.core.config import settings
from app.core.db import get_async_session_ctx
from app.core.log import get_logger
from app.core.policy import policy_for

logger = get_logger("agent.nodes")
from app.domain.models import (
    Approval,
    Assessment,
    AssessmentStatus,
    Audit,
    Decision,
    Step,
    StepStatus,
    utcnow,
)
from app.persistence.finding_repo import FindingRepo
from app.persistence.steering_repo import SteeringRepo
from app.persistence.step_repo import StepRepo
from app.reporting.narrative import build_narrative_context, write_narrative_result
from app.reporting.report import generate_report
import asyncio
from pathlib import Path 


async def intake_node(state: AssessmentState) -> Command:
    """Initialize state for V2 loop from DB and route to supervisor."""
    assessment_id = state["assessment_id"]
    async with get_async_session_ctx() as session:
        assessment = await session.get(Assessment, assessment_id)
        if assessment is None:
            raise LookupError(f"assessment {assessment_id} not found")

        targets = list(assessment.targets or [])
        ports = list(assessment.ports or [])
        exclusions = list(assessment.exclusions or [])

        audit(
            session,
            assessment_id,
            "agent.started",
            {
                "run_id": state["run_id"],
                "loop": "v2",
                "targets": targets,
                "ports": ports,
            },
        )
        await session.commit()

    return Command(
        update={
            "targets": targets,
            "ports": ports,
            "exclusions": exclusions,
            "messages": [],
            "pending_action": None,
            "approval_decision": None,
            "last_handoff": None,
            "turns": {},
            "nudges": 0,
            "no_progress": 0,
            "finished": False,
            "report_narrative": None,
            "supervisor_decision": None,
            "supervisor_directive": None,
            "failure_signal": None,
            "supervisor_calls": 0,
            "observations": [],
            "handoffs": [],
            "decisions": [],
            "steps": [],
            "next_node": "supervisor",
        },
        goto="supervisor",
    )


def _failure_from_state(state: AssessmentState) -> FailureSignal | None:
    raw = state.get("failure_signal")
    if raw and isinstance(raw, dict):
        try:
            return FailureSignal.model_validate(raw)
        except Exception:
            return None
    return None


async def supervisor_node(state: AssessmentState) -> Command:
    """LLM mission director + Python validate_route guard."""
    assessment_id = state["assessment_id"]
    run_id = state["run_id"]
    failure = _failure_from_state(state)

    digest = await build_mission_digest(
        assessment_id=assessment_id,
        run_id=run_id,
        state=state,
        failure=failure,
    )

    async with get_async_session_ctx() as session:
        audit(
            session,
            assessment_id,
            "supervisor.digest",
            {
                "run_id": run_id,
                "failure": failure.model_dump() if failure else None,
                "services_count": len(digest.services),
                "candidates_count": len(digest.candidates),
            },
        )
        await session.commit()

    try:
        proposed = await run_supervisor_agent(
            digest=digest,
            tools=supervisor_tools(assessment_id, run_id),
            response_model=RouteDecision,
            max_tool_calls=settings.supervisor_tool_calls,
        )
    except Exception as exc:
        proposed = deterministic_safe_route(state, digest)
        async with get_async_session_ctx() as session:
            audit(
                session,
                assessment_id,
                "supervisor.unavailable",
                {"run_id": run_id, "error": str(exc)},
            )
            await session.commit()

    decision, rejection = validate_route(proposed, state, digest)

    async with get_async_session_ctx() as session:
        audit(
            session,
            assessment_id,
            "supervisor.route_proposed",
            {
                "run_id": run_id,
                "proposed_role": proposed.next_role,
                "why": proposed.why,
                "confidence": proposed.confidence,
                "overrides_specialist": proposed.overrides_specialist,
                "directive": proposed.directive,
            },
        )
        if failure:
            audit(
                session,
                assessment_id,
                "supervisor.recovered",
                {
                    "run_id": run_id,
                    "failure_kind": failure.kind,
                    "recovered_role": decision.next_role,
                    "attempts": failure.attempts,
                },
            )
        if rejection:
            audit(
                session,
                assessment_id,
                "supervisor.route_rejected",
                {
                    "run_id": run_id,
                    "proposed_role": proposed.next_role,
                    "rejection_reason": rejection,
                    "fallback_role": decision.next_role,
                },
            )
        audit(
            session,
            assessment_id,
            "supervisor.route",
            {
                "run_id": run_id,
                "accepted_role": decision.next_role,
                "why": decision.why,
                "confidence": decision.confidence,
                "directive": decision.directive,
            },
        )
        await session.commit()

    return Command(
        update={
            "role": decision.next_role,
            "supervisor_decision": decision.model_dump(),
            "supervisor_directive": decision.directive,
            "failure_signal": None,
            "last_handoff": None,
            "nudges": 0,
            "no_progress": 0,
            "supervisor_calls": state.get("supervisor_calls", 0) + 1,
            "next_node": decision.next_role,
        },
        goto="brief" if decision.next_role != "review" else "review",
    )


async def brief_node(state: AssessmentState) -> Command:
    """Build specialist context from DB and transition to model."""
    assessment_id = state["assessment_id"]
    role = state["role"]
    directive = state.get("supervisor_directive")

    async with get_async_session_ctx() as session:
        assessment = await session.get(Assessment, assessment_id)
        if assessment is None:
            raise LookupError(f"assessment {assessment_id} not found")

        finding_repo = FindingRepo(session)
        board = await build_evidence_board(session, assessment_id)
        services = await finding_repo.get_services(assessment_id)
        candidates = await finding_repo.get_candidates(assessment_id)
        steering_repo = SteeringRepo(session)
        steering_notes = await steering_repo.take_pending(assessment_id, state.get("run_id"))

    digest = render_brief(
        assessment=assessment,
        role=role,
        board=board,
        services=services,
        candidates=candidates,
        steering=steering_notes,
        supervisor_directive=directive,
    )

    return Command(
        update={
            "messages": [HumanMessage(content=digest)],
            "pending_action": None,
            "approval_decision": None,
            "supervisor_directive": None,
            "nudges": 0,
            "no_progress": 0,
        },
        goto="model",
    )


async def model_node(state: AssessmentState) -> Command:
    """Invoke role model and route tool calls or handoff."""
    role = state["role"]
    cap = min(ROLE_TURN_CAPS.get(role, 8), settings.max_agent_turns)
    turns = dict(state.get("turns", {}))

    if turns.get(role, 0) >= cap:
        signal = FailureSignal(
            role=role,  # type: ignore[arg-type]
            kind="budget_exhausted",
            summary=f"{role} reached its model-call budget ({cap} turns) without a handoff.",
            attempts=turns.get(role, 0),
        )
        return Command(
            update={
                "last_message": signal.summary,
                "failure_signal": signal.model_dump(),
            },
            goto="supervisor",
        )

    model = build_role_model(role).bind_tools(bindable_tools(role))
    messages = list(state.get("messages", []))

    assessment_id = state["assessment_id"]
    async with get_async_session_ctx() as session:
        steering_repo = SteeringRepo(session)
        mid_turn_notes = await steering_repo.take_pending(assessment_id, state.get("run_id"))

    if mid_turn_notes:
        note_texts = "\n".join(f"- {n.text}" for n in mid_turn_notes)
        messages.append(
            HumanMessage(
                content=f"OPERATOR STEERING DIRECTIVE:\n{note_texts}\nIncorporate this steering directive into your current action."
            )
        )

    ai = None
    for attempt in range(1, 4):
        try:
            ai = await model.ainvoke(messages)
            break
        except Exception as exc:
            if attempt == 3:
                logger.error(f"model_ainvoke_exhausted role={role} error={exc}")
                signal = FailureSignal(
                    role=role,  # type: ignore[arg-type]
                    kind="model_error",
                    summary=f"Model invocation failed after retries: {exc}",
                    attempts=max(1, turns.get(role, 0)),
                )
                return Command(
                    update={
                        "messages": messages,
                        "turns": turns,
                        "last_message": signal.summary,
                        "failure_signal": signal.model_dump(),
                    },
                    goto="supervisor",
                )
            logger.warning(f"model_ainvoke_retry role={role} attempt={attempt} error={exc}")
            await asyncio.sleep(1.5 * attempt)
    messages.append(ai)
    turns[role] = turns.get(role, 0) + 1

    tool_calls = list(getattr(ai, "tool_calls", []) or [])

    if not tool_calls:
        if state.get("nudges", 0) < 2:
            return Command(
                update={
                    "messages": messages,
                    "turns": turns,
                    "nudges": state.get("nudges", 0) + 1,
                },
                goto="nudge",
            )
        signal = FailureSignal(
            role=role,  # type: ignore[arg-type]
            kind="no_handoff",
            summary="Model produced no tool call after the allowed nudges.",
            attempts=state.get("nudges", 0) + 1,
        )
        return Command(
            update={
                "messages": messages,
                "turns": turns,
                "last_message": signal.summary,
                "failure_signal": signal.model_dump(),
            },
            goto="supervisor",
        )

    first, *extra = tool_calls
    if extra:
        for call in extra:
            messages.append(
                ToolMessage(
                    tool_call_id=call["id"],
                    name=call.get("name", "unknown"),
                    status="error",
                    content=json.dumps({
                        "ok": False,
                        "status": "error",
                        "summary": "Only one action tool call is executed per turn.",
                        "next_hint": "Re-issue the most important call on the next turn.",
                    }),
                )
            )

    name = first["name"]
    if name == "handoff":
        return Command(
            update={"messages": messages, "turns": turns},
            goto="handoff",
        )
    if is_direct_tool(role, name):
        return Command(
            update={"messages": messages, "turns": turns},
            goto="direct",
        )
    return Command(
        update={"messages": messages, "turns": turns},
        goto="prepare",
    )


async def nudge_node(state: AssessmentState) -> Command:
    """Prompt the model to hand off or choose an action."""
    return Command(
        update={
            "messages": [
                *state["messages"],
                HumanMessage(
                    content=(
                        "You have not handed off. Either call one more action that "
                        "reduces uncertainty, or call handoff(...) with your current "
                        "summary, next_role, why, confidence, stop_reason and open_questions. "
                        "Do not repeat an action that already ran."
                    )
                ),
            ],
        },
        goto="model",
    )


def _last_tool_call(messages: list[AnyMessage]) -> dict[str, Any]:
    for msg in reversed(messages):
        if isinstance(msg, AIMessage) and msg.tool_calls:
            call = msg.tool_calls[0]
            if isinstance(call, dict):
                return call
    raise ValueError("no tool call found in messages")


async def prepare_node(state: AssessmentState) -> Command:
    """Validate tool schema, create planned Step/Approval, and build ActionRequest."""
    tool_call = _last_tool_call(state["messages"])
    role = state["role"]
    assessment_id = state["assessment_id"]

    try:
        spec = lookup_tool(role, tool_call["name"])
    except KeyError as exc:
        obs = error_observation(tool_call["name"], "unknown", str(exc))
        return Command(
            update={
                "messages": [
                    *state["messages"],
                    ToolMessage(
                        tool_call_id=tool_call["id"],
                        name=tool_call["name"],
                        status="error",
                        content=obs.model_dump_json(),
                    ),
                ]
            },
            goto="model",
        )

    # Validate arguments model
    args_raw = tool_call.get("args") or {}
    if isinstance(args_raw, str):
        try:
            args_raw = json.loads(args_raw)
        except Exception:
            args_raw = {}

    try:
        args = spec.args_model.model_validate(args_raw)
    except Exception as exc:
        obs = error_observation(tool_call["name"], getattr(args_raw, "target", "unknown"), f"Schema validation error: {exc}")
        return Command(
            update={
                "messages": [
                    *state["messages"],
                    ToolMessage(
                        tool_call_id=tool_call["id"],
                        name=tool_call["name"],
                        status="error",
                        content=obs.model_dump_json(),
                    ),
                ]
            },
            goto="model",
        )

    target = getattr(args, "target", "")
    rationale = getattr(args, "rationale", "")

    async with get_async_session_ctx() as session:
        assessment = await session.get(Assessment, assessment_id)
        if assessment is None:
            raise LookupError(f"assessment {assessment_id} not found")

        try:
            check_scope(assessment, target)
        except Exception as exc:
            obs = error_observation(spec.action or spec.name, target, str(exc))
            return Command(
                update={
                    "messages": [
                        *state["messages"],
                        ToolMessage(
                            tool_call_id=tool_call["id"],
                            name=tool_call["name"],
                            status="error",
                            content=obs.model_dump_json(),
                        ),
                    ]
                },
                goto="model",
            )

        params = {
            field: getattr(args, field)
            for field in spec.param_fields
            if getattr(args, field, None) is not None
        }
        ports_val = getattr(args, "ports", None)
        if ports_val is not None and "ports" in spec.param_fields:
            if isinstance(ports_val, list):
                params["ports"] = ",".join(str(p) for p in ports_val)
            elif isinstance(ports_val, int):
                params["ports"] = str(ports_val)
            else:
                params["ports"] = str(ports_val)

        action_name = spec.action or spec.name
        if action_name == "curl_tool":
            probe_res = await session.execute(
                select(Audit).where(
                    Audit.assessment_id == state["assessment_id"],
                    Audit.event_type.in_(["action.requested", "action.queued"]),
                )
            )
            probe_events = [
                e for e in probe_res.scalars().all()
                if (e.payload or {}).get("run_id") == state["run_id"]
                and (e.payload or {}).get("action") == "curl_tool"
            ]
            if len(probe_events) >= settings.max_validation_probes:
                obs = error_observation(
                    action_name,
                    target,
                    f"Validation probe budget exhausted ({settings.max_validation_probes} probes per run).",
                )
                return Command(
                    update={
                        "messages": [
                            *state["messages"],
                            ToolMessage(
                                tool_call_id=tool_call["id"],
                                name=tool_call["name"],
                                status="error",
                                content=obs.model_dump_json(),
                            ),
                        ]
                    },
                    goto="model",
                )

        if action_name == "hashcat_crack":
            base = settings.artifacts_path / str(assessment_id)
            base.mkdir(parents=True, exist_ok=True)
            source_step_id = getattr(args, "source_step_id", None)
            hash_val = getattr(args, "hash_value", None)
            hash_file = getattr(args, "hash_file", None)

            if hash_val:
                source_step = await session.get(Step, source_step_id)
                if source_step is None or source_step.assessment_id != assessment_id:
                    obs = error_observation(action_name, target, f"source_step_id {source_step_id} not found")
                    return Command(
                        update={
                            "messages": [
                                *state["messages"],
                                ToolMessage(
                                    tool_call_id=tool_call["id"],
                                    name=tool_call["name"],
                                    status="error",
                                    content=obs.model_dump_json(),
                                ),
                            ]
                        },
                        goto="model",
                    )
                if not source_step.output_path or not Path(source_step.output_path).exists():
                    obs = error_observation(action_name, target, f"source_step_id {source_step_id} has no artifact file")
                    return Command(
                        update={
                            "messages": [
                                *state["messages"],
                                ToolMessage(
                                    tool_call_id=tool_call["id"],
                                    name=tool_call["name"],
                                    status="error",
                                    content=obs.model_dump_json(),
                                ),
                            ]
                        },
                        goto="model",
                    )
                text = Path(source_step.output_path).read_text(errors="replace")
                if hash_val.lower() not in text.lower():
                    obs = error_observation(action_name, target, "hash_value does not appear in that artifact")
                    return Command(
                        update={
                            "messages": [
                                *state["messages"],
                                ToolMessage(
                                    tool_call_id=tool_call["id"],
                                    name=tool_call["name"],
                                    status="error",
                                    content=obs.model_dump_json(),
                                ),
                            ]
                        },
                        goto="model",
                    )
                input_path = base / f"hashcat-input-{source_step_id}.txt"
                input_path.write_text(hash_val.strip() + "\n")
                params["input_path"] = str(input_path)
            elif hash_file:
                input_path = (base / hash_file).resolve()
                if not input_path.is_relative_to(base):
                    obs = error_observation(action_name, target, "hash_file must stay inside the assessment artifact directory")
                    return Command(
                        update={
                            "messages": [
                                *state["messages"],
                                ToolMessage(
                                    tool_call_id=tool_call["id"],
                                    name=tool_call["name"],
                                    status="error",
                                    content=obs.model_dump_json(),
                                ),
                            ]
                        },
                        goto="model",
                    )
                if not input_path.exists():
                    obs = error_observation(action_name, target, f"hash_file {hash_file} does not exist")
                    return Command(
                        update={
                            "messages": [
                                *state["messages"],
                                ToolMessage(
                                    tool_call_id=tool_call["id"],
                                    name=tool_call["name"],
                                    status="error",
                                    content=obs.model_dump_json(),
                                ),
                            ]
                        },
                        goto="model",
                    )
                params["input_path"] = str(input_path)
            else:
                obs = error_observation(action_name, target, "hashcat_crack needs source_step_id + hash_value or hash_file")
                return Command(
                    update={
                        "messages": [
                            *state["messages"],
                            ToolMessage(
                                tool_call_id=tool_call["id"],
                                name=tool_call["name"],
                                status="error",
                                content=obs.model_dump_json(),
                            ),
                        ]
                    },
                    goto="model",
                )

        policy = policy_for(action_name)
        step_repo = StepRepo(session)
        result = await step_repo.create_step(
            assessment=assessment,
            run_id=state["run_id"],
            role=role,
            action=action_name,
            target=target,
            rationale=rationale,
            params=params,
            detail={
                "tool_call_id": tool_call["id"],
                "hypothesis_id": getattr(args, "hypothesis_id", None),
                "evidence_ids": getattr(args, "evidence_ids", []),
                "expected_observation": getattr(args, "expected_observation", None),
                "would_falsify": getattr(args, "would_falsify", None),
            },
            auto_approve=not policy.requires_approval,
        )

    if result.get("error"):
        obs = error_observation(spec.action or spec.name, target, result["error"])
        return Command(
            update={
                "messages": [
                    *state["messages"],
                    ToolMessage(
                        tool_call_id=tool_call["id"],
                        name=tool_call["name"],
                        status="error",
                        content=obs.model_dump_json(),
                    ),
                ]
            },
            goto="model",
        )

    if result.get("duplicate_of_step"):
        obs = Observation(
            ok=True,
            status="succeeded",
            action=spec.action or spec.name,
            target=target,
            step_id=result["duplicate_of_step"],
            summary=f"Action already executed (step {result['duplicate_of_step']}). Not repeated.",
            next_hint="Analyze previous observation or hand off.",
        )
        return Command(
            update={
                "messages": [
                    *state["messages"],
                    ToolMessage(
                        tool_call_id=tool_call["id"],
                        name=tool_call["name"],
                        status="success",
                        content=obs.model_dump_json(),
                    ),
                ]
            },
            goto="model",
        )

    pending = ActionRequest(
        tool_call_id=tool_call["id"],
        tool_name=tool_call["name"],
        action=spec.action or spec.name,
        target=target,
        rationale=rationale,
        step_id=result["step_id"],
        approval_id=result["approval_id"],
        argv=result.get("argv", []),
        risk=policy.risk,  # type: ignore[arg-type]
        requires_approval=policy.requires_approval,
        policy_reason=f"Policy risk={policy.risk}, approve={policy.requires_approval}",
        hypothesis_id=getattr(args, "hypothesis_id", None),
        evidence_ids=getattr(args, "evidence_ids", []),
        expected_observation=getattr(args, "expected_observation", None),
        would_falsify=getattr(args, "would_falsify", None),
    )

    async with get_async_session_ctx() as session:
        audit(
            session,
            assessment_id,
            "decision.recorded",
            {
                "id": f"D-{pending.step_id}",
                "run_id": state["run_id"],
                "role": role,
                "action": pending.action,
                "target": pending.target,
                "hypothesis_id": pending.hypothesis_id,
                "evidence_ids": pending.evidence_ids,
                "observation": "",
                "expected_observation": pending.expected_observation,
                "would_falsify": pending.would_falsify,
                "confidence": 0.6,
                "outcome": "prepared",
                "created_at": utcnow().isoformat(),
            },
        )
        await session.commit()

    return Command(
        update={"pending_action": pending.model_dump()},
        goto="approve",
    )


async def approve_node(state: AssessmentState) -> Command:
    """Approval evaluation: auto-approves by policy or interrupts for human input."""
    pending_raw = state.get("pending_action")
    if not pending_raw:
        return Command(goto="model")
    pending = ActionRequest.model_validate(pending_raw)
    assessment_id = state["assessment_id"]

    async with get_async_session_ctx() as session:
        approval = await session.get(Approval, pending.approval_id)
        step = await session.get(Step, pending.step_id)
        if approval is None or step is None:
            obs = error_observation(pending.action, pending.target, "Step or approval record missing")
            return Command(
                update={
                    "messages": [
                        *state["messages"],
                        ToolMessage(
                            tool_call_id=pending.tool_call_id,
                            name=pending.tool_name or pending.action,
                            status="error",
                            content=obs.model_dump_json(),
                        ),
                    ],
                    "pending_action": None,
                },
                goto="model",
            )

        if approval.decision == Decision.PENDING.value:
            if not pending.requires_approval:
                approval.decision = Decision.APPROVED.value
                approval.actor = "system"
                approval.reason = pending.policy_reason or "auto-approved by policy"
                approval.decided_at = utcnow()
                approval.outcome = "auto-approved"
                audit(
                    session,
                    assessment_id,
                    "approval.auto_approved",
                    {
                        "approval_id": approval.id,
                        "step_id": step.id,
                        "action": pending.action,
                        "argv": list(step.argv),
                    },
                )
                await session.commit()
                approved = True
            else:
                assessment = await session.get(Assessment, assessment_id)
                if assessment:
                    assessment.status = AssessmentStatus.AWAITING_APPROVAL.value
                    await session.commit()

                decision = interrupt({
                    "gate": "action",
                    "approval_id": approval.id,
                    "step_id": step.id,
                    "action": step.action,
                    "target": step.target,
                    "argv": list(step.argv),
                    "rationale": step.rationale,
                    "risk": pending.risk,
                    "requires_approval": True,
                    "hypothesis_id": pending.hypothesis_id,
                    "evidence_ids": pending.evidence_ids,
                    "expected_observation": pending.expected_observation,
                    "would_falsify": pending.would_falsify,
                })

                decision_dict = decision if isinstance(decision, dict) else {}
                approved = str(decision_dict.get("decision", "rejected")).lower() == "approved"
                rejection_reason = decision_dict.get("reason") or "rejected by analyst"
                approval.decision = (
                    Decision.APPROVED.value if approved else Decision.REJECTED.value
                )
                approval.actor = decision_dict.get("actor") or "analyst"
                approval.reason = decision_dict.get("reason") or None
                approval.decided_at = utcnow()
                approval.outcome = "action " + ("approved" if approved else "rejected")
                event_name = "approval.approved" if approved else "approval.rejected"
                audit(
                    session,
                    assessment_id,
                    event_name,
                    {
                        "approval_id": approval.id,
                        "step_id": step.id,
                        "reason": approval.reason,
                        "actor": approval.actor,
                    },
                )
                if not approved:
                    step.status = StepStatus.REJECTED.value
                    step.error = rejection_reason[:500]
                    step.ended_at = utcnow()
                assessment = await session.get(Assessment, assessment_id)
                if assessment:
                    assessment.status = AssessmentStatus.RUNNING.value
                await session.commit()
        else:
            approved = approval.decision == Decision.APPROVED.value

    if not approved:
        obs = rejection_observation(pending, rejection_reason if 'rejection_reason' in locals() else "rejected by analyst")
        return Command(
            update={
                "messages": [
                    *state["messages"],
                    ToolMessage(
                        tool_call_id=pending.tool_call_id,
                        name=pending.tool_name or pending.action,
                        status="error",
                        content=obs.model_dump_json(),
                    ),
                ],
                "pending_action": None,
                "approval_decision": {"decision": "rejected"},
                "observations": [obs.model_dump()],
                "last_message": obs.summary,
            },
            goto="model",
        )

    async with get_async_session_ctx() as session:
        assessment = await session.get(Assessment, assessment_id)
        if assessment is not None:
            assessment.status = AssessmentStatus.RUNNING.value
            await session.commit()

    return Command(
        update={"approval_decision": {"decision": "approved"}},
        goto="execute",
    )


def make_execute_node(executor: Callable[..., Any] | None = None):
    """Factory creating execute_node with optional injected executor."""

    async def execute_node(state: AssessmentState) -> Command:
        pending = ActionRequest.model_validate(state["pending_action"])
        assessment_id = state["assessment_id"]

        async with get_async_session_ctx() as session:
            step = await session.get(Step, pending.step_id)
            approval = await session.get(Approval, pending.approval_id)
            if step is None or approval is None:
                obs = error_observation(pending.action, pending.target, "Step or approval record missing")
                return Command(
                    update={
                        "messages": [
                            *state["messages"],
                            ToolMessage(
                                tool_call_id=pending.tool_call_id,
                                name=pending.tool_name or pending.action,
                                status="error",
                                content=obs.model_dump_json(),
                            ),
                        ],
                        "pending_action": None,
                    },
                    goto="model",
                )

            if approval.decision != Decision.APPROVED.value:
                obs = error_observation(pending.action, pending.target, "Step is not approved")
                return Command(
                    update={
                        "messages": [
                            *state["messages"],
                            ToolMessage(
                                tool_call_id=pending.tool_call_id,
                                name=pending.tool_name or pending.action,
                                status="error",
                                content=obs.model_dump_json(),
                            ),
                        ],
                        "pending_action": None,
                    },
                    goto="model",
                )

            if list(approval.argv or []) != list(step.argv or []):
                step.status = StepStatus.REJECTED.value
                step.error = "approval.argv does not match step.argv"
                await session.commit()
                obs = error_observation(pending.action, pending.target, "argv mismatch between approval and step")
                return Command(
                    update={
                        "messages": [
                            *state["messages"],
                            ToolMessage(
                                tool_call_id=pending.tool_call_id,
                                name=pending.tool_name or pending.action,
                                status="error",
                                content=obs.model_dump_json(),
                            ),
                        ],
                        "pending_action": None,
                    },
                    goto="model",
                )

            # Execute action through executor
            executed = await (executor or execute_action)(
                session,
                assessment_id,
                step.action,
                target=step.target,
                rationale=step.rationale,
                step=step,
            )
            await session.refresh(executed)
            obs = await observation_from_step(session, executed)
            audit(
                session,
                assessment_id,
                "observation.recorded",
                {
                    "run_id": state["run_id"],
                    "step_id": obs.step_id,
                    "action": obs.action,
                    "ok": obs.ok,
                    "status": obs.status,
                    "findings_count": len(obs.findings_created),
                },
            )
            await session.commit()

        return Command(
            update={
                "messages": [
                    *state["messages"],
                    ToolMessage(
                        tool_call_id=pending.tool_call_id,
                        name=pending.tool_name or pending.action,
                        status="success" if obs.ok else "error",
                        content=obs.model_dump_json(),
                    ),
                ],
                "pending_action": None,
                "approval_decision": None,
                "observations": [obs.model_dump()],
                "steps": [
                    {
                        "step_id": obs.step_id,
                        "action": obs.action,
                        "target": obs.target,
                        "status": obs.status,
                    }
                ],
                "last_message": obs.summary,
                "no_progress": 0 if obs.ok else state.get("no_progress", 0) + 1,
            },
            goto="model",
        )

    return execute_node


async def direct_node(state: AssessmentState) -> Command:
    """Execute direct in-process tools like read_artifact, hypotheses, findings."""
    tool_call = _last_tool_call(state["messages"])
    role = state["role"]
    assessment_id = state["assessment_id"]
    spec = lookup_tool(role, tool_call["name"])

    args_raw = tool_call.get("args") or {}
    if isinstance(args_raw, str):
        try:
            args_raw = json.loads(args_raw)
        except Exception:
            args_raw = {}

    async with get_async_session_ctx() as session:
        obs = await run_direct(session, spec, args_raw, state)
        audit(
            session,
            assessment_id,
            "observation.recorded",
            {
                "run_id": state["run_id"],
                "action": obs.action,
                "ok": obs.ok,
                "status": obs.status,
            },
        )
        await session.commit()

    return Command(
        update={
            "messages": [
                *state["messages"],
                ToolMessage(
                    tool_call_id=tool_call["id"],
                    name=tool_call["name"],
                    status="success" if obs.ok else "error",
                    content=obs.model_dump_json(),
                ),
            ],
            "observations": [obs.model_dump()],
            "last_message": obs.summary,
        },
        goto="model",
    )


async def handoff_node(state: AssessmentState) -> Command:
    """Validate specialist handoff and route to supervisor."""
    call = _last_tool_call(state["messages"])
    assessment_id = state["assessment_id"]
    run_id = state["run_id"]
    role = state["role"]

    args_raw = call.get("args") or {}
    if isinstance(args_raw, str):
        try:
            args_raw = json.loads(args_raw)
        except Exception:
            args_raw = {}

    try:
        handoff = Handoff.model_validate(args_raw)
    except Exception as exc:
        return Command(
            update={
                "messages": [
                    *state["messages"],
                    ToolMessage(
                        tool_call_id=call["id"],
                        name="handoff",
                        status="error",
                        content=json.dumps({
                            "ok": False,
                            "status": "error",
                            "summary": f"Invalid handoff: {exc}",
                        }),
                    ),
                ],
                "nudges": state.get("nudges", 0) + 1,
            },
            goto="model",
        )

    async with get_async_session_ctx() as session:
        audit(
            session,
            assessment_id,
            "handoff.created",
            {
                "run_id": run_id,
                "role": role,
                "summary": handoff.summary,
                "next_role": handoff.next_role,
                "why": handoff.why,
                "confidence": handoff.confidence,
                "stop_reason": handoff.stop_reason,
                "finding_ids": handoff.finding_ids,
                "step_ids": handoff.step_ids,
                "open_questions": handoff.open_questions,
            },
        )
        await session.commit()

    return Command(
        update={
            "last_handoff": handoff.model_dump(),
            "handoffs": [handoff.model_dump()],
            "messages": [
                *state["messages"],
                ToolMessage(
                    tool_call_id=call["id"],
                    name="handoff",
                    status="success",
                    content=handoff.model_dump_json(),
                ),
            ],
            "last_message": handoff.summary,
            "finished": True,
        },
        goto="supervisor",
    )


async def review_node(state: AssessmentState) -> Command:
    """Final human delivery review gate."""
    assessment_id = state["assessment_id"]

    async with get_async_session_ctx() as session:
        assessment = await session.get(Assessment, assessment_id)
        board = await build_evidence_board(session, assessment_id)
        if assessment:
            assessment.status = AssessmentStatus.AWAITING_APPROVAL.value
            await session.commit()

    decision = interrupt({
        "gate": "review",
        "role": "review",
        "evidence_board": board.model_dump(),
        "message": "Approve the report, or reject to stop without a report.",
    })

    decision_dict = decision if isinstance(decision, dict) else {}
    approved = str(decision_dict.get("decision", "approved")).lower() == "approved"

    async with get_async_session_ctx() as session:
        assessment = await session.get(Assessment, assessment_id)
        if assessment:
            assessment.status = AssessmentStatus.RUNNING.value if approved else AssessmentStatus.CANCELLED.value
            await session.commit()

    if not approved:
        return Command(
            update={"rejected": True, "finished": True},
            goto=END,
        )

    return Command(
        update={"review_approved": True},
        goto="report_writer",
    )


async def report_writer_node(state: AssessmentState) -> Command:
    """Report narrative generator node (LLM structured output + Python validation)."""
    assessment_id = state["assessment_id"]
    narrative_data = None
    async with get_async_session_ctx() as session:
        try:
            context = await build_narrative_context(session, assessment_id)
            narrative, err = await write_narrative_result(context)
            if narrative is not None:
                narrative_data = narrative.model_dump()
                session.add(
                    Audit(
                        assessment_id=assessment_id,
                        event_type="report.narrative_generated",
                        payload={
                            "findings_count": len(narrative.findings),
                            "executive_summary_len": len(narrative.executive_summary),
                        },
                    )
                )
            else:
                session.add(
                    Audit(
                        assessment_id=assessment_id,
                        event_type="report.narrative_fallback",
                        payload={
                            "reason": "validation_failed_or_model_error",
                            "error": err or "unknown",
                        },
                    )
                )
            await session.commit()
        except Exception as exc:
            logger.exception("report_writer_node unexpected exception: %s", exc)
            session.add(
                Audit(
                    assessment_id=assessment_id,
                    event_type="report.narrative_fallback",
                    payload={"reason": "exception", "error": str(exc)},
                )
            )
            await session.commit()

    return Command(
        update={"report_narrative": narrative_data},
        goto="report",
    )


async def report_node(state: AssessmentState) -> Command:
    """Compile PDF report and finish run."""
    assessment_id = state["assessment_id"]
    narrative = state.get("report_narrative")
    async with get_async_session_ctx() as session:
        report_path = await generate_report(session, assessment_id, narrative=narrative)
        assessment = await session.get(Assessment, assessment_id)
        if assessment:
            assessment.status = AssessmentStatus.COMPLETED.value
            assessment.finished_at = utcnow()
            assessment.report_path = str(report_path)
            await session.commit()

    return Command(
        update={
            "final_report_path": str(report_path),
            "report_path": str(report_path),
            "finished": True,
        },
        goto=END,
    )
