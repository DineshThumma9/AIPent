"""Specialist and model execution nodes for V2 agent loop."""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
import sys
from typing import TYPE_CHECKING, Any

from langchain_core.messages import AIMessage, AnyMessage, HumanMessage, SystemMessage, ToolMessage
from langgraph.types import Command, interrupt

if TYPE_CHECKING:
    from app.agents.state import AssessmentState

from app.actions.catalogue import check_scope
from app.agents.brief import render_brief
from app.agents.contracts import ActionRequest, FailureSignal, Handoff, Observation
from app.agents.mission_brain import ROLE_TURN_CAPS
from app.agents.model import build_role_model
from app.agents.observations import error_observation, rejection_observation
from app.agents.prompts import ROLE_PROMPTS
from app.agents.state import (
    close_dangling_tool_calls,
    get_role_messages,
    update_role_messages,
)
from app.agents.tool_specs import bindable_tools, is_direct_tool, lookup_tool
from app.core.config import settings
from app.core.db import get_async_session_ctx
from app.core.log import get_logger
from app.core.policy import policy_for
from app.domain.models import Approval, Assessment, AssessmentStatus, Decision, Step
from app.persistence import (
    AssessmentRepo,
    AuditRepo,
    SteeringRepo,
    StepRepo,
    load_mission_context,
)

logger = get_logger("agent.nodes.specialist")


def curl_response_fingerprint(observation: dict[str, Any]) -> str | None:
    """Fingerprint an HTTP response independently of the requested path.

    Catches SPA catch-all routing: different paths return byte-identical
    bodies. Those 200s look like progress to the model, so it keeps guessing.
    """
    if observation.get("action") != "curl_request":
        return None
    facts = observation.get("facts") or {}
    status = facts.get("status_code")
    body = facts.get("body_preview")
    if status is None or body is None:
        return None
    digest = hashlib.sha256(str(body).encode("utf-8", "replace")).hexdigest()[:16]
    return f"{status}:{digest}"


def next_no_progress(
    current: int,
    observation: Observation,
    history: list[dict[str, Any]],
) -> int:
    """Count failed probes and duplicate responses as no-progress."""
    facts = observation.facts or {}
    batch_results = facts.get("results")
    if isinstance(batch_results, list) and batch_results:
        codes: list[int] = []
        for item in batch_results:
            try:
                codes.append(int(item.get("status_code") or 0))
            except (TypeError, ValueError):
                codes.append(0)
        if not observation.ok or all(code == 0 or code >= 400 for code in codes):
            return current + 1
        return 0
    try:
        status_code = int(facts.get("status_code") or 0)
    except (TypeError, ValueError):
        status_code = 0

    fingerprint = curl_response_fingerprint(observation.model_dump())
    seen = {
        fp
        for fp in (curl_response_fingerprint(item) for item in history[-15:])
        if fp
    }
    duplicate = fingerprint is not None and fingerprint in seen

    if not observation.ok or status_code >= 400 or duplicate:
        return current + 1
    return 0


def extract_text_handoff(content: Any, role: str) -> dict[str, Any] | None:
    """Detect and parse text-based handoff responses from LLMs into a synthetic tool call."""
    if not isinstance(content, str) or not content.strip():
        return None

    import re
    import uuid

    text = content.strip()
    lower = text.lower()
    if "handoff" not in lower and "next_role" not in lower:
        return None

    next_role_default = "discovery" if role == "recon" else ("validation" if role == "discovery" else "review")

    # 1. Look for ```json { ... } ``` or ``` { ... } ``` block
    json_blocks = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    for block in json_blocks:
        try:
            data = json.loads(block)
            if isinstance(data, dict):
                args = data.get("args") if "args" in data and isinstance(data["args"], dict) else data
                if "next_role" in args or data.get("name") == "handoff":
                    next_r = str(args.get("next_role") or next_role_default).lower()
                    if next_r in ("recon", "discovery", "validation", "review"):
                        return {
                            "id": f"call_handoff_{uuid.uuid4().hex[:8]}",
                            "name": "handoff",
                            "args": {
                                "summary": str(args.get("summary") or args.get("why") or f"Handoff from {role} to {next_r}"),
                                "next_role": next_r,
                                "why": str(args.get("why") or args.get("summary") or f"Proceeding to {next_r}"),
                                "confidence": float(args.get("confidence") if args.get("confidence") is not None else 0.8),
                                "stop_reason": str(args.get("stop_reason") or ("surface_mapped" if role == "recon" else "hypotheses_tested")),
                                "finding_ids": list(args.get("finding_ids") or []),
                                "step_ids": list(args.get("step_ids") or []),
                                "open_questions": list(args.get("open_questions") or []),
                                "recommended_actions": list(args.get("recommended_actions") or []),
                            },
                        }
        except Exception:
            pass

    # 2. Look for bare JSON object with next_role
    bare_matches = re.findall(r"(\{[^{}]*\"next_role\"[^{}]*\})", text, re.DOTALL)
    for block in bare_matches:
        try:
            data = json.loads(block)
            if isinstance(data, dict) and "next_role" in data:
                next_r = str(data.get("next_role") or next_role_default).lower()
                if next_r in ("recon", "discovery", "validation", "review"):
                    return {
                        "id": f"call_handoff_{uuid.uuid4().hex[:8]}",
                        "name": "handoff",
                        "args": {
                            "summary": str(data.get("summary") or data.get("why") or f"Handoff from {role} to {next_r}"),
                            "next_role": next_r,
                            "why": str(data.get("why") or data.get("summary") or f"Proceeding to {next_r}"),
                            "confidence": float(data.get("confidence") if data.get("confidence") is not None else 0.8),
                            "stop_reason": str(data.get("stop_reason") or ("surface_mapped" if role == "recon" else "hypotheses_tested")),
                            "finding_ids": list(data.get("finding_ids") or []),
                            "step_ids": list(data.get("step_ids") or []),
                            "open_questions": list(data.get("open_questions") or []),
                            "recommended_actions": list(data.get("recommended_actions") or []),
                        },
                    }
        except Exception:
            pass

    # 3. Look for handoff(next_role="...", why="...") pattern
    call_match = re.search(r"handoff\s*\(\s*next_role\s*=\s*['\"]([^'\"]+)['\"](?:\s*,\s*why\s*=\s*['\"]([^'\"]+)['\"])?", text, re.IGNORECASE)
    if call_match:
        next_r = call_match.group(1).lower()
        if next_r in ("recon", "discovery", "validation", "review"):
            why = call_match.group(2) or f"Handoff from {role} to {next_r}"
            return {
                "id": f"call_handoff_{uuid.uuid4().hex[:8]}",
                "name": "handoff",
                "args": {
                    "summary": why,
                    "next_role": next_r,
                    "why": why,
                    "confidence": 0.8,
                    "stop_reason": "surface_mapped" if role == "recon" else "hypotheses_tested",
                    "finding_ids": [],
                    "step_ids": [],
                    "open_questions": [],
                    "recommended_actions": [],
                },
            }

    # 4. Look for bold **handoff** or similar keywords
    keyword_match = re.search(r"\bhandoff\b.*?to\s+([a-zA-Z]+)", text, re.IGNORECASE)
    if keyword_match:
        target_role = keyword_match.group(1).lower()
        if target_role in ("recon", "discovery", "validation", "review"):
            return {
                "id": f"call_handoff_{uuid.uuid4().hex[:8]}",
                "name": "handoff",
                "args": {
                    "summary": f"Handoff from {role} to {target_role}",
                    "next_role": target_role,
                    "why": text[:500],
                    "confidence": 0.8,
                    "stop_reason": "surface_mapped" if role == "recon" else "hypotheses_tested",
                    "finding_ids": [],
                    "step_ids": [],
                    "open_questions": [],
                    "recommended_actions": [],
                },
            }

    return None


async def brief_node(state: AssessmentState) -> Command:
    """Build specialist context from DB and transition to model."""
    assessment_id = state["assessment_id"]
    role = state["role"]
    directive = state.get("supervisor_directive")
    logger.info("brief_node: generated brief for role=%s directive=%r", role, directive)

    async with get_async_session_ctx() as session:
        context = await load_mission_context(session, assessment_id, state.get("run_id"))
        await session.commit()

    digest = render_brief(
        assessment=context.assessment,
        role=role,
        board=context.evidence_board,
        services=context.services,
        candidates=context.candidates,
        steering=context.steering_notes,
        supervisor_directive=directive,
        plan=state.get("plan"),
        feedback=state.get("plan_feedback", "") or "",
    )

    existing_role_msgs = close_dangling_tool_calls(get_role_messages(state, role))

    if existing_role_msgs:
        role_msgs = [*existing_role_msgs, HumanMessage(content=f"MISSION UPDATE & DIRECTIVE:\n{digest}")]
    else:
        role_msgs = [HumanMessage(content=digest)]

    update_dict: dict[str, Any] = {
        **update_role_messages(state, role_msgs, role),
        "pending_action": None,
        "approval_decision": None,
        "supervisor_directive": None,
        "nudges": 0,
        "no_progress": 0,
    }

    return Command(
        update=update_dict,
        goto="model",
    )


async def model_node(state: AssessmentState) -> Command:
    """Invoke role model and route tool calls or handoff."""
    role = state["role"]
    assessment_id = state["assessment_id"]
    cap = min(ROLE_TURN_CAPS.get(role, 8), settings.max_agent_turns)
    turns = dict(state.get("turns", {}))

    if turns.get(role, 0) >= cap:
        signal = FailureSignal(
            role=role,  # type: ignore[arg-type]
            kind="budget_exhausted",
            summary=f"{role} reached its model-call budget ({cap} turns) without a handoff.",
            attempts=turns.get(role, 0),
        )
        async with get_async_session_ctx() as session:
            await AuditRepo(session).record_event(
                assessment_id=assessment_id,
                event_type="role.budget_exhausted",
                payload={
                    "run_id": state.get("run_id"),
                    "role": role,
                    "cap": cap,
                    "attempts": turns.get(role, 0),
                    "kind": "budget_exhausted",
                },
            )
            await session.commit()
        update_dict: dict[str, Any] = {
            **update_role_messages(state, get_role_messages(state, role), role),
            "last_message": signal.summary,
            "failure_signal": signal.model_dump(),
        }
        return Command(
            update=update_dict,
            goto="supervisor",
        )

    if state.get("no_progress", 0) >= settings.max_no_progress:
        signal = FailureSignal(
            role=role,  # type: ignore[arg-type]
            kind="no_progress",
            summary=(
                f"{role} produced {state['no_progress']} consecutive failed or "
                "duplicate probes without a handoff; supervisor intervention required."
            ),
            attempts=turns.get(role, 0),
        )
        update_dict = {
            **update_role_messages(state, get_role_messages(state, role), role),
            "last_message": signal.summary,
            "failure_signal": signal.model_dump(),
        }
        return Command(
            update=update_dict,
            goto="supervisor",
        )

    role_model_fn = getattr(sys.modules.get("app.agents.nodes"), "build_role_model", build_role_model)
    model = role_model_fn(role).bind_tools(bindable_tools(role))
    messages = close_dangling_tool_calls(get_role_messages(state, role))
    if role in ROLE_PROMPTS:
        if messages and isinstance(messages[0], SystemMessage):
            messages[0] = SystemMessage(content=ROLE_PROMPTS[role])
        else:
            messages = [SystemMessage(content=ROLE_PROMPTS[role]), *messages]

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
    call_config = {
        "run_name": f"{role}-turn-{turns.get(role, 0) + 1}",
        "tags": [role, f"assessment:{assessment_id}", f"run:{state.get('run_id')}"],
        "metadata": {"assessment_id": assessment_id, "role": role, "run_id": state.get("run_id")},
    }
    logger.info("model_node: role=%s turn=%d/%d invoking model...", role, turns.get(role, 0) + 1, cap)
    for attempt in range(1, 4):
        try:
            try:
                ai = await model.ainvoke(messages, config=call_config)
            except TypeError:
                # Some chat-model wrappers only accept messages.
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
                        **update_role_messages(state, messages, role),
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
    async with get_async_session_ctx() as session:
        await AuditRepo(session).record_event(
            assessment_id=assessment_id,
            event_type="role.turn",
            payload={
                "run_id": state.get("run_id"),
                "role": role,
                "turn": turns[role],
                "cap": cap,
            },
        )
        await session.commit()

    tool_calls = list(getattr(ai, "tool_calls", []) or [])
    if not tool_calls and getattr(ai, "content", None):
        recovered = extract_text_handoff(ai.content, role)
        if recovered:
            logger.info("model_node: role=%s recovered text handoff: %s", role, recovered)
            tool_calls = [recovered]
            try:
                ai.tool_calls = [recovered]
            except Exception:
                pass

    if tool_calls:
        for tc in tool_calls:
            logger.info("model_node: role=%s generated tool_call=%s args=%s", role, tc.get("name"), tc.get("args"))

    if not tool_calls:
        if state.get("nudges", 0) < 2:
            nudge_msg = HumanMessage(
                content=(
                    "You must either select one of your available tools to make progress, "
                    "or call handoff(next_role=..., why=...) to pass control. "
                    "Do not output conversational text alone."
                )
            )
            return Command(
                update={
                    **update_role_messages(state, [*messages, nudge_msg], role),
                    "turns": turns,
                    "nudges": state.get("nudges", 0) + 1,
                },
                goto="model",
            )
        signal = FailureSignal(
            role=role,  # type: ignore[arg-type]
            kind="no_handoff",
            summary="Model produced no tool call after the allowed nudges.",
            attempts=state.get("nudges", 0) + 1,
        )
        return Command(
            update={
                **update_role_messages(state, messages, role),
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
    update_dict = {
        **update_role_messages(state, messages, role),
        "turns": turns,
    }

    if is_direct_tool(role, name) or name == "handoff":
        return Command(
            update=update_dict,
            goto="direct",
        )
    return Command(
        update=update_dict,
        goto="prepare",
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
    role = state["role"]
    assessment_id = state["assessment_id"]
    current_msgs = get_role_messages(state, role)
    tool_call = _last_tool_call(current_msgs)

    try:
        spec = lookup_tool(role, tool_call["name"])
    except KeyError as exc:
        obs = error_observation(tool_call["name"], "unknown", str(exc))
        return Command(
            update=update_role_messages(
                state,
                [
                    *current_msgs,
                    ToolMessage(
                        tool_call_id=tool_call["id"],
                        name=tool_call["name"],
                        status="error",
                        content=obs.model_dump_json(),
                    ),
                ],
                role,
            ),
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
            update=update_role_messages(
                state,
                [
                    *current_msgs,
                    ToolMessage(
                        tool_call_id=tool_call["id"],
                        name=tool_call["name"],
                        status="error",
                        content=obs.model_dump_json(),
                    ),
                ],
                role,
            ),
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
                update=update_role_messages(
                    state,
                    [
                        *current_msgs,
                        ToolMessage(
                            tool_call_id=tool_call["id"],
                            name=tool_call["name"],
                            status="error",
                            content=obs.model_dump_json(),
                        ),
                    ],
                    role,
                ),
                goto="model",
            )

        params: dict[str, Any] = {}
        for field in spec.param_fields:
            value = getattr(args, field, None)
            if value is None:
                continue
            if field == "requests" and value:
                value = [
                    item.model_dump(exclude_none=True)
                    if hasattr(item, "model_dump")
                    else item
                    for item in value
                ]
            params[field] = value
        ports_val = getattr(args, "ports", None)
        if ports_val is not None and "ports" in spec.param_fields:
            if isinstance(ports_val, list):
                params["ports"] = ",".join(str(p) for p in ports_val)
            elif isinstance(ports_val, int):
                params["ports"] = str(ports_val)
            else:
                params["ports"] = str(ports_val)

        action_name = spec.action or spec.name
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
                        update=update_role_messages(
                            state,
                            [
                                *current_msgs,
                                ToolMessage(
                                    tool_call_id=tool_call["id"],
                                    name=tool_call["name"],
                                    status="error",
                                    content=obs.model_dump_json(),
                                ),
                            ],
                            role,
                        ),
                        goto="model",
                    )
                if not source_step.output_path or not Path(source_step.output_path).exists():
                    obs = error_observation(action_name, target, f"source_step_id {source_step_id} has no artifact file")
                    return Command(
                        update=update_role_messages(
                            state,
                            [
                                *current_msgs,
                                ToolMessage(
                                    tool_call_id=tool_call["id"],
                                    name=tool_call["name"],
                                    status="error",
                                    content=obs.model_dump_json(),
                                ),
                            ],
                            role,
                        ),
                        goto="model",
                    )
                text = Path(source_step.output_path).read_text(errors="replace")
                if hash_val.lower() not in text.lower():
                    obs = error_observation(action_name, target, "hash_value does not appear in that artifact")
                    return Command(
                        update=update_role_messages(
                            state,
                            [
                                *current_msgs,
                                ToolMessage(
                                    tool_call_id=tool_call["id"],
                                    name=tool_call["name"],
                                    status="error",
                                    content=obs.model_dump_json(),
                                ),
                            ],
                            role,
                        ),
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
                        update=update_role_messages(
                            state,
                            [
                                *current_msgs,
                                ToolMessage(
                                    tool_call_id=tool_call["id"],
                                    name=tool_call["name"],
                                    status="error",
                                    content=obs.model_dump_json(),
                                ),
                            ],
                            role,
                        ),
                        goto="model",
                    )
                if not input_path.exists():
                    obs = error_observation(action_name, target, f"hash_file {hash_file} does not exist")
                    return Command(
                        update=update_role_messages(
                            state,
                            [
                                *current_msgs,
                                ToolMessage(
                                    tool_call_id=tool_call["id"],
                                    name=tool_call["name"],
                                    status="error",
                                    content=obs.model_dump_json(),
                                ),
                            ],
                            role,
                        ),
                        goto="model",
                    )
                params["input_path"] = str(input_path)
            else:
                obs = error_observation(action_name, target, "hashcat_crack needs source_step_id + hash_value or hash_file")
                return Command(
                    update=update_role_messages(
                        state,
                        [
                            *current_msgs,
                            ToolMessage(
                                tool_call_id=tool_call["id"],
                                name=tool_call["name"],
                                status="error",
                                content=obs.model_dump_json(),
                            ),
                        ],
                        role,
                    ),
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

        if not result.get("error") and not result.get("duplicate_of_step"):
            await AuditRepo(session).record_decision(
                assessment_id=assessment_id,
                run_id=state["run_id"],
                role=role,
                step_id=result["step_id"],
                action=action_name,
                target=target,
                observation="",
                outcome="prepared",
                confidence=0.6,
                hypothesis_id=getattr(args, "hypothesis_id", None),
                evidence_ids=getattr(args, "evidence_ids", []),
                expected_observation=getattr(args, "expected_observation", None),
                would_falsify=getattr(args, "would_falsify", None),
            )
        await session.commit()

    if result.get("error"):
        obs = error_observation(spec.action or spec.name, target, result["error"])
        return Command(
            update=update_role_messages(
                state,
                [
                    *current_msgs,
                    ToolMessage(
                        tool_call_id=tool_call["id"],
                        name=tool_call["name"],
                        status="error",
                        content=obs.model_dump_json(),
                    ),
                ],
                role,
            ),
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
            update=update_role_messages(
                state,
                [
                    *current_msgs,
                    ToolMessage(
                        tool_call_id=tool_call["id"],
                        name=tool_call["name"],
                        status="success",
                        content=obs.model_dump_json(),
                    ),
                ],
                role,
            ),
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

    approved = False
    rejection_reason = "rejected by analyst"
    needs_human_approval = False
    interrupt_payload: dict[str, Any] = {}

    async with get_async_session_ctx() as session:
        step_repo = StepRepo(session)
        audit_repo = AuditRepo(session)
        assessment_repo = AssessmentRepo(session)

        role = state.get("role") or "agent"
        current_msgs = get_role_messages(state, role)

        step = await step_repo.get_by_id(pending.step_id)
        approval = await session.get(Approval, pending.approval_id)
        if approval is None or step is None:
            obs = error_observation(pending.action, pending.target, "Step or approval record missing")
            return Command(
                update={
                    **update_role_messages(
                        state,
                        [
                            *current_msgs,
                            ToolMessage(
                                tool_call_id=pending.tool_call_id,
                                name=pending.tool_name or pending.action,
                                status="error",
                                content=obs.model_dump_json(),
                            ),
                        ],
                        role,
                    ),
                    "pending_action": None,
                },
                goto="model",
            )

        if approval.decision == Decision.PENDING.value:
            if not pending.requires_approval:
                await step_repo.resolve_approval(
                    approval_id=approval.id,
                    decision=Decision.APPROVED.value,
                    actor="system",
                    reason=pending.policy_reason or "auto-approved by policy",
                    outcome="auto-approved",
                )
                await audit_repo.record_event(
                    assessment_id=assessment_id,
                    event_type="approval.auto_approved",
                    payload={
                        "approval_id": approval.id,
                        "step_id": step.id,
                        "action": pending.action,
                        "argv": list(step.argv),
                    },
                )
                await session.commit()
                approved = True
            else:
                needs_human_approval = True
                await assessment_repo.set_status(assessment_id, AssessmentStatus.AWAITING_APPROVAL.value)
                interrupt_payload = {
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
                }
        else:
            approved = approval.decision == Decision.APPROVED.value

    if needs_human_approval:
        decision = interrupt(interrupt_payload)
        decision_dict = decision if isinstance(decision, dict) else {}
        approved = str(decision_dict.get("decision", "rejected")).lower() == "approved"
        rejection_reason = decision_dict.get("reason") or "rejected by analyst"
        actor = decision_dict.get("actor") or "analyst"
        logger.info(
            "approve_node: step=%s action=%s gate resolved with decision=%s by %s",
            interrupt_payload["step_id"],
            interrupt_payload["action"],
            "approved" if approved else "rejected",
            actor,
        )

        async with get_async_session_ctx() as session:
            step_repo = StepRepo(session)
            audit_repo = AuditRepo(session)
            assessment_repo = AssessmentRepo(session)

            if approved:
                await step_repo.resolve_approval(
                    approval_id=interrupt_payload["approval_id"],
                    decision=Decision.APPROVED.value,
                    actor=actor,
                    reason=decision_dict.get("reason"),
                    outcome="action approved",
                )
                await audit_repo.record_event(
                    assessment_id=assessment_id,
                    event_type="approval.approved",
                    payload={
                        "approval_id": interrupt_payload["approval_id"],
                        "step_id": interrupt_payload["step_id"],
                        "reason": decision_dict.get("reason"),
                        "actor": actor,
                    },
                )
            else:
                await step_repo.reject_step(
                    step_id=interrupt_payload["step_id"],
                    error=rejection_reason,
                    reason=rejection_reason,
                    actor=actor,
                )
                await audit_repo.record_event(
                    assessment_id=assessment_id,
                    event_type="approval.rejected",
                    payload={
                        "approval_id": interrupt_payload["approval_id"],
                        "step_id": interrupt_payload["step_id"],
                        "reason": rejection_reason,
                        "actor": actor,
                    },
                )
                await audit_repo.record_decision(
                    assessment_id=assessment_id,
                    run_id=state["run_id"],
                    role=state.get("role") or "agent",
                    step_id=interrupt_payload["step_id"],
                    action=pending.action,
                    target=pending.target,
                    observation=f"Rejected by operator: {rejection_reason[:200]}",
                    outcome="rejected",
                    confidence=0.0,
                    hypothesis_id=pending.hypothesis_id,
                    evidence_ids=pending.evidence_ids,
                    expected_observation=pending.expected_observation,
                    would_falsify=pending.would_falsify,
                )

            await assessment_repo.set_status(assessment_id, AssessmentStatus.RUNNING.value)
            await session.commit()

    if not approved:
        role = state.get("role") or "agent"
        current_msgs = get_role_messages(state, role)
        obs = rejection_observation(pending, rejection_reason if 'rejection_reason' in locals() else "rejected by analyst")
        return Command(
            update={
                **update_role_messages(
                    state,
                    [
                        *current_msgs,
                        ToolMessage(
                            tool_call_id=pending.tool_call_id,
                            name=pending.tool_name or pending.action,
                            status="error",
                            content=obs.model_dump_json(),
                        ),
                    ],
                    role,
                ),
                "pending_action": None,
                "approval_decision": {"decision": "rejected"},
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
            },
            goto="model",
        )

    return Command(
        update={"approval_decision": {"decision": "approved"}},
        goto="execute",
    )


async def handoff_node(state: AssessmentState) -> Command:
    """Validate specialist handoff and route to supervisor."""
    role = state["role"]
    assessment_id = state["assessment_id"]
    run_id = state["run_id"]
    current_msgs = get_role_messages(state, role)
    call = _last_tool_call(current_msgs)

    args_raw = call.get("args") or {}
    if isinstance(args_raw, str):
        try:
            args_raw = json.loads(args_raw)
        except Exception:
            args_raw = {}

    try:
        handoff = Handoff.model_validate(args_raw)
        logger.info(
            "handoff_node: role=%s handing off to next_role=%s reason=%r (stop_reason=%s)",
            role,
            handoff.next_role,
            handoff.why,
            handoff.stop_reason,
        )
    except Exception as exc:
        return Command(
            update={
                **update_role_messages(
                    state,
                    [
                        *current_msgs,
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
                    role,
                ),
                "nudges": state.get("nudges", 0) + 1,
            },
            goto="model",
        )

    async with get_async_session_ctx() as session:
        await AuditRepo(session).record_event(
            assessment_id=assessment_id,
            event_type="handoff.created",
            payload={
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
                "recommended_actions": handoff.recommended_actions,
            },
        )
        await session.commit()

    final_messages = [
        *current_msgs,
        ToolMessage(
            tool_call_id=call["id"],
            name="handoff",
            status="success",
            content=handoff.model_dump_json(),
        ),
    ]
    update_dict: dict[str, Any] = {
        **update_role_messages(state, final_messages, role),
        "last_handoff": handoff.model_dump(),
        "last_message": handoff.summary,
        "finished": True,
    }

    return Command(
        update=update_dict,
        goto="supervisor",
    )
