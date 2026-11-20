"""Execution and direct tool nodes for V2 agent loop."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Callable

from langchain_core.messages import ToolMessage
from langgraph.types import Command

if TYPE_CHECKING:
    from app.agents.state import AssessmentState

from app.actions.executor import execute_action
from app.agents.contracts import ActionRequest
from app.agents.direct_tools import run_direct
from app.agents.nodes.specialist import _last_tool_call, handoff_node, next_no_progress
from app.agents.observations import error_observation, observation_from_step
from app.agents.tool_specs import lookup_tool
from app.core.db import get_async_session_ctx
from app.core.log import get_logger
from app.domain.models import Decision
from app.persistence import AuditRepo, StepRepo

logger = get_logger("agent.nodes.execution")


def make_execute_node(executor: Callable[..., Any] | None = None):
    """Factory creating execute_node with optional injected executor."""

    async def execute_node(state: AssessmentState) -> Command:
        pending = ActionRequest.model_validate(state["pending_action"])
        assessment_id = state["assessment_id"]

        async with get_async_session_ctx() as session:
            step_repo = StepRepo(session)
            audit_repo = AuditRepo(session)

            step = await step_repo.get_by_id(pending.step_id)
            approval = await step_repo.get_approval_for_step(pending.step_id)
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
                await step_repo.reject_step(
                    step_id=step.id,
                    error="approval.argv does not match step.argv",
                )
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
            logger.info("execute_node: executing step=%s action=%s target=%s", step.id, step.action, step.target)
            executed = await (executor or execute_action)(
                session,
                assessment_id,
                step.action,
                target=step.target,
                rationale=step.rationale,
                step=step,
            )
            await session.refresh(executed)
            logger.info("execute_node: finished step=%s status=%s exit_code=%s", step.id, executed.status, executed.exit_code)
            obs = await observation_from_step(session, executed)
            await audit_repo.record_event(
                assessment_id=assessment_id,
                event_type="observation.recorded",
                payload={
                    "run_id": state["run_id"],
                    "step_id": obs.step_id,
                    "action": obs.action,
                    "ok": obs.ok,
                    "status": obs.status,
                    "findings_count": len(obs.findings_created),
                },
            )
            await audit_repo.record_decision(
                assessment_id=assessment_id,
                run_id=state["run_id"],
                role=state.get("role") or step.role,
                step_id=pending.step_id,
                action=pending.action,
                target=pending.target,
                observation=(obs.summary or "")[:300],
                expected_observation=pending.expected_observation,
                would_falsify=pending.would_falsify,
                confidence=0.8 if obs.ok else 0.3,
                outcome=obs.status,
                hypothesis_id=pending.hypothesis_id,
                evidence_ids=pending.evidence_ids,
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
                "no_progress": next_no_progress(
                    state.get("no_progress", 0),
                    obs,
                    state.get("observations", []),
                ),
            },
            goto="model",
        )

    return execute_node


async def direct_node(state: AssessmentState) -> Command:
    """Execute direct in-process tools like read_artifact, hypotheses, findings, handoff."""
    tool_call = _last_tool_call(state["messages"])
    if tool_call.get("name") == "handoff":
        return await handoff_node(state)

    role = state["role"]
    assessment_id = state["assessment_id"]
    spec = lookup_tool(role, tool_call["name"])
    logger.info("direct_node: role=%s running direct tool=%s", role, tool_call.get("name"))

    args_raw = tool_call.get("args") or {}
    if isinstance(args_raw, str):
        try:
            args_raw = json.loads(args_raw)
        except Exception:
            args_raw = {}

    async with get_async_session_ctx() as session:
        obs = await run_direct(session, spec, args_raw, state)
        await AuditRepo(session).record_event(
            assessment_id=assessment_id,
            event_type="observation.recorded",
            payload={
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
