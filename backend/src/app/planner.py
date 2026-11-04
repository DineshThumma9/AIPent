"""Plan contract, deterministic fallback, and the optional Groq planner.

The LLM selects action names and rationales. It never supplies argv. Every plan
is validated against scope and the closed action catalogue before it is stored.
"""

import re
from typing import Literal

from langchain.agents import create_agent
from langchain_core.messages import HumanMessage
from langchain_core.tools import tool
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from app.actions import ACTIONS, completed_actions
from app.config import settings
from app.log import get_logger
from app.models import Assessment, Finding
from app.prompts import PLANNER_SYSTEM_PROMPT, planner_user_prompt

log = get_logger("planner")

ActionName = Literal["recon_services", "nikto_scan", "zap_baseline"]

HTTP_PORTS = {80, 443, 3000, 8000, 8080, 8443}
MAX_PLAN_STEPS = min(4, settings.max_steps)


class PlanStep(BaseModel):
    action: ActionName
    target: str
    rationale: str = Field(min_length=1, max_length=400)


class Plan(BaseModel):
    steps: list[PlanStep] = Field(default_factory=list)
    summary: str = ""


class PlanError(ValueError):
    """The candidate plan violates the contract or the scope."""


def _web_ports_from_findings(findings: list[Finding]) -> list[int]:
    ports: set[int] = set()
    for finding in findings:
        match = re.match(r"tcp/(\d+)", finding.endpoint or "")
        if not match:
            continue
        port = int(match.group(1))
        if port in HTTP_PORTS or "http" in finding.title.lower():
            ports.add(port)
    return sorted(ports)


def web_ports(session: Session, assessment_id: int) -> list[int]:
    findings = session.exec(
        select(Finding).where(Finding.assessment_id == assessment_id)
    ).all()
    return _web_ports_from_findings(findings)


def validate_plan(assessment: Assessment, plan: Plan, completed: set[tuple[str, str]]) -> Plan:
    if len(plan.steps) > MAX_PLAN_STEPS:
        raise PlanError(f"plan has {len(plan.steps)} steps; limit is {MAX_PLAN_STEPS}")

    seen: set[tuple[str, str]] = set()
    accepted: list[PlanStep] = []
    for step in plan.steps:
        if step.action not in ACTIONS:
            raise PlanError(f"unknown action {step.action!r}")
        if step.target in assessment.exclusions:
            raise PlanError(f"target {step.target!r} is excluded")
        if step.target not in assessment.targets:
            raise PlanError(f"target {step.target!r} is outside scope")
        if not step.rationale.strip():
            raise PlanError("each step needs a rationale")
        identity = (step.action, step.target)
        if identity in seen:
            raise PlanError(f"duplicate step {identity}")
        seen.add(identity)
        if identity in completed:
            continue
        accepted.append(step)

    return Plan(steps=accepted, summary=plan.summary)


def deterministic_plan(
    assessment: Assessment,
    completed: set[tuple[str, str]],
    open_web_ports: list[int],
) -> Plan:
    target = assessment.targets[0] if assessment.targets else ""
    steps: list[PlanStep] = []

    if ("recon_services", target) not in completed:
        steps.append(
            PlanStep(
                action="recon_services",
                target=target,
                rationale=(
                    "Service discovery must establish which ports are open before "
                    "any web probe is selected."
                ),
            )
        )
    elif open_web_ports:
        if ("nikto_scan", target) not in completed:
            steps.append(
                PlanStep(
                    action="nikto_scan",
                    target=target,
                    rationale=(
                        f"An HTTP service is already known on port "
                        f"{open_web_ports[0]}; an active Nikto probe is in scope."
                    ),
                )
            )
        if ("zap_baseline", target) not in completed:
            steps.append(
                PlanStep(
                    action="zap_baseline",
                    target=target,
                    rationale=(
                        "A passive ZAP baseline adds an independent web view of "
                        "the same endpoint."
                    ),
                )
            )

    return Plan(
        steps=steps[:MAX_PLAN_STEPS],
        summary="Deterministic plan from the closed action catalogue.",
    )


@tool
def submit_plan(steps: list[PlanStep], summary: str = "") -> str:
    """Submit the complete ordered assessment plan.

    Args:
        steps: One to four actions, in execution order.
        summary: One sentence explaining the plan.
    """
    return f"plan accepted with {len(steps)} step(s)"


def _extract_plan(result: dict) -> Plan:
    for message in reversed(result.get("messages", [])):
        for call in getattr(message, "tool_calls", []) or []:
            if call.get("name") == "submit_plan":
                return Plan.model_validate(call.get("args", {}))
    raise PlanError("planner did not call submit_plan")


def llm_plan(
    assessment: Assessment,
    completed: set[tuple[str, str]],
    open_web_ports: list[int],
) -> Plan:
    from app.middleware import middleware_setup
    from app.models import ThinkingLevel

    if not settings.groq_api_key:
        raise PlanError("GROQ_API_KEY is not configured")

    agent = create_agent(
        model=f"groq:{settings.llm_model}",
        tools=[submit_plan],
        system_prompt=PLANNER_SYSTEM_PROMPT,
        # The user middleware's tool-error wrapper is async-only; submit_plan
        # cannot fail, so the sync planner uses the remaining middleware.
        middleware=[
            item
            for item in middleware_setup(ThinkingLevel.LOW)
            if type(item).__name__ != "handle_tool_errors"
        ],
    )
    facts = (
        f"open web ports: {', '.join(map(str, open_web_ports))}"
        if open_web_ports
        else "no open web ports confirmed yet"
    )
    prompt = planner_user_prompt(
        title=assessment.title,
        request=assessment.request,
        targets=assessment.targets,
        ports=assessment.ports,
        exclusions=assessment.exclusions,
        completed=[f"{action}@{target}" for action, target in sorted(completed)],
        facts=facts,
    )
    result = agent.invoke(
        {"messages": [HumanMessage(content=prompt)]},
        config={"recursion_limit": 30},
    )
    return _extract_plan(result)


def build_plan(
    session: Session,
    assessment: Assessment,
) -> tuple[Plan, str]:
    """Return a validated plan and the source that produced it."""
    completed = completed_actions(session, assessment.id or 0)
    open_web_ports = web_ports(session, assessment.id or 0)

    if settings.groq_api_key:
        try:
            candidate = llm_plan(assessment, completed, open_web_ports)
            plan = validate_plan(assessment, candidate, completed)
            if plan.steps:
                return plan, "groq"
            log.info("LLM returned an empty plan; using deterministic fallback")
        except Exception as exc:  # noqa: BLE001 - the fallback is the safety net
            log.warning("LLM planner unavailable: %s", str(exc)[:300])

    plan = deterministic_plan(assessment, completed, open_web_ports)
    return validate_plan(assessment, plan, completed), "deterministic"
