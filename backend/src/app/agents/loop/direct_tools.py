"""Direct tool execution for the V2 loop.

Direct tools are safe in-process reads/writes that do not invoke external
scanners or require human approval.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from app.agents.loop.contracts import Observation
from app.agents.loop.reasoning import record_hypothesis, update_hypothesis
from app.agents.loop.tool_specs import ToolSpec
from app.core.config import settings
from app.domain.models import Step
from app.persistence.finding_repo import FindingRepo


async def read_artifact(
    session: AsyncSession,
    assessment_id: int,
    step_id: int,
    max_chars: int = 4000,
    search: str | None = None,
) -> Observation:
    step = await session.get(Step, step_id)
    if step is None or step.assessment_id != assessment_id:
        return Observation(
            ok=False,
            status="error",
            action="read_artifact",
            target=str(step_id),
            summary=f"Step {step_id} not found in this assessment",
            errors=[f"step {step_id} not found"],
        )

    if not step.output_path or not Path(step.output_path).exists():
        return Observation(
            ok=False,
            status="error",
            action="read_artifact",
            target=step.target,
            summary=f"Step {step_id} has no artifact file",
            errors=["no artifact file"],
        )

    try:
        path = Path(step.output_path)
        # Verify artifact is within data directory
        data_dir = settings.artifacts_path.resolve()
        if not path.resolve().is_relative_to(data_dir) and not str(path).startswith("/tmp"):
            return Observation(
                ok=False,
                status="blocked",
                action="read_artifact",
                target=step.target,
                summary="Access to artifact outside allowed directory is blocked",
                errors=["path traversal blocked"],
            )

        content = path.read_text(encoding="utf-8", errors="replace")
        max_chars = min(max_chars, 8000)

        if search:
            idx = content.lower().find(search.lower())
            if idx != -1:
                start = max(0, idx - 200)
                end = min(len(content), start + max_chars)
                excerpt = content[start:end]
            else:
                excerpt = f"Search term {search!r} not found in artifact."
        else:
            excerpt = content[:max_chars]

        return Observation(
            ok=True,
            status="succeeded",
            action="read_artifact",
            target=step.target,
            step_id=step.id,
            summary=f"Read {len(excerpt)} chars from artifact for step {step_id}:\n{excerpt}",
        )
    except Exception as exc:
        return Observation(
            ok=False,
            status="error",
            action="read_artifact",
            target=step.target,
            summary=f"Failed reading artifact: {exc}",
            errors=[str(exc)],
        )


async def list_services(
    session: AsyncSession,
    assessment_id: int,
    limit: int = 50,
) -> Observation:
    repo = FindingRepo(session)
    services = await repo.get_services(assessment_id)
    summaries = [f"{s.endpoint or s.asset}: {s.title}" for s in services[:limit]]
    summary_text = (
        f"Found {len(services)} services:\n" + "\n".join(f"- {s}" for s in summaries)
        if services
        else "No services found."
    )
    return Observation(
        ok=True,
        status="succeeded",
        action="list_services",
        target="in-scope targets",
        summary=summary_text,
    )


async def list_findings(
    session: AsyncSession,
    assessment_id: int,
    status: str | None = None,
    limit: int = 50,
) -> Observation:
    repo = FindingRepo(session)
    candidates = await repo.get_candidates(assessment_id)
    if status:
        candidates = [c for c in candidates if c.status == status]
    summaries = [f"#{c.id} [{c.status}] {c.title} ({c.asset})" for c in candidates[:limit]]
    summary_text = (
        f"Found {len(candidates)} findings:\n" + "\n".join(f"- {c}" for c in summaries)
        if candidates
        else "No findings matching criteria."
    )
    return Observation(
        ok=True,
        status="succeeded",
        action="list_findings",
        target="assessment",
        summary=summary_text,
    )


async def update_finding_status(
    session: AsyncSession,
    assessment_id: int,
    finding_id: int,
    status: str,
    reasoning: str,
) -> Observation:
    repo = FindingRepo(session)
    res = await repo.update_status(
        finding_id=finding_id,
        assessment_id=assessment_id,
        status=status,
        reasoning=reasoning,
        actor="validation",
    )
    if "error" in res:
        return Observation(
            ok=False,
            status="error",
            action="update_finding_status",
            target=str(finding_id),
            summary=f"Failed to update finding #{finding_id}: {res['error']}",
            errors=[res["error"]],
        )
    return Observation(
        ok=True,
        status="succeeded",
        action="update_finding_status",
        target=str(finding_id),
        summary=f"Updated finding #{finding_id} status to {status}. Reasoning: {reasoning}",
        findings_updated=[finding_id],
    )


async def run_direct(
    session: AsyncSession,
    spec: ToolSpec,
    args: dict[str, Any],
    state: dict[str, Any],
) -> Observation:
    """Dispatch execution of a direct tool."""
    assessment_id = state["assessment_id"]
    run_id = state["run_id"]
    role = state["role"]

    if spec.name == "read_artifact":
        return await read_artifact(session, assessment_id, **args)
    if spec.name == "list_services":
        return await list_services(session, assessment_id, **args)
    if spec.name == "list_findings":
        return await list_findings(session, assessment_id, **args)
    if spec.name == "record_hypothesis":
        return await record_hypothesis(
            session=session,
            assessment_id=assessment_id,
            run_id=run_id,
            role=role,
            **args,
        )
    if spec.name == "update_hypothesis":
        return await update_hypothesis(
            session=session,
            assessment_id=assessment_id,
            run_id=run_id,
            role=role,
            **args,
        )
    if spec.name == "update_finding_status":
        return await update_finding_status(
            session=session,
            assessment_id=assessment_id,
            finding_id=args["finding_id"],
            status=args["status"],
            reasoning=args.get("reasoning", ""),
        )

    raise ValueError(f"unknown direct tool {spec.name}")
