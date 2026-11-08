"""Single execution path for catalogued actions.

Resolve the argv, run the tool (or the in-process HTTP probe), keep the
artifact and persist evidence. A tool failure is recorded on the Step, never
raised into the graph.

The database layer is fully async: every caller passes an ``AsyncSession``.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import func
from sqlalchemy.ext.asyncio import AsyncSession

# Registry of in-flight scanner processes keyed by assessment_id, so that
# stop_run can terminate a child process when an operator cancels a run.
_active_processes: dict[int, asyncio.subprocess.Process] = {}


def register_process(assessment_id: int, process: asyncio.subprocess.Process) -> None:
    """Store a live subprocess so stop_run can terminate it."""
    _active_processes[assessment_id] = process


def terminate_process(assessment_id: int) -> None:
    """Send SIGTERM to the active process for an assessment, if any."""
    process = _active_processes.pop(assessment_id, None)
    if process is not None and process.returncode is None:
        process.terminate()
from sqlmodel import select

from app.actions.catalogue import (
    ACTIONS,
    _artifact_dir,
    _web_port,
    check_scope,
    get_action,
    mcp_tool_call,
    resolve_argv,
    transport_target,
)
from app.adapters.base import FindingDraft
from app.core.config import settings
from app.domain.correlate import canonical_key
from app.domain.models import (
    Assessment,
    Approval,
    Audit,
    Evidence,
    Finding,
    Step,
    StepStatus,
    utcnow,
)
from app.integrations.mcp_client import GatewayClient
from app.integrations.zap_guided import run_zap_baseline


@dataclass
class MCPResult:
    text: str
    calls: list[dict]


SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


async def _next_seq(session: AsyncSession, assessment_id: int) -> int:
    result = await session.execute(
        select(func.max(Step.seq)).where(Step.assessment_id == assessment_id)
    )
    current = result.scalar()
    return (current or 0) + 1


def _audit(
    session: AsyncSession, assessment_id: int, event_type: str, payload: dict
) -> None:
    session.add(Audit(assessment_id=assessment_id, event_type=event_type, payload=payload))


async def _save_findings(
    session: AsyncSession,
    assessment_id: int,
    step: Step,
    drafts: list[FindingDraft],
) -> tuple[int, int]:
    added = 0
    merged = 0
    for draft in drafts:
        key = canonical_key(draft)
        result = await session.execute(
            select(Finding).where(
                Finding.assessment_id == assessment_id,
                Finding.canonical_key == key,
            )
        )
        existing = result.scalars().first()

        if existing is None:
            finding = Finding(
                assessment_id=assessment_id,
                canonical_key=key,
                asset=draft.asset,
                endpoint=draft.endpoint,
                title=draft.title,
                description=draft.description,
                severity=draft.severity.value,
                confidence=draft.confidence,
                status=draft.status.value,
                origin=draft.origin.value,
                impact=draft.impact,
                remediation=draft.remediation,
                cvss=draft.cvss,
                cve=draft.cve,
                cwe=draft.cwe,
            )
            session.add(finding)
            await session.flush()
            target_finding = finding
            added += 1
        else:
            target_finding = existing
            target_finding.updated_at = utcnow()
            target_finding.confidence = max(
                existing.confidence or 0, draft.confidence
            )
            if SEVERITY_RANK.get(draft.severity.value, 9) < SEVERITY_RANK.get(
                existing.severity, 9
            ):
                target_finding.severity = draft.severity.value
            if not existing.description:
                target_finding.description = draft.description
            if not existing.remediation:
                target_finding.remediation = draft.remediation
            if draft.cve:
                target_finding.cve = sorted(set(existing.cve or []) | set(draft.cve))
            if draft.cwe:
                target_finding.cwe = sorted(set(existing.cwe or []) | set(draft.cwe))
            if draft.status.value == "confirmed" and existing.status != "confirmed":
                target_finding.status = "confirmed"
            merged += 1

        evidence_result = await session.execute(
            select(Evidence).where(Evidence.finding_id == target_finding.id)
        )
        current_evidence = list(evidence_result.scalars().all())
        for evidence in draft.evidence:
            duplicate = any(
                row.step_id == step.id
                and row.locator == evidence.locator
                and row.excerpt == evidence.excerpt
                for row in current_evidence
            )
            if duplicate:
                continue
            session.add(
                Evidence(
                    finding_id=target_finding.id,
                    step_id=step.id,
                    locator=evidence.locator,
                    excerpt=evidence.excerpt,
                )
            )
            current_evidence.append(
                Evidence(
                    finding_id=target_finding.id,
                    step_id=step.id,
                    locator=evidence.locator,
                    excerpt=evidence.excerpt,
                )
            )

        # Two independent tools observing the same key is confirmation, not a
        # guess. One tool's report keeps the finding suspected.
        tools = {
            row.locator.get("tool")
            for row in current_evidence
            if row.locator.get("tool")
        }
        if len(tools) >= 2:
            target_finding.status = "confirmed"
    return added, merged


async def _run(
    argv: list[str],
    timeout: int,
    assessment_id: int | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a scanner subprocess and register it for possible termination."""
    process = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    if assessment_id is not None:
        register_process(assessment_id, process)

    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=timeout
        )
    except asyncio.TimeoutError:
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
        raise
    finally:
        if assessment_id is not None:
            _active_processes.pop(assessment_id, None)

    return subprocess.CompletedProcess(
        argv,
        process.returncode,
        stdout.decode(errors="replace") if stdout else "",
        stderr.decode(errors="replace") if stderr else "",
    )


async def execute_action(
    session: AsyncSession,
    assessment_id: int,
    action: str,
    target: str | None = None,
    rationale: str = "",
    timeout: int | None = None,
    step: Step | None = None,
) -> Step:
    """Resolve, run and record one catalogued action."""
    assessment = await session.get(Assessment, assessment_id)
    if assessment is None:
        raise LookupError(f"assessment {assessment_id} not found")

    spec = get_action(action)
    target = target or assessment.targets[0]
    check_scope(assessment, target)
    timeout = timeout or settings.scan_timeout

    if step is None:
        step = Step(
            assessment_id=assessment_id,
            seq=await _next_seq(session, assessment_id),
            action=action,
            target=target,
            rationale=rationale,
        )
        session.add(step)
        await session.commit()
        await session.refresh(step)
    else:
        step.rationale = rationale or step.rationale
        step.target = target
        step.status = StepStatus.RUNNING.value
        step.error = None

    # If the tool supplied argv (agent-owned command), use it exactly as
    # approved. Only resolve from the closed catalogue when no argv was
    # stored (e.g. legacy recon_services without custom flags).
    if not step.argv:
        # Recover params from the approval detail if available.
        params: dict[str, Any] | None = None
        result = await session.execute(
            select(Approval).where(
                Approval.assessment_id == assessment_id,
                Approval.step_id == step.id,
            ).order_by(Approval.id.desc())
        )
        approval = result.scalars().first()
        if approval and approval.detail:
            params = approval.detail.get("params")
        step.argv = resolve_argv(action, assessment, target, step.id or 0, params=params)
    step.status = StepStatus.RUNNING.value
    await session.commit()
    await session.refresh(step)

    transport = (
        "mcp"
        if (
            action != "curl_tool"
            and settings.mcp_enabled
            and settings.mcp_transport == "gateway"
        )
        else spec.transport
    )
    alias = transport_target(target) if transport == "mcp" else target
    if alias != target:
        _audit(
            session,
            assessment_id,
            "target.translated",
            {"scope_target": target, "transport_target": alias},
        )

    _audit(
        session,
        assessment_id,
        "step.started",
        {
            "step_id": step.id,
            "action": action,
            "tool": spec.tool,
            "transport": transport,
            "target": target,
            "argv": step.argv,
        },
    )
    await session.commit()

    artifact = _artifact_dir(assessment_id) / f"{step.id}{spec.suffix}"
    try:
        if action == "curl_tool":
            text = await _run_curl(step, assessment)
            step.exit_code = 0
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_text(text, encoding="utf-8")
            step.output_path = str(artifact)
            step.output_sha256 = hashlib.sha256(artifact.read_bytes()).hexdigest()
        elif settings.mcp_enabled and settings.mcp_transport == "gateway":
            result = await _run_gateway(action, assessment, target, step)
            text = result.text
            step.exit_code = 0
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_text(text, encoding="utf-8")
            step.output_path = str(artifact)
            step.output_sha256 = hashlib.sha256(
                artifact.read_bytes()
            ).hexdigest()
            for call in result.calls:
                _audit(
                    session,
                    assessment_id,
                    "mcp.call",
                    {
                        "step_id": step.id,
                        "action": action,
                        "tool": call["tool"],
                        "arguments": call["arguments"],
                    },
                )
            await session.commit()
        else:
            process = await _run(step.argv, timeout, assessment_id=assessment_id)

            if process.returncode not in spec.ok_codes:
                detail = (process.stderr or process.stdout).strip()[-500:]
                raise RuntimeError(detail or f"{spec.tool} exited {process.returncode}")

            if spec.output == "file":
                if not artifact.exists():
                    detail = (process.stderr or process.stdout).strip()[-500:]
                    raise RuntimeError(detail or f"{spec.tool} produced no report")
                text = artifact.read_text(encoding="utf-8", errors="replace")
            else:
                text = process.stdout
                artifact.parent.mkdir(parents=True, exist_ok=True)
                artifact.write_text(text, encoding="utf-8")

            step.exit_code = process.returncode
            step.output_path = str(artifact)
            step.output_sha256 = hashlib.sha256(artifact.read_bytes()).hexdigest()

        drafts = spec.parse(text, target, _web_port(assessment))
        added, merged = await _save_findings(session, assessment_id, step, drafts)
        step.status = StepStatus.SUCCEEDED.value
        _audit(
            session,
            assessment_id,
            "step.succeeded",
            {
                "step_id": step.id,
                "action": action,
                "tool": spec.tool,
                "transport": transport,
                "findings_added": added,
                "findings_merged": merged,
            },
        )
    except FileNotFoundError:
        step.status = StepStatus.BLOCKED.value
        step.error = f"{spec.tool} is not installed or not on PATH"
        _audit(
            session,
            assessment_id,
            "step.blocked",
            {"step_id": step.id, "tool": spec.tool, "error": step.error},
        )
    except (TimeoutError, subprocess.TimeoutExpired):
        step.status = StepStatus.TIMEOUT.value
        step.error = f"timed out after {timeout}s"
        _audit(
            session,
            assessment_id,
            "step.timeout",
            {"step_id": step.id, "tool": spec.tool},
        )
    except Exception as exc:  # noqa: BLE001 - a tool failure is recorded, not raised
        step.status = StepStatus.FAILED.value
        step.error = str(exc)[:500]
        _audit(
            session,
            assessment_id,
            "step.failed",
            {"step_id": step.id, "tool": spec.tool, "error": step.error},
        )

    step.ended_at = utcnow()
    await session.commit()
    await session.refresh(step)
    return step


async def _run_curl(step: Step, assessment: Assessment) -> str:
    """Execute a curl_tool step locally and produce the artifact JSON.

    The agent-generated argv carries the exact method/url/headers/body the
    human action gate approved.
    """
    from app.actions.probe import run_curl

    if len(step.argv) < 5:
        raise ValueError(f"curl_tool argv incomplete: {step.argv}")

    method = step.argv[1]
    url = step.argv[2]
    headers = json.loads(step.argv[3] or "{}")
    expected_status = int(step.argv[4])
    body = step.argv[5] if len(step.argv) > 5 else ""

    probe = await run_curl(
        method=method,
        url=url,
        headers=headers,
        body=body,
        expected_status=expected_status,
        timeout=15,
    )
    artifact_payload = {
        "curl_result": probe.model_dump(),
        "expected_status": expected_status,
        "step_id": step.id,
        "assessment_id": assessment.id,
    }
    return json.dumps(artifact_payload, indent=2)


async def _run_gateway(
    action: str,
    assessment: Assessment,
    target: str,
    step: Step,
) -> MCPResult:
    # The step stores the exact approved descriptor. Use it rather than
    # re-deriving the arguments, so the approved command is the one that runs.
    if len(step.argv) >= 3 and step.argv[0] == "mcp":
        tool = step.argv[1]
        try:
            arguments = json.loads(step.argv[2])
        except json.JSONDecodeError:
            tool, arguments = mcp_tool_call(action, assessment, target)
    else:
        tool, arguments = mcp_tool_call(action, assessment, target)
    calls: list[dict] = []

    async with GatewayClient() as gateway:
        if action == "zap_baseline":
            text, zap_calls = await run_zap_baseline(
                gateway,
                arguments["target_url"],
                idempotency_key=f"aipent:{assessment.id}:{step.id}",
            )
            calls.extend(zap_calls)
        else:
            text = await gateway.call(tool, arguments)
            calls.append({"tool": tool, "arguments": arguments})

    return MCPResult(text=text, calls=calls)
