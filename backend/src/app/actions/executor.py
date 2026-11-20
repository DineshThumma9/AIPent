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
    is_local_exempt,
    mcp_tool_call,
    resolve_argv,
    transport_target,
)
from app.actions.evidence import link_step_evidence
from app.adapters.base import FindingDraft
from app.core.config import settings
from app.domain.models import (
    Assessment,
    Approval,
    Audit,
    Finding,
    Step,
    StepStatus,
    utcnow,
)
from app.integrations.mcp_client import GatewayClient
from app.integrations.zap_guided import run_zap_baseline
from app.persistence.finding_repo import FindingRepo


@dataclass
class MCPResult:
    text: str
    calls: list[dict]


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
    return await FindingRepo(session).save_drafts(assessment_id, step, drafts)


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

    if not step.argv:
        step.argv = resolve_argv(action, assessment, target, step.id or 0, params=params)
    step.status = StepStatus.RUNNING.value
    await session.commit()
    await session.refresh(step)

    transport = (
        "mcp"
        if (
            not is_local_exempt(action)
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
        if action == "curl_request":
            result = await _run_gateway(action, assessment, target, step)
            text = result.text
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_text(text, encoding="utf-8")
            step.output_path = str(artifact)
            step.output_sha256 = hashlib.sha256(artifact.read_bytes()).hexdigest()
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
            tool_error = _curl_tool_error(text)
            if tool_error:
                raise RuntimeError(tool_error)
            step.exit_code = 0
        elif transport == "mcp":
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
                    if spec.tool == "hashcat":
                        artifact.parent.mkdir(parents=True, exist_ok=True)
                        artifact.touch()
                    else:
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

        if step.output_path:
            is_web_action = action in ("curl_request", "zap_spider", "ffuf_scan", "nikto_scan")
            target_url = ""
            if action == "curl_request" and isinstance(params, dict):
                target_url = str(params.get("url") or "")
            elif isinstance(target, str):
                target_url = target
            try:
                from app.parsers import create_sidecar_manifest

                if is_web_action or any(
                    str(step.output_path).lower().endswith(ext)
                    for ext in (".html", ".htm", ".js", ".json")
                ):
                    await asyncio.to_thread(
                        create_sidecar_manifest, step.output_path, url=target_url
                    )
            except Exception:
                pass

        drafts = spec.parse(text, target, _web_port(assessment))
        added, merged = await _save_findings(session, assessment_id, step, drafts)

        if action == "curl_request" and params:
            try:
                linked_finding_id = int(params.get("finding_id") or 0)
            except (TypeError, ValueError):
                linked_finding_id = 0
            if linked_finding_id:
                finding = await FindingRepo(session).get(linked_finding_id)
                if finding is not None and finding.assessment_id == assessment_id:
                    await link_step_evidence(
                        session, step, linked_finding_id, text=text
                    )

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


def _curl_tool_error(text: str) -> str | None:
    """Return a curl transport error, or None when the request produced a response.

    HTTP status codes (including 4xx/5xx) are valid observations for the agent;
    only failures without a status code (DNS, connection, timeout) fail the step.
    """
    try:
        payload = json.loads(text)
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("batch"):
        results = payload.get("results") or []
        errors = [
            item.get("error")
            for item in results
            if isinstance(item, dict) and item.get("error")
        ]
        if results and len(errors) == len(results):
            return f"all batch requests failed: {errors[0]}"[:500]
        return None
    if payload.get("ok") is not False:
        return None
    if payload.get("code") is not None:
        return None
    return str(
        payload.get("message")
        or payload.get("error_details")
        or payload.get("error")
        or "curl_request failed"
    )[:500]


async def _run_curl_batch(requests: list[dict[str, Any]]) -> MCPResult:
    """Run up to 3 independent curl requests concurrently on one gateway session."""
    if not requests or len(requests) > 3:
        raise ValueError("curl_request batch must contain between 1 and 3 requests")

    async with GatewayClient() as gateway:
        outcomes = await asyncio.gather(
            *(gateway.call("curl_request", request) for request in requests),
            return_exceptions=True,
        )

    results: list[dict[str, Any]] = []
    calls: list[dict] = []
    for index, (request, outcome) in enumerate(zip(requests, outcomes)):
        calls.append({"tool": "curl_request", "arguments": request})
        entry: dict[str, Any] = {"index": index, "request": request}
        if isinstance(outcome, BaseException):
            entry["error"] = str(outcome)[:300]
        else:
            try:
                entry["result"] = json.loads(outcome)
            except (TypeError, json.JSONDecodeError):
                entry["result"] = {"raw": outcome}
        results.append(entry)

    return MCPResult(
        text=json.dumps({"batch": True, "results": results}, indent=2),
        calls=calls,
    )


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

    if tool == "curl_request" and isinstance(arguments, dict) and arguments.get("batch"):
        return await _run_curl_batch(arguments["batch"])

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
