"""Single execution path for catalogued actions.

Resolve the argv, run the tool (or the in-process HTTP probe), keep the
artifact and persist evidence. A tool failure is recorded on the Step, never
raised into the graph.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import func
from sqlmodel import Session, select

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
    Audit,
    Evidence,
    Finding,
    Severity,
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


def _next_seq(session: Session, assessment_id: int) -> int:
    current = session.exec(
        select(func.max(Step.seq)).where(Step.assessment_id == assessment_id)
    ).one()
    return (current or 0) + 1


def _audit(session: Session, assessment_id: int, event_type: str, payload: dict) -> None:
    session.add(Audit(assessment_id=assessment_id, event_type=event_type, payload=payload))


def _save_findings(
    session: Session, assessment_id: int, step: Step, drafts: list[FindingDraft]
) -> tuple[int, int]:
    added = 0
    merged = 0
    for draft in drafts:
        key = canonical_key(draft)
        existing = session.exec(
            select(Finding).where(
                Finding.assessment_id == assessment_id,
                Finding.canonical_key == key,
            )
        ).first()

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
            session.flush()
            target_finding = finding
            added += 1
        else:
            target_finding = existing
            target_finding.updated_at = utcnow()
            target_finding.confidence = max(existing.confidence, draft.confidence)
            if SEVERITY_RANK.get(draft.severity.value, 9) < SEVERITY_RANK.get(
                existing.severity, 9
            ):
                target_finding.severity = draft.severity.value
            if not existing.description:
                target_finding.description = draft.description
            if not existing.remediation:
                target_finding.remediation = draft.remediation
            if draft.cve:
                target_finding.cve = sorted(set(existing.cve) | set(draft.cve))
            if draft.cwe:
                target_finding.cwe = sorted(set(existing.cwe) | set(draft.cwe))
            if draft.status.value == "confirmed" and existing.status != "confirmed":
                target_finding.status = "confirmed"
            merged += 1

        current_evidence = session.exec(
            select(Evidence).where(Evidence.finding_id == target_finding.id)
        ).all()
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


async def _run(argv: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return await asyncio.to_thread(
        subprocess.run, argv, capture_output=True, text=True, timeout=timeout
    )


async def execute_action(
    session: Session,
    assessment_id: int,
    action: str,
    target: str | None = None,
    rationale: str = "",
    timeout: int | None = None,
    step: Step | None = None,
) -> Step:
    """Resolve, run and record one catalogued action."""
    assessment = session.get(Assessment, assessment_id)
    if assessment is None:
        raise LookupError(f"assessment {assessment_id} not found")

    spec = get_action(action)
    target = target or assessment.targets[0]
    check_scope(assessment, target)
    timeout = timeout or settings.scan_timeout

    if step is None:
        step = Step(
            assessment_id=assessment_id,
            seq=_next_seq(session, assessment_id),
            action=action,
            target=target,
            rationale=rationale,
        )
        session.add(step)
        session.commit()
        session.refresh(step)
    else:
        step.rationale = rationale or step.rationale
        step.target = target
        step.status = StepStatus.RUNNING.value
        step.error = None

    # If the tool supplied argv (agent-owned command), use it exactly as
    # approved. Only resolve from the closed catalogue when no argv was
    # stored (e.g. legacy recon_services without custom flags).
    if not step.argv:
        step.argv = resolve_argv(action, assessment, target, step.id or 0)
    step.status = StepStatus.RUNNING.value
    session.commit()
    session.refresh(step)

    transport = (
        "mcp"
        if settings.mcp_enabled and settings.mcp_transport == "gateway"
        else spec.transport
    )
    alias = transport_target(target)
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
    session.commit()

    artifact = _artifact_dir(assessment_id) / f"{step.id}{spec.suffix}"
    try:
        if action == "http_probe":
            text = await _run_http_probe(step, assessment)
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
            session.commit()
        else:
            process = await _run(step.argv, timeout)

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
        added, merged = _save_findings(session, assessment_id, step, drafts)
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
    except subprocess.TimeoutExpired:
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
    session.commit()
    session.refresh(step)
    return step


def completed_actions(session: Session, assessment_id: int) -> set[tuple[str, str]]:
    """Actions already succeeded, keyed by (action, target)."""
    rows = session.exec(
        select(Step).where(
            Step.assessment_id == assessment_id,
            Step.status == StepStatus.SUCCEEDED.value,
        )
    ).all()
    return {
        (row.action, row.target or row.argv[-1])
        for row in rows
        if row.action in ACTIONS and (row.target or row.argv)
    }


async def _run_http_probe(step: Step, assessment: Assessment) -> str:
    """Execute an http_probe step locally and produce the artifact JSON.

    The agent-generated argv carries the exact method/url/headers/body the
    human action gate approved.
    """
    from app.actions.probe import run_probe

    if len(step.argv) < 5:
        raise ValueError(f"http_probe argv incomplete: {step.argv}")

    method = step.argv[1]
    url = step.argv[2]
    headers = json.loads(step.argv[3] or "{}")
    expected_status = int(step.argv[4])
    body = step.argv[5] if len(step.argv) > 5 else ""

    probe = await run_probe(
        method=method,
        url=url,
        headers=headers,
        body=body,
        expected_status=expected_status,
        timeout=15,
    )
    artifact_payload = {
        "probe_result": probe.model_dump(),
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
