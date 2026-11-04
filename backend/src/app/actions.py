"""Closed action catalogue and the single execution path.

The LLM never supplies argv. It names an action and a target; this module
resolves the fixed command, keeps the artifact, and persists evidence.
"""

import asyncio
import hashlib
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal

from sqlalchemy import func
from sqlmodel import Session, select

from app.adapters import nikto, nmap, zap
from app.adapters.base import FindingDraft
from app.config import settings
from app.correlate import canonical_key
from app.models import (
    Assessment,
    Audit,
    Evidence,
    Finding,
    Severity,
    Step,
    StepStatus,
    utcnow,
)

ARTIFACT_DIR = settings.artifacts_path

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class ScopeError(ValueError):
    """Target is not in the assessment's authorised scope."""


class UnknownAction(ValueError):
    """The plan named an action outside the closed catalogue."""


@dataclass(frozen=True)
class ActionSpec:
    name: str
    tool: str
    gate: Literal["plan", "action"]
    suffix: str
    output: Literal["stdout", "file"]
    transport: Literal["local", "docker", "mcp"]
    ok_codes: tuple[int, ...]
    build_argv: Callable[[Assessment, str, Path], list[str]]
    parse: Callable[[str, str, int], list[FindingDraft]]


def _web_port(assessment: Assessment) -> int:
    return (assessment.ports or [3000])[0]


def _artifact_dir(assessment_id: int) -> Path:
    directory = ARTIFACT_DIR / str(assessment_id)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _nmap_argv(assessment: Assessment, target: str, _output: Path) -> list[str]:
    return nmap.argv(target, assessment.ports or [3000])


def _nikto_argv(assessment: Assessment, target: str, output: Path) -> list[str]:
    return nikto.argv(target, _web_port(assessment), str(output))


def _zap_argv(assessment: Assessment, target: str, output: Path) -> list[str]:
    return zap.argv(
        target,
        _web_port(assessment),
        str(output),
        _artifact_dir(assessment.id or 0),
    )


ACTIONS: dict[str, ActionSpec] = {
    "recon_services": ActionSpec(
        name="recon_services",
        tool="nmap",
        gate="plan",
        suffix=".nmap.xml",
        output="stdout",
        transport="local",
        ok_codes=(0,),
        build_argv=_nmap_argv,
        parse=lambda text, _host, _port: nmap.scan(text),
    ),
    "nikto_scan": ActionSpec(
        name="nikto_scan",
        tool="nikto",
        gate="action",
        suffix=".nikto.json",
        output="file",
        transport="local",
        ok_codes=(0,),
        build_argv=_nikto_argv,
        parse=lambda text, host, port: nikto.scan(text, host, port),
    ),
    "zap_baseline": ActionSpec(
        name="zap_baseline",
        tool="zap",
        gate="plan",
        suffix=".zap.json",
        output="file",
        transport="docker",
        ok_codes=(0, 1, 2),  # baseline exits 1/2 when alerts are present
        build_argv=_zap_argv,
        parse=lambda text, host, port: zap.scan(text, host, port),
    ),
}


def get_action(name: str) -> ActionSpec:
    try:
        return ACTIONS[name]
    except KeyError as exc:
        raise UnknownAction(f"action {name!r} is not in the catalogue") from exc


def resolve_argv(action: str, assessment: Assessment, target: str, step_id: int) -> list[str]:
    spec = get_action(action)
    output = _artifact_dir(assessment.id or 0) / f"{step_id}{spec.suffix}"
    return spec.build_argv(assessment, target, output)


def check_scope(assessment: Assessment, target: str) -> None:
    if target in assessment.exclusions or target not in assessment.targets:
        raise ScopeError(f"{target} is not in scope for assessment {assessment.id}")


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

    step.argv = resolve_argv(action, assessment, target, step.id or 0)
    step.status = StepStatus.RUNNING.value
    session.commit()
    session.refresh(step)

    _audit(
        session,
        assessment_id,
        "step.started",
        {
            "step_id": step.id,
            "action": action,
            "tool": spec.tool,
            "transport": spec.transport,
            "target": target,
            "argv": step.argv,
        },
    )
    session.commit()

    artifact = _artifact_dir(assessment_id) / f"{step.id}{spec.suffix}"
    try:
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
                "transport": spec.transport,
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
