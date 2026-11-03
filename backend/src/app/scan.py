"""Run one action, keep the raw artifact, persist findings."""

import asyncio
import hashlib
import subprocess
from pathlib import Path

from sqlalchemy import func
from sqlmodel import Session, select

from app.adapters import nmap
from app.adapters.base import FindingDraft
from app.config import settings
from app.models import (
    Assessment,
    Audit,
    Evidence,
    Finding,
    Step,
    StepStatus,
    utcnow,
)

ARTIFACT_DIR = settings.artifacts_path


class ScopeError(ValueError):
    """Target is not in the assessment's authorised scope."""


def _check_scope(assessment: Assessment, target: str) -> None:
    if target not in assessment.targets:
        raise ScopeError(f"{target} is not in scope for assessment {assessment.id}")


def _next_seq(session: Session, assessment_id: int) -> int:
    current = session.exec(
        select(func.max(Step.seq)).where(Step.assessment_id == assessment_id)
    ).one()
    return (current or 0) + 1


def _audit(session: Session, assessment_id: int, event_type: str, payload: dict) -> None:
    session.add(Audit(assessment_id=assessment_id, event_type=event_type, payload=payload))


async def _run(argv: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    # Subprocess is blocking; keep it off the event loop.
    return await asyncio.to_thread(
        subprocess.run, argv, capture_output=True, text=True, timeout=timeout
    )


def _save_findings(
    session: Session, assessment_id: int, step: Step, drafts: list[FindingDraft]
) -> int:
    added = 0
    for draft in drafts:
        existing = session.exec(
            select(Finding).where(
                Finding.assessment_id == assessment_id,
                Finding.canonical_key == draft.canonical_key,
            )
        ).first()
        if existing is not None:
            existing.updated_at = utcnow()
            continue

        finding = Finding(
            assessment_id=assessment_id,
            canonical_key=draft.canonical_key,
            asset=draft.asset,
            endpoint=draft.endpoint,
            title=draft.title,
            description=draft.description,
            severity=draft.severity.value,
            confidence=draft.confidence,
            status=draft.status.value,
            origin=draft.origin.value,
        )
        session.add(finding)
        session.flush()
        for evidence in draft.evidence:
            session.add(
                Evidence(
                    finding_id=finding.id,
                    step_id=step.id,
                    locator=evidence.locator,
                    excerpt=evidence.excerpt,
                )
            )
        added += 1
    return added


async def run_scan(
    session: Session,
    assessment_id: int,
    target: str | None = None,
    timeout: int | None = None,
) -> Step:
    assessment = session.get(Assessment, assessment_id)
    if assessment is None:
        raise LookupError(f"assessment {assessment_id} not found")

    target = target or assessment.targets[0]
    _check_scope(assessment, target)
    ports = assessment.ports or [3000]
    timeout = timeout or settings.scan_timeout

    step = Step(
        assessment_id=assessment_id,
        seq=_next_seq(session, assessment_id),
        action="recon_services",
        argv=nmap.argv(target, ports),
        rationale=f"Manual nmap service scan of in-scope target {target}",
        status=StepStatus.RUNNING.value,
    )
    session.add(step)
    session.commit()
    session.refresh(step)
    _audit(session, assessment_id, "step.started", {"step_id": step.id, "argv": step.argv})
    session.commit()

    try:
        process = await _run(step.argv, timeout)
        step.exit_code = process.returncode
        step.output_sha256 = hashlib.sha256(process.stdout.encode()).hexdigest()

        artifact: Path = ARTIFACT_DIR / str(assessment_id) / f"{step.id}.nmap.xml"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text(process.stdout, encoding="utf-8")
        step.output_path = str(artifact)

        if process.returncode != 0:
            detail = (process.stderr or process.stdout).strip()[-400:]
            raise RuntimeError(detail or f"nmap exited {process.returncode}")

        added = _save_findings(session, assessment_id, step, nmap.scan(process.stdout))
        step.status = StepStatus.SUCCEEDED.value
        _audit(
            session,
            assessment_id,
            "step.succeeded",
            {"step_id": step.id, "findings_added": added},
        )
    except subprocess.TimeoutExpired:
        step.status = StepStatus.TIMEOUT.value
        step.error = f"timed out after {timeout}s"
        _audit(session, assessment_id, "step.timeout", {"step_id": step.id})
    except Exception as exc:  # noqa: BLE001 - step failure is recorded, not raised
        step.status = StepStatus.FAILED.value
        step.error = str(exc)[:500]
        _audit(
            session,
            assessment_id,
            "step.failed",
            {"step_id": step.id, "error": step.error},
        )

    step.ended_at = utcnow()
    session.commit()
    session.refresh(step)
    return step
