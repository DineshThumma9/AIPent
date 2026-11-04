"""Typst report generation from the evidence of record.

The database is the only source. Findings, scores, approvals and artifact hashes
are copied into a JSON file; the Typst template reads it, so Python never
hand-escapes markup.
"""

import hashlib
import json
import shutil
from pathlib import Path

from sqlmodel import Session, col, select

import typst
from app import risk
from app.actions import ACTIONS, ARTIFACT_DIR
from app.log import get_logger
from app.models import Approval, Assessment, Audit, Evidence, Finding, Step

log = get_logger("report")

TEMPLATE = Path(__file__).resolve().parent / "templates" / "report.typ"


def _iso(value) -> str:
    return value.isoformat() if value else ""


def _counts(findings: list[Finding]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def build_report_data(session: Session, assessment: Assessment) -> dict:
    assessment_id = assessment.id or 0
    findings = session.exec(
        select(Finding)
        .where(Finding.assessment_id == assessment_id)
        .order_by(col(Finding.id))
    ).all()
    evidence = session.exec(
        select(Evidence)
        .join(Finding, Evidence.finding_id == Finding.id)
        .where(Finding.assessment_id == assessment_id)
        .order_by(Evidence.id)
    ).all()
    steps = session.exec(
        select(Step)
        .where(Step.assessment_id == assessment_id)
        .order_by(Step.seq)
    ).all()
    approvals = session.exec(
        select(Approval)
        .where(Approval.assessment_id == assessment_id)
        .order_by(col(Approval.id))
    ).all()

    scores = {finding.id: risk.finding_score(finding) for finding in findings}
    ordered = sorted(
        findings,
        key=lambda finding: scores[finding.id]["score"],
        reverse=True,
    )
    risk_summary = risk.summarize(findings)

    tools = {
        ACTIONS[step.action].tool
        for step in steps
        if step.action in ACTIONS and step.status == "succeeded"
    }

    finding_rows = []
    for finding in ordered:
        score = scores[finding.id]
        rows = [row for row in evidence if row.finding_id == finding.id]
        finding_rows.append(
            {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "score": score["score"],
                "confidence": round(finding.confidence, 2),
                "status": finding.status,
                "asset": finding.asset,
                "endpoint": finding.endpoint or "",
                "description": finding.description,
                "impact": finding.impact,
                "remediation": finding.remediation,
                "cve": finding.cve,
                "cwe": finding.cwe,
                "evidence": [
                    {
                        "tool": row.locator.get("tool", "nmap"),
                        "excerpt": row.excerpt[:500],
                        "locator": json.dumps(row.locator, sort_keys=True),
                    }
                    for row in rows
                ],
            }
        )

    return {
        "assessment": {
            "id": assessment_id,
            "title": assessment.title,
            "request": assessment.request or "(no additional request text)",
            "targets": assessment.targets,
            "ports": assessment.ports,
            "exclusions": assessment.exclusions,
            "status": assessment.status,
            "created_at": _iso(assessment.created_at),
            "finished_at": _iso(assessment.finished_at),
        },
        "risk": {
            "score": risk_summary["score"],
            "counts": _counts(findings),
            "confirmed": sum(1 for finding in findings if finding.status == "confirmed"),
        },
        "tool_count": len(tools),
        "findings": finding_rows,
        "steps": [
            {
                "seq": step.seq,
                "action": step.action,
                "target": step.target or (step.argv[-1] if step.argv else ""),
                "status": step.status,
                "exit_code": step.exit_code if step.exit_code is not None else "",
            }
            for step in steps
        ],
        "artifacts": [
            {
                "seq": step.seq,
                "path": step.output_path or "",
                "sha": step.output_sha256 or "",
                "target": step.target or "",
            }
            for step in steps
            if step.output_path
        ],
        "approvals": [
            {
                "action": approval.action.replace("_", " "),
                "decision": approval.decision,
                "actor": approval.actor or "",
                "reason": approval.reason or "",
            }
            for approval in approvals
        ],
    }


def generate_report(session: Session, assessment_id: int) -> Path:
    assessment = session.get(Assessment, assessment_id)
    if assessment is None:
        raise LookupError(f"assessment {assessment_id} not found")

    directory = ARTIFACT_DIR / str(assessment_id)
    directory.mkdir(parents=True, exist_ok=True)
    data_path = directory / "report-data.json"
    typ_path = directory / f"report-{assessment_id}.typ"
    pdf_path = directory / f"report-{assessment_id}.pdf"

    data_path.write_text(
        json.dumps(build_report_data(session, assessment), indent=2),
        encoding="utf-8",
    )
    shutil.copyfile(TEMPLATE, typ_path)

    final = typ_path
    try:
        typst.compile(str(typ_path), output=str(pdf_path), root=str(directory))
        final = pdf_path
    except Exception:  # noqa: BLE001 - keep the source even if PDF fails
        log.exception("Typst compilation failed assessment=%s", assessment_id)
        session.add(
            Audit(
                assessment_id=assessment_id,
                event_type="report.compile_failed",
                payload={"source": str(typ_path)},
            )
        )

    digest = hashlib.sha256(final.read_bytes()).hexdigest()
    assessment.report_path = str(final)
    assessment.report_sha256 = digest
    session.add(
        Audit(
            assessment_id=assessment_id,
            event_type="report.generated",
            payload={"path": str(final), "sha256": digest},
        )
    )
    session.commit()
    return final
