"""Typst report generation from the evidence of record.

The database is the only source. Findings, scores, approvals and artifact hashes
are copied into a JSON file; the Typst template reads it, so Python never
hand-escapes markup.
"""

import asyncio
import hashlib
import json
import re
import shutil
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import col, select

import typst
from app.domain import risk
from app.actions import ACTIONS, ARTIFACT_DIR
from app.core.log import get_logger
from app.domain.models import Approval, Assessment, Audit, Evidence, Finding, FindingCve, Step
from app.reporting.common import (
    clean_endpoint as _clean_endpoint,
    clean_finding_title as _clean_finding_title,
    clean_text as _clean_text,
    count_severities as _counts,
    format_human_timestamp,
    iso_timestamp as _iso,
    parse_methodology_blocks,
)
from app.reporting.narrative import ReportNarrative

log = get_logger("report")

TEMPLATE = Path(__file__).resolve().parent / "templates" / "report.typ"


ACTION_TITLES = {
    "recon_services": "Port & Service Scan (Nmap)",
    "whatweb": "Technology Fingerprinting (WhatWeb)",
    "dirb_scan": "Directory Enumeration (Dirb)",
    "nikto_scan": "Web Server Scan (Nikto)",
    "zap_baseline": "Baseline Web Audit (ZAP)",
    "curl_tool": "HTTP Verification Probe (curl)",
    "curl_request": "HTTP Verification Probe (curl-mcp)",
    "sqlmap_scan": "SQL Injection Test (Sqlmap)",
    "hashcat_crack": "Offline Hash Analysis (Hashcat)",
    "sslscan": "TLS/SSL Configuration Scan",
}


async def build_report_data(
    session: AsyncSession,
    assessment: Assessment,
    narrative: ReportNarrative | None = None,
) -> dict:
    assessment_id = assessment.id or 0
    result = await session.execute(
        select(Finding)
        .where(Finding.assessment_id == assessment_id)
        .order_by(col(Finding.id))
    )
    findings = list(result.scalars().all())

    result = await session.execute(
        select(Evidence)
        .join(Finding, Evidence.finding_id == Finding.id)
        .where(Finding.assessment_id == assessment_id)
        .order_by(Evidence.id)
    )
    evidence = list(result.scalars().all())

    result = await session.execute(
        select(Step)
        .where(Step.assessment_id == assessment_id)
        .order_by(Step.seq)
    )
    steps = list(result.scalars().all())

    result = await session.execute(
        select(Approval)
        .where(Approval.assessment_id == assessment_id)
        .order_by(col(Approval.id))
    )
    approvals = list(result.scalars().all())

    result = await session.execute(
        select(FindingCve)
        .join(Finding, FindingCve.finding_id == Finding.id)
        .where(Finding.assessment_id == assessment_id)
    )
    finding_cves = list(result.scalars().all())
    cves_by_finding: dict[int, list[FindingCve]] = {}
    for fc in finding_cves:
        cves_by_finding.setdefault(fc.finding_id, []).append(fc)

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
    executed_steps = [
        step for step in steps if step.status in ("succeeded", "failed", "timeout")
    ]
    mcp_steps = [
        step for step in executed_steps if step.argv and step.argv[0] == "mcp"
    ]

    by_id = {item.finding_id: item for item in (narrative.findings if narrative else [])}
    finding_rows = []
    for finding in ordered:
        score = scores[finding.id]
        rows = [row for row in evidence if row.finding_id == finding.id]
        clean_title = _clean_finding_title(finding.title)
        item = by_id.get(finding.id)
        fc_rows = cves_by_finding.get(finding.id, [])
        corroborating = sorted(
            list(
                {
                    (row.locator.get("tool") if isinstance(row.locator, dict) else None) or "nmap"
                    for row in rows
                }
            )
        )
        finding_rows.append(
            {
                "id": finding.id,
                "title": clean_title,
                "severity": finding.severity,
                "cvss": finding.cvss,
                "score": score["score"],
                "confidence": round(finding.confidence, 2),
                "status": finding.status,
                "asset": _clean_endpoint(finding.asset),
                "endpoint": _clean_endpoint(finding.endpoint),
                "description": _clean_text(finding.description),
                "impact": _clean_text(finding.impact),
                "remediation": _clean_text(finding.remediation),
                "cve": finding.cve,
                "cwe": finding.cwe,
                "corroborating_tools": corroborating,
                "finding_cves": [
                    {
                        "cve_id": fc.cve_id,
                        "source": fc.source,
                        "source_url": fc.source_url,
                        "catalog_release": fc.catalog_release,
                        "match_reason": fc.match_reason,
                        "confidence": fc.confidence,
                    }
                    for fc in fc_rows
                ],
                "narrative": item.model_dump() if item else None,
                "evidence": [
                    {
                        "tool": (row.locator.get("tool") if isinstance(row.locator, dict) else "nmap") or "nmap",
                        "excerpt": _clean_text(row.excerpt[:500]),
                        "locator": json.dumps(row.locator, sort_keys=True) if isinstance(row.locator, dict) else str(row.locator),
                    }
                    for row in rows
                ],
            }
        )

    from app.intel.cve import cve_snapshot_label
    cve_snapshot = cve_snapshot_label()

    narrative_dict = (
        narrative.model_dump()
        if narrative
        else {
            "executive_summary": "",
            "methodology": "",
            "risk_overview": "",
            "findings": [],
            "limitations": "",
            "recommendations": [],
            "conclusion": "",
        }
    )
    narrative_dict["methodology_blocks"] = parse_methodology_blocks(narrative_dict.get("methodology"))

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
            "created_at_human": format_human_timestamp(assessment.created_at),
            "finished_at_human": format_human_timestamp(assessment.finished_at),
        },
        "risk": {
            "score": risk_summary["score"],
            "counts": _counts(findings),
            "confirmed": sum(1 for finding in findings if finding.status == "confirmed"),
        },
        "tool_count": len(tools),
        "mcp": bool(mcp_steps),
        "mcp_only": bool(executed_steps) and len(mcp_steps) == len(executed_steps),
        "cve_snapshot": cve_snapshot,
        "findings": finding_rows,
        "steps": [
            {
                "seq": step.seq,
                "action": step.action,
                "target": step.target or (step.argv[-1] if step.argv else ""),
                "status": step.status,
                "exit_code": step.exit_code if step.exit_code is not None else "",
                "error": step.error or "",
            }
            for step in steps
        ],
        "artifacts": [
            {
                "seq": step.seq,
                "action": step.action,
                "action_title": ACTION_TITLES.get(step.action, step.action.replace("_", " ").title()),
                "path": Path(step.output_path).name if step.output_path else "",
                "full_path": step.output_path or "",
                "sha": step.output_sha256 or "",
                "target": _clean_endpoint(step.target) if step.target else "",
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
        "narrative": narrative_dict,
        "narrative_source": "llm" if narrative else "evidence-only",
    }


async def generate_report(
    session: AsyncSession,
    assessment_id: int,
    narrative: ReportNarrative | dict | None = None,
) -> Path:
    assessment = await session.get(Assessment, assessment_id)
    if assessment is None:
        raise LookupError(f"assessment {assessment_id} not found")

    from app.domain.models import AssessmentStatus, utcnow

    # When generating final report, ensure finished_at is stamped and in-progress statuses finalized
    if assessment.finished_at is None:
        assessment.finished_at = utcnow()
    if assessment.status in (
        AssessmentStatus.RUNNING.value,
        AssessmentStatus.REPORTING.value,
        AssessmentStatus.PLANNING.value,
        AssessmentStatus.AWAITING_APPROVAL.value,
    ):
        assessment.status = AssessmentStatus.COMPLETED.value
    await session.commit()
    await session.refresh(assessment)

    if isinstance(narrative, dict):
        try:
            narrative = ReportNarrative.model_validate(narrative)
        except Exception as exc:
            log.warning("failed to parse narrative dict; falling back: %s", exc)
            narrative = None

    directory = ARTIFACT_DIR / str(assessment_id)
    directory.mkdir(parents=True, exist_ok=True)
    data_path = directory / "report-data.json"
    narrative_path = directory / "report-narrative.json"
    typ_path = directory / f"report-{assessment_id}.typ"
    pdf_path = directory / f"report-{assessment_id}.pdf"

    if narrative:
        narrative_path.write_text(
            json.dumps(narrative.model_dump(), indent=2),
            encoding="utf-8",
        )

    data = await build_report_data(session, assessment, narrative=narrative)
    data_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    shutil.copyfile(TEMPLATE, typ_path)

    final = typ_path
    try:
        await asyncio.to_thread(
            typst.compile, str(typ_path), output=str(pdf_path), root=str(directory)
        )
        final = pdf_path
    except Exception as exc:
        log.warning("Typst compilation failed assessment=%s error=%s", assessment_id, exc)
        # Fallback to evidence-only if compilation failed with LLM narrative
        if narrative is not None:
            try:
                log.info("Attempting fallback Typst compilation with narrative=None")
                fallback_data = await build_report_data(session, assessment, narrative=None)
                data_path.write_text(json.dumps(fallback_data, indent=2), encoding="utf-8")
                await asyncio.to_thread(
                    typst.compile, str(typ_path), output=str(pdf_path), root=str(directory)
                )
                final = pdf_path
            except Exception:
                log.exception("Typst fallback compilation also failed assessment=%s", assessment_id)
                session.add(
                    Audit(
                        assessment_id=assessment_id,
                        event_type="report.compile_failed",
                        payload={"source": str(typ_path)},
                    )
                )
        else:
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
    await session.commit()
    return final
