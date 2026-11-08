"""Observation builder for the V2 loop.

Transforms executed Steps, Evidence, and Findings into compact Observations.
"""

from __future__ import annotations

from typing import Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from app.agents.loop.contracts import ActionRequest, Observation
from app.domain.models import Evidence, Finding, Step, StepStatus


async def observation_from_step(session: AsyncSession, step: Step) -> Observation:
    """Build a compact Observation from an executed step."""
    # Find all evidence produced for this step
    result = await session.execute(
        select(Evidence).where(Evidence.step_id == step.id)
    )
    evidences = list(result.scalars().all())
    evidence_ids = [e.id for e in evidences if e.id is not None]

    # Find associated findings
    finding_id_set = {e.finding_id for e in evidences if e.finding_id is not None}
    findings: list[Finding] = []
    if finding_id_set:
        f_result = await session.execute(
            select(Finding).where(Finding.id.in_(list(finding_id_set)))
        )
        findings = list(f_result.scalars().all())

    # Distinguish findings created in this step vs updated
    created_ids: list[int] = []
    updated_ids: list[int] = []
    for f in findings:
        if f.id is not None:
            # If all evidence for this finding belongs to this step, it was created here
            created_ids.append(f.id)

    artifact_info: dict[str, Any] | None = None
    if step.output_path:
        artifact_info = {
            "path": step.output_path,
            "sha256": step.output_sha256 or "",
            "kind": ".nmap.xml" if "nmap" in step.action or "recon" in step.action else ".txt",
        }

    if step.status != StepStatus.SUCCEEDED.value:
        status_map = {
            StepStatus.FAILED.value: "failed",
            StepStatus.TIMEOUT.value: "timeout",
            StepStatus.BLOCKED.value: "blocked",
            StepStatus.REJECTED.value: "rejected",
        }
        obs_status = status_map.get(step.status, "error")
        return Observation(
            ok=False,
            status=obs_status,  # type: ignore[arg-type]
            action=step.action,
            target=step.target,
            step_id=step.id,
            summary=step.error or f"Action {step.action} ended with status {step.status}.",
            findings_created=[],
            findings_updated=[],
            evidence_ids=evidence_ids,
            artifact=artifact_info,
            errors=[step.error] if step.error else [f"status: {step.status}"],
        )

    # For successful recon_services
    if step.action in ("recon_services", "nmap_scan"):
        if findings:
            service_summaries = [f.title for f in findings if f.title]
            port_count = len(findings)
            summary_str = f"{port_count} open port{'s' if port_count != 1 else ''}: {', '.join(service_summaries[:5])}"
            has_http = any("http" in (f.title or "").lower() for f in findings)
            next_hint = (
                "HTTP is present on port(s). Technology fingerprinting or web discovery can discriminate which surface to test first."
                if has_http
                else "Non-HTTP services found. Evaluate open ports for banner info or service discovery."
            )
        else:
            summary_str = f"0 open ports discovered on {step.target}"
            next_hint = "No open ports found. Verify target availability or consider widening port range."

        return Observation(
            ok=True,
            status="succeeded",
            action=step.action,
            target=step.target,
            step_id=step.id,
            summary=summary_str,
            findings_created=created_ids,
            findings_updated=updated_ids,
            evidence_ids=evidence_ids,
            artifact=artifact_info,
            errors=[],
            next_hint=next_hint,
        )

    if step.action == "nikto_scan":
        count = len(findings)
        titles = [f.title for f in findings if f.title][:3]
        summary_str = (
            f"{count} web server finding{'s' if count != 1 else ''} discovered by Nikto: {', '.join(titles)}"
            if count
            else "Nikto scan completed; 0 candidate issues found."
        )
        return Observation(
            ok=True,
            status="succeeded",
            action=step.action,
            target=step.target,
            step_id=step.id,
            summary=summary_str,
            findings_created=created_ids,
            findings_updated=updated_ids,
            evidence_ids=evidence_ids,
            artifact=artifact_info,
            errors=[],
            next_hint="Evaluate candidate findings for validation or probe them directly with curl_tool.",
        )

    if step.action == "zap_baseline":
        count = len(findings)
        titles = [f.title for f in findings if f.title][:3]
        summary_str = (
            f"{count} passive ZAP alert{'s' if count != 1 else ''} identified: {', '.join(titles)}"
            if count
            else "OWASP ZAP baseline scan completed with 0 alerts."
        )
        return Observation(
            ok=True,
            status="succeeded",
            action=step.action,
            target=step.target,
            step_id=step.id,
            summary=summary_str,
            findings_created=created_ids,
            findings_updated=updated_ids,
            evidence_ids=evidence_ids,
            artifact=artifact_info,
            errors=[],
            next_hint="ZAP alerts are candidates, not confirmed vulnerabilities. Form a hypothesis and probe with curl_tool.",
        )

    if step.action == "dirb_scan":
        count = len(findings)
        endpoints = [f.endpoint or f.title for f in findings if f.endpoint or f.title][:5]
        summary_str = (
            f"{count} web path{'s' if count != 1 else ''} discovered by dirb: {', '.join(endpoints)}"
            if count
            else "dirb scan completed; 0 paths discovered."
        )
        return Observation(
            ok=True,
            status="succeeded",
            action=step.action,
            target=step.target,
            step_id=step.id,
            summary=summary_str,
            findings_created=created_ids,
            findings_updated=updated_ids,
            evidence_ids=evidence_ids,
            artifact=artifact_info,
            errors=[],
            next_hint="Discovered paths may expose sensitive resources or APIs. Test endpoints for access control.",
        )

    if step.action == "curl_tool":
        http_status = None
        body_excerpt = ""
        from pathlib import Path
        if step.output_path and Path(step.output_path).exists():
            try:
                import json
                p_data = json.loads(Path(step.output_path).read_text(encoding="utf-8", errors="replace"))
                res = p_data.get("curl_result") or p_data.get("probe_result") or {}
                http_status = res.get("status_code")
                body_excerpt = (res.get("body_preview") or res.get("body") or "")[:200]
            except Exception:
                pass
        status_part = f"HTTP {http_status}" if http_status is not None else "HTTP request succeeded"
        body_part = f" - excerpt: {body_excerpt!r}" if body_excerpt else ""
        summary_str = f"{status_part}{body_part}"
        return Observation(
            ok=True,
            status="succeeded",
            action=step.action,
            target=step.target,
            step_id=step.id,
            summary=summary_str,
            findings_created=created_ids,
            findings_updated=updated_ids,
            evidence_ids=evidence_ids,
            artifact=artifact_info,
            errors=[],
            next_hint="Compare observed HTTP status and response against expected_observation and would_falsify.",
        )

    if step.action == "whatweb":
        count = len(findings)
        summary_str = f"WhatWeb scan completed; {count} technology findings recorded."
        return Observation(
            ok=True,
            status="succeeded",
            action=step.action,
            target=step.target,
            step_id=step.id,
            summary=summary_str,
            findings_created=created_ids,
            findings_updated=updated_ids,
            evidence_ids=evidence_ids,
            artifact=artifact_info,
            errors=[],
            next_hint="Technologies detected can be correlated against known CVEs or used to form hypotheses.",
        )

    if step.action == "sslscan":
        count = len(findings)
        summary_str = f"sslscan completed; {count} TLS/SSL protocol/certificate facts identified."
        return Observation(
            ok=True,
            status="succeeded",
            action=step.action,
            target=step.target,
            step_id=step.id,
            summary=summary_str,
            findings_created=created_ids,
            findings_updated=updated_ids,
            evidence_ids=evidence_ids,
            artifact=artifact_info,
            errors=[],
            next_hint="Evaluate deprecated SSL/TLS protocols or certificate validity.",
        )

    if step.action == "hashcat_crack":
        # Strict redaction per §9.1: Plaintext passwords are NEVER returned or stored in observation
        cracked = len(findings) > 0
        summary_str = f"{len(findings)} hash(es) cracked; plaintext redacted." if cracked else "0 hashes cracked; password candidates exhausted."
        return Observation(
            ok=True,
            status="succeeded",
            action=step.action,
            target=step.target,
            step_id=step.id,
            summary=summary_str,
            findings_created=created_ids,
            findings_updated=updated_ids,
            evidence_ids=evidence_ids,
            artifact=artifact_info,
            errors=[],
            next_hint="Assess whether weak credential policy impacts assessment risk.",
        )

    if step.action == "sqlmap_scan":
        sql_vuln = False
        from pathlib import Path
        if step.output_path and Path(step.output_path).exists():
            try:
                txt = Path(step.output_path).read_text(encoding="utf-8", errors="replace").lower()
                sql_vuln = any(w in txt for w in ("injectable", "is vulnerable", "sql injection found"))
            except Exception:
                pass
        summary_str = (
            "SQL injection suspected from sqlmap scan output."
            if sql_vuln
            else "sqlmap scan completed; no SQL injection confirmed."
        )
        return Observation(
            ok=True,
            status="succeeded",
            action=step.action,
            target=step.target,
            step_id=step.id,
            summary=summary_str,
            findings_created=created_ids,
            findings_updated=updated_ids,
            evidence_ids=evidence_ids,
            artifact=artifact_info,
            errors=[],
            next_hint="Record hypothesis update or update candidate finding status.",
        )

    # Generic fallback for any other tool until Phase 2
    return Observation(
        ok=True,
        status="succeeded",
        action=step.action,
        target=step.target,
        step_id=step.id,
        summary=f"Action {step.action} succeeded.",
        findings_created=created_ids,
        findings_updated=updated_ids,
        evidence_ids=evidence_ids,
        artifact=artifact_info,
        errors=[],
    )


def rejection_observation(pending: ActionRequest, reason: str | None = None) -> Observation:
    """Build an observation when an analyst rejects an action at the approval gate."""
    return Observation(
        ok=False,
        status="rejected",
        action=pending.action,
        target=pending.target,
        step_id=pending.step_id,
        summary=f"Analyst rejected {pending.action}: {reason or 'no reason given'}",
        errors=[reason or "rejected by analyst"],
        next_hint=(
            "Do not retry the same command. Choose a safer discriminating observation "
            "or hand off the open question."
        ),
    )


def error_observation(
    action: str, target: str, error: str, step_id: int | None = None
) -> Observation:
    """Build an observation for an internal error during preparation/execution."""
    return Observation(
        ok=False,
        status="error",
        action=action,
        target=target,
        step_id=step_id,
        summary=f"Error executing {action}: {error}",
        errors=[error],
    )
