"""Observation builder for the V2 loop.

Transforms executed Steps, Evidence, and Findings into compact Observations.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from app.actions.evidence import SQLMAP_PROOF
from app.agents.loop.contracts import ActionRequest, Observation
from app.domain.models import Evidence, Finding, Step, StepStatus


def _curl_batch_facts(entry: dict[str, Any]) -> dict[str, Any]:
    """Normalize one result from a batched curl artifact."""
    request = entry.get("request") if isinstance(entry.get("request"), dict) else {}
    result = entry.get("result") if isinstance(entry.get("result"), dict) else {}
    result_request = (
        result.get("request") if isinstance(result.get("request"), dict) else {}
    )
    response = (
        result.get("response") if isinstance(result.get("response"), dict) else {}
    )

    raw_status = response.get("status_code") or result.get("code")
    try:
        status = int(raw_status) if raw_status is not None else None
    except (TypeError, ValueError):
        status = None

    body = response.get("body") or result.get("body") or ""
    excerpt = ""
    json_items: int | None = None
    if isinstance(body, str):
        cleaned = re.sub(
            r"<style[^>]*>[\s\S]*?</style>", "", body, flags=re.IGNORECASE
        )
        excerpt = cleaned[:300]
    elif body:
        excerpt = str(body)[:300]
    try:
        parsed_body = json.loads(body) if isinstance(body, str) else body
        rows = parsed_body.get("data") if isinstance(parsed_body, dict) else None
        if isinstance(rows, list):
            json_items = len(rows)
    except (TypeError, ValueError):
        json_items = None

    error = entry.get("error") or result.get("error_details") or result.get("error")
    if error is None and result.get("ok") is False and status is None:
        error = result.get("message") or "request failed"

    return {
        "index": entry.get("index"),
        "url": str(result_request.get("url") or request.get("url") or ""),
        "method": str(
            result_request.get("method") or request.get("method") or "GET"
        ).upper(),
        "status_code": status,
        "json_items": json_items,
        "body_excerpt": excerpt,
        "error": str(error)[:300] if error else None,
    }


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
            next_hint="Evaluate candidate findings for validation or probe them directly with curl_request.",
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
            next_hint="ZAP alerts are candidates, not confirmed vulnerabilities. Form a hypothesis and probe with curl_request.",
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

    if step.action == "curl_request":
        p_data: dict[str, Any] = {}
        if step.output_path and Path(step.output_path).exists():
            try:
                loaded = json.loads(
                    Path(step.output_path).read_text(
                        encoding="utf-8", errors="replace"
                    )
                )
                if isinstance(loaded, dict):
                    p_data = loaded
            except Exception:
                p_data = {}

        if p_data.get("batch"):
            results = [
                _curl_batch_facts(entry)
                for entry in (p_data.get("results") or [])
                if isinstance(entry, dict)
            ]
            parts: list[str] = []
            for item in results:
                label = f"#{item['index']}" if item.get("index") is not None else "#"
                if item.get("error"):
                    parts.append(
                        f"{label} {item['method']} {item['url']} -> error: {item['error']}"
                    )
                else:
                    part = (
                        f"{label} {item['method']} {item['url']} "
                        f"-> HTTP {item.get('status_code')}"
                    )
                    if item.get("json_items") is not None:
                        part += f" ({item['json_items']} items)"
                    parts.append(part)
            summary_str = (
                f"{len(results)} probes: " + "; ".join(parts)
                if results
                else "Curl batch produced no results."
            )
            statuses = [
                item["status_code"]
                for item in results
                if item.get("status_code") is not None
            ]
            if any(item.get("error") for item in results):
                next_hint = "Some batched requests failed at the transport level. Retry those individually; do not repeat the whole batch."
            elif any(status >= 500 for status in statuses):
                next_hint = "A batched request returned 5xx. Inspect that result's artifact entry before retrying."
            elif any(status in (401, 403) for status in statuses):
                next_hint = "One or more batched requests require authentication. Do not retry the batch blindly."
            elif any(200 <= status < 300 for status in statuses):
                next_hint = "Compare the successful responses. Batch only independent probes; follow dependent auth flows with single requests."
            else:
                next_hint = "Compare each result against expected_observation and would_falsify."
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
                facts={"batch": True, "results": results},
                errors=[item["error"] for item in results if item.get("error")],
                next_hint=next_hint,
            )

        http_status = None
        body_excerpt = ""
        body_full = ""
        json_items: int | None = None
        request_url = ""
        headers: dict[str, Any] = {}
        res = p_data.get("curl_result") or p_data.get("probe_result") or {}
        request = p_data.get("request") or {}
        if isinstance(request, dict):
            request_url = str(request.get("url") or "")
        if not request_url and isinstance(res, dict):
            request_url = str(res.get("url") or "")

        # 1. curl-mcp format: { ok, code, status, response: { status_code, headers, body } }
        if "response" in p_data and isinstance(p_data["response"], dict):
            resp = p_data["response"]
            http_status = resp.get("status_code") or p_data.get("code")
            headers = resp.get("headers") or {}
            body_full = resp.get("body") or ""
        # 2. Legacy in-process probe format
        elif "curl_result" in p_data or "probe_result" in p_data:
            http_status = res.get("status_code")
            headers = res.get("headers") or {}
            body_full = res.get("body_preview") or res.get("body") or ""
        else:
            http_status = p_data.get("code") or p_data.get("status_code")
            body_full = p_data.get("body") or ""

        if isinstance(body_full, str):
            # Strip heavy inline styles so directory listings and API responses aren't masked
            cleaned = re.sub(r"<style[^>]*>[\s\S]*?</style>", "", body_full, flags=re.IGNORECASE)
            body_excerpt = cleaned[:1000]
        else:
            body_excerpt = str(body_full)[:1000]

        try:
            parsed_body = (
                json.loads(body_full)
                if isinstance(body_full, str)
                else body_full
            )
            rows = (
                parsed_body.get("data")
                if isinstance(parsed_body, dict)
                else None
            )
            if isinstance(rows, list):
                json_items = len(rows)
        except (TypeError, ValueError):
            json_items = None

        status_part = f"HTTP {http_status}" if http_status is not None else "HTTP request succeeded"
        if json_items is not None:
            status_part += f" ({json_items} items)"
        body_part = f" - excerpt: {body_excerpt!r}" if body_excerpt else ""
        summary_str = f"{status_part}{body_part}"

        if http_status in (400, 422):
            next_hint = "HTTP 4xx: Server rejected request syntax or payload structure. Inspect response body for validation errors, adjust JSON fields/headers, and retry."
        elif http_status in (401, 403):
            next_hint = f"HTTP {http_status}: Authentication or authorization required. Analyze headers, test for bypass, or inspect public paths."
        elif http_status == 404:
            next_hint = "HTTP 404: path does not exist. Do not retry variants; use dirb results or read the API documentation artifact."
        elif http_status == 500 and "Unexpected path" in body_excerpt:
            next_hint = "HTTP 500 with 'Unexpected path': the route does not exist. Stop guessing endpoints; read the API/swagger artifact or use a path already discovered."
        elif http_status == 500:
            next_hint = "HTTP 500: Server exception occurred. Check if payload triggered an unhandled database error or query crash."
        elif json_items is not None and ("search" in request_url or "q=" in request_url):
            next_hint = (
                f"Search endpoint returned {json_items} items. Compare this with a benign "
                "baseline; a payload that changes the row count is evidence of injection. "
                "Record it with record_finding, cite both step ids, and hand off."
            )
        else:
            next_hint = "Compare observed HTTP status and response against expected_observation and would_falsify."

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
            facts={
                "status_code": http_status,
                "headers": headers,
                "body_preview": body_excerpt,
                "json_items": json_items,
                "request_url": request_url,
            },
            errors=[],
            next_hint=next_hint,
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
        text = ""
        if step.output_path:
            path = Path(step.output_path)
            if path.exists():
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    text = ""

        sql_vuln = SQLMAP_PROOF in text.lower()
        server_errors = bool(
            re.search(r"HTTP error codes detected[\s\S]*?\b5\d\d\b", text, re.IGNORECASE)
        )
        if sql_vuln:
            summary_str = "SQL injection confirmed by sqlmap."
            next_hint = (
                "Attach this sqlmap step to the candidate finding as proof, "
                "then record the verdict."
            )
        elif server_errors:
            summary_str = (
                "sqlmap found no injection point at the requested bounds, but "
                "the target returned 5xx to test payloads."
            )
            next_hint = (
                "This negative is inconclusive: escalate level/risk once or test "
                "a different parameter before concluding not injectable."
            )
        else:
            summary_str = "sqlmap scan completed; no SQL injection confirmed."
            next_hint = "Record the negative result or test a different parameter."
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
