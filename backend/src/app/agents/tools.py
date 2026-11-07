"""Tool layer for the three specialist roles.

Each role gets a different tool list. The LLM chooses what to do inside its
role; every action tool *queues* work behind the shared human gate. No tool
executes a scanner or touches the target directly.

Roles:
  recon        scan_services, nmap_scan, query_findings, query_steps, handoff
  discovery    web_scan, nikto_scan, sqlmap_scan, dirb_scan, query_findings,
               query_steps, handoff
  validation   http_probe, invoke_skill, query_findings, query_steps,
               update_finding_status, handoff
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from langchain_core.tools import tool
from sqlalchemy import func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from app.actions.probe import SAFE_METHODS
from app.adapters import nikto
from app.agents.context import current_assessment_id, current_role, current_run_id
from app.agents.control import ROLES, record_handoff
from app.agents.gate import queue_step
from app.core.config import settings
from app.core.db import get_async_session_ctx
from app.domain.models import (
    Assessment,
    Audit,
    Evidence,
    Finding,
    Step,
    StepStatus,
    utcnow,
)
from app.skills.loader import AGENT_SKILL_MAP, SKILL_REGISTRY

ACTOR = "assessment_agent"
SCANNERS = {
    "nikto": "nikto_scan",
    "nikto_scan": "nikto_scan",
    "zap": "zap_baseline",
    "zap_baseline": "zap_baseline",
}


def _context() -> tuple[int, str] | None:
    assessment_id = current_assessment_id.get()
    run_id = current_run_id.get()
    if assessment_id is None or run_id is None:
        return None
    return assessment_id, run_id


def _missing_context() -> dict[str, Any]:
    return {"error": "no active assessment run context"}


def _audit(
    session: AsyncSession, assessment_id: int, event_type: str, payload: dict
) -> None:
    session.add(
        Audit(
            assessment_id=assessment_id,
            actor=ACTOR,
            event_type=event_type,
            payload=payload,
        )
    )


def _role() -> str | None:
    return current_role.get()


def _role_refusal(role: str | None, allowed: str) -> dict[str, Any] | None:
    """Defense in depth: a role cannot call another role's action tool."""
    if role and role != allowed:
        return {
            "error": (
                f"this tool belongs to the {allowed} role; "
                f"the active role is {role}"
            )
        }
    return None


def _probe_url(target: str, path: str, assessment: Assessment) -> str:
    if path.startswith(("http://", "https://")):
        return path
    if target.startswith(("http://", "https://")):
        base = target.rstrip("/")
    else:
        port = (assessment.ports or [3000])[0]
        base = f"http://{target}:{port}"
    return base + (path if path.startswith("/") else f"/{path}")


@tool("scan_services")
async def scan_services(target: str, rationale: str = "") -> dict[str, Any]:
    """Queue an nmap service/port scan for one authorised target.

    Use this first to learn which ports and services exist. The action pauses
    at the human action gate; its findings appear in the database after the
    gate executes it, not in this tool result.

    Args:
        target: one of the assessment's authorised targets.
        rationale: why this scan is the right next step.
    """
    ctx = _context()
    if ctx is None:
        return _missing_context()
    assessment_id, run_id = ctx

    role = _role()
    refusal = _role_refusal(role, "recon")
    if refusal:
        return refusal

    async with get_async_session_ctx() as session:
        assessment = await session.get(Assessment, assessment_id)
        if assessment is None:
            return {"error": f"assessment {assessment_id} not found"}
        return await queue_step(
            session,
            assessment,
            run_id,
            role or "recon",
            "recon_services",
            target,
            rationale or "Service and port discovery",
        )


@tool("nmap_scan")
async def nmap_scan(
    flags: str,
    ports: str,
    target: str,
    rationale: str = "",
) -> dict[str, Any]:
    """Queue an nmap scan with agent-supplied flags and port range.

    You own the command: any nmap flags, any port range, any timing template.
    The action pauses at the human gate (per policy) and the exact argv you
    supply is what gets approved and executed.

    Args:
        flags: nmap flags (e.g. "-sS -sV -T4 -Pn" or "-sS -p 1-1000").
        ports: port range or list (e.g. "1-1000", "3000", "21,22,80,443").
        target: one of the assessment's authorised targets.
        rationale: why this scan is the right next step.
    """
    ctx = _context()
    if ctx is None:
        return _missing_context()
    assessment_id, run_id = ctx

    role = _role()
    refusal = _role_refusal(role, "recon")
    if refusal:
        return refusal

    if not flags or not flags.strip():
        return {"error": "flags are required for nmap_scan"}
    if not ports or not ports.strip():
        return {"error": "ports are required for nmap_scan"}

    argv = ["nmap"] + flags.strip().split() + ["-p", ports.strip(), "-oX", "-", target]

    async with get_async_session_ctx() as session:
        assessment = await session.get(Assessment, assessment_id)
        if assessment is None:
            return {"error": f"assessment {assessment_id} not found"}
        return await queue_step(
            session,
            assessment,
            run_id,
            role or "recon",
            "nmap_scan",
            target,
            rationale or f"nmap {flags} -p {ports}",
            argv=argv,
        )


@tool("nikto_scan")
async def nikto_scan(
    flags: str,
    target: str,
    rationale: str = "",
) -> dict[str, Any]:
    """Queue nikto with agent-supplied flags.

    You own the nikto command line. The output path is handled automatically.

    Args:
        flags: nikto flags (e.g. "-Tuning 123" or "-e db").
        target: one of the assessment's authorised targets.
        rationale: what you expect this scan to add.
    """
    ctx = _context()
    if ctx is None:
        return _missing_context()
    assessment_id, run_id = ctx

    role = _role()
    refusal = _role_refusal(role, "discovery")
    if refusal:
        return refusal

    async with get_async_session_ctx() as session:
        assessment = await session.get(Assessment, assessment_id)
        if assessment is None:
            return {"error": f"assessment {assessment_id} not found"}
        if not assessment.ports:
            return {
                "error": (
                    "no authorised web ports on this assessment; run "
                    "nmap_scan first to establish what is open"
                )
            }
        port = assessment.ports[0]
        base_cmd = nikto.command()
        argv = [
            *base_cmd,
            "-h",
            target,
            "-p",
            str(port),
        ] + flags.strip().split() + [
            "-nointeractive",
            "-Format",
            "json",
        ]
        return await queue_step(
            session,
            assessment,
            run_id,
            role or "discovery",
            "nikto_scan",
            target,
            rationale or f"nikto {flags}",
            argv=argv,
        )


@tool("sqlmap_scan")
async def sqlmap_scan(
    flags: str,
    target: str,
    rationale: str = "",
) -> dict[str, Any]:
    """Queue sqlmap with agent-supplied flags.

    High-risk action: requires human approval at the gate by default policy.
    You own the sqlmap command line.

    Args:
        flags: sqlmap flags (e.g. "--batch --dbs --level 2").
        target: one of the assessment's authorised targets.
        rationale: what you expect this scan to add.
    """
    ctx = _context()
    if ctx is None:
        return _missing_context()
    assessment_id, run_id = ctx

    role = _role()
    refusal = _role_refusal(role, "discovery")
    if refusal:
        return refusal

    async with get_async_session_ctx() as session:
        assessment = await session.get(Assessment, assessment_id)
        if assessment is None:
            return {"error": f"assessment {assessment_id} not found"}
        if not assessment.ports:
            return {
                "error": (
                    "no authorised web ports on this assessment; run "
                    "nmap_scan first to establish what is open"
                )
            }
        port = assessment.ports[0]
        url = f"http://{target}:{port}/"
        argv = ["sqlmap", "-u", url] + flags.strip().split()
        return await queue_step(
            session,
            assessment,
            run_id,
            role or "discovery",
            "sqlmap_scan",
            target,
            rationale or f"sqlmap {flags}",
            argv=argv,
        )


@tool("dirb_scan")
async def dirb_scan(
    flags: str,
    wordlist: str,
    target: str,
    rationale: str = "",
) -> dict[str, Any]:
    """Queue dirb with agent-supplied flags and wordlist.

    You own the dirb command line. The output path is handled automatically.

    Args:
        flags: dirb flags (e.g. "-S" or "-r").
        wordlist: path to the wordlist file.
        target: one of the assessment's authorised targets.
        rationale: what you expect this scan to add.
    """
    ctx = _context()
    if ctx is None:
        return _missing_context()
    assessment_id, run_id = ctx

    role = _role()
    refusal = _role_refusal(role, "discovery")
    if refusal:
        return refusal

    async with get_async_session_ctx() as session:
        assessment = await session.get(Assessment, assessment_id)
        if assessment is None:
            return {"error": f"assessment {assessment_id} not found"}
        if not assessment.ports:
            return {
                "error": (
                    "no authorised web ports on this assessment; run "
                    "nmap_scan first to establish what is open"
                )
            }
        port = assessment.ports[0]
        url = f"http://{target}:{port}/"
        argv = ["dirb", url, wordlist] + flags.strip().split()
        return await queue_step(
            session,
            assessment,
            run_id,
            role or "discovery",
            "dirb_scan",
            target,
            rationale or f"dirb {wordlist} {flags}",
            argv=argv,
        )


@tool("web_scan")
async def web_scan(scanner: str, target: str, rationale: str = "") -> dict[str, Any]:
    """Queue a web scanner (nikto or zap) against one authorised target.

    Nikto is an active web configuration probe; ZAP is a passive baseline.
    Both use the first authorised web port. The action pauses at the human
    action gate and its alerts are stored as SUSPECTED findings afterwards.

    Args:
        scanner: "nikto" or "zap".
        target: one of the assessment's authorised targets.
        rationale: what you expect this scanner to add.
    """
    ctx = _context()
    if ctx is None:
        return _missing_context()
    assessment_id, run_id = ctx

    action = SCANNERS.get((scanner or "").strip().lower())
    if action is None:
        return {"error": "scanner must be 'nikto' or 'zap'"}

    role = _role()
    refusal = _role_refusal(role, "discovery")
    if refusal:
        return refusal

    async with get_async_session_ctx() as session:
        assessment = await session.get(Assessment, assessment_id)
        if assessment is None:
            return {"error": f"assessment {assessment_id} not found"}
        if not assessment.ports:
            return {
                "error": (
                    "no authorised web ports on this assessment; run "
                    "scan_services first to establish what is open"
                )
            }
        return await queue_step(
            session,
            assessment,
            run_id,
            role or "discovery",
            action,
            target,
            rationale or f"{scanner} web scan",
        )


@tool("http_probe")
async def http_probe(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: str = "",
    expected_status: int = 200,
    rationale: str = "",
    finding_id: int | None = None,
) -> dict[str, Any]:
    """Queue one safe, non-destructive HTTP probe behind the human action gate.

    GET, HEAD and POST are the only permitted methods. The probe stores the
    exact method, URL, headers and body the human approves. The URL host and
    port must be inside the assessment scope; identical probes are
    deduplicated and the probe budget is capped.

    Only the validation role may call this. The response arrives in the next
    observation after the gate executes the approved probe.

    Args:
        method: GET, HEAD or POST.
        url: absolute http(s) URL inside the authorised scope.
        headers: optional request headers.
        body: optional request body (POST).
        expected_status: status code the hypothesis predicts.
        rationale: the falsifiable reason for this probe.
        finding_id: SUSPECTED finding this probe tests, when applicable.
    """
    ctx = _context()
    if ctx is None:
        return _missing_context()
    assessment_id, run_id = ctx

    role = _role()
    refusal = _role_refusal(role, "validation")
    if refusal:
        return refusal

    method = (method or "GET").upper()
    if method not in SAFE_METHODS:
        return {
            "error": (
                f"method {method} refused: only GET, HEAD and POST probes are "
                "safe; destructive verbs need a separate authorised action"
            )
        }

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return {"error": "url must be an absolute http(s) URL"}
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    async with get_async_session_ctx() as session:
        assessment = await session.get(Assessment, assessment_id)
        if assessment is None:
            return {"error": f"assessment {assessment_id} not found"}
        if host in assessment.exclusions or host not in assessment.targets:
            return {"error": f"{host} is not in scope for assessment {assessment_id}"}
        if assessment.ports and port not in assessment.ports:
            return {
                "error": (
                    f"port {port} is not in the authorised port list "
                    f"{assessment.ports}"
                )
            }
        if finding_id is not None:
            finding = await session.get(Finding, finding_id)
            if finding is None or finding.assessment_id != assessment_id:
                return {
                    "error": f"finding {finding_id} is not in the current assessment"
                }

        result = await session.execute(
            select(Step).where(
                Step.assessment_id == assessment_id,
                Step.action == "http_probe",
                Step.status.in_(
                    [
                        StepStatus.PLANNED.value,
                        StepStatus.RUNNING.value,
                        StepStatus.SUCCEEDED.value,
                    ]
                ),
            )
        )
        planned = list(result.scalars().all())
        if len(planned) >= settings.max_validation_probes:
            return {
                "error": (
                    f"probe budget exhausted ({settings.max_validation_probes} "
                    "probes planned/executed for this assessment); interpret the "
                    "probes already run and hand off"
                )
            }

        descriptor = [
            "http_probe",
            method,
            url,
            json.dumps(headers or {}, sort_keys=True),
            str(expected_status),
            body or "",
        ]
        return await queue_step(
            session,
            assessment,
            run_id,
            role or "validation",
            "http_probe",
            host,
            rationale or "Verification probe",
            argv=descriptor,
            detail={
                "method": method,
                "url": url,
                "expected_status": expected_status,
                "finding_id": finding_id,
                "rationale": rationale,
            },
        )


@tool("invoke_skill")
async def invoke_skill(
    skill_name: str,
    finding_id: int,
    hypothesis: str,
) -> dict[str, Any]:
    """Load a verification skill and generate safe probe candidates.

    Skills are generic playbooks. Pick the one that matches the evidence, then
    state a falsifiable hypothesis (for example: "the /ftp listing is reachable
    without authentication"). The skill returns candidate probes; you still
    choose which ones to queue with http_probe.

    Only the validation role may invoke verification skills.

    Args:
        skill_name: registered skill name.
        finding_id: the finding this hypothesis applies to.
        hypothesis: falsifiable statement the probes will test.
    """
    ctx = _context()
    if ctx is None:
        return _missing_context()
    assessment_id, run_id = ctx

    role = _role()
    refusal = _role_refusal(role, "validation")
    if refusal:
        return refusal

    async with get_async_session_ctx() as session:
        allowed = AGENT_SKILL_MAP.get("validation_agent", [])
        if skill_name not in allowed:
            return {
                "error": (
                    f"skill {skill_name!r} is not allowed for the validation "
                    f"role; allowed: {allowed}"
                )
            }
        skill = SKILL_REGISTRY.get(skill_name)
        if skill is None:
            return {"error": f"unknown skill: {skill_name}"}

        finding = await session.get(Finding, finding_id)
        if finding is None or finding.assessment_id != assessment_id:
            return {"error": f"finding {finding_id} not found in this assessment"}
        assessment = await session.get(Assessment, assessment_id)
        if assessment is None:
            return {"error": "assessment missing"}

        evidence_result = await session.execute(
            select(Evidence).where(Evidence.finding_id == finding.id)
        )
        evidence_rows = list(evidence_result.scalars().all())
        result = skill.generate_probes(
            {
                "id": finding.id,
                "title": finding.title,
                "description": finding.description,
                "endpoint": finding.endpoint,
                "canonical_key": finding.canonical_key,
                "evidence": [
                    {"excerpt": row.excerpt, "locator": row.locator}
                    for row in evidence_rows
                ],
            },
            hypothesis,
            {
                "targets": assessment.targets,
                "ports": assessment.ports,
                "exclusions": assessment.exclusions,
            },
        )
        _audit(
            session,
            assessment_id,
            "verification.skill_invoked",
            {
                "run_id": run_id,
                "role": role,
                "skill": skill_name,
                "finding_id": finding_id,
                "hypothesis": hypothesis,
                "probe_count": len(result.probes),
                "reasoning": result.reasoning[:500],
            },
        )
        await session.commit()

        probes = []
        for probe in result.probes:
            probes.append(
                {
                    "action": probe.action,
                    "target": probe.target,
                    "method": probe.method,
                    "path": probe.path,
                    "url": _probe_url(probe.target, probe.path, assessment),
                    "headers": probe.headers,
                    "expected_status": probe.expected_status,
                    "rationale": probe.rationale,
                }
            )

        return {
            "skill": skill_name,
            "finding_id": finding_id,
            "hypothesis": hypothesis,
            "probes": probes,
            "reasoning": result.reasoning,
            "next": (
                "Choose the few probes that actually test the hypothesis and queue "
                "them with http_probe(method, url, headers, expected_status, "
                "rationale, finding_id). Every probe waits at the action gate."
            ),
        }


@tool("query_findings")
async def query_findings(
    status: str | None = None,
    canonical_key_contains: str | None = None,
    limit: int = 20,
) -> dict[str, Any]:
    """Return findings for the active assessment, newest first.

    Args:
        status: suspected, confirmed, false_positive, or None for all.
        canonical_key_contains: substring match on canonical_key.
        limit: maximum rows to return (1-50).
    """
    ctx = _context()
    if ctx is None:
        return _missing_context()
    assessment_id, _ = ctx
    limit = max(1, min(int(limit or 20), 50))

    async with get_async_session_ctx() as session:
        query = select(Finding).where(Finding.assessment_id == assessment_id)
        if status:
            query = query.where(Finding.status == status)
        result = await session.execute(query)
        rows = list(result.scalars().all())
        if canonical_key_contains:
            rows = [row for row in rows if canonical_key_contains in row.canonical_key]
        rows.sort(key=lambda row: row.updated_at, reverse=True)
        return {
            "count": len(rows[:limit]),
            "total": len(rows),
            "findings": [
                {
                    "id": row.id,
                    "canonical_key": row.canonical_key,
                    "title": row.title,
                    "severity": row.severity,
                    "confidence": row.confidence,
                    "status": row.status,
                    "endpoint": row.endpoint,
                    "asset": row.asset,
                    "cwe": row.cwe,
                    "origin": row.origin,
                }
                for row in rows[:limit]
            ],
        }


@tool("query_steps")
async def query_steps(
    action: str | None = None,
    status: str | None = None,
    limit: int = 10,
) -> dict[str, Any]:
    """Return recent action results, newest first.

    Use this to inspect what the gate actually executed, including failures
    and rejected approvals.

    Args:
        action: optional action filter (recon_services, nikto_scan, zap_baseline, http_probe).
        status: optional status filter (planned, succeeded, failed, timeout, blocked, rejected).
        limit: maximum rows to return (1-30).
    """
    ctx = _context()
    if ctx is None:
        return _missing_context()
    assessment_id, _ = ctx
    limit = max(1, min(int(limit or 10), 30))

    async with get_async_session_ctx() as session:
        query = select(Step).where(Step.assessment_id == assessment_id)
        if action:
            query = query.where(Step.action == action)
        if status:
            query = query.where(Step.status == status)
        result = await session.execute(
            query.order_by(Step.seq.desc()).limit(limit)
        )
        steps = list(result.scalars().all())
        rows = []
        for step in steps:
            linked_result = await session.execute(
                select(func.count(Evidence.id)).where(Evidence.step_id == step.id)
            )
            linked = linked_result.scalar()
            rows.append(
                {
                    "step_id": step.id,
                    "seq": step.seq,
                    "action": step.action,
                    "target": step.target,
                    "status": step.status,
                    "exit_code": step.exit_code,
                    "error": step.error,
                    "rationale": step.rationale,
                    "findings_linked": linked or 0,
                    "artifact": bool(step.output_path),
                    "artifact_sha256": step.output_sha256,
                }
            )
        return {"count": len(rows), "steps": rows}


@tool("update_finding_status")
async def update_finding_status(
    finding_id: int,
    status: str,
    reasoning: str,
) -> dict[str, Any]:
    """Record one verdict with an audit-trail reasoning string.

    CONFIRMED and FALSE_POSITIVE are refused unless the finding has at least
    one executed http_probe evidence row. Leave the finding SUSPECTED when the
    probes were inconclusive; that is an honest outcome, not a failure.

    Only the validation role may record a verdict.

    Args:
        finding_id: finding under verification.
        status: confirmed, false_positive, or suspected.
        reasoning: concrete probe evidence supporting the verdict.
    """
    ctx = _context()
    if ctx is None:
        return _missing_context()
    assessment_id, run_id = ctx

    role = _role()
    refusal = _role_refusal(role, "validation")
    if refusal:
        return refusal

    if status not in ("confirmed", "false_positive", "suspected"):
        return {"error": "status must be confirmed, false_positive, or suspected"}

    async with get_async_session_ctx() as session:
        row = await session.get(Finding, finding_id)
        if row is None or row.assessment_id != assessment_id:
            return {"error": f"finding {finding_id} not in current assessment"}

        if status in ("confirmed", "false_positive"):
            evidence_result = await session.execute(
                select(Evidence).where(Evidence.finding_id == finding_id)
            )
            evidence = list(evidence_result.scalars().all())
            executed = any(
                (item.locator or {}).get("tool") == "http_probe"
                and (item.locator or {}).get("http_status") is not None
                for item in evidence
            )
            if not executed:
                return {
                    "error": (
                        "verdict blocked: no executed http_probe evidence is "
                        "linked to this finding. Queue probes with "
                        "http_probe(..., finding_id=...) and wait for the action "
                        "gate to execute them."
                    )
                }

        old = row.status
        row.status = status
        row.updated_at = utcnow()
        _audit(
            session,
            assessment_id,
            "verification.status_updated",
            {
                "run_id": run_id,
                "role": role,
                "finding_id": finding_id,
                "from": old,
                "to": status,
                "by": ACTOR,
                "reasoning": reasoning,
            },
        )
        await session.commit()
        return {
            "updated": True,
            "finding_id": finding_id,
            "status": status,
            "previous": old,
            "audited": True,
        }


NEXT_ROLE_ALLOWED = {
    "recon": {"discovery", "review"},
    "discovery": {"validation", "review"},
    "validation": {"review"},
}


@tool("handoff")
async def handoff(
    summary: str,
    decisions: list[dict] | None = None,
    finding_ids: list[int] | None = None,
    step_ids: list[int] | None = None,
    next_recommendation: str = "review",
    needs_input: bool = False,
    question: str = "",
    open_questions: list[str] | None = None,
) -> dict[str, Any]:
    """End your role with a typed handoff.

    The graph reads this handoff to decide the next role. Python validates the
    recommendation and every ID before the transition. Call this once, after
    the work you want this role to do is queued or finished.

    Args:
        summary: 2-5 sentences on what you learned and what remains uncertain.
        decisions: list of {what, why, profile/params} objects.
        finding_ids: findings this role relied on or produced.
        step_ids: steps this role queued or relied on.
        next_recommendation: "discovery", "validation", or "review".
        needs_input: true when you need the operator to decide.
        question: one concrete question when needs_input is true.
        open_questions: questions that do not block the handoff.
    """
    ctx = _context()
    if ctx is None:
        return _missing_context()
    assessment_id, run_id = ctx
    role = _role()
    if role not in ROLES:
        return {"error": "handoff requires an active specialist role"}

    summary = (summary or "").strip()
    if not summary:
        return {"error": "handoff summary is required"}

    recommendation = (next_recommendation or "review").strip().lower()
    allowed = NEXT_ROLE_ALLOWED[role]
    if recommendation not in allowed:
        return {
            "error": (
                f"{role} cannot recommend {recommendation!r}; "
                f"allowed: {sorted(allowed)}"
            )
        }
    if needs_input and not (question or "").strip():
        return {"error": "needs_input=true requires one concrete question"}

    decisions = decisions or []
    finding_ids = [int(item) for item in (finding_ids or [])]
    step_ids = [int(item) for item in (step_ids or [])]

    async with get_async_session_ctx() as session:
        for finding_id in finding_ids:
            finding = await session.get(Finding, finding_id)
            if finding is None or finding.assessment_id != assessment_id:
                return {
                    "error": f"finding {finding_id} is not in the current assessment"
                }
        for step_id in step_ids:
            step = await session.get(Step, step_id)
            if step is None or step.assessment_id != assessment_id:
                return {"error": f"step {step_id} is not in the current assessment"}

        payload = record_handoff(
            session,
            assessment_id,
            run_id,
            role,
            {
                "summary": summary,
                "decisions": decisions,
                "finding_ids": finding_ids,
                "step_ids": step_ids,
                "next_recommendation": recommendation,
                "needs_input": needs_input,
                "question": question,
                "open_questions": open_questions or [],
            },
        )
        _audit(
            session,
            assessment_id,
            "role.handoff",
            {
                "run_id": run_id,
                "role": role,
                "next_recommendation": recommendation,
                "summary": summary[:500],
            },
        )
        await session.commit()
        return {
            "handoff_recorded": True,
            "role": role,
            "next_recommendation": recommendation,
            "needs_input": needs_input,
            "summary": payload["summary"],
            "note": "The role is ending. The graph will route from this handoff.",
        }


RECON_TOOLS = [scan_services, nmap_scan, query_findings, query_steps, handoff]
DISCOVERY_TOOLS = [
    web_scan,
    nikto_scan,
    sqlmap_scan,
    dirb_scan,
    query_findings,
    query_steps,
    handoff,
]
VALIDATION_TOOLS = [
    http_probe,
    invoke_skill,
    query_findings,
    query_steps,
    update_finding_status,
    handoff,
]

ROLE_TOOLS = {
    "recon": RECON_TOOLS,
    "discovery": DISCOVERY_TOOLS,
    "validation": VALIDATION_TOOLS,
}
