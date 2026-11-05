"""Tool layer for the single assessment agent.

There is one agent loop. The LLM chooses what to do; every tool either reads
state or *queues* an action behind the shared human gate. No tool executes a
scanner or touches the target directly.

Tools available:
  scan_services        queue nmap service discovery
  web_scan             queue nikto or zap against a scoped target
  http_probe           queue one safe HTTP probe bound to a finding
  invoke_skill         load a phase-allowed verification playbook
  query_findings       read findings for the active assessment
  query_steps          read recent action results
  update_finding_status record a verdict (requires executed probe evidence)
  advance_phase        record the phase the agent is entering
  finish               declare active work complete and go to final review
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from langchain_core.tools import tool
from sqlalchemy import func
from sqlmodel import Session, select

from app.agents.context import current_assessment_id, current_run_id
from app.agents.control import (
    PHASE_AGENT,
    current_phase,
    record_finish,
    record_phase,
)
from app.agents.gate import queue_step
from app.actions.probe import SAFE_METHODS
from app.core.config import settings
from app.core.db import get_engine
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


def _audit(session: Session, assessment_id: int, event_type: str, payload: dict) -> None:
    session.add(
        Audit(
            assessment_id=assessment_id,
            actor=ACTOR,
            event_type=event_type,
            payload=payload,
        )
    )


def _phase(session: Session, assessment_id: int, run_id: str) -> str:
    return current_phase(session, assessment_id, run_id)


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
def scan_services(target: str, rationale: str = "") -> dict[str, Any]:
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

    with Session(get_engine(), expire_on_commit=False) as session:
        assessment = session.get(Assessment, assessment_id)
        if assessment is None:
            return {"error": f"assessment {assessment_id} not found"}
        phase = _phase(session, assessment_id, run_id)
        return queue_step(
            session,
            assessment,
            run_id,
            phase,
            "recon_services",
            target,
            rationale or "Service and port discovery",
        )


@tool("web_scan")
def web_scan(scanner: str, target: str, rationale: str = "") -> dict[str, Any]:
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

    with Session(get_engine(), expire_on_commit=False) as session:
        assessment = session.get(Assessment, assessment_id)
        if assessment is None:
            return {"error": f"assessment {assessment_id} not found"}
        if not assessment.ports:
            return {
                "error": (
                    "no authorised web ports on this assessment; run "
                    "scan_services first to establish what is open"
                )
            }
        phase = _phase(session, assessment_id, run_id)
        return queue_step(
            session,
            assessment,
            run_id,
            phase,
            action,
            target,
            rationale or f"{scanner} web scan",
        )


@tool("sqlmap_scan")
def sqlmap_scan(
    target: str,
    params: str = "--batch --dbs",
    rationale: str = "",
) -> dict[str, Any]:
    """Queue SQLMap against one authorised target to test for SQL injection.

    SQLMap runs in --batch mode automatically and only against in-scope URLs.
    The action pauses at the human action gate; its raw output is stored as an
    artifact for review.

    Args:
        target: one of the assessment's authorised targets.
        params: extra SQLMap parameters (default "--batch --dbs").
        rationale: why SQL injection is suspected on this target.
    """
    ctx = _context()
    if ctx is None:
        return _missing_context()
    assessment_id, run_id = ctx

    with Session(get_engine(), expire_on_commit=False) as session:
        assessment = session.get(Assessment, assessment_id)
        if assessment is None:
            return {"error": f"assessment {assessment_id} not found"}
        if not assessment.ports:
            return {
                "error": (
                    "no authorised web ports on this assessment; run "
                    "scan_services first to establish what is open"
                )
            }
        phase = _phase(session, assessment_id, run_id)
        return queue_step(
            session,
            assessment,
            run_id,
            phase,
            "sqlmap_scan",
            target,
            rationale or "SQL injection testing",
            detail={"params": params},
        )


@tool("dirb_scan")
def dirb_scan(
    target: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    rationale: str = "",
) -> dict[str, Any]:
    """Queue Dirb to brute-force directories and files on one authorised target.

    Dirb uses the common wordlist by default. The action pauses at the human
    action gate; its raw output is stored as an artifact for review.

    Args:
        target: one of the assessment's authorised targets.
        wordlist: path to the wordlist Dirb should use.
        rationale: why directory enumeration is useful on this target.
    """
    ctx = _context()
    if ctx is None:
        return _missing_context()
    assessment_id, run_id = ctx

    with Session(get_engine(), expire_on_commit=False) as session:
        assessment = session.get(Assessment, assessment_id)
        if assessment is None:
            return {"error": f"assessment {assessment_id} not found"}
        if not assessment.ports:
            return {
                "error": (
                    "no authorised web ports on this assessment; run "
                    "scan_services first to establish what is open"
                )
            }
        phase = _phase(session, assessment_id, run_id)
        return queue_step(
            session,
            assessment,
            run_id,
            phase,
            "dirb_scan",
            target,
            rationale or "Directory and file enumeration",
            detail={"wordlist": wordlist},
        )


@tool("http_probe")
def http_probe(
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

    Call this only in the validation phase. The response arrives in the next
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

    with Session(get_engine(), expire_on_commit=False) as session:
        assessment = session.get(Assessment, assessment_id)
        if assessment is None:
            return {"error": f"assessment {assessment_id} not found"}
        phase = _phase(session, assessment_id, run_id)
        if phase != "validation":
            return {
                "error": (
                    f"http_probe belongs to validation (current phase: {phase}). "
                    "Call advance_phase('validation', reason) first."
                )
            }
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
            finding = session.get(Finding, finding_id)
            if finding is None or finding.assessment_id != assessment_id:
                return {
                    "error": f"finding {finding_id} is not in the current assessment"
                }

        planned = session.exec(
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
        ).all()
        if len(planned) >= settings.max_validation_probes:
            return {
                "error": (
                    f"probe budget exhausted ({settings.max_validation_probes} "
                    "probes planned/executed for this assessment); interpret the "
                    "probes already run or call finish"
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
        return queue_step(
            session,
            assessment,
            run_id,
            phase,
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
def invoke_skill(
    skill_name: str,
    finding_id: int,
    hypothesis: str,
) -> dict[str, Any]:
    """Load a verification skill and generate safe probe candidates.

    Skills are generic playbooks. Pick the one that matches the evidence, then
    state a falsifiable hypothesis (for example: "the /ftp listing is reachable
    without authentication"). The skill returns candidate probes; you still
    choose which ones to queue with http_probe.

    Only skills allowed for the current phase can be invoked. Advancing to
    validation unlocks the full verification set.

    Args:
        skill_name: registered skill name.
        finding_id: the finding this hypothesis applies to.
        hypothesis: falsifiable statement the probes will test.
    """
    ctx = _context()
    if ctx is None:
        return _missing_context()
    assessment_id, run_id = ctx

    with Session(get_engine(), expire_on_commit=False) as session:
        phase = _phase(session, assessment_id, run_id)
        agent_name = PHASE_AGENT.get(phase, "validation_agent")
        allowed = AGENT_SKILL_MAP.get(agent_name, [])
        if skill_name not in allowed:
            return {
                "error": (
                    f"skill {skill_name!r} is not allowed for {agent_name} "
                    f"in phase {phase!r}; allowed: {allowed}"
                )
            }
        skill = SKILL_REGISTRY.get(skill_name)
        if skill is None:
            return {"error": f"unknown skill: {skill_name}"}

        finding = session.get(Finding, finding_id)
        if finding is None or finding.assessment_id != assessment_id:
            return {"error": f"finding {finding_id} not found in this assessment"}
        assessment = session.get(Assessment, assessment_id)
        if assessment is None:
            return {"error": "assessment missing"}

        evidence_rows = session.exec(
            select(Evidence).where(Evidence.finding_id == finding.id)
        ).all()
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
                "phase": phase,
                "agent": agent_name,
                "skill": skill_name,
                "finding_id": finding_id,
                "hypothesis": hypothesis,
                "probe_count": len(result.probes),
                "reasoning": result.reasoning[:500],
            },
        )
        session.commit()

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
def query_findings(
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

    with Session(get_engine(), expire_on_commit=False) as session:
        query = select(Finding).where(Finding.assessment_id == assessment_id)
        if status:
            query = query.where(Finding.status == status)
        rows = session.exec(query).all()
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
def query_steps(
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

    with Session(get_engine(), expire_on_commit=False) as session:
        query = select(Step).where(Step.assessment_id == assessment_id)
        if action:
            query = query.where(Step.action == action)
        if status:
            query = query.where(Step.status == status)
        steps = session.exec(query.order_by(Step.seq.desc()).limit(limit)).all()
        rows = []
        for step in steps:
            linked = session.exec(
                select(func.count(Evidence.id)).where(Evidence.step_id == step.id)
            ).one()
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
def update_finding_status(
    finding_id: int,
    status: str,
    reasoning: str,
) -> dict[str, Any]:
    """Record one verdict with an audit-trail reasoning string.

    CONFIRMED and FALSE_POSITIVE are refused unless the finding has at least
    one executed http_probe evidence row. Leave the finding SUSPECTED when the
    probes were inconclusive; that is an honest outcome, not a failure.

    Call this only in the validation phase.

    Args:
        finding_id: finding under verification.
        status: confirmed, false_positive, or suspected.
        reasoning: concrete probe evidence supporting the verdict.
    """
    ctx = _context()
    if ctx is None:
        return _missing_context()
    assessment_id, run_id = ctx

    if status not in ("confirmed", "false_positive", "suspected"):
        return {"error": "status must be confirmed, false_positive, or suspected"}

    with Session(get_engine(), expire_on_commit=False) as session:
        phase = _phase(session, assessment_id, run_id)
        if phase != "validation":
            return {
                "error": (
                    f"verdicts belong to validation (current phase: {phase}). "
                    "Call advance_phase('validation', reason) first."
                )
            }
        row = session.get(Finding, finding_id)
        if row is None or row.assessment_id != assessment_id:
            return {"error": f"finding {finding_id} not in current assessment"}

        if status in ("confirmed", "false_positive"):
            evidence = session.exec(
                select(Evidence).where(Evidence.finding_id == finding_id)
            ).all()
            executed = any(
                (item.locator or {}).get("tool") == "http_probe" for item in evidence
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
                "phase": phase,
                "finding_id": finding_id,
                "from": old,
                "to": status,
                "by": ACTOR,
                "reasoning": reasoning,
            },
        )
        session.commit()
        return {
            "updated": True,
            "finding_id": finding_id,
            "status": status,
            "previous": old,
            "audited": True,
        }


@tool("advance_phase")
def advance_phase(phase: str, reason: str) -> dict[str, Any]:
    """Record the assessment phase you are entering.

    The methodology is recon -> discovery -> validation -> finish. The phase is
    your own working label: it unlocks phase-specific skills and is written to
    the audit trail. It does not restrict scope or safety; those are enforced by
    the action tools themselves.

    Args:
        phase: recon, discovery, or validation.
        reason: why this phase is the right place to work now.
    """
    ctx = _context()
    if ctx is None:
        return _missing_context()
    assessment_id, run_id = ctx
    phase = (phase or "").strip().lower()

    with Session(get_engine(), expire_on_commit=False) as session:
        previous = _phase(session, assessment_id, run_id)
        if phase == previous:
            return {
                "phase": phase,
                "previous": previous,
                "changed": False,
                "note": "already in this phase",
            }
        try:
            payload = record_phase(
                session, assessment_id, run_id, phase, reason or "", previous
            )
        except ValueError as exc:
            return {"error": str(exc)}
        session.commit()
        return {
            "phase": phase,
            "previous": previous,
            "changed": True,
            "reason": reason,
            "audited": bool(payload),
        }


@tool("finish")
def finish(reason: str) -> dict[str, Any]:
    """Declare active work complete and send the findings to final human review.

    Call this when the coverage is adequate or further work has low value. The
    graph stops the loop after this call; the analyst reviews the findings
    before a report is generated.

    Args:
        reason: short summary of coverage and what remains uncertain.
    """
    ctx = _context()
    if ctx is None:
        return _missing_context()
    assessment_id, run_id = ctx

    with Session(get_engine(), expire_on_commit=False) as session:
        record_finish(session, assessment_id, run_id, reason or "")
        session.commit()
        return {
            "finished": True,
            "reason": reason,
            "next": "final human review gate; no further actions will run",
        }


ASSESSMENT_TOOLS = [
    scan_services,
    web_scan,
    sqlmap_scan,
    dirb_scan,
    http_probe,
    invoke_skill,
    query_findings,
    query_steps,
    update_finding_status,
    advance_phase,
    finish,
]
