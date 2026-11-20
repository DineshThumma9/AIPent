"""Report narrative schemas, context builder, prompt, and anti-hallucination validation.

Python is the security and anti-hallucination barrier. The LLM never writes raw Typst
markup; it outputs structured JSON conforming to ReportNarrative.
"""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel, Field, model_validator
from sqlalchemy.ext.asyncio import AsyncSession

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage
from app.agents.prompts import ROLE_PROMPTS
from app.adapters.base import strip_html
from app.agents.reasoning import build_evidence_board
from app.core.config import settings
from app.core.log import get_logger
from app.domain import risk
from app.domain.models import Approval, Assessment, Audit, Evidence, Finding, FindingCve, Step, utcnow
from app.persistence.assessment_repo import AssessmentRepo
from app.persistence.finding_repo import FindingRepo
from app.persistence.step_repo import StepRepo
from app.reporting.common import (
    clean_endpoint as _clean_endpoint,
    clean_finding_title as _clean_finding_title,
    clean_text as _clean_text,
    count_severities as _counts,
    iso_timestamp as _iso,
)
from app.agents.contracts import ReportNarrative, FindingNarrative
log = get_logger("reporting.narrative")



CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
CVSS_PATTERN = re.compile(
    r"\bCVSS(?:\s+(?:v\d(?:\.\d)?\s+)?(?:score\s+)?(?:of\s+)?|:?\s*)(\d+(?:\.\d+)?)\b",
    re.IGNORECASE,
)
CONFIRMED_PATTERN = re.compile(r"\b(confirmed|confirming)\b", re.IGNORECASE)

KNOWN_PLAINTEXT_PASSWORDS = {
    "password",
    "admin",
    "123456",
    "letmein",
    "welcome",
    "qwerty",
    "admin123",
    "password123",
    "root",
    "toor",
}

CREDENTIAL_CTX_PATTERN = re.compile(
    r"(?i)\b(password|passwd|pwd|credential|secret)s?(\s*[:=]\s*|\s+(?:was found to be|found to be|is|was)\s+)([\"']?)([\w!@#$%^&*()_+=-]+)\3",
)


def redact_credentials(text: str) -> str:
    """Scrub plaintext lab credentials found in a credential context."""
    def _replace(match: re.Match) -> str:
        prefix = match.group(1)
        sep = match.group(2)
        quote = match.group(3)
        val = match.group(4)
        if val.lower() in KNOWN_PLAINTEXT_PASSWORDS:
            log.warning("Redacting lab credential from narrative text")
            return f"{prefix}{sep}{quote}[REDACTED]{quote}"
        return match.group(0)

    return CREDENTIAL_CTX_PATTERN.sub(_replace, text)


def claims_confirmed(text: str) -> bool:
    """Check if text claims confirmation, excluding explicit negations."""
    scrubbed = re.sub(r"\b(?:not|never)\s+confirmed\b", "unconfirmed", text, flags=re.IGNORECASE)
    return bool(CONFIRMED_PATTERN.search(scrubbed))


def validate_narrative(narrative: ReportNarrative, context: dict[str, Any]) -> None:
    """Anti-hallucination validation boundary.

    Rules:
    1. Every finding_id must exist in context findings.
    2. No duplicate finding ids.
    3. Every context finding appears at most once.
    4. No CVE strings not present in that finding's context CVE list (and globally).
    5. No CVSS score fabrication (reject numeric mentions when cvss is null, or mismatch).
    6. No 'confirmed' claims for suspected/candidate findings.
    7. Plaintext password redaction and check.
    """
    context_findings = {f["id"]: f for f in context.get("findings", [])}

    # 1. Every finding_id exists in context
    for fn in narrative.findings:
        if fn.finding_id not in context_findings:
            raise ValueError(
                f"narrative finding_id {fn.finding_id} does not exist in assessment findings"
            )

    # 2. No duplicate finding IDs
    seen_ids: set[int] = set()
    for fn in narrative.findings:
        if fn.finding_id in seen_ids:
            raise ValueError(f"duplicate finding_id {fn.finding_id} in narrative findings")
        seen_ids.add(fn.finding_id)

    # 4. CVE checks
    all_allowed_cves = {
        c.upper()
        for f in context.get("findings", [])
        for c in (f.get("cve") or [])
    }
    for fn in narrative.findings:
        cf = context_findings[fn.finding_id]
        allowed_cves = {c.upper() for c in (cf.get("cve") or [])}
        finding_text = " ".join([
            fn.technical_analysis,
            fn.impact,
            fn.remediation,
            fn.confidence_statement,
            fn.observed_vs_inferred,
        ])
        mentioned_cves = {m.upper() for m in CVE_PATTERN.findall(finding_text)}
        unauthorized = mentioned_cves - allowed_cves
        if unauthorized:
            raise ValueError(
                f"finding {fn.finding_id} narrative mentions unauthorized/unverified CVE(s): "
                f"{', '.join(sorted(unauthorized))}"
            )

    # Global CVE check across top-level narrative sections
    top_level_text = " ".join([
        narrative.executive_summary,
        narrative.methodology,
        narrative.risk_overview,
        narrative.limitations,
        narrative.conclusion,
    ] + narrative.recommendations)
    mentioned_top_cves = {m.upper() for m in CVE_PATTERN.findall(top_level_text)}
    unauthorized_top = mentioned_top_cves - all_allowed_cves
    if unauthorized_top:
        raise ValueError(
            f"report narrative mentions unauthorized/unverified CVE(s): {', '.join(sorted(unauthorized_top))}"
        )

    # 5. CVSS check
    for fn in narrative.findings:
        cf = context_findings[fn.finding_id]
        cf_cvss = cf.get("cvss")
        finding_text = " ".join([
            fn.technical_analysis,
            fn.impact,
            fn.remediation,
            fn.confidence_statement,
            fn.observed_vs_inferred,
        ])
        matches = CVSS_PATTERN.findall(finding_text)
        if cf_cvss is None:
            if matches:
                raise ValueError(
                    f"finding {fn.finding_id} has no CVSS score (cvss is null), "
                    f"but narrative claims CVSS score {matches[0]}"
                )
        else:
            for m in matches:
                val = float(m)
                if abs(round(val, 1) - round(float(cf_cvss), 1)) > 0.15:
                    raise ValueError(
                        f"finding {fn.finding_id} has CVSS {cf_cvss}, "
                        f"but narrative claims fabricated CVSS score {m}"
                    )

    # 6. Suspected / candidate status check
    for fn in narrative.findings:
        cf = context_findings[fn.finding_id]
        status = str(cf.get("status", "")).lower()
        if status in ("suspected", "candidate"):
            finding_text = " ".join([
                fn.technical_analysis,
                fn.impact,
                fn.remediation,
                fn.confidence_statement,
                fn.observed_vs_inferred,
            ])
            if claims_confirmed(finding_text):
                raise ValueError(
                    f"finding {fn.finding_id} has status '{status}' but narrative claims 'confirmed'"
                )

    # 7. Redact credentials across all narrative strings
    for fn in narrative.findings:
        fn.technical_analysis = redact_credentials(fn.technical_analysis)
        fn.impact = redact_credentials(fn.impact)
        fn.remediation = redact_credentials(fn.remediation)
        fn.confidence_statement = redact_credentials(fn.confidence_statement)
        fn.observed_vs_inferred = redact_credentials(fn.observed_vs_inferred)

    narrative.executive_summary = redact_credentials(narrative.executive_summary)
    narrative.methodology = redact_credentials(narrative.methodology)
    narrative.risk_overview = redact_credentials(narrative.risk_overview)
    narrative.limitations = redact_credentials(narrative.limitations)
    narrative.conclusion = redact_credentials(narrative.conclusion)
    narrative.recommendations = [redact_credentials(r) for r in narrative.recommendations]

    # Phase 5.5: CVE provenance grounding checks
    for cf in context.get("findings", []):
        cves = cf.get("cve") or []
        if "finding_cves" in cf:
            finding_cves = cf.get("finding_cves") or []
            fc_map = {fc["cve_id"].upper(): fc for fc in finding_cves}
            for cve in cves:
                cve_upper = cve.upper()
                if cve_upper not in fc_map:
                    raise ValueError(
                        f"finding {cf['id']} CVE '{cve}' lacks required provenance in finding_cve"
                    )
                if not fc_map[cve_upper].get("source_url"):
                    raise ValueError(
                        f"finding {cf['id']} CVE '{cve}' has empty source_url in finding_cve"
                    )

    # Authority check: citations must cite NVD or vendor advisory, not vulnify as security authority
    all_narrative_text = " ".join([
        narrative.executive_summary,
        narrative.methodology,
        narrative.risk_overview,
        narrative.limitations,
        narrative.conclusion,
    ] + [
        " ".join([fn.technical_analysis, fn.impact, fn.remediation, fn.confidence_statement])
        for fn in narrative.findings
    ])
    if re.search(r"\b(?:according to|per|reported by|authoritative source:?)\s+vulnify\b", all_narrative_text, re.IGNORECASE):
        raise ValueError("citations must point to NVD or vendor advisories, not vulnify as authority")


async def build_narrative_context(session: AsyncSession, assessment_id: int) -> dict[str, Any]:
    """Assemble compact JSON context pack for the report writer LLM.

    Caps evidence excerpts at 800 chars and enforces assessment isolation.
    """
    assessment_repo = AssessmentRepo(session)
    finding_repo = FindingRepo(session)
    step_repo = StepRepo(session)

    assessment = await assessment_repo.get(assessment_id)
    if not assessment:
        raise LookupError(f"assessment {assessment_id} not found")

    findings = await finding_repo.get_all(assessment_id, limit=10000)
    evidence = await finding_repo.get_all_evidence(assessment_id)
    steps = await step_repo.get_all(assessment_id)
    approvals = await step_repo.get_all_approvals(assessment_id)
    finding_cves = await finding_repo.get_all_cves(assessment_id)

    cves_by_finding: dict[int, list[FindingCve]] = {}
    for fc in finding_cves:
        cves_by_finding.setdefault(fc.finding_id, []).append(fc)

    board = await build_evidence_board(session, assessment_id)
    risk_summary = risk.summarize(findings)

    evidence_by_finding: dict[int, list[Evidence]] = {}
    for ev in evidence:
        if ev.finding_id is not None:
            evidence_by_finding.setdefault(ev.finding_id, []).append(ev)

    scores = {f.id: risk.finding_score(f) for f in findings}
    ordered_findings = sorted(
        findings,
        key=lambda f: scores[f.id]["score"],
        reverse=True,
    )

    finding_items = []
    for idx, f in enumerate(ordered_findings):
        f_id = f.id or 0
        rows = evidence_by_finding.get(f_id, [])
        fc_rows = cves_by_finding.get(f_id, [])
        tools = sorted(
            list(
                {
                    (e.locator.get("tool") if isinstance(e.locator, dict) else None) or "nmap"
                    for e in rows
                }
            )
        )
        max_excerpt = 800 if idx < 10 else 200
        finding_items.append({
            "id": f_id,
            "title": _clean_finding_title(f.title),
            "severity": f.severity,
            "cvss": f.cvss,
            "cve": f.cve or [],
            "cwe": f.cwe or [],
            "status": f.status,
            "confidence": round(f.confidence, 2),
            "asset": _clean_endpoint(f.asset),
            "endpoint": _clean_endpoint(f.endpoint),
            "description": _clean_text(f.description),
            "impact": _clean_text(f.impact),
            "remediation": _clean_text(f.remediation),
            "evidence": [
                {
                    "id": row.id,
                    "tool": (row.locator.get("tool") if isinstance(row.locator, dict) else "nmap") or "nmap",
                    "excerpt": _clean_text(row.excerpt[:max_excerpt]),
                    "locator": row.locator if isinstance(row.locator, dict) else {},
                }
                for row in rows
            ],
            "corroborating_tools": tools,
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
            "narrative": None,
        })

    step_items = [
        {
            "seq": s.seq,
            "action": s.action,
            "target": s.target or (s.argv[-1] if s.argv else ""),
            "status": s.status,
            "error": s.error or "",
        }
        for s in steps
    ]

    approval_items = [
        {
            "action": a.action.replace("_", " "),
            "decision": a.decision,
            "actor": a.actor or "",
            "reason": a.reason or "",
        }
        for a in approvals
    ]

    reasoning_dict = {
        "open_questions": board.open_questions,
        "hypotheses": [
            {
                "id": h.id,
                "statement": h.statement,
                "status": h.status,
            }
            for h in board.hypotheses
        ],
    }

    from app.intel.cve import cve_snapshot_label
    cve_snapshot = cve_snapshot_label()

    return {
        "assessment": {
            "id": assessment_id,
            "title": assessment.title,
            "request": assessment.request or "",
            "targets": assessment.targets or [],
            "ports": assessment.ports or [],
            "exclusions": assessment.exclusions or [],
            "started_at": _iso(assessment.created_at),
            "finished_at": _iso(assessment.finished_at or utcnow()),
        },
        "risk": {
            "score": risk_summary["score"],
            "counts": _counts(findings),
            "confirmed": sum(1 for f in findings if f.status == "confirmed"),
            "suspected": sum(1 for f in findings if f.status in ("suspected", "candidate")),
        },
        "cve_snapshot": cve_snapshot,
        "findings": finding_items,
        "steps": step_items,
        "approvals": approval_items,
        "reasoning": reasoning_dict,
    }


def _is_nvidia_model(model: Any) -> bool:
    """Check if model is ChatNVIDIA to avoid guided_json incompatibility."""
    if model is None:
        return False
    cls_name = type(model).__name__
    module_name = getattr(type(model), "__module__", "")
    return "nvidia" in cls_name.lower() or "nvidia" in module_name.lower()


def _extract_report_narrative(raw_obj: Any) -> ReportNarrative | None:
    """Extract ReportNarrative from Pydantic object, dict, or AIMessage/text."""
    if isinstance(raw_obj, ReportNarrative):
        return raw_obj
    if isinstance(raw_obj, dict):
        try:
            return ReportNarrative.model_validate(raw_obj)
        except Exception:
            pass

    content = getattr(raw_obj, "content", None) or (raw_obj if isinstance(raw_obj, str) else None)
    candidates: list[str] = []
    if content and isinstance(content, str):
        candidates.append(content)

    additional_kwargs = getattr(raw_obj, "additional_kwargs", {}) or {}
    for k in ("reasoning", "reasoning_content"):
        if additional_kwargs.get(k):
            candidates.append(str(additional_kwargs[k]))

    for text in candidates:
        m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if m:
            try:
                return ReportNarrative.model_validate(json.loads(m.group(1)))
            except Exception:
                pass
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return ReportNarrative.model_validate(json.loads(text[start : end + 1]))
            except Exception:
                pass

    return None


async def write_narrative_result(
    context: dict[str, Any],
    model: BaseChatModel | None = None,
) -> tuple[ReportNarrative | None, str | None]:
    """Invoke the LLM for report narrative generation and validate output.

    Returns (narrative, None) on success or (None, error_str) on failure.
    """
    if model is None:
        from app.agents.model import build_report_model
        try:
            model = build_report_model()
        except Exception as exc:
            log.warning("failed to build report model: %s", exc)
            return None, f"build_report_model failed: {exc}"

    messages = [
        SystemMessage(content=ROLE_PROMPTS.get("report_writer")),
        HumanMessage(content=json.dumps(context, indent=2)),
    ]

    # For ChatNVIDIA, bypass with_structured_output to prevent guided_json 400 errors
    if _is_nvidia_model(model):
        try:
            response = await model.ainvoke(messages)
            narrative = _extract_report_narrative(response)
            if narrative is None:
                raise ValueError("failed to extract valid ReportNarrative JSON from NVIDIA model output")
            validate_narrative(narrative, context)
            return narrative, None
        except Exception as exc:
            log.warning("report narrative invoke failed with NVIDIA model: %s", exc)
            return None, str(exc)

    try:
        structured = model.with_structured_output(ReportNarrative)
        response = await structured.ainvoke(messages)

        if isinstance(response, dict):
            narrative = ReportNarrative.model_validate(response)
        elif isinstance(response, ReportNarrative):
            narrative = response
        elif isinstance(response, str):
            narrative = ReportNarrative.model_validate_json(response)
        else:
            narrative = _extract_report_narrative(response)
            if narrative is None:
                raise TypeError(f"unexpected model response type: {type(response)}")

        validate_narrative(narrative, context)
        return narrative, None
    except Exception as exc:
        log.warning("structured output failed; attempting direct invoke fallback: %s", exc)
        try:
            raw_resp = await model.ainvoke(messages)
            narrative = _extract_report_narrative(raw_resp)
            if narrative:
                validate_narrative(narrative, context)
                return narrative, None
        except Exception as exc2:
            log.warning("direct invoke fallback also failed: %s", exc2)
        log.warning("report narrative validation or invoke failed: %s", exc)
        return None, str(exc)


async def write_narrative(
    context: dict[str, Any],
    model: BaseChatModel | None = None,
) -> ReportNarrative | None:
    """Wrapper matching specification §8.5."""
    narrative, _ = await write_narrative_result(context, model)
    return narrative
