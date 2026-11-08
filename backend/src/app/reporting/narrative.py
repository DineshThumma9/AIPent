"""Report narrative schemas, context builder, prompt, and anti-hallucination validation.

Python is the security and anti-hallucination barrier. The LLM never writes raw Typst
markup; it outputs structured JSON conforming to ReportNarrative.
"""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import col, select

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage

from app.adapters.base import strip_html
from app.agents.loop.reasoning import build_evidence_board
from app.core.config import settings
from app.core.log import get_logger
from app.domain import risk
from app.domain.models import Approval, Assessment, Audit, Evidence, Finding, FindingCve, Step

log = get_logger("reporting.narrative")


class FindingNarrative(BaseModel):
    finding_id: int
    technical_analysis: str = Field(min_length=1, max_length=4000)
    impact: str = Field(min_length=1, max_length=2000)
    remediation: str = Field(min_length=1, max_length=2000)
    confidence_statement: str = Field(min_length=1, max_length=1000)
    observed_vs_inferred: str = Field(min_length=1, max_length=1500)


class ReportNarrative(BaseModel):
    executive_summary: str = Field(min_length=1, max_length=4000)
    methodology: str = Field(min_length=1, max_length=3000)
    risk_overview: str = Field(min_length=1, max_length=2500)
    findings: list[FindingNarrative] = Field(default_factory=list)
    limitations: str = Field(min_length=1, max_length=2500)
    recommendations: list[str] = Field(default_factory=list, max_length=12)
    conclusion: str = Field(min_length=1, max_length=2000)


REPORT_WRITER_PROMPT = """You are a senior VAPT report writer preparing a
client-ready report for an authorized, lab-only assessment.

You receive a JSON evidence pack. You may only use facts present in that pack.
You must not invent a CVE, CWE, CVSS score, affected asset, exploit result, or
remediation step. If the pack does not contain a value, omit it or say it was
not established.

Write for two audiences at once:
- an executive who needs business impact, risk, and what to fix first;
- an engineer who needs the observation, the inference, and the remediation.

For every finding, separate:
- OBSERVED: what a tool or probe actually showed, with evidence ids;
- INFERRED: what you conclude from it, and how confident that is.

Mention rejected approvals, failed steps, timeouts, and open questions in the
limitations section. A rejected action is not a finding; it is a coverage gap.

Return JSON matching the provided schema. No markdown, no preamble.
"""

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


def _iso(value: Any) -> str:
    return value.isoformat() if value else ""


def _clean_text(text: str | None) -> str:
    if not text:
        return ""
    text = strip_html(text)
    text = re.sub(r"^\[\d+\]\s*", "", text.strip())
    text = re.sub(r"^/:\s*", "", text)
    return text.strip()


def _counts(findings: list[Finding]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


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
    assessment = await session.get(Assessment, assessment_id)
    if not assessment:
        raise LookupError(f"assessment {assessment_id} not found")

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

    board = await build_evidence_board(session, assessment_id)
    risk_summary = risk.summarize(findings)

    evidence_by_finding: dict[int, list[Evidence]] = {}
    for ev in evidence:
        if ev.finding_id is not None:
            evidence_by_finding.setdefault(ev.finding_id, []).append(ev)

    finding_items = []
    for f in findings:
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
        finding_items.append({
            "id": f_id,
            "title": _clean_text(f.title),
            "severity": f.severity,
            "cvss": f.cvss,
            "cve": f.cve or [],
            "cwe": f.cwe or [],
            "status": f.status,
            "confidence": round(f.confidence, 2),
            "asset": f.asset,
            "endpoint": f.endpoint or "",
            "description": _clean_text(f.description),
            "impact": _clean_text(f.impact),
            "remediation": _clean_text(f.remediation),
            "evidence": [
                {
                    "id": row.id,
                    "tool": (row.locator.get("tool") if isinstance(row.locator, dict) else "nmap") or "nmap",
                    "excerpt": _clean_text(row.excerpt[:800]),
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

    from app.intel.cve import get_cve_catalog
    catalog = get_cve_catalog()
    cve_snapshot = f"{settings.vulnify_release} (2026-11-02)" if catalog.is_available else "CVE enrichment disabled"

    return {
        "assessment": {
            "id": assessment_id,
            "title": assessment.title,
            "request": assessment.request or "",
            "targets": assessment.targets or [],
            "ports": assessment.ports or [],
            "exclusions": assessment.exclusions or [],
            "started_at": _iso(assessment.created_at),
            "finished_at": _iso(assessment.finished_at),
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

    structured = model.with_structured_output(ReportNarrative)
    try:
        response = await structured.ainvoke([
            SystemMessage(content=REPORT_WRITER_PROMPT),
            HumanMessage(content=json.dumps(context, indent=2)),
        ])

        if isinstance(response, dict):
            narrative = ReportNarrative.model_validate(response)
        elif isinstance(response, ReportNarrative):
            narrative = response
        elif isinstance(response, str):
            narrative = ReportNarrative.model_validate_json(response)
        else:
            raise TypeError(f"unexpected model response type: {type(response)}")

        validate_narrative(narrative, context)
        return narrative, None
    except Exception as exc:
        log.warning("report narrative validation or invoke failed: %s", exc)
        return None, str(exc)


async def write_narrative(
    context: dict[str, Any],
    model: BaseChatModel | None = None,
) -> ReportNarrative | None:
    """Wrapper matching specification §8.5."""
    narrative, _ = await write_narrative_result(context, model)
    return narrative
