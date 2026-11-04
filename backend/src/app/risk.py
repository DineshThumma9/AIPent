"""Deterministic risk scoring.

No LLM writes a score. The formula and factors are visible in the report so a
reviewer can reproduce every number.

risk (0-10) = severity weight x (0.5 + 0.5 x confidence) x exposure x impact
"""

from sqlmodel import Session, select

from app.models import Assessment, Finding

SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 10.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.0,
    "info": 0.0,
}


def exposure(asset: str) -> tuple[str, float]:
    if asset in {"127.0.0.1", "::1", "localhost"} or asset.startswith("127."):
        return "loopback", 0.7
    if asset.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.")):
        return "internal", 0.85
    return "external", 1.0


def impact(endpoint: str | None) -> tuple[str, float]:
    value = endpoint or ""
    if value.startswith("http"):
        return "app", 1.0
    if value.startswith(("tcp/", "udp/")):
        return "service", 0.8
    return "host", 0.9


def finding_score(finding: Finding) -> dict:
    weight = SEVERITY_WEIGHT.get(finding.severity, 0.0)
    exposure_band, exposure_factor = exposure(finding.asset)
    impact_band, impact_factor = impact(finding.endpoint)
    confidence = max(0.0, min(1.0, finding.confidence))
    score = weight * (0.5 + 0.5 * confidence) * exposure_factor * impact_factor
    return {
        "finding_id": finding.id,
        "title": finding.title,
        "severity": finding.severity,
        "severity_weight": weight,
        "confidence": confidence,
        "exposure": exposure_band,
        "exposure_factor": exposure_factor,
        "impact": impact_band,
        "impact_factor": impact_factor,
        "score": round(min(score, 10.0), 2),
    }


def summarize(findings: list[Finding]) -> dict:
    scores = [finding_score(finding) for finding in findings]
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return {
        "score": max((row["score"] for row in scores), default=0.0),
        "counts": counts,
        "finding_count": len(findings),
        "top": sorted(scores, key=lambda row: row["score"], reverse=True)[:5],
    }


def refresh_risk(session: Session, assessment_id: int) -> dict:
    assessment = session.get(Assessment, assessment_id)
    findings = session.exec(
        select(Finding).where(Finding.assessment_id == assessment_id)
    ).all()
    summary = summarize(findings)
    if assessment is not None:
        assessment.risk_score = summary["score"]
        session.commit()
    return summary
