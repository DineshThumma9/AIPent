"""Direct tool execution for the V2 loop.

Direct tools are safe in-process reads/writes that do not invoke external
scanners or require human approval.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from app.agents.loop.contracts import Observation
from app.agents.loop.reasoning import record_hypothesis, update_hypothesis
from app.agents.loop.tool_specs import ToolSpec
from app.core.config import settings
from app.domain.models import Step
from app.persistence.finding_repo import FindingRepo


async def read_artifact(
    session: AsyncSession,
    assessment_id: int,
    step_id: int,
    max_chars: int = 4000,
    search: str | None = None,
) -> Observation:
    step = await session.get(Step, step_id)
    if step is None or step.assessment_id != assessment_id:
        return Observation(
            ok=False,
            status="error",
            action="read_artifact",
            target=str(step_id),
            summary=f"Step {step_id} not found in this assessment",
            errors=[f"step {step_id} not found"],
        )

    if not step.output_path or not Path(step.output_path).exists():
        return Observation(
            ok=False,
            status="error",
            action="read_artifact",
            target=step.target,
            summary=f"Step {step_id} has no artifact file",
            errors=["no artifact file"],
        )

    try:
        path = Path(step.output_path)
        # Verify artifact is within data directory
        data_dir = settings.artifacts_path.resolve()
        if not path.resolve().is_relative_to(data_dir) and not str(path).startswith("/tmp"):
            return Observation(
                ok=False,
                status="blocked",
                action="read_artifact",
                target=step.target,
                summary="Access to artifact outside allowed directory is blocked",
                errors=["path traversal blocked"],
            )

        content = path.read_text(encoding="utf-8", errors="replace")
        max_chars = min(max_chars, 8000)

        if search:
            idx = content.lower().find(search.lower())
            if idx != -1:
                start = max(0, idx - 200)
                end = min(len(content), start + max_chars)
                excerpt = content[start:end]
            else:
                excerpt = f"Search term {search!r} not found in artifact."
        else:
            excerpt = content[:max_chars]

        return Observation(
            ok=True,
            status="succeeded",
            action="read_artifact",
            target=step.target,
            step_id=step.id,
            summary=f"Read {len(excerpt)} chars from artifact for step {step_id}:\n{excerpt}",
        )
    except Exception as exc:
        return Observation(
            ok=False,
            status="error",
            action="read_artifact",
            target=step.target,
            summary=f"Failed reading artifact: {exc}",
            errors=[str(exc)],
        )


async def list_services(
    session: AsyncSession,
    assessment_id: int,
    limit: int = 50,
) -> Observation:
    repo = FindingRepo(session)
    services = await repo.get_services(assessment_id)
    summaries = [f"{s.endpoint or s.asset}: {s.title}" for s in services[:limit]]
    summary_text = (
        f"Found {len(services)} services:\n" + "\n".join(f"- {s}" for s in summaries)
        if services
        else "No services found."
    )
    return Observation(
        ok=True,
        status="succeeded",
        action="list_services",
        target="in-scope targets",
        summary=summary_text,
    )


async def list_findings(
    session: AsyncSession,
    assessment_id: int,
    status: str | None = None,
    limit: int = 50,
) -> Observation:
    repo = FindingRepo(session)
    candidates = await repo.get_candidates(assessment_id)
    if status:
        candidates = [c for c in candidates if c.status == status]
    summaries = [f"#{c.id} [{c.status}] {c.title} ({c.asset})" for c in candidates[:limit]]
    summary_text = (
        f"Found {len(candidates)} findings:\n" + "\n".join(f"- {c}" for c in summaries)
        if candidates
        else "No findings matching criteria."
    )
    return Observation(
        ok=True,
        status="succeeded",
        action="list_findings",
        target="assessment",
        summary=summary_text,
    )


async def update_finding_status(
    session: AsyncSession,
    assessment_id: int,
    finding_id: int,
    status: str,
    reasoning: str,
) -> Observation:
    repo = FindingRepo(session)
    res = await repo.update_status(
        finding_id=finding_id,
        assessment_id=assessment_id,
        status=status,
        reasoning=reasoning,
        actor="validation",
    )
    if "error" in res:
        return Observation(
            ok=False,
            status="error",
            action="update_finding_status",
            target=str(finding_id),
            summary=f"Failed to update finding #{finding_id}: {res['error']}",
            errors=[res["error"]],
        )
    return Observation(
        ok=True,
        status="succeeded",
        action="update_finding_status",
        target=str(finding_id),
        summary=f"Updated finding #{finding_id} status to {status}. Reasoning: {reasoning}",
        findings_updated=[finding_id],
    )


async def lookup_cve_direct(
    session: AsyncSession,
    assessment_id: int,
    cve_id: str | None = None,
    vendor: str | None = None,
    product: str | None = None,
    version: str | None = None,
    cpe: str | None = None,
) -> Observation:
    from app.intel.cve import get_cve_catalog

    catalog = get_cve_catalog()
    if not catalog.is_available:
        return Observation(
            ok=True,
            status="succeeded",
            action="lookup_cve",
            target=cve_id or f"{vendor}:{product}",
            summary="CVE intelligence disabled (catalog not available).",
            facts={"available": False, "cve": None, "candidates": []},
        )

    if cve_id:
        record = catalog.hydrate(cve_id)
        if not record:
            return Observation(
                ok=True,
                status="succeeded",
                action="lookup_cve",
                target=cve_id,
                summary=f"CVE {cve_id} not found in catalog.",
                facts={"available": True, "found": False, "cve_id": cve_id},
            )
        summary = (
            f"CVE {record.cve_id}: CVSS {record.cvss_score or 'N/A'} ({record.cvss_severity or 'unknown'}). "
            f"KEV listed: {record.kev}. EPSS: {record.epss_score or 'N/A'}. "
            f"{record.summary[:200]}"
        )
        return Observation(
            ok=True,
            status="succeeded",
            action="lookup_cve",
            target=record.cve_id,
            summary=summary,
            facts={
                "available": True,
                "found": True,
                "cve_id": record.cve_id,
                "title": record.title,
                "cvss_score": record.cvss_score,
                "cvss_severity": record.cvss_severity,
                "cwe": record.cwe,
                "kev": record.kev,
                "epss_score": record.epss_score,
                "references": [r.url for r in record.references[:5]],
            },
        )

    # Candidate search
    candidates = catalog.candidates(vendor=vendor or "", product=product or "", version=version, cpe=cpe)
    if not candidates:
        target = cpe or f"{vendor}:{product}:{version or '*'}"
        return Observation(
            ok=True,
            status="succeeded",
            action="lookup_cve",
            target=target,
            summary=f"No grounded CVE candidates found for {target}.",
            facts={"available": True, "candidates": []},
        )

    cve_list = [c.cve_id for c in candidates[:10]]
    summary = f"Found {len(candidates)} candidate CVEs (top: {', '.join(cve_list[:5])})."
    return Observation(
        ok=True,
        status="succeeded",
        action="lookup_cve",
        target=cpe or f"{vendor}:{product}",
        summary=summary,
        facts={
            "available": True,
            "candidates": [
                {
                    "cve_id": c.cve_id,
                    "cvss_score": c.cvss_score,
                    "cvss_severity": c.cvss_severity,
                    "confidence": c.confidence,
                    "match_reason": c.match_reason,
                    "source_url": c.source_url,
                }
                for c in candidates[:10]
            ],
        },
    )


async def hash_identify_direct(
    session: AsyncSession,
    assessment_id: int,
    hash_value: str,
    source_step_id: int,
) -> Observation:
    """Identify the hash type using local heuristics, verifying it appears in the artifact."""
    from app.domain.models import Audit

    step = await session.get(Step, source_step_id)
    if step is None or step.assessment_id != assessment_id:
        return Observation(
            ok=False,
            status="error",
            action="hash_identify",
            target=hash_value[:16],
            summary=f"Source step {source_step_id} not found in this assessment.",
            errors=[f"step {source_step_id} not found"],
        )

    if not step.output_path or not Path(step.output_path).exists():
        return Observation(
            ok=False,
            status="error",
            action="hash_identify",
            target=hash_value[:16],
            summary=f"Source step {source_step_id} has no artifact file.",
            errors=["artifact file not found"],
        )

    text = Path(step.output_path).read_text(errors="replace")
    clean_val = hash_value.strip()
    if clean_val.lower() not in text.lower():
        return Observation(
            ok=False,
            status="rejected",
            action="hash_identify",
            target=clean_val[:16],
            summary="Hash identification rejected: hash_value does not appear in the source step artifact.",
            errors=["hash_value not present in artifact"],
        )

    # Local Python heuristics per §9.1
    candidates: list[dict[str, Any]] = []
    confidence = "medium"

    if clean_val.startswith(("$2a$", "$2b$", "$2y$")):
        candidates.append({"mode": 3200, "name": "bcrypt"})
        confidence = "high"
    elif clean_val.startswith("$6$"):
        candidates.append({"mode": 1800, "name": "sha512crypt"})
        confidence = "high"
    elif clean_val.startswith("$5$"):
        candidates.append({"mode": 7400, "name": "sha256crypt"})
        confidence = "high"
    elif clean_val.startswith("$1$"):
        candidates.append({"mode": 500, "name": "md5crypt"})
        confidence = "high"
    elif len(clean_val) == 32 and all(c in "0123456789abcdefABCDEF" for c in clean_val):
        candidates.append({"mode": 0, "name": "MD5"})
        candidates.append({"mode": 2600, "name": "md5(md5($pass))"})
        confidence = "medium"
    elif len(clean_val) == 40 and all(c in "0123456789abcdefABCDEF" for c in clean_val):
        candidates.append({"mode": 100, "name": "SHA-1"})
        candidates.append({"mode": 110, "name": "sha1($pass.$salt)"})
        confidence = "medium"
    elif len(clean_val) == 64 and all(c in "0123456789abcdefABCDEF" for c in clean_val):
        candidates.append({"mode": 1400, "name": "SHA-256"})
        confidence = "medium"
    else:
        confidence = "low"

    session.add(
        Audit(
            assessment_id=assessment_id,
            event_type="hash.identified",
            payload={
                "source_step_id": source_step_id,
                "candidates": candidates,
                "confidence": confidence,
            },
        )
    )
    await session.commit()

    cand_names = [c["name"] for c in candidates]
    summary = (
        f"Identified {len(candidates)} candidate algorithm(s): {', '.join(cand_names)} (confidence: {confidence})."
        if candidates
        else f"Could not determine hash format for {clean_val[:16]}... (confidence: low)."
    )

    return Observation(
        ok=True,
        status="succeeded",
        action="hash_identify",
        target=f"step:{source_step_id}",
        summary=summary,
        facts={
            "candidates": candidates,
            "confidence": confidence,
            "source_step_id": source_step_id,
        },
    )


async def run_direct(
    session: AsyncSession,
    spec: ToolSpec,
    args: dict[str, Any],
    state: dict[str, Any],
) -> Observation:
    """Dispatch execution of a direct tool."""
    assessment_id = state["assessment_id"]
    run_id = state["run_id"]
    role = state["role"]

    if spec.name == "read_artifact":
        return await read_artifact(session, assessment_id, **args)
    if spec.name == "list_services":
        return await list_services(session, assessment_id, **args)
    if spec.name == "list_findings":
        return await list_findings(session, assessment_id, **args)
    if spec.name == "lookup_cve":
        return await lookup_cve_direct(session, assessment_id, **args)
    if spec.name == "hash_identify":
        return await hash_identify_direct(session, assessment_id, **args)
    if spec.name == "record_hypothesis":
        return await record_hypothesis(
            session=session,
            assessment_id=assessment_id,
            run_id=run_id,
            role=role,
            **args,
        )
    if spec.name == "update_hypothesis":
        return await update_hypothesis(
            session=session,
            assessment_id=assessment_id,
            run_id=run_id,
            role=role,
            **args,
        )
    if spec.name == "update_finding_status":
        return await update_finding_status(
            session=session,
            assessment_id=assessment_id,
            finding_id=args["finding_id"],
            status=args["status"],
            reasoning=args.get("reasoning", ""),
        )

    raise ValueError(f"unknown direct tool {spec.name}")
