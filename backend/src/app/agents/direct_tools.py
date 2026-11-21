"""Direct tool execution for the V2 loop.

Direct tools are safe in-process reads/writes that do not invoke external
scanners or require human approval.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.contracts import Observation
from app.agents.reasoning import record_hypothesis, update_hypothesis
from app.agents.tool_specs import ToolSpec
from app.core.config import settings
from app.parsers import read_sidecar_manifest
from app.persistence.audit_repo import AuditRepo
from app.persistence.finding_repo import FindingRepo
from app.persistence.step_repo import StepRepo


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _finding_slug(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:60] or "finding"


async def read_artifact(
    session: AsyncSession,
    assessment_id: int,
    step_id: int,
    max_chars: int = 4000,
    search: str | None = None,
    offset: int = 0,
    view: str | None = None,
    **kwargs: Any,
) -> Observation:
    step = await StepRepo(session).get_by_id(step_id)
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

        manifest = read_sidecar_manifest(path)
        view_mode = (view or kwargs.get("view") or "").lower().strip()

        # 1. Manifest view mode
        if view_mode in ("manifest", "forms", "routes", "files"):
            if not manifest:
                return Observation(
                    ok=True,
                    status="succeeded",
                    action="read_artifact",
                    target=step.target,
                    step_id=step.id,
                    summary=f"No sidecar manifest available for step {step_id} ({path.name}).",
                    facts={},
                )

            if view_mode == "routes":
                content_out = json.dumps(manifest.get("routes", []), indent=2)
            elif view_mode == "files":
                content_out = json.dumps(manifest.get("files", []), indent=2)
            elif view_mode == "forms":
                content_out = json.dumps(manifest.get("forms", []), indent=2)
            else:
                content_out = json.dumps(manifest, indent=2)

            return Observation(
                ok=True,
                status="succeeded",
                action="read_artifact",
                target=step.target,
                step_id=step.id,
                summary=f"Manifest ({view_mode}) for step {step_id} ({path.name}):\n{content_out[:max_chars]}",
                facts={"manifest": manifest},
            )

        content = path.read_text(encoding="utf-8", errors="replace")
        max_chars = min(max(max_chars, 100), 8000)
        offset = max(0, int(offset or 0))

        # 2. Search mode (Grep-style multi-match)
        if search is not None and str(search).strip():
            search_str = str(search).lower().strip()
            lines = content.splitlines()

            # For normal line-based files: line grep with context
            if len(lines) > 1 and max(len(l) for l in lines) < 2500:
                matching_indices = [
                    idx for idx, line in enumerate(lines) if search_str in line.lower()
                ]

                if not matching_indices:
                    excerpt = f"Search term {search!r} not found in artifact."
                else:
                    parts: list[str] = [
                        f"Found {len(matching_indices)} match(es) for {search!r}:"
                    ]
                    shown = 0
                    for m_idx in matching_indices[:8]:
                        start_ctx = max(0, m_idx - 1)
                        end_ctx = min(len(lines), m_idx + 2)
                        block_lines = [
                            f"  {ln + 1:4d}: {lines[ln]}" for ln in range(start_ctx, end_ctx)
                        ]
                        parts.append(f"[Match {shown + 1} at line {m_idx + 1}]:\n" + "\n".join(block_lines))
                        shown += 1
                        if sum(len(p) for p in parts) >= max_chars - 200:
                            break

                    if len(matching_indices) > shown:
                        parts.append(f"... (+{len(matching_indices) - shown} more matches truncated)")
                    excerpt = "\n\n".join(parts)[:max_chars]
            else:
                # For single-line minified files (or huge lines)
                first_idx = content.lower().find(search_str, offset)
                if first_idx != -1:
                    start = max(0, first_idx - 200)
                    end = min(len(content), start + max_chars)
                    excerpt = content[start:end]
                else:
                    excerpt = f"Search term {search!r} not found in artifact."
        else:
            manifest_banner = ""
            if manifest and offset == 0:
                routes_cnt = len(manifest.get("routes", []))
                forms_cnt = len(manifest.get("forms", []))
                files_cnt = len(manifest.get("files", []))
                manifest_banner = f"[Manifest: {routes_cnt} route(s), {forms_cnt} form(s), {files_cnt} file(s)]\n"

            raw_slice = content[offset : offset + max_chars]
            excerpt = f"{manifest_banner}{raw_slice}"

        return Observation(
            ok=True,
            status="succeeded",
            action="read_artifact",
            target=step.target,
            step_id=step.id,
            summary=f"Read {len(excerpt)} chars from artifact for step {step_id} (offset {offset}, total {len(content)} chars):\n{excerpt}",
            facts={},
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
    **kwargs: Any,
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
    **kwargs: Any,
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
    reasoning: str = "",
    **kwargs: Any,
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


async def record_finding(
    session: AsyncSession,
    assessment_id: int,
    run_id: str,
    role: str,
    title: str = "",
    asset: str = "",
    endpoint: str = "",
    severity: str | None = None,
    description: str = "",
    evidence_step_ids: list[int] | None = None,
    reasoning: str = "",
    cwe: list[str] | None = None,
    finding_id: int | str | None = None,
    **kwargs: Any,
) -> Observation:
    """Create or extend a finding from the agent's own observation."""
    clean_finding_id: int | None = None
    if finding_id not in (None, "", "none", "None", "null", "NULL"):
        try:
            clean_finding_id = int(finding_id)
        except (ValueError, TypeError):
            clean_finding_id = None

    repo = FindingRepo(session)
    res = await repo.record_agent_finding(
        assessment_id=assessment_id,
        run_id=run_id,
        role=role,
        title=title,
        asset=asset,
        endpoint=endpoint,
        severity=severity,
        description=description,
        evidence_step_ids=evidence_step_ids,
        reasoning=reasoning,
        cwe=cwe,
        finding_id=clean_finding_id,
    )
    if not res["ok"]:
        return Observation(
            ok=False,
            status=res["status"],
            action="record_finding",
            target=asset,
            summary=res["summary"],
            errors=res.get("errors", []),
        )

    finding = res["finding"]
    created = res["created"]
    evidence_ids = res["evidence_ids"]
    await session.commit()

    return Observation(
        ok=True,
        status="succeeded",
        action="record_finding",
        target=asset,
        findings_created=[finding.id] if created else [],
        findings_updated=[] if created else [finding.id],
        evidence_ids=evidence_ids,
        summary=(
            f"Recorded finding #{finding.id} as suspected with "
            f"{len(evidence_ids)} evidence row(s)."
            if created
            else f"Extended finding #{finding.id} with "
            f"{len(evidence_ids)} new evidence row(s)."
        ),
        facts={
            "finding_id": finding.id,
            "created": created,
            "evidence_ids": evidence_ids,
        },
        next_hint=(
            "Run a targeted proving probe, then confirm with "
            "update_finding_status."
        ),
    )


async def lookup_cve_direct(
    session: AsyncSession,
    assessment_id: int,
    cve_id: str | None = None,
    vendor: str | None = None,
    product: str | None = None,
    version: str | None = None,
    cpe: str | None = None,
    **kwargs: Any,
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
    **kwargs: Any,
) -> Observation:
    """Identify the hash type using local heuristics, verifying it appears in the artifact."""
    step = await StepRepo(session).get_by_id(source_step_id)
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

    await AuditRepo(session).record_event(
        assessment_id=assessment_id,
        event_type="hash.identified",
        payload={
            "source_step_id": source_step_id,
            "candidates": candidates,
            "confidence": confidence,
        },
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

    try:
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
        if spec.name == "record_finding":
            return await record_finding(
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
                finding_id=args.get("finding_id", 0),
                status=args.get("status", "suspected"),
                reasoning=args.get("reasoning", ""),
            )

        raise ValueError(f"unknown direct tool {spec.name}")
    except Exception as exc:
        return Observation(
            ok=False,
            status="error",
            action=spec.name,
            target=str(args.get("target") or args.get("step_id") or "direct_tool"),
            summary=f"Direct tool {spec.name} failed with error: {exc}",
            errors=[str(exc)],
        )
