"""Finding and Evidence persistence."""

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from app.domain.models import (
    Audit,
    Evidence,
    Finding,
    FindingCve,
    utcnow,
)
from app.persistence.base import BaseRepo

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
STATUS_RANK = {"suspected": 0, "confirmed": 1, "false_positive": 2}


class FindingRepo(BaseRepo):
    """All database access for findings and evidence."""

    async def create(
        self,
        assessment_id: int,
        canonical_key: str,
        asset: str,
        title: str,
        description: str = "",
        severity: str = "info",
        confidence: float = 0.5,
        endpoint: str | None = None,
        cwe: list[str] | None = None,
        cve: list[str] | None = None,
        origin: str = "tool",
        status: str = "suspected",
    ) -> Finding:
        finding = Finding(
            assessment_id=assessment_id,
            canonical_key=canonical_key,
            asset=asset,
            endpoint=endpoint,
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            cwe=cwe or [],
            cve=cve or [],
            origin=origin,
            status=status,
        )
        self.session.add(finding)
        await self.session.flush()

        if cve and finding.id:
            for item in cve:
                await self.record_finding_cve(
                    finding_id=finding.id,
                    cve_id=item,
                    source="scanner_reference",
                    match_reason="scanner_reference",
                    commit=False,
                )

        await self.session.commit()
        await self.session.refresh(finding)
        return finding

    async def record_finding_cve(
        self,
        finding_id: int,
        cve_id: str,
        source: str = "nvd",
        source_url: str = "",
        match_reason: str = "cpe_exact",
        confidence: str = "high",
        catalog_release: str | None = None,
        commit: bool = True,
    ) -> FindingCve:
        from app.core.config import settings
        from app.intel.cve import get_cve_catalog

        clean_cve = cve_id.strip().upper()
        if not source_url:
            catalog = get_cve_catalog()
            refs = catalog.references(clean_cve)
            source_url = refs[0].url if refs else f"https://nvd.nist.gov/vuln/detail/{clean_cve}"

        # Check existing row
        existing = await self.session.execute(
            select(FindingCve).where(
                FindingCve.finding_id == finding_id,
                FindingCve.cve_id == clean_cve,
            )
        )
        row = existing.scalars().first()
        if row:
            return row

        fc = FindingCve(
            finding_id=finding_id,
            cve_id=clean_cve,
            source=source,
            source_url=source_url,
            catalog_release=catalog_release or settings.vulnify_release,
            match_reason=match_reason,
            confidence=confidence,
        )
        self.session.add(fc)
        if commit:
            await self.session.commit()
            await self.session.refresh(fc)
        else:
            await self.session.flush()
        return fc

    async def get_cves_for_finding(self, finding_id: int) -> list[FindingCve]:
        result = await self.session.execute(
            select(FindingCve).where(FindingCve.finding_id == finding_id)
        )
        return list(result.scalars().all())

    async def get_all_cves(self, assessment_id: int) -> list[FindingCve]:
        result = await self.session.execute(
            select(FindingCve)
            .join(Finding, FindingCve.finding_id == Finding.id)
            .where(Finding.assessment_id == assessment_id)
        )
        return list(result.scalars().all())

    async def get(self, finding_id: int) -> Finding | None:
        return await self.session.get(Finding, finding_id)

    async def get_all(
        self,
        assessment_id: int,
        status: str | None = None,
        canonical_key_contains: str | None = None,
        limit: int = 20,
    ) -> list[Finding]:
        statement = select(Finding).where(Finding.assessment_id == assessment_id)
        if status:
            statement = statement.where(Finding.status == status)
        result = await self.session.execute(statement)
        rows = list(result.scalars().all())
        if canonical_key_contains:
            rows = [
                row for row in rows if canonical_key_contains in row.canonical_key
            ]
        rows.sort(key=lambda row: row.updated_at, reverse=True)
        return rows[:limit]

    async def count_by_assessment(self, assessment_id: int) -> int:
        result = await self.session.execute(
            select(Finding).where(Finding.assessment_id == assessment_id)
        )
        return len(list(result.scalars().all()))

    async def get_candidates(self, assessment_id: int) -> list[Finding]:
        """Return findings that are not service facts (nmap/open ports)."""
        result = await self.session.execute(
            select(Finding).where(Finding.assessment_id == assessment_id)
        )
        rows = list(result.scalars().all())
        return [
            row
            for row in rows
            if not (
                (row.canonical_key or "").startswith("nmap:")
                or (row.title or "").lower().startswith("open ")
            )
        ]

    async def get_services(self, assessment_id: int) -> list[Finding]:
        """Return service findings (nmap/open ports only)."""
        result = await self.session.execute(
            select(Finding).where(Finding.assessment_id == assessment_id)
        )
        rows = list(result.scalars().all())
        return [
            row
            for row in rows
            if (row.canonical_key or "").startswith("nmap:")
            or (row.title or "").lower().startswith("open ")
        ]

    async def rank_candidates(self, assessment_id: int) -> list[Finding]:
        """Return candidate findings ranked by status, severity, confidence."""
        rows = await self.get_candidates(assessment_id)
        return sorted(
            rows,
            key=lambda row: (
                STATUS_RANK.get(row.status, 9),
                SEVERITY_RANK.get(row.severity, 9),
                -float(row.confidence or 0),
                -(row.updated_at.timestamp() if row.updated_at else 0),
            ),
        )

    async def update_status(
        self,
        finding_id: int,
        assessment_id: int,
        status: str,
        reasoning: str,
        actor: str = "assessment_agent",
    ) -> dict[str, Any]:
        """Update finding status with audit trail.

        CONFIRMED and FALSE_POSITIVE require at least one executed
        curl_tool evidence row with a non-null http_status.
        """
        from app.agents.control import audit

        row = await self.session.get(Finding, finding_id)
        if row is None or row.assessment_id != assessment_id:
            return {"error": f"finding {finding_id} not in current assessment"}

        if status not in ("confirmed", "false_positive", "suspected"):
            return {"error": "status must be confirmed, false_positive, or suspected"}

        if status in ("confirmed", "false_positive"):
            evidence_result = await self.session.execute(
                select(Evidence).where(Evidence.finding_id == finding_id)
            )
            evidence = list(evidence_result.scalars().all())
            executed = any(
                (item.locator or {}).get("tool") == "curl_tool"
                and (item.locator or {}).get("http_status") is not None
                for item in evidence
            )
            if not executed:
                return {
                    "error": (
                        "verdict blocked: no executed curl_tool evidence is "
                        "linked to this finding. Queue requests with "
                        "curl_tool(..., finding_id=...) and wait for the action "
                        "gate to execute them."
                    )
                }

        old = row.status
        row.status = status
        row.updated_at = utcnow()
        self.session.add(
            Audit(
                assessment_id=assessment_id,
                actor=actor,
                event_type="verification.status_updated",
                payload={
                    "finding_id": finding_id,
                    "from": old,
                    "to": status,
                    "by": actor,
                    "reasoning": reasoning,
                },
            )
        )
        await self.session.commit()
        return {
            "updated": True,
            "finding_id": finding_id,
            "status": status,
            "previous": old,
            "audited": True,
        }

    async def add_evidence(
        self,
        finding_id: int,
        step_id: int,
        locator: dict[str, Any],
        excerpt: str = "",
    ) -> Evidence:
        evidence = Evidence(
            finding_id=finding_id,
            step_id=step_id,
            locator=locator,
            excerpt=excerpt[:600],
        )
        self.session.add(evidence)
        await self.session.commit()
        await self.session.refresh(evidence)
        return evidence

    async def get_evidence_for_finding(self, finding_id: int) -> list[Evidence]:
        result = await self.session.execute(
            select(Evidence).where(Evidence.finding_id == finding_id)
        )
        return list(result.scalars().all())
