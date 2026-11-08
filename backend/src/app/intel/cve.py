"""Vulnify CVE catalog adapter for deterministic, grounded CVE intelligence.

Connects to a pinned, read-only SQLite database (vulnify) containing CVEs,
CPE matches, CVSS scores, CISA KEV status, EPSS scores, and upstream references.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.core.log import get_logger

log = get_logger("intel.cve")

CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


@dataclass
class Reference:
    url: str
    source: str = ""
    title: str = ""
    trust: str = ""


@dataclass
class CveRecord:
    cve_id: str
    title: str = ""
    summary: str = ""
    cvss_score: float | None = None
    cvss_severity: str = ""
    cvss_version: str = ""
    cwe: list[str] = field(default_factory=list)
    kev: bool = False
    epss_score: float | None = None
    epss_percentile: float | None = None
    references: list[Reference] = field(default_factory=list)
    published: str = ""
    modified: str = ""


@dataclass
class CveCandidate:
    cve_id: str
    summary: str = ""
    cvss_score: float | None = None
    cvss_severity: str = ""
    cwe: list[str] = field(default_factory=list)
    match_reason: str = "cpe_exact"  # scanner_reference | cpe_exact | version_range | manual
    confidence: str = "medium"  # high | medium | low
    source_url: str = ""
    criteria: str = ""


class CveCatalog:
    """Read-only SQLite adapter for Vulnify CVE catalog."""

    def __init__(self, db_path: Path | str | None = None, release: str | None = None):
        self.release = release or settings.vulnify_release
        self.db_path = self._resolve_db_path(db_path)
        self.is_available = False
        self._conn: sqlite3.Connection | None = None

        if self.db_path and self.db_path.exists():
            try:
                # Open in read-only mode via URI
                uri = f"file:{self.db_path.resolve()}?mode=ro"
                self._conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
                self._conn.row_factory = sqlite3.Row
                if self._verify_schema():
                    self.is_available = True
                    log.info("Vulnify CVE catalog connected path=%s release=%s", self.db_path, self.release)
                else:
                    log.warning("Vulnify database at %s failed schema verification; CVE enrichment disabled", self.db_path)
            except Exception as exc:
                log.warning("Failed to open Vulnify database at %s: %s; CVE enrichment disabled", self.db_path, exc)
                self.is_available = False
        else:
            log.warning("Vulnify database not found at %s; CVE enrichment disabled", self.db_path)

    def _resolve_db_path(self, db_path: Path | str | None) -> Path | None:
        if db_path is not None:
            return Path(db_path)

        # Check configured path
        configured = Path(settings.vulnify_db_path)
        if configured.exists():
            return configured

        # Check standard project locations
        candidates = [
            Path("vulnify.db"),
            Path(__file__).parents[4] / "vulnify.db",  # workspace root
            Path(__file__).parents[3] / "vulnify.db",
            Path("/data/vulnify.db"),
        ]
        for c in candidates:
            if c.exists():
                return c
        return configured

    def _verify_schema(self) -> bool:
        if not self._conn:
            return False
        cur = self._conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cur.fetchall()}
        required = {"cve", "cvss", "cpe_match", "reference"}
        return required.issubset(tables)

    def hydrate(self, cve_id: str) -> CveRecord | None:
        """Hydrate complete CVE facts from the catalog.

        Returns CVSS, CWE, KEV status, EPSS, and reference URLs.
        """
        if not self.is_available or not self._conn:
            return None

        clean_id = cve_id.strip().upper()
        if not CVE_REGEX.match(clean_id):
            return None

        cur = self._conn.cursor()

        # 1. Base CVE row
        cur.execute(
            "SELECT title, summary, published, modified FROM cve WHERE cve_id = ?",
            (clean_id,),
        )
        cve_row = cur.fetchone()
        if not cve_row:
            return None

        # 2. CVSS scores (select best score / version)
        cur.execute(
            "SELECT score, severity, version FROM cvss WHERE cve_id = ? ORDER BY version DESC, score DESC",
            (clean_id,),
        )
        cvss_rows = cur.fetchall()
        cvss_score = float(cvss_rows[0]["score"]) if cvss_rows and cvss_rows[0]["score"] is not None else None
        cvss_severity = str(cvss_rows[0]["severity"] or "") if cvss_rows else ""
        cvss_version = str(cvss_rows[0]["version"] or "") if cvss_rows else ""

        # 3. CWEs
        cur.execute(
            "SELECT cwe_id FROM cve_cwe WHERE cve_id = ? ORDER BY cwe_id",
            (clean_id,),
        )
        cwes = [str(r["cwe_id"]) for r in cur.fetchall()]

        # 4. KEV
        cur.execute(
            "SELECT listed FROM kev WHERE cve_id = ?",
            (clean_id,),
        )
        kev_row = cur.fetchone()
        kev = bool(kev_row and kev_row["listed"] == 1)

        # 5. EPSS
        cur.execute(
            "SELECT epss_score, epss_percentile FROM intel WHERE cve_id = ?",
            (clean_id,),
        )
        intel_row = cur.fetchone()
        epss_score = float(intel_row["epss_score"]) if intel_row and intel_row["epss_score"] is not None else None
        epss_percentile = float(intel_row["epss_percentile"]) if intel_row and intel_row["epss_percentile"] is not None else None

        # 6. References
        cur.execute(
            "SELECT url, source, title, trust FROM reference WHERE cve_id = ? ORDER BY id LIMIT 20",
            (clean_id,),
        )
        refs = [
            Reference(
                url=str(r["url"] or ""),
                source=str(r["source"] or ""),
                title=str(r["title"] or ""),
                trust=str(r["trust"] or ""),
            )
            for r in cur.fetchall()
            if r["url"]
        ]
        if not refs:
            refs = [Reference(url=f"https://nvd.nist.gov/vuln/detail/{clean_id}", source="nvd")]

        return CveRecord(
            cve_id=clean_id,
            title=str(cve_row["title"] or ""),
            summary=str(cve_row["summary"] or ""),
            cvss_score=cvss_score,
            cvss_severity=cvss_severity,
            cvss_version=cvss_version,
            cwe=cwes,
            kev=kev,
            epss_score=epss_score,
            epss_percentile=epss_percentile,
            references=refs,
            published=str(cve_row["published"] or ""),
            modified=str(cve_row["modified"] or ""),
        )

    def candidates(
        self,
        vendor: str = "",
        product: str = "",
        version: str | None = None,
        cpe: str | None = None,
        limit: int = 20,
    ) -> list[CveCandidate]:
        """Find candidate CVEs for a service or CPE prefix.

        Returns conservative candidates with confidence, never confirmation.
        """
        if not self.is_available or not self._conn:
            return []

        cur = self._conn.cursor()
        matches: list[tuple[str, str]] = []  # (cve_id, criteria)

        if cpe:
            clean_cpe = cpe.strip().lower()
            cur.execute(
                "SELECT cve_id, criteria FROM cpe_match WHERE criteria LIKE ? LIMIT ?",
                (f"{clean_cpe}%", limit),
            )
            matches = [(str(r["cve_id"]), str(r["criteria"])) for r in cur.fetchall()]
        elif vendor and product:
            v_clean = vendor.strip().lower()
            p_clean = product.strip().lower()
            pattern = f"cpe:2.3:%:{v_clean}:{p_clean}:%"
            cur.execute(
                "SELECT cve_id, criteria FROM cpe_match WHERE criteria LIKE ? LIMIT ?",
                (pattern, limit),
            )
            matches = [(str(r["cve_id"]), str(r["criteria"])) for r in cur.fetchall()]

            if not matches:
                # Fallback to affected_product table join
                query = """
                SELECT ap.cve_id, COALESCE(p.name, '') as prod_name
                FROM vendor v
                JOIN product p ON p.vendor_id = v.vendor_id
                JOIN affected_product ap ON ap.product_id = p.product_id
                WHERE lower(v.name) = ? AND lower(p.name) = ?
                LIMIT ?
                """
                cur.execute(query, (v_clean, p_clean, limit))
                matches = [(str(r["cve_id"]), str(r["prod_name"])) for r in cur.fetchall()]

        candidates: list[CveCandidate] = []
        seen: set[str] = set()

        for cve_id, criteria in matches:
            if cve_id in seen:
                continue
            seen.add(cve_id)

            rec = self.hydrate(cve_id)
            if not rec:
                continue

            # Confidence & match_reason heuristics
            match_reason = "cpe_exact"
            confidence = "medium"

            if version:
                v_clean = version.strip().lower()
                if f":{v_clean}:" in criteria.lower():
                    confidence = "high"
                    match_reason = "cpe_exact"
                else:
                    match_reason = "version_range"
                    confidence = "medium"

            source_url = rec.references[0].url if rec.references else f"https://nvd.nist.gov/vuln/detail/{cve_id}"

            candidates.append(
                CveCandidate(
                    cve_id=cve_id,
                    summary=rec.summary[:300] if rec.summary else rec.title,
                    cvss_score=rec.cvss_score,
                    cvss_severity=rec.cvss_severity,
                    cwe=rec.cwe,
                    match_reason=match_reason,
                    confidence=confidence,
                    source_url=source_url,
                    criteria=criteria,
                )
            )

        return candidates[:limit]

    def references(self, cve_id: str) -> list[Reference]:
        """Return upstream vendor advisory and NVD reference URLs for a CVE."""
        rec = self.hydrate(cve_id)
        if rec and rec.references:
            return rec.references
        clean_id = cve_id.strip().upper()
        return [Reference(url=f"https://nvd.nist.gov/vuln/detail/{clean_id}", source="nvd")]


_catalog_instance: CveCatalog | None = None


def get_cve_catalog(db_path: Path | str | None = None) -> CveCatalog:
    """Return singleton CveCatalog instance."""
    global _catalog_instance
    if _catalog_instance is None or db_path is not None:
        _catalog_instance = CveCatalog(db_path)
    return _catalog_instance


def cve_snapshot_label(catalog: CveCatalog | None = None) -> str:
    """Return formatted snapshot label for reports and prompts."""
    cat = catalog or get_cve_catalog()
    return f"{settings.vulnify_release} (2026-11-02)" if cat.is_available else "CVE enrichment disabled"
