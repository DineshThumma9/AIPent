"""Sensitive Storage Exposure Skill - Probe Generator."""

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.skills.loader import Skill, SkillMetadata, SkillInvocationResult, ProbeSpec


class SensitiveStorageSkill(Skill):
    @property
    def metadata(self) -> SkillMetadata:
        return SkillMetadata(
            name="sensitive_storage",
            title="Sensitive Storage Exposure",
            description=(
                "Detects exposed sensitive files, directories, backups and storage "
                "endpoints via targeted non-destructive GET requests. Use when scanners "
                "flag directory listings, backup extensions, or storage directories."
            ),
            category="verification",
            tags=["directory-listing", "backup-files", "exposed-data", "config-files"],
            triggers=["directory listing", "backup", ".bak", ".swp", ".old", ".orig", "robots.txt", "exposed file", "directory index"],
        )

    def generate_probes(self, finding: dict, hypothesis: str, assessment: dict) -> SkillInvocationResult:
        target = assessment.get("targets", ["127.0.0.1"])[0]
        port = assessment.get("ports", [3000])[0]
        title = finding.get("title", "").lower()
        description = finding.get("description", "").lower()
        evidence_excerpts = " ".join(
            e.get("excerpt", "") for e in finding.get("evidence", [])
        ).lower()
        text = " ".join([title, description, evidence_excerpts])

        patterns = self._load_file_dictionary()
        probes: list[ProbeSpec] = []

        # 1. Suspected paths extracted from the finding itself
        suspected = self._extract_paths(evidence_excerpts, description)
        for path in suspected:
            probes.append(ProbeSpec(
                target=target,
                method="GET",
                path=path,
                expected_status=200,
                rationale=f"Path referenced by scanner evidence: {path}",
            ))

        # 2. Storage directories hinted by evidence or common defaults
        storage_dirs = self._select_storage_dirs(text, patterns)
        for path in storage_dirs:
            probes.append(ProbeSpec(
                target=target,
                method="GET",
                path=path,
                expected_status=200,
                rationale=f"Enumerate storage directory for listing exposure: {path}",
            ))

        # 3. Backup extensions for already-suspected files
        base_paths = suspected or ["/package.json", "/.env", "/config.json"]
        for path in base_paths.copy():
            for ext in patterns.get("backup_extensions", [".bak", ".old", ".swp", "~"]):
                probes.append(ProbeSpec(
                    target=target,
                    method="GET",
                    path=f"{path}{ext}",
                    expected_status=200,
                    rationale=f"Backup extension probe for {path}",
                ))

        # 4. VCS metadata (generic, high value, cheap)
        for path in patterns.get("vcs_paths", [".git/HEAD", ".svn/entries", ".hg/store"]):
            probes.append(ProbeSpec(
                target=target,
                method="GET",
                path=f"/{path}",
                expected_status=200,
                rationale="VCS metadata probe",
            ))

        # 5. robots.txt informationalprobe
        probes.append(ProbeSpec(
            target=target,
            method="GET",
            path="/robots.txt",
            expected_status=200,
            rationale="robots.txt may reveal hidden/protected storage paths",
        ))

        return SkillInvocationResult(
            skill_name=self.metadata.name,
            finding_id=finding.get("id", 0),
            hypothesis=hypothesis,
            probes=probes,
            reasoning=(
                f"Generated {len(probes)} probes: {len(suspected)} evidence paths, "
                f"{len(storage_dirs)} storage dirs, "
                f"{len(base_paths) * len(patterns.get('backup_extensions', []))} backup extensions, "
                f"{len(patterns.get('vcs_paths', []))} VCS paths, 1 robots.txt."
            ),
        )

    def evaluate(self, probe_results: list[dict], finding: dict) -> tuple[str, str]:
        confirmed, redirected, forbidden, not_found = [], [], [], []
        for result in probe_results:
            probe = result.get("probe", {})
            response = result.get("response", {})
            status = response.get("status_code", 0)
            path = probe.get("path", "/")

            if status in (301, 302, 303, 307, 308):
                redirected.append(path)
            elif status == 403:
                forbidden.append(path)
            elif status == 404:
                not_found.append(path)
            elif status == 200:
                classification = classify_response(response.get("body", ""), path)
                if classification.sensitive or classification.listing_type:
                    confirmed.append((path, classification.listing_type, classification.category))
                else:
                    not_found.append(path)

        if confirmed:
            listing = [c for c in confirmed if c[1]]
            files = [c for c in confirmed if not c[1]]
            msg = []
            if listing:
                msg.append(f"Directory listings exposed on {len(listing)} path(s): {[c[0] for c in listing]}")
            if files:
                msg.append(f"Sensitive file content served on {len(files)} path(s)")
            return "confirmed", "; ".join(msg)

        if redirected:
            return "false_positive", (
                f"All {len(redirected)} suspected path(s) redirect to an auth page; "
                "no unauthenticated exposure: " + ", ".join(redirected[:5])
            )

        if forbidden:
            return "suspected", f"403 on {len(forbidden)} path(s); needs authenticated re-check"

        return "false_positive", f"No listings or sensitive content found ({len(not_found)} probes 404/plain 200)"

    # ------------------------------------------------------------------
    def _extract_paths(self, text: str, description: str) -> list[str]:
        import re
        paths = set()
        for match in re.findall(r"(?:https?://[^/\s'\"\]]+)?(/[A-Za-z0-9_\-./%]+\.[A-Za-z0-9]{1,8})", text):
            if not match.startswith("//"):
                paths.add(match)
        # directories mentioned like /ftp or /public
        for match in re.findall(r"(?:\s|:)(/[A-Za-z0-9_\-]+(?:/)?)(?=\s|$|,|\.|\))", description):
            if len(match) > 1 and not match.startswith("//"):
                paths.add(match)
        return sorted(paths)[:10]  # cap probe count

    def _select_storage_dirs(self, text: str, patterns: dict) -> list[str]:
        dirs = []
        for keyword, candidates in patterns.get("storage_dirs", {}).items():
            if keyword in text:
                dirs.extend(candidates)
        if not dirs:
            dirs = patterns.get("storage_dirs", {}).get("default", ["/public", "/downloads", "/uploads"])
        return sorted(set(dirs))[:8]

    def _load_file_dictionary(self) -> dict:
        ref = Path(__file__).parent.parent / "references" / "common_exposed_files.json"
        if ref.exists():
            return json.loads(ref.read_text())
        return {"backup_extensions": [".bak", ".old", ".swp", "~"],
                "vcs_paths": [".git/HEAD"],
                "storage_dirs": {"default": ["/public"]}}


# ---- Response classification (also used standalone) ----------------------------

@dataclass
class ResponseClassification:
    listing_type: str | None  # "apache_index", "nginx_index", "json_listing", None
    category: str | None      # "config", "backup", "credentials", "docs", "personal", None
    sensitive: bool           # content matched sensitive keyword heuristics


def classify_response(body: str, path: str) -> ResponseClassification:
    low = body.lower()
    listing_type = None
    if "directory listing for" in low or "<h1>index of" in low:
        listing_type = "apache_index"
    elif low.strip().startswith("{") and re.search(r'"(?:files|items|entries|data)"\s*:', low):
        listing_type = "json_listing"
    elif "<h1" in low and 'href="../' in low and "last modified" in low:
        listing_type = "nginx_index"

    category = None
    if ".env" in path or "config.json" in path or "config.yml" in path:
        category = "config"
    if ".bak" in path or ".swp" in path or ".old" in path:
        category = "backup"
    if any(k in low for k in ("api_key", "secret", "password", "token")):
        category = "credentials"
    if any(k in low for k in ("invoice", "acquisition", "gdpr", "personal data")):
        category = "personal"

    sensitive = category is not None or listing_type is not None
    return ResponseClassification(listing_type, category, sensitive)


skill = SensitiveStorageSkill()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--format", choices=["json", "text"], default="json")
    args = parser.parse_args()

    input_data = json.load(sys.stdin)
    finding = input_data.get("finding", {})
    hypothesis = input_data.get("hypothesis", "Directory listing may expose internal files")
    assessment = input_data.get("assessment", {"targets": ["127.0.0.1"], "ports": [3000]})

    result = skill.generate_probes(finding, hypothesis, assessment)

    output = {"probes": [p.__dict__ | {"headers": p.headers} for p in result.probes], "reasoning": result.reasoning}
    if args.format == "json":
        json.dump(output, sys.stdout, indent=2)
    else:
        for p in result.probes:
            print(f"{p.method} {p.path} → expected {p.expected_status} ({p.rationale})")