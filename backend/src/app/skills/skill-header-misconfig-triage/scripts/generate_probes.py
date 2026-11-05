"""Header Misconfiguration Triage Skill - Probe Generator."""

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.skills.loader import Skill, SkillMetadata, SkillInvocationResult, ProbeSpec


ATTACK_ORIGIN = "https://attacker.example"


class HeaderMisconfigTriageSkill(Skill):
    @property
    def metadata(self) -> SkillMetadata:
        return SkillMetadata(
            name="header_misconfig_triage",
            title="Security Header Misconfiguration Triage",
            description=(
                "Triages duplicate security-header alerts across scanners and probes "
                "whether permissive CORS/cookie policy applies to authenticated API "
                "endpoints vs harmless public assets. Use when 2+ tools flag CSP/HSTS/"
                "XFO/XCTO or CORS reflection."
            ),
            category="verification",
            tags=["csp", "hsts", "x-frame-options", "cors", "cookies"],
            triggers=[
                "content security policy", "csp", "x-frame-options", "clickjacking",
                "x-content-type-options", "mime", "hsts", "access-control-allow-origin", "cors",
            ],
        )

    def generate_probes(self, finding: dict, hypothesis: str, assessment: dict) -> SkillInvocationResult:
        target = assessment.get("targets", ["127.0.0.1"])[0]
        port = assessment.get("ports", [3000])[0]

        patterns = self._load_baseline()
        api_paths = patterns.get("api_paths", ["/api", "/rest"])
        static_paths = patterns.get("static_paths", ["/main.js", "/favicon.ico"])
        login_paths = patterns.get("login_paths", ["/login"])

        probes: list[ProbeSpec] = []

        # 1. Baseline header fetch (unauthenticated root)
        probes.append(ProbeSpec(
            target=target, method="GET", path="/", headers={},
            expected_status=200, rationale="Baseline response headers for family triage",
        ))

        # 2. CORS reflection probes on API endpoints
        for api_path in api_paths:
            probes.append(ProbeSpec(
                target=target, method="GET", path=api_path, headers={"Origin": ATTACK_ORIGIN},
                expected_status=200, rationale=f"CORS reflection test on API path {api_path}",
            ))

        # 3. CORS reflection probe on one static asset (baseline permissiveness)
        for static_path in static_paths:
            probes.append(ProbeSpec(
                target=target, method="GET", path=static_path, headers={"Origin": ATTACK_ORIGIN},
                expected_status=200, rationale=f"CORS reflection baseline on static asset {static_path}",
            ))

        # 4. Cookie flag inspection on login/set-cookie path
        for login_path in login_paths:
            probes.append(ProbeSpec(
                target=target, method="GET", path=login_path, headers={},
                expected_status=200, rationale=f"Inspect Set-Cookie flags on {login_path}",
            ))

        text = " ".join([finding.get("title", ""), finding.get("description", ""),
                         " ".join(e.get("excerpt", "") for e in finding.get("evidence", []))]).lower()
        # If scanner specifically referenced an API endpoint, probe it exactly
        for term in ("access-control-allow-origin", "cors"):
            if term in text:
                import re
                for match in re.findall(r"(?:https?://[^/\s'\"\]]+)?(/(?:api|rest|graphql)[A-Za-z0-9_\-/.]*)", text):
                    probes.append(ProbeSpec(
                        target=target, method="GET", path=match, headers={"Origin": ATTACK_ORIGIN},
                        expected_status=200, rationale=f"CORS test on scanner-described endpoint {match}",
                    ))

        return SkillInvocationResult(
            skill_name=self.metadata.name,
            finding_id=finding.get("id", 0),
            hypothesis=hypothesis,
            probes=probes,
            reasoning=(
                f"Generated {len(probes)} probes: 1 baseline, {len(api_paths)+1} CORS API tests, "
                f"{len(static_paths)} static CORS baseline, {len(login_paths)} cookie checks."
            ),
        )

    def evaluate(self, probe_results: list[dict], finding: dict) -> tuple[str, str]:
        missing_headers: list[str] = []
        cors_api = []
        cors_static = []
        session_cookie_flags = []

        for result in probe_results:
            probe = result.get("probe", {})
            response = result.get("response", {})
            if response.get("status_code", 0) not in (200, 301, 302, 403):
                continue
            path = probe.get("path", "/")
            headers = response.get("headers", {}) or {}
            possession = classify_headers(headers)

            if path == "/":
                for family, present in possession.items():
                    if not present and family in ("csp", "hsts", "xfo", "xcto"):
                        missing_headers.append(family)

            acao = (headers.get("access-control-allow-origin") or "").strip()
            reflects = acao == ATTACK_ORIGIN or acao == "*"
            if reflects:
                if probe.get("headers", {}).get("Origin") == ATTACK_ORIGIN:
                    if any(api in path for api in ("/api", "/rest", "/graphql", "/v1", "/v2")):
                        cors_api.append(path)
                    else:
                        cors_static.append(path)

            set_cookie = headers.get("set-cookie", "")
            if set_cookie and ("session" in set_cookie.lower() or "jwt" in set_cookie.lower()):
                http_only = "httponly" in set_cookie.lower()
                secure = "secure" in set_cookie.lower()
                samesite = "samesite" in set_cookie.lower()
                if not (http_only and secure and samesite):
                    session_cookie_flags.append(f"{path} (secure={secure}, httponly={http_only}, samesite={samesite})")

        findings = []
        if cors_api:
            findings.append(
                f"ACAO reflection on authenticated API paths {cors_api} (attacker origin echoed)"
            )
        if missing_headers and len(missing_headers) >= 3:
            findings.append(f"Baseline missing ≥3 security headers: {missing_headers}")
        elif missing_headers:
            findings.append(f"Baseline missing headers: {missing_headers}")
        if cors_static and not cors_api:
            findings.append(
                "Permissive CORS only on public static assets; not applied on API (contextual, medium)"
            )
        if session_cookie_flags:
            findings.append(f"Weak session cookie flags: {session_cookie_flags}")

        if cors_api:
            return "confirmed", "; ".join(findings)
        if len(missing_headers) >= 3:
            return "confirmed", "; ".join(findings)
        if missing_headers:
            return "suspected", "; ".join(findings)
        if cors_static:
            return "suspected", "; ".join(findings)
        return "false_positive", f"No header baseline deviations verified across {len(probe_results)} probes"

    # ------------------------------------------------------------------
    def _load_baseline(self) -> dict:
        ref = Path(__file__).parent.parent / "references" / "owasp_header_baseline.json"
        if ref.exists():
            return json.loads(ref.read_text())
        return {
            "api_paths": ["/api", "/rest"],
            "static_paths": ["/main.js", "/favicon.ico"],
            "login_paths": ["/login"],
        }


@dataclass
class Possession:
    csp: bool
    hsts: bool
    xfo: bool
    xcto: bool


def classify_headers(headers: dict) -> dict:
    h = {k.lower(): v for k, v in (headers or {}).items()}
    csp_value = h.get("content-security-policy", "")
    return {
        "csp": "content-security-policy" in h,
        "hsts": "strict-transport-security" in h,
        "xfo": "x-frame-options" in h or "frame-ancestors" in csp_value.lower(),
        "xcto": "x-content-type-options" in h,
    }


skill = HeaderMisconfigTriageSkill()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--format", choices=["json", "text"], default="json")
    args = parser.parse_args()

    input_data = json.load(sys.stdin)
    finding = input_data.get("finding", {})
    hypothesis = input_data.get("hypothesis", "Permissive header policy may apply to API routes")
    assessment = input_data.get("assessment", {"targets": ["127.0.0.1"], "ports": [3000]})

    result = skill.generate_probes(finding, hypothesis, assessment)

    output = {"probes": [p.__dict__ for p in result.probes], "reasoning": result.reasoning}
    if args.format == "json":
        json.dump(output, sys.stdout, indent=2)
    else:
        for p in result.probes:
            print(f"{p.method} {p.path} → expected {p.expected_status} ({p.rationale})")