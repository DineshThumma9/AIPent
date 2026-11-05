"""SPA Route Discovery Skill - Probe Generator.

Generic SPA route discovery for any Angular/React/Vue/Svelte application.
Juice Shop specific routes are in references/spa_route_patterns.json as examples.
"""

import json
import sys
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.skills.loader import Skill, SkillMetadata, SkillInvocationResult, ProbeSpec


class SpaRouteDiscoverySkill(Skill):
    @property
    def metadata(self) -> SkillMetadata:
        return SkillMetadata(
            name="spa_route_discovery",
            title="SPA Route Discovery",
            description=(
                "Discovers hidden SPA routes by detecting wildcard fallbacks and "
                "probing framework-specific admin/debug paths. Use when nmap/Nikto "
                "detects React/Angular/Vue/Svelte, or crawl reveals SPA bundle paths."
            ),
            category="verification",
            tags=["spa", "react", "angular", "vue", "svelte", "wildcard", "hidden-routes"],
            triggers=["spa", "react", "angular", "vue", "svelte", "main.js", "vendor.js", "chunk", "bundle"],
        )

    def generate_probes(self, finding: dict, hypothesis: str, assessment: dict) -> SkillInvocationResult:
        target = assessment.get("targets", ["127.0.0.1"])[0]
        port = assessment.get("ports", [3000])[0]

        probes: list[ProbeSpec] = []
        evidence = finding.get("evidence", [])
        title = finding.get("title", "").lower()
        description = finding.get("description", "").lower()
        endpoint = finding.get("endpoint", "")

        # Detect framework from evidence
        framework = self._detect_framework(evidence, title, description, endpoint)

        # Load framework-specific routes from references
        route_patterns = self._load_route_patterns(framework)

        # 1. Wildcard fallback detection probe (always run)
        wildcard_path = f"/definitely-random-uuid-404-check-{uuid.uuid4().hex[:8]}"
        probes.append(ProbeSpec(
            target=target,
            method="GET",
            path=wildcard_path,
            expected_status=200,
            rationale="Detect SPA wildcard fallback (404 returns 200 with root HTML)"
        ))

        # 2. Framework-specific hidden routes (from references)
        hidden_routes = route_patterns.get("hidden_routes", [])
        for route in hidden_routes:
            probes.append(ProbeSpec(
                target=target,
                method="GET",
                path=route,
                expected_status=200,
                rationale=f"Probe for hidden {framework or 'SPA'} route: {route}"
            ))

        # 3. Debug/actuator endpoints (generic)
        debug_routes = route_patterns.get("debug_routes", [])
        for route in debug_routes:
            probes.append(ProbeSpec(
                target=target,
                method="GET",
                path=route,
                expected_status=200,
                rationale=f"Probe for debug/actuator endpoint: {route}"
            ))

        # 4. CORS testing on API endpoints (generic common patterns)
        api_routes = route_patterns.get("api_routes", [])
        for api_route in api_routes:
            probes.append(ProbeSpec(
                target=target,
                method="GET",
                path=api_route,
                headers={"Origin": "https://attacker.com"},
                expected_status=200,
                rationale=f"Test CORS reflection on API endpoint: {api_route}"
            ))

        # 5. Common admin panel paths (generic)
        admin_routes = route_patterns.get("admin_routes", [])
        for route in admin_routes:
            probes.append(ProbeSpec(
                target=target,
                method="GET",
                path=route,
                expected_status=200,
                rationale=f"Probe for common admin panel path: {route}"
            ))

        return SkillInvocationResult(
            skill_name=self.metadata.name,
            finding_id=finding.get("id", 0),
            hypothesis=hypothesis,
            probes=probes,
            reasoning=f"Detected framework: {framework or 'unknown'}. Generated {len(probes)} probes: 1 wildcard check, {len(hidden_routes)} hidden routes, {len(debug_routes)} debug endpoints, {len(api_routes)} CORS tests, {len(admin_routes)} admin panels."
        )

    def evaluate(self, probe_results: list[dict], finding: dict) -> tuple[str, str]:
        wildcard_confirmed = False
        hidden_routes_found = []
        debug_endpoints_found = []
        cors_reflected = []
        admin_panels_found = []

        for result in probe_results:
            probe = result.get("probe", {})
            response = result.get("response", {})
            status = response.get("status_code", 0)
            body = response.get("body", "")
            headers = response.get("headers", {})

            path = probe.get("path", "")
            expected = probe.get("expected_status", 200)

            # Wildcard check
            if "404-check" in path and status == 200:
                if "<html" in body.lower() or "<!doctype html" in body.lower():
                    wildcard_confirmed = True

            # Hidden route check
            if status == 200 and any(x in path for x in ["score-board", "administration", "admin", "login", "register", "profile"]):
                # Verify content differs from wildcard baseline
                if not wildcard_confirmed or body != result.get("baseline_body", ""):
                    hidden_routes_found.append(path)

            # Debug endpoint check
            if status == 200 and any(x in path for x in ["actuator", "health", "metrics", "debug", "swagger", "api-docs", "graphql"]):
                debug_endpoints_found.append(path)

            # CORS check
            if probe.get("headers", {}).get("Origin") == "https://attacker.com":
                acao = headers.get("access-control-allow-origin", "")
                if acao == "https://attacker.com" or acao == "*":
                    cors_reflected.append(path)

            # Admin panel check
            if status == 200 and any(x in path for x in ["/admin", "/administrator", "/backend", "/controlpanel", "/dashboard", "/manage"]):
                admin_panels_found.append(path)

        # Evaluation logic
        findings = []

        if wildcard_confirmed:
            findings.append("SPA wildcard fallback detected - generic file alerts are false positives")

        if hidden_routes_found:
            findings.append(f"Hidden routes confirmed: {hidden_routes_found}")

        if debug_endpoints_found:
            findings.append(f"Debug/actuator endpoints exposed: {debug_endpoints_found}")

        if cors_reflected:
            findings.append(f"CORS misconfiguration on API endpoints: {cors_reflected}")

        if admin_panels_found:
            findings.append(f"Admin panels accessible: {admin_panels_found}")

        if not findings:
            return "suspected", "No hidden routes, debug endpoints, or CORS issues confirmed"

        # Determine overall status
        if any("CORS" in f or "Admin panels" in f or "Debug" in f for f in findings):
            return "confirmed", "; ".join(findings)

        if hidden_routes_found and not wildcard_confirmed:
            return "confirmed", "; ".join(findings)

        if wildcard_confirmed and not hidden_routes_found:
            return "false_positive", findings[0]

        return "suspected", "; ".join(findings)

    def _detect_framework(self, evidence: list, title: str, description: str, endpoint: str) -> str | None:
        text = " ".join([title, description, endpoint] + [e.get("excerpt", "") for e in evidence]).lower()

        # Angular indicators
        if any(x in text for x in ["ng-app", "ng-controller", "ng-version", "angular", "zone.js"]):
            return "angular"

        # React indicators
        if any(x in text for x in ["react", "__react", "react-dom", "react-router", "createroot", "hydrateroot"]):
            return "react"

        # Vue indicators
        if any(x in text for x in ["vue", "vue.js", "__vue", "createapp", "vue-router"]):
            return "vue"

        # Svelte indicators
        if any(x in text for x in ["svelte", "__svelte", "svelte-hmr"]):
            return "svelte"

        # Generic SPA bundle indicators
        if any(x in text for x in ["main.js", "vendor.js", "chunk.", "bundle.", "webpack", "polyfills.js"]):
            return "generic"

        return None

    def _load_route_patterns(self, framework: str | None) -> dict:
        """Load route patterns from references file."""
        ref_file = Path(__file__).parent.parent / "references" / "spa_route_patterns.json"
        if not ref_file.exists():
            return self._default_patterns()

        with open(ref_file) as f:
            all_patterns = json.load(f)

        # Merge framework-specific + generic
        patterns = all_patterns.get("generic_spa", {}).copy()
        if framework and framework in all_patterns:
            fw_patterns = all_patterns[framework]
            for key, value in fw_patterns.items():
                if key in patterns:
                    patterns[key].extend(value)
                else:
                    patterns[key] = value

        # Normalize keys
        return {
            "hidden_routes": patterns.get("hash_routes", []) + patterns.get("history_routes", []) + patterns.get("common_hidden_routes", []),
            "debug_routes": patterns.get("debug_routes", []),
            "api_routes": patterns.get("api_routes", ["/api", "/rest", "/graphql", "/v1", "/v2"]),
            "admin_routes": patterns.get("common_hidden_routes", []),
        }

    def _default_patterns(self) -> dict:
        return {
            "hidden_routes": ["/admin", "/administration", "/login", "/register", "/profile"],
            "debug_routes": ["/actuator", "/health", "/metrics", "/swagger", "/api-docs"],
            "api_routes": ["/api", "/rest", "/graphql", "/v1"],
            "admin_routes": ["/admin", "/administrator", "/backend", "/dashboard"],
        }


# Export for registry
skill = SpaRouteDiscoverySkill()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--format", choices=["json", "text"], default="json")
    args = parser.parse_args()

    input_data = json.load(sys.stdin)
    finding = input_data.get("finding", {})
    hypothesis = input_data.get("hypothesis", "SPA wildcard fallback may mask 404s")
    assessment = input_data.get("assessment", {"targets": ["127.0.0.1"], "ports": [3000]})

    result = skill.generate_probes(finding, hypothesis, assessment)

    output = {
        "probes": [
            {
                "action": p.action,
                "target": p.target,
                "method": p.method,
                "path": p.path,
                "headers": p.headers,
                "expected_status": p.expected_status,
                "rationale": p.rationale,
            }
            for p in result.probes
        ],
        "reasoning": result.reasoning,
    }

    if args.format == "json":
        json.dump(output, sys.stdout, indent=2)
    else:
        for p in result.probes:
            print(f"{p.method} {p.path} → expected {p.expected_status} ({p.rationale})")