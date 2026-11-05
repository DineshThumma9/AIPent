"""SQL Injection Safe Verification Skill - Probe Generator."""

import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.skills.loader import Skill, SkillMetadata, SkillInvocationResult, ProbeSpec


class SqliSafeVerificationSkill(Skill):
    ATTACK_ORIGIN_UNUSED = ""

    @property
    def metadata(self) -> SkillMetadata:
        return SkillMetadata(
            name="sqli_safe_verification",
            title="SQL Injection Safe Verification",
            description=(
                "Verifies suspected SQL injection using safe non-destructive boolean-differential "
                "probes and error-reflection analysis. Never dumps data; invasive tools like sqlmap "
                "require a human approval gate. Use when a query parameter reflects database errors "
                "or boolean behaviour."
            ),
            category="verification",
            tags=["sqli", "boolean-differential", "error-reflection", "safe-testing"],
            triggers=["sql injection", "inject", "sqlmap", "union select", "quote handling", "syntax error", "or 1=1"],
        )

    def generate_probes(self, finding: dict, hypothesis: str, assessment: dict) -> SkillInvocationResult:
        target = assessment.get("targets", ["127.0.0.1"])[0]
        port = assessment.get("ports", [3000])[0]

        patterns = self._load_probe_patterns()
        probes: list[ProbeSpec] = []
        reasoning_parts = []

        # 1. Extract candidates from evidence/description
        candidates = self._extract_candidates(finding)
        for idx, candidate in enumerate(candidates):
            path = candidate["path"]
            param = candidate["param"]
            base_value = candidate.get("value", "1")
            method = candidate.get("method", "GET").upper()

            # Baseline (unmodified) as reference
            probes.append(ProbeSpec(
                target=target, method=method, path=self._with_param(path, param, base_value),
                headers={}, expected_status=200,
                rationale=f"Baseline unmodified request for {param}",
            ))

            # TRUE/FALSE boolean differential probes
            for label, marker in (
                ("true", self._quote_containing(path, param, base_value, patterns["true_markers"])),
                ("false", self._quote_containing(path, param, base_value, patterns["false_markers"])),
            ):
                method2, url, body = self._decompose_request(target, method, url=marker, path=path, param=param, is_path=marker is None)
                probes.append(ProbeSpec(
                    target=target, method=method2, path=url, headers=self._add_body_json(body),
                    expected_status=200,
                    rationale=f"{label}-probe boolean differential on {param} (non-destructive)",
                ))

            # Syntax-error probe (plain quote)
            probes.append(ProbeSpec(
                target=target, method=method,
                path=self._with_param(path, param, f"{base_value}'"),
                headers={}, expected_status=200,
                rationale=f"Illicit DB syntax error reflection on {param}",
            ))

            reasoning_parts.append(f"Candidate {idx}: {method} {path} param={param}")

        # 2. If no candidate extracted, fall back to generic params from patterns
        if not candidates:
            for endpoint in patterns.get("generic_endpoints", []):
                probes.append(ProbeSpec(
                    target=target, method="GET",
                    path=endpoint.replace("/{param}", "?id=1'"),
                    headers={}, expected_status=200,
                    rationale=f"Generic SQL injection candidate: {endpoint}",
                ))

        return SkillInvocationResult(
            skill_name=self.metadata.name,
            finding_id=finding.get("id", 0),
            hypothesis=hypothesis,
            probes=probes,
            reasoning=("; ".join(reasoning_parts) + f" — {len(probes)} probes generated (safe, non-destructive)").strip("; "),
        )

    def evaluate(self, probe_results: list[dict], finding: dict) -> tuple[str, str]:
        base_length: int | None = None
        true_length: int | None = None
        false_length: int | None = None
        errors = []
        waf = False

        for result in probe_results:
            probe = result.get("probe", {})
            response = result.get("response", {})
            path = probe.get("path", "")

            if response.get("status_code", 0) in (403,):
                waf = True
                continue
            body = response.get("body", "") or ""

            # DB / ORM error signature detection
            for engine, sigs in ERROR_SIGNATURES.items():
                if any(sig in body.lower() for sig in sigs):
                    if engine not in errors:
                        errors.append(engine)

            rationale = probe.get("rationale", "")
            length = len(body)
            if rationale.startswith("Baseline unmodified"):
                base_length = length
            elif rationale.startswith("true-probe"):
                true_length = length
            elif rationale.startswith("false-probe"):
                false_length = length

        findings = []
        if errors:
            findings.append(f"DISTINCTIVE DB/ORM error signatures observed in {len(errors)} probes: {errors}")
        if base_length and true_length and false_length:
            true_delta = abs(true_length - base_length)
            false_delta = abs(false_length - base_length)
            if abs(true_delta - false_delta) >= 200 and max(true_length, false_length) > min(true_length, false_length):
                findings.append(
                    f"Boolean differential: TRUE {true_length}B vs FALSE {false_length}B vs baseline {base_length}B"
                )
        if waf:
            findings.append("WAF-like 403 blocked some probes; may need approved retest")

        if any("Boolean differential:" in f for f in findings) or errors:
            return "confirmed", ("; ".join(findings) or "SQL injection markers confirmed (safe verification only)")

        if findings:
            return "suspected", "; ".join(findings)

        return "false_positive", "No boolean differential or error reflection observed across all safe probes"

    # ------------------------------------------------------------------
    def _extract_candidates(self, finding: dict) -> list[dict]:
        import re
        candidates = []
        evidence = finding.get("evidence", [])
        text = " ".join(
            [finding.get("title", ""), finding.get("description", "")]
            + [e.get("excerpt", "") for e in evidence]
        )
        urls = re.findall(r"(?:https?://[^'\"\s]+|/(?:[A-Za-z0-9_\-]+)/[A-Za-z0-9_\-./?&=]*)", text)
        params = re.findall(r"(?:[?&]|\b)([a-z_]{2,24})\s*[=:]+", text)
        methods = re.findall(r"\b(GET|POST|PUT|DELETE|PATCH)\b", text, re.IGNORECASE)
        method = methods[0].upper() if methods else "GET"

        seen = set()
        for url in urls[:4]:
            url = url.split("'")[0].split('"')[0].split('`')[0]
            if url.startswith("http"):
                parsed = url.split("?")
                base_path = parsed[0].split("://", 1)[-1]
                base_path = "/" + base_path if not base_path.startswith("/") else base_path
                qs = parsed[1] if len(parsed) > 1 else ""
                kv = re.findall(r"([a-zA-Z_]+)=([A-Za-z0-9%\-]+)?", qs)
            else:
                base_path = url.split("?")[0]
                kv = re.findall(r"([a-zA-Z_]+)=([A-Za-z0-9%\-]+)?", url)
            if not kv:
                continue
            for param, value in kv[:2]:
                key = (base_path, param)
                if key in seen:
                    continue
                seen.add(key)
                candidates.append({
                    "path": base_path,
                    "param": param,
                    "value": value or "1",
                    "method": method,
                })
        return candidates

    def _with_param(self, path: str, param: str, value: str) -> str:
        sep = "&" if "?" in path else "?"
        return f"{path}{sep}{param}={value}"

    def _quote_containing(self, path: str, param: str, value: str, marker: str) -> str:
        return self._with_param(path, param, f"{value}{marker}")

    def _decompose_request(self, target: str, method: str, url: str, path: str, param: str, is_path: bool):
        # Boolean markers live in the URL for GET/PUT/DELETE
        if method in ("GET", "DELETE", "PUT", "PATCH", "HEAD"):
            return method, url, {}
        # POST bodies go as JSON for typical modern apps
        body = {param: self._last_param_value(url)}
        return method, path, body

    def _last_param_value(self, url: str) -> str:
        from urllib.parse import urlparse, parse_qsl
        val = ""
        try:
            query = urlparse(url).query
            val = dict(parse_qsl(query)).get("q", "")
        except Exception:
            pass
        return val or "1"

    def _add_body_json(self, body: dict) -> dict:
        if not body:
            return {}
        return {"Content-Type": "application/json"}

    def _load_probe_patterns(self) -> dict:
        ref = Path(__file__).parent.parent / "references" / "safe_probe_patterns.json"
        if ref.exists():
            return json.loads(ref.read_text())
        return {
            "true_markers": " AND 1=1",
            "false_markers": " AND 1=2",
            "generic_endpoints": ["/search?page=1'"],
        }


ERROR_SIGNATURES = {
    "sqlite": ["sqliteerror", "sqlite_constraint", "unrecognized token", "sqlite"],
    "postgres": ["syntax error at or near", "postgresql", "psycopg2", "pg_query"],
    "mysql": ["you have an error in your sql syntax", "mysql2", "mariadb", "er_warn_index_conflict"],
    "mssql": ["unclosed quotation mark", "microsoft ole db provider", "sqlserverexception", "odbc sql server driver"],
    "oracle": ["ora-01756", "oracle error", "jdbc driver"],
    "sequelize": ["sequelize", "sequelizeconnectionerror", "databaserror"],
    "prisma": ["prisma client", "prisma unknown argument", "invalid `prisma.` invocation"],
}


skill = SqliSafeVerificationSkill()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--format", choices=["json", "text"], default="json")
    args = parser.parse_args()

    input_data = json.load(sys.stdin)
    finding = input_data.get("finding", {})
    hypothesis = input_data.get("hypothesis", "Boolean differential may confirm injectable parameter")
    assessment = input_data.get("assessment", {"targets": ["127.0.0.1"], "ports": [3000]})

    result = skill.generate_probes(finding, hypothesis, assessment)

    output = {"probes": [p.__dict__ for p in result.probes], "reasoning": result.reasoning}
    if args.format == "json":
        json.dump(output, sys.stdout, indent=2)
    else:
        for p in result.probes:
            print(f"{p.method} {p.path} ({p.rationale})")