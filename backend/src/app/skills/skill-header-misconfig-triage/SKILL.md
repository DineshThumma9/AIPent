# Skill: header_misconfig_triage

## Description
Triages duplicate security-header alerts from multiple scanners and probes whether permissive CORS/cookie policy applies to authenticated API endpoints versus harmless public assets. Use when 2+ tools flag missing CSP/HSTS/XFO/XCTO, or Access-Control-Allow-Origin reflects arbitrary origins.

## Metadata
- **Name**: header_misconfig_triage
- **Title**: Security Header Misconfiguration Triage
- **Category**: verification
- **Tags**: csp, hsts, x-frame-options, x-content-type-options, cors, cookies, header-dedup
- **Triggers**: content security policy, csp, x-frame-options, clickjacking, x-content-type-options, mime, strict-transport-security, hsts, access-control-allow-origin, cors, cookie flags

## Workflow

### 1. Consolidate Alerts
- Group all SUSPECTED header findings for the same asset/port by family (see correlate.py families)
- Build one coherent finding per family with union of evidence

### 2. Fetch Live Response Headers (baseline)
- Single GET to the site root, parse response headers
- Record present/missing: CSP, X-FO, XCTO, HSTS, cache headers, cookie flags

### 3. CORS Reflection Triage (only if scanner claims `*` or reflected Origin)
- For each API-ish path in references/api_paths, probe with `Origin: https://attacker.com`
- Also probe one STATIC asset path to observe baseline permissiveness
- Reflection (ACAO echoes origin or `*` with ACAC true) on API = real misconfig
- Reflection only on static assets = contextual, downgrade

### 4. Cookie Flag Inspection
- If Set-Cookie observed: check HttpOnly, Secure, Path, SameSite
- Only session-named cookies count for session flags; analytics-only cookies not "session secrets"

## Decision Table

| Observation | Status | Severity |
|-------------|--------|----------|
| API path reflects attacker Origin | CONFIRMED | high |
| All paths (incl. static) lack CSP/HSTS/XFO | CONFIRMED | medium |
| Only one static asset index flagged | FALSE_POSITIVE | low |
| Cookie has Set-Cookie plain but no session cookie | SUSPECTED | low |
| 403 on all API probes | SUSPECTED | low |

## Scripts
- `scripts/generate_probes.py` — stdin finding JSON → stdout probes (header fetch + CORS matrix)
- `scripts/classify_headers.py` — from one response: list missing baseline headers and CORS verdict

## References
- `references/owasp_header_baseline.json` — Header baseline policy
- `references/header_triage.md` — Family merging + CDN false alarm guidance

## Assets
- `assets/sample_header_finding.json`
- `assets/sample_probes.json`
