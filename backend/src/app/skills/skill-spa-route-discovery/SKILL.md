# Skill: spa_route_discovery

## Description
Discovers hidden SPA routes by detecting wildcard fallbacks (404 as 200) and probing framework-specific admin/debug paths. Use when nmap/Nikto detects React/Angular/Vue, or crawl reveals SPA bundle paths (main.js, vendor.js, chunk files).

## Metadata
- **Name**: spa_route_discovery
- **Title**: SPA Route Discovery
- **Category**: verification
- **Tags**: spa, react, angular, vue, wildcard, hidden-routes, juice-shop
- **Triggers**: spa, react, angular, vue, main.js, vendor.js, chunk, score-board, administration

## Workflow

### 1. Detect SPA Framework
- Check finding evidence for framework indicators (X-Powered-By, bundle paths, meta tags)
- Confirm target is a Single Page Application

### 2. Wildcard Fallback Detection
- Probe `/definitely-random-uuid-404-check-{timestamp}`
- If response is 200 with root HTML (not JSON/error page) → wildcard confirmed
- Mark generic file alerts (e.g., `/JAMonAdmin.jsp`, `/manager/html`) as FALSE_POSITIVE

### 3. Framework-Specific Route Probing
| Framework | Hidden Routes to Probe |
|-----------|------------------------|
| Angular | `/#/score-board`, `/#/administration`, `/#/admin`, `/#/login`, `/#/register` |
| React | `/score-board`, `/administration`, `/admin`, `/login`, `/register` (check both hash and history mode) |
| Vue | `/#/score-board`, `/#/administration`, `/#/admin`, `/#/login`, `/#/register` |

### 4. CORS Testing on Discovered Routes
- For each confirmed route, test `Origin: https://attacker.com`
- If reflected → CORS misconfiguration on authenticated route

### 5. Evidence Collection
- Record wildcard detection (status, body preview)
- Record each probed route (status, matched route pattern)
- Record CORS test results

## Decision Table

| Observation | Action | Expected Outcome |
|-------------|--------|------------------|
| Wildcard fallback detected | Mark generic file findings as FALSE_POSITIVE | Reduces false positives |
| Hidden admin route returns 200 | Create CONFIRMED finding | Juice Shop Score Board challenge |
| Hidden admin route returns 404/302 | Keep as SUSPECTED or FALSE_POSITIVE | No false confirmation |
| CORS reflected on /rest/* | Create CONFIRMED CORS finding | Real impact |

## Juice Shop Targets
- **Score Board** challenge: `/#/score-board` (Angular) or `/score-board` (React/Vue)
- **Administration** challenge: `/#/administration`

## Scripts
- `scripts/generate_probes.py` — Main entry: stdin finding JSON → stdout probes JSON
- `scripts/check_spa_wildcard.py` — Standalone wildcard detector

## References
- `references/spa_route_patterns.json` — Framework-specific route dictionaries
- `references/wildcard_detection.md` — Deep dive on 404-as-200 patterns

## Assets
- `assets/sample_finding.json` — Sample SPA finding for testing
- `assets/sample_probes.json` — Expected probe output