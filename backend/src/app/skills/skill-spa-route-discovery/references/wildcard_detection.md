# SPA Wildcard Fallback Detection

## The Problem

Single Page Applications (SPAs) often configure their web server to return `index.html` for **all** routes (including non-existent ones) so the client-side router can handle navigation. This creates a "wildcard fallback" where:

- Request to `/any-random-path` → Returns `200 OK` with `index.html`
- Scanner sees `200 OK` → Reports "found" file/directory
- Result: **Massive false positives** for file/directory enumeration

## Detection Strategy

### Probe Design
```
GET /definitely-random-uuid-404-check-{random_hex}
```

### Positive Indicators (Wildcard Confirmed)
- HTTP 200 status
- Response body contains `<html` or `<!doctype html`
- Response body matches the root `/` response (or contains same SPA bundle references)
- Content-Type: `text/html`

### Negative Indicators (No Wildcard)
- HTTP 404 status
- HTTP 302 redirect to login/error page
- Content-Type: `application/json` with error message
- Content-Type: `text/plain` with "Not Found"

## Framework-Specific Behaviors

| Framework | Typical Config | Wildcard Pattern |
|-----------|----------------|------------------|
| Angular (CLI) | `index.html` for all routes | Hash mode: `/#/anything` → 200 |
| React (CRA/Vite) | `index.html` fallback | History mode: `/anything` → 200 |
| Vue (CLI) | `index.html` fallback | Both modes common |
| Next.js | File-based routing | Only defined routes → 200 |

## Impact on Findings

### False Positives to Suppress
When wildcard is confirmed, these scanner alerts become FALSE_POSITIVE:
- Nikto: `/JAMonAdmin.jsp`, `/manager/html`, `/console`, `/phpmyadmin`
- ZAP: Directory listing, exposed backup files, config files
- Generic: Any `.jsp`, `.php`, `.asp`, `.aspx` on Node.js/Python/Go apps

### True Positives to Investigate
- Hidden SPA routes (`/#/admin`, `/administration`) that return 200 with **different** content than root
- API endpoints (`/rest/*`, `/api/*`) that return JSON (not HTML)

## Verification Protocol

1. **Baseline**: GET `/` → store body hash/length
2. **Wildcard Probe**: GET `/random-uuid` → compare to baseline
3. **Route Probes**: GET candidate routes → check if content differs from baseline
4. **Content Analysis**: If route returns 200 but body == baseline → wildcard (not real route)
5. **API Check**: If route returns JSON → real endpoint (not wildcard)

## Juice Shop Specifics

OWASP Juice Shop (Angular) uses hash routing with wildcard fallback:
- `/#/score-board` → 200, different content (Score Board challenge)
- `/#/administration` → 200, different content (Administration challenge)
- `/random` → 200, same as `/` (wildcard)
- `/rest/user/profile` → 200, JSON (real API)

## Implementation Notes

The `check_spa_wildcard.py` script:
- Generates cryptographically random path (12 hex chars)
- Follows redirects (max 5)
- Checks for HTML doctype in response
- Returns structured JSON for automation

The `generate_probes.py` skill:
- Runs wildcard check first
- Only probes framework-specific routes if wildcard NOT detected OR to confirm hidden routes
- Tests CORS on API endpoints separately