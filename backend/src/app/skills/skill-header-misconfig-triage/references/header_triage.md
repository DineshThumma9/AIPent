# Header Triage: Family Merging & CDN False Alarms

## Family Merging

Multiple scanners emit overlapping header alerts. Consolidate by family before probing:

| Family | Nikto phrasing | ZAP pluginid | Canonical key |
|--------|----------------|--------------|---------------|
| CSP | "Suggested security header missing: content-security-policy" | 10038 | `web:csp:<host>:<port>` |
| X-Frame-Options | "anti-clickjacking X-Frame-Options header is not present" | 10020 | `web:x-frame-options:<host>:<port>` |
| XCTO | "X-Content-Type-Options header is not set" | 10021 | `web:x-content-type-options:<host>:<port>` |
| HSTS | "HTTP Strict Transport Security" | 10055 | `web:hsts:<host>:<port>` |
| CORS | "Access-Control-Allow-Origin: *" | 10098 | `web:cors:<host>:<port>` |

Merging rule: keep highest severity, merge evidence, keep best confidence.

## Assessment Decision Tree

```
1. Baseline GET / → current headers.
2. Does the scanner claim a specific real endpoint or just the site root?
   root only        → fetch baseline, report missing families
   specific API     → probe that endpoint + generic API list
   claim on "any"   → probe API + one static asset as permissiveness baseline

3. CORS reflection probe results:
   API echoes attacker origin OR ACAO:"*" + ACAC:true     → CONFIRMED (high)
   Static assets permissive, API not                       → SUSPECTED (contextual, medium)
   Everything permissive                                   → CONFIRMED (medium, site-wide)
   403 on all API probes                                   → SUSPECTED (auth wall)

4. Cookies:
   session-named cookie without Secure/HttpOnly/SameSite   → CONFIRMED (medium)
   no cookies set on login endpoint                        → keep original alert SUSPECTED/low
```

## CDN / Public Asset False Alarms

When ACAO reflection appears ONLY on public static paths (`/fonts/`, `/img/`, `/static/`), it is:
- normal for CDN-hosted assets,
- not a direct session leak.

Mark finding SUSPECTED (medium) if the CSP claim persists, not CONFIRMED.
Do not bury the original alert: leave a note in remediation:
"Restrict ACAO to trusted origins on developed endpoints; CDN assets may remain permissive."

## CSP Notes

CSP that is present but allows `unsafe-inline` scripts or `*` script-src is weak:
- Report as SUSPECTED with description, not CONFIRMED until one bypass vector is shown.

## HSTS Notes

For pure http:// targets, HSTS is meaningless:
- Downgrade severity to low and mark SUSPECTED;
- note "HSTS applies only to HTTPS transport."

## X-Frame-Options Notes

CSP `frame-ancestors` satisfies the clickjacking family:
- If CSP present with frame-ancestors restriction, treat X-Frame-Options family as satisfied (false_positive root alert).
