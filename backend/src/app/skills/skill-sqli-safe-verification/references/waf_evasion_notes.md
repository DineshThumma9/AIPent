# Probe Shaping Notes (NOT an Evasion Manual)

The goal of this skill is *safe, provable, repeatable* verification — not WAF bypass.
This page documents the "quiet" shapes this skill uses so that the agent produces
interoperable, low-noise probes:

| Goal | Probe shape |Notes |
|------|-------------|------|
| Confirm boolean controllability | append ` AND 1=1` / ` AND 1=2 --` | minimal, no encoding tricks |
| Trigger verifiable DB error | append bare `'` first; if 500, try `%27` second | 2 attempts max | 
| Derive context sensitivity | compare baseline body length/shape rough hash | no timing |
| Detect WAF | single 403/429 observation recorded, no evasive retries | report honestly |

Do NOT claim bypass capability. If a WAF blocks a probe, it is honest to mark
"needs approval gate for sqlmap" instead of trying to sneak around it.

## Trigger-side notes

- Request location rules: only the discrepancy path shared by the scanner evidence
  (e.g., Nikto references a specific `<url>`; ZAP alerts contain `uri`).
- For every candidate parameter the agent also captures the response headers
  (`Content-Length`, any `X-Powered-By` banner, `set-cookie`) but does not
  persist any secrets/token in the artifact file (strip `Cookie`, `Authorization`).

## Report pairing to the PS-1 malware/source-injection rule

- All probes are static, deterministic, and small (<10 per round);
- The produce reasoning is auditable: each probe cites evidence + a rationale.
- No fabricated CVEs. The skill identifies "injectable boolean dermatology" and
  "ORM/db error reflection" only. It does not claim, name, or rank CVE/CWE beyond
  what is directly mapped in the zero-hallucination triad (e.g., CWE-89).
