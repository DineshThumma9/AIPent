# Skill: sqli_safe_verification

## Description
Verifies suspected SQL injection using safe non-destructive boolean-differential probes and error-reflection analysis. Never dumps data, never runs destructive SQL. Any heavy tool (sqlmap) requires a human Approved approval gate. Use when a query parameter search/login form reflects database errors or behaves inconsistently with quotes appended.

## Metadata
- **Name**: sqli_safe_verification
- **Title**: SQL Injection Safe Verification
- **Category**: verification
- **Tags**: sqli, boolean-differential, error-reflection, safe-testing, sqlmap
- **Triggers**: sql injection, inject, sqlmap, query parameter, union select, quote handling, syntax error, or 1=1

## Workflow

### 1. Locate Candidate Parameter
- From evidence, extract the request endpoint + parameter name (query string or form field)
- Confirm the endpoint accepts GET or POST; choose probe shapes accordingly

### 2. Differential Probe Series
Send probe pairs (same shape, different expected truth value):
- TRUE probe: value appended with ` AND 1=1` (or `--` comment terminator depending on evidence)
- FALSE probe: value appended with ` AND 1=2`
- Baseline: original value unchanged
- Syntax-error probe: basic quote append to elicit a distinctive DB error
- Compare: status code, body length, error string, timing

### 3. Error Reflection Analysis
- Detect recognizable engine errors in the FALSE/TRUE probe responses:
  - SQLite: `SQLITE_ERROR`, `SQLITE_CONSTRAINT`, `unrecognized token`
  - PostgreSQL: `ERROR:`, `syntax error at or near`, `psycopg2`
  - MySQL/MariaDB: `You have an error in your SQL syntax`
  - MSSQL: `Unclosed quotation mark`, `SQLServerException`
  - ORM layers: `sequelize`, `sequelizeconnectionerror`, `prisma client`, `mysql2`
- ORM/database error reveal = CONFIRMED error-based weakness (still safe)

### 4. Truth-Value Differential Verdict
If TRUE probe response length/status differs from FALSE by threshold:
- Count difference > 1.2× baseline: `confirmed` (boolean-based weakness)
- Differences within noise → `suspected` (needs more context)

### 5. NEVER DO
- No data extraction (no union dumps, no sleep(), no declare)
- No UPDATE/INSERT/DELETE/DROP/ALTER
- sqlmap or automation tools only behind an explicit approval gate

## Decision Table

| Observation | Status | Reasoning |
|-------------|--------|-----------|
| TRUE vs FALSE response length/status differ >1000 bytes | CONFIRMED | boolean-based |
| Distinctive DB/ORM error traces in probe response | CONFIRMED | error-based |
| Errors but no length differential | SUSPECTED | retry with quote-context fixation |
| Identical 200/404s everywhere | FALSE_POSITIVE | no injectable surface |
| 403 on all probes (WAF) | SUSPECTED | blocked; needs approval-renegotiation |
| 500 errors everywhere | SUSPECTED | app issues, not proof |

## Scripts
- `scripts/generate_probes.py` — stdin finding JSON → stdout probes JSON
- `scripts/eval_response.py` — classifies one probe-pair response

## References
- `references/safe_probe_patterns.json` — agreed safe probe shapes per DB engine
- `references/waf_evasion_notes.md` — NOT bypass notes; only quieter probing patterns

## Assets
- `assets/sample_sqli_finding.json`
- `assets/sample_probes.json`
