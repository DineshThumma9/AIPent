# Skill: sensitive_storage

## Description
Detects exposed sensitive files, directories, backups and storage endpoints via targeted non-destructive GET requests. Use when scanners flag directory listings, backup extensions (.bak/.swp), or mention /ftp, /public, /uploads, legal/personal data files.

## Metadata
- **Name**: sensitive_storage
- **Title**: Sensitive Storage Exposure
- **Category**: verification
- **Tags**: directory-listing, backup-files, exposed-data, robots, ftp, public-storage, config-files
- **Triggers**: directory listing, backup, .bak, .swp, .old, .orig, .save, .tmp, /ftp, /public, /uploads, config.json, exposed robots.txt, directory index

## Workflow

### 1. Parse Scanner Alert
- Classify finding type: directory listing / backup file / exposed storage / config file
- Extract suspected paths, file extensions and storage directories from evidence

### 2. Common File Path Probing
- Probe generic sensitive file dictionary (see references)
- Categories: VCS metadata, config files, backups, docs, secrets, IDE files, docker/cloud config

### 3. Directory Listing Detection
- Compare probe response body against heuristics:
  - Apache/Nginx autoindex HTML patterns
  - JSON object listings (`{"files": [...]}`)
  - Anchor-heavy listings without navigation text

### 4. Content Sensitivity Classification
- Read excerpt and score against filetype/shop/classification table
- Mark PII / credentials / keys as higher severity

### 5. Redirect / Auth Wall Disambiguation
- A 30x to /login → **not exposure** (protected) → SUSPECTED stays or downgrade
- 200 with sensitive content → **exposure confirmed**

## Decision Table

| Observation | Action | Status |
|-------------|--------|--------|
| 200 + directory listing (autoindex/json) | CONFIRMED | yes |
| 200 + backup file with real source code | CONFIRMED | yes |
| 200 + robots.txt with sensitive paths | CONFIRMED (informational) | yes |
| 302/301 to login page | FALSE_POSITIVE if finding claimed open access | yes |
| 403 on all probes | Keep SUSPECTED (needs more recon) | yes |
| 404 everywhere and no listing heuristics | FALSE_POSITIVE | yes |

## Scripts
- `scripts/generate_probes.py` — stdin finding JSON → stdout probes JSON
- `scripts/classify_response.py` — classify one response body: listing type + sensitivity

## References
- `references/common_exposed_files.json` — Sensitive file/dictionary list
- `references/directory_listing_patterns.md` — Autoindex + JSON listing detection cheatsheet

## Assets
- `assets/sample_finding.json`
- `assets/sample_probes.json`
