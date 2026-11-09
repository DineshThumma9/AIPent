# AIPENT — AI-Powered Unified VAPT Agent

> **Innovation Hackathon Submission: AI Agent for Automated Penetration Testing**  
> *Final Participant Problem Statement: AI-Powered Unified VAPT Agent*  
> *Fully compliant with Hackathon Rules, NIST SP 800-115, OWASP Top 10, and Human-in-the-Loop Governance.*

[![Tests](https://img.shields.io/badge/backend%20tests-128%20passed-brightgreen)](#verification)
[![Frontend](https://img.shields.io/badge/frontend%20tests-16%20passed-brightgreen)](#verification)
[![Python](https://img.shields.io/badge/python-3.12-blue)](#prerequisites)
[![React](https://img.shields.io/badge/react-19%20%7C%20vite-61dafb)](#prerequisites)
[![LangGraph](https://img.shields.io/badge/orchestration-LangGraph%20v2-orange)](#architecture)
[![Safety](https://img.shields.io/badge/safety-human--in--the--loop%20gated-red)](#safety-governance--ethical-boundaries)

---

## Executive Summary

Penetration testing typically forces security analysts to spend more time aggregating and formatting outputs from disconnected scanners than evaluating genuine security risks. 

**AIPENT** solves this problem by providing a context-aware, adaptive, and evidence-driven conversational AI agent. Instead of blindly executing predefined script sequences, AIPENT orchestrates an end-to-end vulnerability assessment through a **three-specialist LangGraph loop** (`Recon` → `Discovery` → `Validation`), correlates multi-tool evidence into a unified finding model, enforces a **mandatory human approval gate** before every active probe, and compiles an executive-ready, cryptographically verifiable VAPT report in PDF format.

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                AIPENT End-to-End VAPT Lifecycle                                 │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
   Analyst Request ➔ Adaptive Plan ➔ Gated Scan Orchestration ➔ Raw Ingestion ➔ AI Correlation
         ➔ Risk Prioritization ➔ Human Review & Active Validation ➔ Unified VAPT Report (PDF)
```

---

## Problem Statement & Hackathon Alignment

AIPENT is engineered specifically against the Hackathon Problem Statement and Rules:

| Requirement Category | Hackathon Section | AIPENT Solution |
| :--- | :--- | :--- |
| **End-to-End Workflow** | Problem Statement §3 | Full lifecycle: Natural-language request ➔ Plan ➔ Scans ➔ Ingestion ➔ Correlation ➔ Risk Ranking ➔ Human Gate ➔ Typst PDF Report. |
| **Adaptive Reasoning** | Problem Statement §1, §2 | Evidence-based reasoning using an explicit `EvidenceBoard`: formulates hypotheses, identifies falsifiers, selects contextual tools, and avoids repeated actions. |
| **Tool Scope & Coverage** | Problem Statement §4, §6 | **Clears mandatory prototype requirement** with 3 live engines covering network & web (Nmap, Nikto, OWASP ZAP), plus auxiliary probe tools. |
| **Integration Transparency** | Problem Statement §4, §6, §9.6 | Truthful disclosure matrix classifying all 7 named tools as *Live*, *Import-only*, *Planned*, or *Unsupported*. |
| **Evidence & Traceability** | Problem Statement §5.5, §13 | Raw output excerpts, step pointers, and cryptographic SHA-256 digests. Zero hallucinated CVEs (offline CVE Grounding). |
| **Human-in-the-Loop** | Problem Statement §5.7, Rules §10.6 | Mandatory action approval gates before any active probe or scanner executes. Exact command line (`argv`) displayed. |
| **Client-Ready VAPT Report** | Problem Statement §5.8, §7 | Automated Typst PDF compilation containing all 6 required sections (§7.1 through §7.6) plus an evidence artifact index. |

---

## 7-Tool Integration Status Matrix (§4, §6, §9.6)

In strict accordance with **Problem Statement §4, §6** and **Hackathon Rules §3.4, §3.6** (Honest Capability Disclosure), the table below documents the truthful integration status across all seven named tools:

| # | Tool Name | Hackathon Expected Role | AIPENT Status | Implementation Architecture |
| :-: | :--- | :--- | :---: | :--- |
| **1** | **Nmap** | Host, port, service discovery & enumeration | **LIVE** | Native subprocess execution + XML stream parser ([`adapters/nmap.py`](backend/src/app/adapters/nmap.py)). |
| **2** | **Nikto** | Web server configuration & known issues | **LIVE** | Native subprocess execution + JSON result parser ([`adapters/nikto.py`](backend/src/app/adapters/nikto.py)). |
| **3** | **OWASP ZAP** | Web application & API vulnerability scanning | **LIVE** | Docker MCP Gateway / baseline scan runner ([`adapters/zap.py`](backend/src/app/adapters/zap.py)). |
| **4** | **Burp Suite** | Web testing & analyst-assisted validation | **PLANNED** | Roadmap: XML/JSON issue export parser and extension bridge. |
| **5** | **Nessus** | Infrastructure vulnerability assessment | **PLANNED** | Roadmap: `.nessus` v2 XML finding import adapter. |
| **6** | **OpenVAS** | Infrastructure vulnerability correlation | **PLANNED** | Roadmap: GMP/OMP API connector and XML report ingestion. |
| **7** | **Metasploit** | Controlled PoC validation (human-approved only) | **PLANNED** | Roadmap: Human-gated MSF RPC validation runner (strictly non-autonomous). |

### Auxiliary Tools Implemented (Beyond Baseline)

AIPENT provides additional specialized verification tools integrated into its closed execution catalogue:

- **`curl_tool` (Live):** Safe, non-destructive HTTP request/response inspection with header & digest capture ([`actions/probe.py`](backend/src/app/actions/probe.py)).
- **`whatweb` (Live):** Technology stack, CMS, and framework fingerprinting ([`adapters/whatweb.py`](backend/src/app/adapters/whatweb.py)).
- **`sslscan` (Live):** TLS/SSL cipher suite, certificate expiry, and protocol security auditing ([`adapters/sslscan.py`](backend/src/app/adapters/sslscan.py)).
- **`sqlmap` (Live - Human Gated):** Non-destructive SQL injection verification under operator approval.
- **`hashcat` (Live - Human Gated):** Controlled credential strength validation.

---

## Docker MCP Gateway & Sandboxed Tool Supply (§4, §6)

AIPENT introduces an enterprise-grade **Docker MCP Gateway** architecture that cleanly decouples agent reasoning from tool execution. Instead of running scanner binaries natively on the host as unconfined root processes, AIPENT connects to a **single unified endpoint** (`http://127.0.0.1:8812/sse`) managed by the Docker MCP Gateway.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              AIPENT MCP Gateway Topology                               │
└────────────────────────────────────────────────────────────────────────────────────────┘

    AIPENT Backend (FastAPI / LangGraph)
                  │
                  ▼  (Single SSE Connection: http://127.0.0.1:8812/sse)
    ┌─────────────────────────────┐
    │      Docker MCP Gateway     │  catalog: aipent.yaml (Port :8812)
    └──────────────┬──────────────┘
                   │
  ┌────────────────┼────────────────────────┬────────────────────────┐
  │ (stdio)        │ (Streamable HTTP)      │ (Streamable HTTP)      │ (Streamable HTTP)
  ▼                ▼                        ▼                        ▼
┌──────────────┐ ┌────────────────────────┐ ┌──────────────────────┐ ┌──────────────────────┐
│  Kali Linux  │ │    OWASP ZAP Stack     │ │    Curl MCP Server   │ │   Vulnify CVE MCP    │
│  MCP Server  │ │    (dtkmn/mcp-zap)     │ │ (@calibress/curl-mcp)│ │    (FastMCP Bridge)  │
├──────────────┤ ├────────────────────────┤ ├──────────────────────┤ ├──────────────────────┤
│ • nmap_scan  │ │ • zap_crawl_start      │ │ • curl_request       │ │ • search_cve         │
│ • nikto_scan │ │ • zap_crawl_status     │ │   (Safe, isolated    │ │ • get_cve_details    │
│ • dirb_scan  │ │ • zap_passive_scan_wait│ │    HTTP requests)    │ │ • lookup_kev         │
│ • whatweb    │ │ • zap_report_generate  │ └──────────────────────┘ └──────────────────────┘
│ • sqlmap     │ └───────────┬────────────┘
│ • hashcat    │             │
└──────────────┘             ▼
                     ┌───────────────┐
                     │  zaproxy:8090 │
                     │  (Daemon Core)│
                     └───────────────┘
```

### 1. Single-Point Tool Supply
The backend communicates exclusively with the Gateway via standard Model Context Protocol (MCP) Server-Sent Events (SSE). The LLM never manages scanner processes, container lifecycles, or network ports directly; it interacts with normalized, schema-validated tools.

- **Kali Linux MCP Server (`cyberillo/kali-mcp-server:latest`):** A long-lived stdio container exposing `nmap`, `nikto`, `dirb`, `whatweb`, `sqlmap`, and `hashcat`.
- **OWASP ZAP MCP Server (`dtkmn/mcp-zap-server:v0.17.1`):** A remote streamable HTTP service on port `7456` driving ZAP's automated spidering, AJAX crawling, and passive analysis.
- **Curl MCP Server (`@calibress/curl-mcp`):** A lightweight HTTP microservice on port `7458` enabling granular request dispatching, header inspection, and response verification.
- **Vulnify MCP Server (`vulnify-mcp`):** A FastMCP container exposing local SQLite CVE intelligence.

### 2. Sandboxing & Safety Architecture ("Safeways")
AIPENT enforces multi-layered defense-in-depth to guarantee safety during automated assessments:

1. **Zero Shell Access:** The agent possesses **no** `sh`, `bash`, or arbitrary command execution tool. The LLM can only invoke strictly defined schemas with validated arguments.
2. **Containerized Process Isolation:** All scanner processes execute inside disposable, non-root Docker containers. A scanner fault or exploit payload cannot compromise the host filesystem.
3. **Loopback & Network Segregation:** The Gateway is bound strictly to loopback `127.0.0.1`. Containers communicate with lab targets through the controlled `host.docker.internal:host-gateway` bridge.
4. **Human Action Gatekeeper:** Dangerous or active actions (`sqlmap`, `curl_request`, `zap`) halt execution and require explicit analyst approval. The gate displays the verbatim `argv`, destination, and rationale.
5. **Execution Ceilings:** Strict duration limits (`ZAP_MAX_SPIDER_SCAN_DURATION=2m`, scan timeout `600s`, maximum 40 turns) prevent runaway loops or unintentional denial of service.

---

### 3. Starting the MCP Server Stack & Gateway

#### Step 1: Configure Environment
```bash
cp deploy/mcp-zap/.env.example deploy/mcp-zap/.env
# Verify or edit MCP_API_KEY and ZAP_API_KEY
```

#### Step 2: Start ZAP & Vulnify Compose Services
```bash
docker compose -f deploy/mcp-zap/compose.yaml up -d
```

#### Step 3: Launch the Docker MCP Gateway
```bash
./deploy/mcp-gateway/start.sh
```
*`start.sh` automatically installs `aipent.yaml` into `~/.docker/mcp/catalogs/`, writes isolated secrets to `~/.docker/mcp/aipent-secrets.env` (mode 0600), starts the curl daemon, and launches the gateway on `127.0.0.1:8812`.*

---

### 4. Containerized Backend (`backend/Dockerfile` & Compose)

AIPENT provides a production-grade multi-stage `backend/Dockerfile` based on `python:3.12-slim-bookworm` with `uv` package caching, system fonts for Typst PDF compilation, and container healthchecks.

To run the backend as a container:
```bash
# Start backend via root Compose
docker compose up -d backend
```
Or build the backend image standalone:
```bash
docker build -t aipent-backend:latest ./backend
```

---

## Architecture & Reasoning Loop

AIPENT uses a multi-agent StateGraph orchestrated with **LangGraph V2** and persistent SQLite checkpointing.

```
                            ┌────────────────────────┐
                            │    Analyst Request     │
                            │ (Target, Ports, Scope) │
                            └───────────┬────────────┘
                                        │
                                        ▼
                            ┌────────────────────────┐
                            │      Intake Node       │
                            │ (Validates Boundaries) │
                            └───────────┬────────────┘
                                        │
                                        ▼
                             ┌──────────────────────┐
                             │  SUPERVISOR ROUTER   │◀────────────────┐
                             │ (Evaluates Hypotheses│                 │
                             │  & Selects Next Role)│                 │
                             └──────────┬───────────┘                 │
                                        │                             │
          ┌─────────────────────────────┼─────────────────────────────┤
          │                             │                             │
          ▼                             ▼                             ▼
   ┌───────────────┐             ┌───────────────┐             ┌───────────────┐
   │  Recon Role   │             │Discovery Role │             │Validation Role│
   │  (nmap,       │             │  (nikto,      │             │  (curl_tool,  │
   │   whatweb,    │             │   zap,        │             │   sqlmap,     │
   │   sslscan)    │             │   dirb)       │             │   hashcat)    │
   └──────┬────────┘             └───────┬───────┘             └───────┬───────┘
          │                             │                             │
          └─────────────────────────────┼─────────────────────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────┐
                         │      HUMAN ACTION GATE      │
                         │   (Policy: Auto vs Pause)   │
                         └──────────────┬──────────────┘
                                        │
                         [Operator Approves / Rejects / Steers]
                                        │
                                        ▼
                         ┌─────────────────────────────┐
                         │       Action Executor       │
                         │ (Executes Subprocess / MCP) │
                         └──────────────┬──────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────┐
                         │   Normalizer & Deduplicator │
                         │ (Extracts Evidence & CVEs)  │
                         └──────────────┬──────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────┐
                         │      Final Review Gate      │
                         │ (Analyst Accepts Delivery)  │
                         └──────────────┬──────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────┐
                         │    Typst Report Compiler    │
                         │  (Client-Ready VAPT PDF)    │
                         └─────────────────────────────┘
```

### The Three Specialist Roles

1. **Recon Specialist:** Enumerates open ports, service banners, TLS configurations, and technology stacks without touching application logic.
2. **Discovery Specialist:** Maps endpoints, checks for known web server vulnerabilities, scans directories, and runs DAST baselines.
3. **Validation Specialist:** Formulates falsifiable hypotheses and executes safe, controlled probes (`curl_tool`, parameter checks) to confirm suspected findings.

### EvidenceBoard & Adaptive Memory

AIPENT maintains an active `EvidenceBoard` persisted in SQLite across turns:
- **Hypotheses:** Candidate vulnerabilities under active investigation (Status: `open`, `supported`, `refuted`, `inconclusive`).
- **Decisions:** Structured records capturing *Action*, *Target*, *Observation*, *Expected Observation*, and *What Would Falsify*.
- **Correlation:** Findings begin as `suspected` and are promoted to `confirmed` only when verified by a secondary probe or multi-tool corroboration.

---

## Safety, Governance & Ethical Boundaries

AIPENT is designed from the ground up to operate within authorized environments and comply with **Hackathon Rules §9 & §10**:

1. **Strict Scope Enforcement (Rule §9.1, §9.6):** Targets and ports are validated before an action can be queued. HTTP probes re-validate URL hostnames and ports. Requests outside the declared boundary are rejected.
2. **Policy-Enforced Human Action Gate (Rule §10.6):** High-risk actions (`sqlmap`, `curl_tool`, `zap`, `hashcat`) automatically pause the agent loop. The operator is presented with the exact command line (`argv`), rationale, and target before approving, rejecting, or injecting steering instructions.
3. **No Autonomous Offensive Exploitation (Problem Statement §2, §5.7):** The agent never performs uncontrolled exploitation or executes arbitrary shell scripts. All tools execute from a closed action catalogue.
4. **Zero Hallucinated Findings (Rule §10.4, Problem Statement §5.6):** CVEs, CVSS ratings, and CWEs are extracted strictly from tool output parsers and cross-checked against a local offline NVD database snapshot. Fabricated CVEs are programmatically rejected.
5. **Cryptographic Proof of Work (Problem Statement §5.5, §13):** Every tool output is saved to disk as an immutable artifact with an associated SHA-256 hash. The final report references these exact hashes in its Evidence Index.

---

## Professional VAPT Report Compliance (§7)

AIPENT compiles a professional, client-ready PDF report using **Typst**. The generated deliverable matches every subsection of Problem Statement §7:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        VAPT Report Architecture                        │
├────────────────────────────────────────────────────────────────────────┤
│ §7.1 Executive Summary      │ Scope, overall posture, & score          │
│ §7.2 Assessment Methodology │ Rules of engagement, assets, tool summary│
│ §7.3 Severity Distribution  │ Critical / High / Med / Low / Info breakdown
│ §7.4 Detailed Findings      │ Asset, CVSS, CVE/CWE, raw evidence, status
│ §7.5 Impact & Remediation   │ Business impact, actionable fixes, refs  │
│ §7.6 Assessment Limitations │ Scope constraints, assumptions, approvals│
│ Evidence Index (Bonus)      │ Cryptographic SHA-256 table of artifacts │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 5-Minute Demonstration Walkthrough (Judges' Checklist §10)

Follow this 5-minute checklist to evaluate AIPENT during a live demonstration against the authorized OWASP Juice Shop lab target:

### Step 1: Start the Lab & AIPENT Desk
```bash
# 1. Start the authorized Juice Shop lab
docker compose -f lab.lvl1.yml up -d

# 2. Start the unified backend and frontend web desk
cd frontend && npm run dev
```
Open your browser at `http://localhost:5173`.

### Step 2: Enter Scope & Conversational Request (§10.1)
1. In the Mission Desk, create an assessment:
   - **Title:** `Juice Shop Security Assessment`
   - **Target:** `127.0.0.1`
   - **Port:** `3000`
   - **Request:** `Perform an authorized reconnaissance and web vulnerability assessment against the target store.`
2. Observe scope enforcement registering the boundary and displaying the engagement rules.

### Step 3: Observe Adaptive Planning & Recon (§10.2, §10.3)
1. Start the run. Watch the **Supervisor** route to the **Recon Specialist**.
2. Recon dispatches `nmap_scan` and `whatweb`.
3. Notice the real-time progress bar, live step cards with duration and exit codes, and service surface mapping.

### Step 4: Inspect the Human Action Gate (§10.5)
1. When the agent advances to discovery and validation (`curl_tool` or `zap_baseline`), execution **pauses at the Human Action Gate**.
2. Review the gate card: inspect the exact `argv` command, target, and rationale.
3. Click **Approve** (or test **Steer** by entering developer guidance in the prompt). The action executes and records an immutable audit event.

### Step 5: Verify AI Correlation & Deduplication (§10.4)
1. Watch the agent formulate hypotheses in the reasoning thread.
2. Note findings appearing first as `suspected` and transitioning to `confirmed` upon multi-tool verification.
3. Confirm that duplicate alerts for the same endpoint are consolidated without losing underlying evidence pointers.

### Step 6: Review & Final Report Download (§10.6, §10.7)
1. At the conclusion of testing, the agent pauses at the **Final Review Gate**.
2. Inspect the synthesized risk score and vulnerability counts.
3. Click **Approve Final Report**. The backend compiles the Typst PDF.
4. Click **Download PDF Report**: verify all §7 sections, actionable remediation recommendations, and the cryptographic SHA-256 evidence index.

---

## CVE Intelligence: Vulnify Database Setup

AIPENT achieves **deterministic, zero-hallucination CVE intelligence** by querying a pinned, normalized offline SQLite database: [**Vulnify**](https://github.com/mez-0/vulnify) (by mez-0).

### What's in Vulnify
- **Full CVE Corpus:** 417,000+ normalized CVEs from upstream CVEProject (cvelistV5) and NVD.
- **Enrichment:** Official CVSS v2/v3/v3.1 scores, CPE configuration matching, CWE taxonomy, and upstream advisory URLs.
- **Threat Signals:** CISA Known Exploited Vulnerabilities (KEV) and FIRST EPSS exploit probabilities.
- **Offline Architecture:** AIPENT queries `vulnify.db` directly in-process via [`app.intel.cve.CveCatalog`](backend/src/app/intel/cve.py) in read-only mode with sub-millisecond lookups—requiring no external network calls during security scans.

### Setup & Verification Script (`setup_vulnify.sh`)

To make getting the database seamless without complex manual steps, run the included setup script at the project root:

```bash
# 1. Verify existing DB or decompress a local archive
./setup_vulnify.sh

# 2. (Optional) If you do not have vulnify.db yet and have internet connectivity:
./setup_vulnify.sh --download
```

The script automatically:
1. Detects an existing `vulnify.db` and verifies table counts (`cve`, `kev`, `cpe_match`).
2. Decompresses pre-downloaded `vulnify.db.zst` or `vulnify.db.zip` using `zstd`, `unzstd`, or Python.
3. Provides exact fallback instructions for downloading release assets manually via `gh release download -R mez-0/vulnify --pattern "vulnify.db.zst"`.

An optional Dockerized FastMCP bridge is also maintained in [`vulnify-mcp/`](vulnify-mcp/) and configured in [`deploy/mcp-zap/compose.yaml`](deploy/mcp-zap/compose.yaml).

---

## Quickstart & Installation

### Prerequisites
- Linux / macOS / WSL2
- Python 3.12+
- Node.js 20+
- Docker (for lab target container)
- `uv` (recommended) or `pip`

### 1. Setup Backend (Local or Docker)

**Option A: Local Virtual Environment**
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
cp .env.example .env
# Edit backend/.env to set your API keys (OpenRouter, Groq, Ollama, etc.)
```

**Option B: Docker Container**
```bash
cp backend/.env.example backend/.env
# Edit backend/.env, then launch backend container
docker compose up -d backend
```

### 2. Setup Frontend
```bash
cd frontend
npm install
```

### 3. Start Environment
```bash
# Start backend and web desk together
cd frontend && npm run dev
```

---

## Verification & Test Results

AIPENT includes full automated test suites across both backend and frontend:

```bash
# Backend unit & integration test suite (128 passed)
cd backend && .venv/bin/pytest backend/tests

# Frontend unit tests & production build verification (16 passed)
cd frontend && npm test && npm run build
```

---

## Project Directory Layout

```
aipent/
├── backend/
│   ├── src/app/
│   │   ├── actions/            # Closed action catalogue & subprocess executor
│   │   ├── adapters/           # Tool parsers: nmap, nikto, zap, whatweb, sslscan, hashcat
│   │   ├── agents/             # LangGraph V2 StateGraph, specialist roles & human gate
│   │   ├── api/                # FastAPI REST endpoints & SSE event streaming
│   │   ├── core/               # DB, policy, config, and in-process notifications
│   │   ├── domain/             # SQLModel models: Assessment, Step, Finding, Evidence, Approval
│   │   └── reporting/          # Typst PDF report compiler & executive templates
│   ├── tests/                  # 128 automated pytest unit and integration tests
│   └── scripts/                # Observation test suites & challenge verification
├── frontend/
│   ├── src/
│   │   ├── components/         # Mission Conversation desk, approval cards, side record
│   │   ├── hooks/              # SSE live event streaming hooks
│   │   └── lib/                # Schemas, mission state folding & API client
│   └── scripts/dev.mjs         # Dual-process orchestrator for API + Vite
├── deploy/                     # Docker MCP Gateway configurations (Kali + ZAP)
├── lab.lvl1.yml                # Authorized Juice Shop lab compose target
├── lab.lvl2.yml                # Authorized DVWA lab compose target
└── README.md
```

---

## Third-Party Attributions & Open Source Compliance

In compliance with **Hackathon Rules §4.5 & §7.3**, AIPENT gratefully acknowledges the following open-source technologies:

- **Vulnify (by mez-0):** Offline CVE, KEV, EPSS, and CPE normalized intelligence pipeline and SQLite corpus ([github.com/mez-0/vulnify](https://github.com/mez-0/vulnify)).
- **LangGraph & LangChain:** Stateful multi-agent graph orchestration (MIT License).
- **FastAPI & Starlette:** High-performance async REST and SSE API framework (MIT License).
- **SQLAlchemy & SQLModel:** Database ORM and schema modeling (MIT License).
- **Typst:** High-speed document and PDF typesetting system (Apache 2.0 License).
- **Nmap, Nikto, OWASP ZAP:** Industry-standard security assessment tools (GPL / Apache 2.0).
- **React, Vite, Zustand, TailwindCSS:** Frontend interface and reactive desk framework (MIT License).
- **IBM Plex Fonts:** Professional typography (SIL Open Font License).

---

## Authors & Hackathon Team

Developed for the **DataOps Innovation Hackathon: AI Agent for Automated Penetration Testing**.  
All demonstrations and automated tests are conducted strictly on locally hosted, organizer-authorized lab environments.
