# AIPENT — AI-Powered Unified VAPT Agent

> **Innovation Hackathon Submission: AI Agent for Automated Penetration Testing**  
> *Final Participant Problem Statement: AI-Powered Unified VAPT Agent*  
> *Fully compliant with Hackathon Rules, NIST SP 800-115, OWASP Top 10, and Human-in-the-Loop Governance.*

[![Tests](https://img.shields.io/badge/backend%20tests-181%20passed-brightgreen)](#verification)
[![Frontend](https://img.shields.io/badge/frontend%20tests-28%20passed-brightgreen)](#verification)
[![Python](https://img.shields.io/badge/python-3.12-blue)](#prerequisites)
[![React](https://img.shields.io/badge/react-19%20%7C%20vite-61dafb)](#prerequisites)
[![LangGraph](https://img.shields.io/badge/orchestration-LangGraph%20v2-orange)](#architecture)
[![Safety](https://img.shields.io/badge/safety-human--in--the--loop%20gated-red)](#safety-governance--ethical-boundaries)

---

## Executive Summary

Penetration testing typically forces security analysts to spend more time aggregating and formatting outputs from disconnected scanners than evaluating genuine security risks.

**AIPENT** solves this problem by providing a context-aware, adaptive, and evidence-driven conversational AI agent. Instead of blindly executing predefined script sequences, AIPENT orchestrates an end-to-end vulnerability assessment through an **interactive Supervisor planning gate** (editable in both Web UI and Terminal CLI), a **three-specialist LangGraph loop** (`Recon` → `Discovery` → `Validation`) powered by high-speed engines (`ffuf`, `katana`, `nuclei`, `nmap`, `nikto`, `zap`), in-memory client-side JavaScript and artifact parsers, multi-tool evidence correlation, **dual-layer human approval gates** (initial plan review + active probe gating), and an executive-ready, cryptographically verifiable VAPT report in PDF format.

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                AIPENT End-to-End VAPT Lifecycle                                 │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
   Analyst Request ➔ Supervisor Plan ➔ Operator Plan Review & Edit Gate ➔ Gated Scan Orchestration
      ➔ Fast Ingestion & JS/HTML Parsers ➔ AI Correlation ➔ Risk Prioritization ➔ Active Validation Gate
                                    ➔ Unified VAPT Report (PDF)
```

---

## Problem Statement & Hackathon Alignment

AIPENT is engineered specifically against the Hackathon Problem Statement and Rules:

| Requirement Category | Hackathon Section | AIPENT Solution |
| :--- | :--- | :--- |
| **End-to-End Workflow** | Problem Statement §3 | Full lifecycle: Natural-language request ➔ Adaptive Supervisor Plan ➔ Interactive Operator Review Gate ➔ Gated Scans ➔ Ingestion & Parsers ➔ Correlation ➔ Risk Ranking ➔ Final Human Gate ➔ Typst PDF Report. |
| **Adaptive Reasoning** | Problem Statement §1, §2 | Evidence-based reasoning using an explicit `EvidenceBoard`: formulates hypotheses, identifies falsifiers, selects contextual tools, and avoids repeated actions. |
| **Tool Scope & Coverage** | Problem Statement §4, §6 | **Clears mandatory prototype requirement** with 3 live engines covering network & web (Nmap, Nikto, OWASP ZAP), plus high-velocity discovery and validation tools (`ffuf`, `katana`, `nuclei`, `whatweb`, `sslscan`, `sqlmap`, `hashcat`, `curl_batch`). |
| **Integration Transparency** | Problem Statement §4, §6, §9.6 | Truthful disclosure matrix classifying all 7 named tools as *Live*, *Import-only*, *Planned*, or *Unsupported*. |
| **Evidence & Traceability** | Problem Statement §5.5, §13 | Raw output excerpts, step pointers, and cryptographic SHA-256 digests. Zero hallucinated CVEs (offline CVE Grounding via Vulnify). |
| **Human-in-the-Loop** | Problem Statement §5.7, Rules §10.6 | **Dual-layer approval gates:** Initial assessment plan review & customization before scanning begins, plus mandatory action gates before any active probe or scanner executes (verbatim `argv` displayed). |
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

AIPENT provides additional specialized discovery, fuzzing, and verification tools integrated into its closed execution catalogue:

- **`ffuf` (Live):** Ultra-fast Go directory and parameter fuzzing with automated Single-Page Application (SPA) calibration (filtering fallback `index.html` responses) and curated high-signal API wordlists (< 1.5s execution) ([`adapters/ffuf.py`](backend/src/app/adapters/ffuf.py)).
- **`katana` (Live):** Next-generation headless web crawler parsing client-side JavaScript bundles (`main.js`, `vendor.js`), discovering hidden REST endpoints, route schemas, and API paths in 2–3 seconds ([`adapters/katana.py`](backend/src/app/adapters/katana.py)).
- **`nuclei` (Live):** Fast, template-based vulnerability scanner running targeted template packs (exposures, misconfigurations, swagger API, SQLi auth bypass, CVEs) with zero false positives ([`adapters/nuclei.py`](backend/src/app/adapters/nuclei.py)).
- **`curl_batch` / `curl_tool` (Live):** Batched and single safe HTTP request/response inspection with header, status, and cryptographic SHA-256 digest capture ([`actions/probe.py`](backend/src/app/actions/probe.py), [`agents/direct_tools.py`](backend/src/app/agents/direct_tools.py)).
- **`whatweb` (Live):** Technology stack, CMS, and framework fingerprinting ([`adapters/whatweb.py`](backend/src/app/adapters/whatweb.py)).
- **`sslscan` (Live):** TLS/SSL cipher suite, certificate expiry, and protocol security auditing ([`adapters/sslscan.py`](backend/src/app/adapters/sslscan.py)).
- **`sqlmap` (Live - Human Gated):** Non-destructive SQL injection verification under operator approval ([`adapters/sqlmap.py`](backend/src/app/adapters/sqlmap.py)).
- **`hashcat` (Live - Human Gated):** Controlled credential strength validation ([`adapters/hashcat.py`](backend/src/app/adapters/hashcat.py)).

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
│ • ffuf_scan  │ │ • zap_passive_scan_wait│ │    HTTP requests)    │ │ • lookup_kev         │
│ • katana_crawl││ • zap_report_generate  │ └──────────────────────┘ └──────────────────────┘
│ • nuclei_scan│ └───────────┬────────────┘
│ • whatweb    │             │
│ • sqlmap     │             ▼
│ • hashcat    │     ┌───────────────┐
│ • dirb_scan  │     │  zaproxy:8090 │
└──────────────┘     │  (Daemon Core)│
                     └───────────────┘
```

### 1. Single-Point Tool Supply & Smart Hybrid Execution
The backend communicates with the Gateway via standard Model Context Protocol (MCP) Server-Sent Events (SSE). The LLM never manages scanner processes, container lifecycles, or network ports directly; it interacts with normalized, schema-validated tools.

- **Kali Linux MCP Server (`cyberillo/kali-mcp-server:latest`):** A long-lived stdio container exposing `nmap`, `nikto`, `ffuf`, `katana`, `nuclei`, `whatweb`, `sqlmap`, `hashcat`, and `dirb`.
- **Smart Local Acceleration:** When high-throughput binaries are installed locally on the host (`ffuf`, `katana`, `nuclei`, `hashcat`), AIPENT automatically detects them and enables zero-latency local execution with real-time output streaming, avoiding container serialization overhead while maintaining 100% policy, scope, and approval gate parity.
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

### 3. Starting the Entire Stack (One Command)

AIPENT provides a unified launcher that automatically boots the MCP containers, Docker MCP Gateway, backend API, and frontend web desk in the correct dependency sequence with built-in health checks and graceful teardown:

```bash
# Start the full stack (MCP infrastructure + Gateway + Backend + Frontend)
./start.sh

# Or start the full stack including the OWASP Juice Shop lab target:
./start.sh --with-lab
```

#### Individual Component Control (Under the Hood)
If you prefer running services individually:

1. **Start MCP Tool Containers (ZAP, Vulnify, Curl, Typst, Kali, Nuclei, Katana):**
   ```bash
   docker compose -f mcp/compose.yaml up -d
   ```
   *(Pulls and initializes all containerized tool engines and MCP services in one command).*
2. **Launch Docker MCP Gateway:**
   ```bash
   ./gateway/start.sh
   ```
3. **Start Backend API:**
   ```bash
   cd backend && uv run uvicorn app.main:app --port 8010
   ```
4. **Start Frontend Desk:**
   ```bash
   cd frontend && npm run dev:web
   ```
*(Run `./start.sh --stop` to stop background processes and Docker services, or `./start.sh --status` to inspect health).*


---

## Architecture & Reasoning Loop

> **Comprehensive Technical Specification:** For the complete, detailed specification of the multi-agent topology, closed Observe-Reason-Act loop, inter-agent communication channels, and telemetry pipelines, see [`docs/AGENT_ARCHITECTURE_AND_COMMUNICATION.md`](docs/AGENT_ARCHITECTURE_AND_COMMUNICATION.md).

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
                            ┌────────────────────────┐
                            │     Planning Node      │
                            │ (Drafts Initial Plan)  │
                            └───────────┬────────────┘
                                        │
                                        ▼
                         ╔══════════════════════════════╗
                         ║   INITIAL PLAN REVIEW GATE   ║
                         ║  (Web UI / CLI Plan Editor)  ║
                         ╚══════════════╤═══════════════╝
                                        │ [Operator Edits & Approves Plan]
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
   │  (nmap,       │             │ (ffuf, katana,│             │ (curl_batch,  │
   │   whatweb,    │             │  nuclei, nikto│             │  sqlmap,      │
   │   sslscan)    │             │  zap_baseline)│             │  hashcat)     │
   └──────┬────────┘             └───────┬───────┘             └───────┬───────┘
          │                             │                             │
          └─────────────────────────────┼─────────────────────────────┘
                                        │
                                        ▼
                         ╔══════════════════════════════╗
                         ║      HUMAN ACTION GATE       ║
                         ║   (Policy: Auto vs Pause)    ║
                         ╚══════════════╤═══════════════╝
                                        │ [Operator Approves / Rejects / Steers]
                                        ▼
                         ┌─────────────────────────────┐
                         │       Action Executor       │
                         │ (Executes Subprocess / MCP) │
                         └──────────────┬──────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────┐
                         │  Parsers, Normalizer & Dedup│
                         │(Extracts JS Routes/CVE/CWE) │
                         └──────────────┬──────────────┘
                                        │
                                        ▼
                         ╔══════════════════════════════╗
                         ║      Final Review Gate       ║
                         ║  (Analyst Accepts Delivery)  ║
                         ╚══════════════╤═══════════════╝
                                        │
                                        ▼
                         ┌─────────────────────────────┐
                         │    Typst Report Compiler    │
                         │  (Client-Ready VAPT PDF)    │
                         └─────────────────────────────┘
```

### 1. Interactive Assessment Plan Gate & Plan Editor
Before any network probe or scan is queued, the **Planning Node** analyzes the operator's natural language request, declared targets, and authorized boundaries.
- **Automated Plan Drafting:** Formulates an initial structured plan (`PlanStep` list with action, target, and rationale).
- **Interactive Web UI Plan Editor:** Displays a dedicated card in the mission desk where operators can reorder steps, add custom commands (`+ Add Step`), delete unnecessary actions (`✕`), or swap engines before executing.
- **Terminal CLI Plan Review:** Provides interactive `[A]ccept / [E]dit / [R]eject` options in terminal mode.
- Once approved, the plan is committed to the graph state (`state['plan']`) and guides specialist routing.

### 2. The Three Specialist Roles
1. **Recon Specialist:** Enumerates open ports, service banners, TLS cipher suites, and technology fingerprints (`nmap_scan`, `whatweb`, `sslscan`) without executing application-level probes.
2. **Discovery Specialist:** Maps attack surfaces using high-speed crawlers and fuzzers: parses client-side JavaScript bundles with `katana`, fuzzes hidden API endpoints with `ffuf` (SPA-calibrated), runs targeted CVE template packs with `nuclei`, and conducts web server baseline checks (`nikto`, `zap_baseline`).
3. **Validation Specialist:** Formulates falsifiable hypotheses, parses discovered artifacts, and runs safe, controlled probes (`curl_batch`, `curl_request`, `sqlmap`, `hashcat`) to confirm or refute suspected vulnerabilities.

### 3. Static Response & Bundle Parsers (`backend/src/app/parsers/`)
To eliminate LLM context bloat and hallucination during discovery, AIPENT integrates dedicated, in-memory static parsers:
- **`js_parser`:** Dissects modern SPA JavaScript bundles (`main.js`, `vendor.js`, `runtime.js`), extracting hardcoded REST routes (`/rest/admin/...`, `/api-docs/`, `/ftp/`), secrets, and API schemas.
- **`html_parser`:** Parses raw HTML responses, directory listings, comments, and embedded forms.
- **`json_parser`:** Ingests OpenAPI / Swagger schemas and API payloads.
- **`manifest`:** Aggregates discovered routes, files, endpoints, and technologies into a persistent sidecar manifest per target.

### 4. Decoupled Persistence & Bounded State Architecture
AIPENT enforces strict decoupling between graph execution and relational persistence:
- **Clean Repository Pattern:** All database operations are encapsulated in dedicated repositories ([`app.persistence.assessment_repo.AssessmentRepo`](backend/src/app/persistence/assessment_repo.py), [`StepRepo`](backend/src/app/persistence/step_repo.py), [`FindingRepo`](backend/src/app/persistence/finding_repo.py), [`AuditRepo`](backend/src/app/persistence/audit_repo.py)).
- **Pure In-Memory Observation Builders:** [`observation_from_step`](backend/src/app/agents/observations.py) operates completely in-memory with zero ad-hoc SQL queries.
- **Bounded State & Anti-Amnesia:** Observations and steps in `AssessmentState` are strictly capped (max 10 entries) to prevent unbounded memory growth and token exhaustion while preserving critical decision history and rejection records.
- **Domain Event Folding:** State reconstruction folds timeline events in the domain layer ([`app.domain.reasoning`](backend/src/app/domain/reasoning.py)) to eliminate circular dependencies.

### 5. Multi-Model Support & Run-Start Manifest
AIPENT supports plug-and-play LLM providers across both cloud and local setups:
- **Supported Providers:** Cerebras (ultra-fast inference), Groq, Ollama, DeepSeek, OpenAI, NVIDIA NIM, and Anthropic.
- **Run-Start Transparency:** At mission initiation, AIPENT logs and broadcasts a full configuration manifest detailing:
  - Model provider and name per agent role (`supervisor`, `recon`, `discovery`, `validation`, `coordinator`, `report`).
  - Turn budgets per role (Recon: 3, Discovery: 4, Validation: 8; global turn limit: 60).
  - Tool execution ceilings (max 10 tool calls per supervisor step; max 30 supervisor calls per run; recursion limit: 160).

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
docker compose -f labs/lab.lvl1.yml up -d

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

### Step 3: Review & Customize Proposed Plan (Interactive Plan Editor) (§10.2)
1. Start the run. Watch the **Planning Node** generate a structured assessment plan tailored to the request.
2. The agent pauses at the **Initial Plan Review Gate** (`AWAITING_PLAN`).
3. In the Web UI **Review Proposed Assessment Plan** editor (or Terminal CLI prompt):
   - Review proposed scan actions (`nmap_scan`, `katana_crawl`, `ffuf_scan`, `nuclei_scan`).
   - Add new steps (`+ Add Step`), remove redundant checks (`✕`), or adjust targets.
4. Click **Approve Plan** to commit the strategy to graph state and commence execution.

### Step 4: Observe High-Speed Recon & Discovery (§10.3)
1. Watch the **Supervisor** route to the **Recon Specialist** for port & service enumeration (`nmap_scan`, `whatweb`).
2. The agent transitions to the **Discovery Specialist**:
   - `katana_crawl` parses client-side JavaScript bundles (`main.js`, `vendor.js`), discovering hidden REST endpoints (`/ftp`, `/rest/admin`, `/api-docs`) in **2–3 seconds**.
   - `ffuf_scan` executes with automated SPA calibration, fuzzing high-value routes in **< 1.5 seconds** while discarding false-positive `index.html` fallback responses.
3. Notice live step cards with duration, exit codes, and sidecar manifest route extraction in real-time.

### Step 5: Inspect the Human Action Gate (§10.5)
1. When the agent advances to active probes and validation (`sqlmap`, `curl_batch`, or active `zap`), execution **pauses at the Human Action Gate**.
2. Review the gate card: inspect the exact command line (`argv`), destination target, and hypothesis rationale.
3. Click **Approve** (or test **Steer** by injecting developer guidance). The action executes and records an immutable audit trail.

### Step 6: Verify AI Correlation & Deduplication (§10.4)
1. Watch the agent formulate hypotheses on the `EvidenceBoard` in the reasoning thread.
2. Note findings appearing first as `suspected` and transitioning to `confirmed` upon multi-tool verification.
3. Confirm that duplicate alerts for the same endpoint are consolidated without losing underlying raw evidence pointers or SHA-256 hashes.

### Step 7: Review & Final Report Download (§10.6, §10.7)
1. At the conclusion of testing, the agent pauses at the **Final Review Gate**.
2. Inspect the synthesized risk score, executive summary, and vulnerability breakdown.
3. Click **Approve Final Report**. The backend compiles the client-ready Typst PDF deliverable.
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

An optional Dockerized FastMCP bridge is also maintained in [`vulnify-mcp/`](vulnify-mcp/) and configured in [`mcp/compose.yaml`](mcp/compose.yaml).

---

## Quickstart & Installation



### Prerequisites
- Linux / macOS / WSL2
- Python 3.12+
- Node.js 20+
- Docker & Docker Compose (for lab targets and MCP container services)
- `uv` (recommended) or `pip`

---

### 1. Docker MCP Gateway CLI Plugin (`docker mcp`)

The Docker MCP Gateway requires the **`docker-mcp`** CLI plugin (from [`docker/mcp-gateway`](https://github.com/docker/mcp-gateway)).

> **Important for Linux / Standalone Docker Engine:** While Docker Desktop may manage MCP components via UI extensions, standalone Docker Engine on Linux **does not pre-bundle** the `docker mcp` CLI plugin. You must install it into your user CLI plugins directory.

#### Linux / WSL2 / macOS Installation
```bash
# 1. Create the Docker CLI plugins directory
mkdir -p ~/.docker/cli-plugins

# 2. Download and unpack the latest release binary (adjust architecture if arm64)
curl -fsSL https://github.com/docker/mcp-gateway/releases/latest/download/docker-mcp-linux-amd64.tar.gz | tar -xz -C ~/.docker/cli-plugins/

# 3. Grant executable permissions
chmod +x ~/.docker/cli-plugins/docker-mcp

# 4. Verify installation
docker mcp version
```

---

### 2. Project Discovery & Web Fuzzing Engines (`ffuf`, `katana`, `nuclei`)

AIPENT includes native adapters for three high-velocity discovery and vulnerability validation engines:

| Tool | Role in AIPENT | Primary Capability |
| :--- | :--- | :--- |
| **`ffuf`** | Discovery Specialist | High-speed directory and API parameter fuzzing with automated SPA auto-calibration (`-ac`) to filter fallback `index.html` noise. |
| **`katana`** | Discovery Specialist | Next-generation headless web crawler that parses client-side JavaScript bundles (`main.js`, `vendor.js`), discovering hidden endpoints, routes, and API schemas. |
| **`nuclei`** | Discovery & Validation | Fast, template-driven vulnerability scanner executing targeted CVE, exposure, and misconfiguration template packs with verified proof-of-concept output. |

#### Tool Execution Architecture (Containerized & Native Acceleration)
- **Containerized Execution via Docker MCP Gateway:** Like `nmap`, `nikto`, `sqlmap`, and `dirb`, `katana_crawl` and `nuclei_scan` execute through the containerized Docker MCP Gateway (`cyberillo/kali-mcp-server`), keeping tool dependencies isolated inside containers without requiring host installation.
- **Docker Compose Tool Binding:** All containerized images (`cyberillo/kali-mcp-server`, `projectdiscovery/nuclei`, `projectdiscovery/katana`) are wired directly in [`mcp/compose.yaml`](mcp/compose.yaml) and included in the root [`docker-compose.yml`](docker-compose.yml). Running `docker compose up` (or `./start.sh`) coordinates and fetches all tool images automatically.
- **Local Fuzzing Acceleration (`ffuf`):** For directory and API route fuzzing with automated SPA calibration (`-ac`), native binary execution is supported via [`LOCAL_PREFERRED_ACTIONS`](backend/src/app/actions/catalogue.py).

#### Installation Options

##### Option A: Using Go (Recommended)
Ensure Go is installed (`export PATH="$HOME/go/bin:$HOME/.local/bin:$PATH"`):
```bash
# 1. Install ffuf (v2)
go install github.com/ffuf/ffuf/v2@latest

# 2. Install ProjectDiscovery katana
go install github.com/projectdiscovery/katana/cmd/katana@latest

# 3. Install ProjectDiscovery nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# 4. Download / update initial Nuclei vulnerability templates
nuclei -update-templates
```

##### Option B: Using Homebrew (macOS / Linux)
```bash
brew install ffuf katana nuclei
nuclei -update-templates
```

##### Option C: Using `pdtm` (ProjectDiscovery Tool Manager)
```bash
go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest
pdtm -install katana,nuclei
nuclei -update-templates
```

##### Option D: Pre-compiled GitHub Release Binaries (Direct Download)
You can download pre-compiled releases directly from their GitHub repositories:
- **`ffuf`:** [github.com/ffuf/ffuf/releases](https://github.com/ffuf/ffuf/releases)
- **`katana`:** [github.com/projectdiscovery/katana/releases](https://github.com/projectdiscovery/katana/releases)
- **`nuclei`:** [github.com/projectdiscovery/nuclei/releases](https://github.com/projectdiscovery/nuclei/releases)

Place the extracted binaries in `~/.local/bin/` or `/usr/local/bin/` and verify:
```bash
ffuf -V && katana -version && nuclei -version
```

---

### Typst Compiler (For Professional PDF Reports)

AIPENT supports two compilation modes:
1. **Dockerized Compiler (Zero Setup - Recommended):** The official `ghcr.io/typst/typst:latest` container is included in `mcp/compose.yaml` and automatically invoked as a seamless fallback if native Typst is not present.
2. **Native Binary (Optional):** If you prefer compiling natively, install Typst via your package manager:
   - **macOS:** `brew install typst`
   - **Linux:** `sudo pacman -S typst` or `sudo snap install typst`
   - **Windows:** `winget install --id Typst.Typst`

---

### Quickstart (One Command)

```bash
# 1. Install dependencies (first time only)
cd backend && uv sync && cd ../frontend && npm install && cd ..

# 2. Run the entire stack in one command (services start in background)
./start.sh --with-lab

# Or run the stack and stream live backend & agent run logs in the terminal:
./start.sh --with-lab --logs
```

Your mission desk is instantly available at **`http://localhost:5173`**!

To inspect stack health:
```bash
./start.sh --status
```

To stop all services and containers:
```bash
./start.sh --stop
```

### Terminal CLI (`./aipent`)

AIPENT includes a rich terminal CLI for running security assessments, monitoring multi-agent reasoning in real-time, deciding human gates, and compiling reports:

```bash
# View CLI help, key options, and examples:
./aipent --help

# Run an unattended assessment with all requests auto-approved:
./aipent scan http://127.0.0.1:3000 -y

# Run quiet unattended mode (clean terminal; full logs stream to backend/data/aipent.log):
./aipent scan http://127.0.0.1:3000 -y -s

# Pass an assessment query / objective with auto-approval:
./aipent scan http://127.0.0.1:3000 -r "Find SQL injection and XSS on /rest/products" -y
./aipent scan http://127.0.0.1:3000 -q "Test auth bypass vulnerabilities" --auto-approve

# Direct shorthand syntax (without explicit 'scan'):
./aipent http://127.0.0.1:3000 -y
./aipent http://127.0.0.1:3000 -y -s

# Scan specific ports with scope exclusions:
./aipent scan 192.168.1.50 -p 80,443,8080 -e "/admin,/logout" -y

# List previous assessments, view status, steer agent, or compile report:
./aipent list
./aipent status 1
./aipent steer 1 "Focus on JWT token forgery flaws"
./aipent report 1
```

---

## Verification & Test Results

AIPENT includes full automated test suites across both backend and frontend:

```bash
# Backend unit & integration test suite (181 passed across 6 domain packages)
cd backend && uv run pytest tests

# Frontend unit tests & production build verification (28 passed)
cd frontend && npm test && npm run build
```

---

## Project Directory Layout

```
aipent/
├── backend/
│   ├── src/app/
│   │   ├── actions/            # Closed action catalogue & execution router
│   │   ├── adapters/           # Adapters: nmap, nikto, zap, ffuf, katana, nuclei, whatweb, sslscan, sqlmap, hashcat
│   │   ├── parsers/            # Static parsers: html_parser, js_parser, json_parser, target manifest
│   │   ├── agents/
│   │   │   ├── nodes/          # Modular LangGraph nodes: intake, planning, supervisor, specialist, execution, reporting
│   │   │   ├── mission_brain.py# Initial plan synthesis, turn budgeting, & specialist prompting
│   │   │   ├── state.py        # Bounded AssessmentState model & event contracts
│   │   │   └── observations.py # Pure in-memory observation builders
│   │   ├── persistence/        # Decoupled DB repos: AssessmentRepo, StepRepo, FindingRepo, AuditRepo
│   │   ├── intel/              # Offline Vulnify SQLite CVE intelligence & KEV catalog
│   │   ├── api/                # FastAPI REST endpoints & SSE event streaming
│   │   ├── core/               # DB engine, policy engine, config, and notifications
│   │   ├── domain/             # SQLModel models & domain reasoning event folding
│   │   └── reporting/          # Typst PDF report compiler & executive templates
│   ├── tests/                  # 181 automated pytest unit and integration tests
│   │   ├── agent_intelligence/ # Contracts, evidence board, planning gates, role budgets
│   │   ├── scanners_and_tools/ # Adapters (ffuf, katana, nuclei), parsers, scope, policy
│   │   ├── persistence_and_repo/# Repositories & mission context preloading
│   │   ├── correlation_and_dedup/# Evidence consolidation & finding promotion
│   │   ├── reporting_and_narrative/# Typst report compilation & executive synthesis
│   │   └── e2e_and_api/        # End-to-end lifecycle & API endpoint tests
│   └── scripts/                # Observation test suites & challenge verification
├── frontend/
│   ├── src/
│   │   ├── components/         # Mission Conversation desk, Assessment Plan Editor, approval cards
│   │   ├── hooks/              # SSE live event streaming hooks
│   │   └── lib/                # Schemas, mission state folding & API client
│   └── scripts/dev.mjs         # Dual-process orchestrator for API + Vite
├── start.sh                    # Unified one-command stack launcher
├── gateway/                    # Docker MCP Gateway runner & catalog (:8812)
├── mcp/                        # MCP tool containers & compose (ZAP, Vulnify, Curl, Typst)
├── labs/                       # Authorized lab compose targets (Juice Shop, DVWA)
├── docs/                       # Technical specs, AGENT_ARCHITECTURE_AND_COMMUNICATION.md, slides, ideas
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
- **ffuf (by joohoi):** Fast web fuzzer for directory and parameter discovery (MIT License).
- **Katana & Nuclei (by ProjectDiscovery):** Next-generation crawling and template-based vulnerability scanning (MIT License).
- **React, Vite, Zustand, TailwindCSS:** Frontend interface and reactive desk framework (MIT License).
- **IBM Plex Fonts:** Professional typography (SIL Open Font License).

---

## Authors & Hackathon Team

Developed for the **DataOps Innovation Hackathon: AI Agent for Automated Penetration Testing**.  
All demonstrations and automated tests are conducted strictly on locally hosted, organizer-authorized lab environments.
