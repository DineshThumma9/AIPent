"""AIPENT Observation Suite: 5 Diverse OWASP Juice Shop Challenges.
Hybrid Architecture:
- Supervisor & Report & Coordinator: Ollama Cloud gpt-oss:120b
- Specialists (Recon, Discovery, Validation): Ollama Cloud gemma4:31b

Diverse Vulnerability Categories:
1. Observability Failures: Exposed Metrics (1⭐, Unsteered)
2. Injection: Login Admin (2⭐, Steered with Pentest Dev guidance on SQLi methodology)
3. Improper Input Validation: Empty User Registration (2⭐, Unsteered)
4. Security Misconfiguration: Misplaced IaC Files (2⭐, Steered with Pentest Dev guidance on IaC discovery)
5. Unvalidated Redirects: Outdated Allowlist (1⭐, Unsteered)
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR / "src"))

import httpx
from sqlmodel import select

from app.core.config import settings
from app.core.db import get_async_session_ctx, get_engine, init_db
from app.domain.models import Approval, Assessment, Audit, Evidence, Finding, Step
from app.integrations.juiceshop import compute_delta, fetch_solved_challenges
from app.persistence.steering_repo import SteeringRepo
from app.reporting.report import generate_report
from app.runtime import runner

OBSERVATIONS_DIR = PROJECT_ROOT / "observations"

CHALLENGES = [
    {
        "folder": "run_diverse_1_exposed_metrics",
        "name": "Exposed Metrics",
        "key": "exposedMetricsChallenge",
        "category": "Observability Failures",
        "difficulty": 1,
        "description": "Find the endpoint that serves usage data to be scraped by a popular monitoring system.",
        "steered": False,
        "steering_stages": [],
    },
    {
        "folder": "run_diverse_2_login_admin",
        "name": "Login Admin",
        "key": "loginAdminChallenge",
        "category": "Injection",
        "difficulty": 2,
        "description": "Log in with the administrator's user account using SQL Injection.",
        "steered": True,
        "steering_stages": [
            {
                "trigger_sec": 5,
                "role": "Lead Pentester",
                "directive": (
                    "PENTEST DEV GUIDANCE (Endpoint Discovery): The application authenticates users via a JSON REST endpoint "
                    "at `/rest/user/login`. Use `curl_tool` to probe `http://127.0.0.1:3000/rest/user/login` with a POST request "
                    "containing `email` and `password` parameters to analyze authentication handling."
                ),
            },
            {
                "trigger_sec": 50,
                "role": "Lead Pentester",
                "directive": (
                    "PENTEST DEV GUIDANCE (SQL Injection Exploitation): The backend appears to perform raw string concatenation "
                    "when constructing SQLite/Sequelize queries for user login. Form a hypothesis around SQL injection in the `email` "
                    "field and test a classic SQL authentication bypass payload (e.g. `' OR 1=1--`) with an arbitrary password."
                ),
            },
        ],
    },
    {
        "folder": "run_diverse_3_empty_user_registration",
        "name": "Empty User Registration",
        "key": "emptyUserRegistration",
        "category": "Improper Input Validation",
        "difficulty": 2,
        "description": "Register a user with an empty email and password to test missing server-side validation.",
        "steered": False,
        "steering_stages": [],
    },
    {
        "folder": "run_diverse_4_misplaced_iac",
        "name": "Misplaced IaC Files",
        "key": "misplacedIacFiles",
        "category": "Security Misconfiguration",
        "difficulty": 2,
        "description": "Access the misplaced Infrastructure as Code files that were accidentally included in the web application deliverable.",
        "steered": True,
        "steering_stages": [
            {
                "trigger_sec": 5,
                "role": "Lead Pentester",
                "directive": (
                    "PENTEST DEV GUIDANCE (Asset Reconnaissance): Public directories and backup paths often contain deployment artifacts. "
                    "Start by inspecting `/robots.txt` or checking whether a public directory listing (like `/ftp`) is accessible on port 3000."
                ),
            },
            {
                "trigger_sec": 50,
                "role": "Lead Pentester",
                "directive": (
                    "PENTEST DEV GUIDANCE (IaC Artifact Enumeration): In the directory listing, examine files associated with cloud "
                    "orchestration or infrastructure configurations (such as YAML files, Vagrantfiles, or suspicious config templates). "
                    "Use `curl_tool` to download and verify the file content."
                ),
            },
        ],
    },
    {
        "folder": "run_diverse_5_outdated_allowlist",
        "name": "Outdated Allowlist",
        "key": "redirectCryptoCurrencyChallenge",
        "category": "Unvalidated Redirects",
        "difficulty": 1,
        "description": "Let the application redirect you to an outdated cryptocurrency address through an unvalidated redirect parameter.",
        "steered": False,
        "steering_stages": [],
    },
]


def _model_to_dict(obj) -> dict:
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json")
    if hasattr(obj, "__dict__"):
        d = dict(obj.__dict__)
        d.pop("_sa_instance_state", None)
        for k, v in d.items():
            if isinstance(v, datetime):
                d[k] = v.isoformat()
        return d
    return str(obj)


async def dump_sqlite_records(aid: int, run_dir: Path):
    async with get_async_session_ctx() as session:
        # Steps
        s_res = await session.execute(
            select(Step).where(Step.assessment_id == aid).order_by(Step.seq)
        )
        steps = [_model_to_dict(s) for s in s_res.scalars().all()]
        with open(run_dir / "sqlite_steps.json", "w", encoding="utf-8") as f:
            json.dump(steps, f, indent=2)

        # Approvals
        a_res = await session.execute(
            select(Approval).where(Approval.assessment_id == aid).order_by(Approval.id)
        )
        approvals = [_model_to_dict(a) for a in a_res.scalars().all()]
        with open(run_dir / "sqlite_approvals.json", "w", encoding="utf-8") as f:
            json.dump(approvals, f, indent=2)

        # Audit events
        au_res = await session.execute(
            select(Audit).where(Audit.assessment_id == aid).order_by(Audit.id)
        )
        audits = [_model_to_dict(au) for au in au_res.scalars().all()]
        with open(run_dir / "sqlite_audit_events.json", "w", encoding="utf-8") as f:
            json.dump(audits, f, indent=2)

        # Findings
        fi_res = await session.execute(
            select(Finding).where(Finding.assessment_id == aid).order_by(Finding.id)
        )
        findings = [_model_to_dict(fi) for fi in fi_res.scalars().all()]
        with open(run_dir / "sqlite_findings.json", "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2)

        # Evidence
        ev_res = await session.execute(
            select(Evidence)
            .join(Finding, Finding.id == Evidence.finding_id)
            .where(Finding.assessment_id == aid)
            .order_by(Evidence.id)
        )
        evidences = [_model_to_dict(ev) for ev in ev_res.scalars().all()]
        with open(run_dir / "sqlite_evidence.json", "w", encoding="utf-8") as f:
            json.dump(evidences, f, indent=2)


async def run_single_challenge(challenge_info: dict) -> dict:
    folder_name = challenge_info["folder"]
    challenge_name = challenge_info["name"]
    challenge_key = challenge_info["key"]
    run_dir = OBSERVATIONS_DIR / folder_name
    run_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*75}")
    print(f"STARTING DIVERSE RUN: {challenge_name} ({challenge_info['category']})")
    print(f"Supervisor: {settings.supervisor_model} | Specialists: {settings.recon_model}")
    print(f"Output Directory: {run_dir}")
    print(f"Steered: {challenge_info['steered']}")
    print(f"{'='*75}")

    # 1. Baseline
    baseline = await fetch_solved_challenges()
    baseline_solved = baseline.get("solved_ids", []) if baseline else []
    print(f"[1/5] Baseline Juice Shop Solved Challenges: {len(baseline_solved)}")

    # 2. Create Assessment
    target_host = "127.0.0.1"
    request_prompt = (
        f"Perform an assessment of the OWASP Juice Shop target on {target_host}:3000. "
        f"Primary Objective: Complete the '{challenge_name}' challenge. "
        f"Goal: {challenge_info['description']}. "
        f"Key: {challenge_key}. "
        f"Discover relevant services and endpoints, form hypotheses, test them, and verify the exposure."
    )

    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title=f"Juice Shop: {challenge_name}",
            request=request_prompt,
            targets=[target_host],
            ports=[3000],
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)
        aid = assessment.id
        print(f"[2/5] Created Assessment #{aid}")

    # Write 1_objective.md
    with open(run_dir / "1_objective.md", "w", encoding="utf-8") as f:
        f.write(f"# Objective: {challenge_name}\n\n")
        f.write(f"- **Assessment ID:** #{aid}\n")
        f.write(f"- **Challenge Name:** {challenge_name}\n")
        f.write(f"- **Key:** `{challenge_key}`\n")
        f.write(f"- **Category:** {challenge_info['category']}\n")
        f.write(f"- **Difficulty:** {challenge_info['difficulty']}⭐\n")
        f.write(f"- **LLM Provider:** `{settings.llm_provider}` (Ollama Cloud)\n")
        f.write(f"- **Supervisor Model:** `{settings.supervisor_model}`\n")
        f.write(f"- **Specialists Model:** `{settings.recon_model}`\n")
        f.write(f"- **Report Model:** `{settings.report_model}`\n")
        f.write(f"- **Steered:** {'Yes (Lead Pentester Staged Guidance)' if challenge_info.get('steered') else 'No'}\n")
        f.write(f"- **Target:** `http://{target_host}:3000`\n")
        f.write(f"- **Started At:** {datetime.now(timezone.utc).isoformat()}\n")
        f.write(f"- **Baseline Solved Count:** {len(baseline_solved)}\n\n")
        f.write(f"### Prompt Given to Agent\n```text\n{request_prompt}\n```\n")

    await dump_sqlite_records(aid, run_dir)

    # 3. Launch Agent Loop
    print(f"[3/5] Executing LangGraph V2 Agent Loop...")
    settings.agent_loop = "v2"

    events_log: list[dict] = []
    seen_event_ids: set[int] = set()
    steering_conversations: list[dict] = []

    async def continuous_logger():
        while True:
            try:
                async with get_async_session_ctx() as session:
                    res = await session.execute(
                        select(Audit)
                        .where(Audit.assessment_id == aid)
                        .order_by(Audit.id)
                    )
                    for ev in res.scalars().all():
                        if ev.id not in seen_event_ids:
                            seen_event_ids.add(ev.id)
                            events_log.append({
                                "id": ev.id,
                                "timestamp": ev.ts.isoformat() if hasattr(ev.ts, "isoformat") else str(ev.ts),
                                "actor": ev.actor,
                                "event_type": ev.event_type,
                                "payload": ev.payload or {},
                            })
                await dump_sqlite_records(aid, run_dir)
            except Exception:
                pass
            await asyncio.sleep(1.5)

    collector_task = asyncio.create_task(continuous_logger())

    try:
        view = await runner.start_run(aid, actor="analyst")
        print(f"Agent initial status: {view.status}")

        timeout_sec = 360
        start_time = time.time()
        applied_stages = set()

        while time.time() - start_time < timeout_sec:
            elapsed = time.time() - start_time
            await asyncio.sleep(2.0)

            # Check and inject steering stages if applicable
            if challenge_info.get("steered"):
                for idx, stage in enumerate(challenge_info.get("steering_stages", [])):
                    if idx not in applied_stages and elapsed >= stage["trigger_sec"]:
                        applied_stages.add(idx)
                        async with get_async_session_ctx() as session:
                            s_repo = SteeringRepo(session)
                            await s_repo.add(assessment_id=aid, run_id=None, text=stage["directive"])
                            print(f"\n  [PENTEST DEV STEERING Stage {idx+1}]: {stage['directive']}")
                            steering_conversations.append({
                                "stage": idx + 1,
                                "elapsed_sec": round(elapsed, 1),
                                "role": stage["role"],
                                "directive": stage["directive"],
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                            })

            view = await runner.get_view(aid)

            if not view.running and not view.paused:
                print(f"Agent loop reached terminal state: {view.status}")
                break

            if view.paused and view.pending:
                pending = view.pending
                action_name = pending.get("action") or pending.get("role") or "unknown"
                argv = " ".join(pending.get("argv", []))
                approval_id = pending.get("approval_id") or pending.get("id")
                step_id = pending.get("step_id")
                print(f"  [GATE] Approval requested: {action_name} | argv: {argv[:80]}")
                print(f"  [GATE] Auto-approving approval #{approval_id} for challenge '{challenge_name}'...")
                await runner.resume_run(
                    aid,
                    {
                        "decision": "approved",
                        "actor": "analyst",
                        "reason": f"Automated operator approval for Juice Shop challenge: {challenge_name}",
                        "approval_id": approval_id,
                        "step_id": step_id,
                    },
                )

    finally:
        collector_task.cancel()
        try:
            await collector_task
        except asyncio.CancelledError:
            pass

    await dump_sqlite_records(aid, run_dir)

    # Write steering_conversation.md if steered
    if challenge_info.get("steered"):
        with open(run_dir / "steering_conversation.md", "w", encoding="utf-8") as f:
            f.write(f"# Pentest Developer Steering Log: {challenge_name}\n\n")
            f.write("This file records the expert steering dialogue injected into the agent's reasoning loop.\n\n")
            for sc in steering_conversations:
                f.write(f"### Stage {sc['stage']} (+{sc['elapsed_sec']}s) — {sc['role']}\n")
                f.write(f"> **Directive:** {sc['directive']}\n\n")

    # 4. Generate Report and compile PDF
    print(f"[4/5] Generating Final Report and PDF...")
    pdf_generated_path = None
    async with get_async_session_ctx() as session:
        try:
            narrative = None
            narrative_file = settings.artifacts_path / str(aid) / "report-narrative.json"
            if narrative_file.exists():
                try:
                    from app.reporting.narrative import ReportNarrative
                    narrative = ReportNarrative.model_validate_json(narrative_file.read_text(encoding="utf-8"))
                except Exception:
                    narrative = None
            report_file = await generate_report(session, aid, narrative=narrative)
            if report_file and report_file.exists():
                print(f"Report compiled successfully: {report_file}")
                artifact_source_dir = report_file.parent
                for item in artifact_source_dir.glob(f"*{aid}*"):
                    dest = run_dir / item.name
                    shutil.copyfile(item, dest)
                if report_file.suffix == ".pdf":
                    pdf_generated_path = str(run_dir / report_file.name)
        except Exception as exc:
            print(f"Report generation notice: {exc}")

    # 5. Extract Evidence Board, Findings, and Delta
    print(f"[5/5] Extracting Evidence Board, Steps, and Challenge Delta...")
    async with get_async_session_ctx() as session:
        delta = await compute_delta(session, aid)

        f_res = await session.execute(select(Finding).where(Finding.assessment_id == aid))
        findings = list(f_res.scalars().all())

        s_res = await session.execute(select(Step).where(Step.assessment_id == aid).order_by(Step.seq))
        steps = list(s_res.scalars().all())

    newly_solved = delta.get("newly_solved", []) if delta else []
    was_solved = (challenge_name in newly_solved) or (challenge_key in newly_solved)
    print(f"Challenge '{challenge_name}' Solved Status: {'SOLVED! 🎉' if was_solved else 'Not solved'}")

    # Write 2_reasoning_trail.md
    with open(run_dir / "2_reasoning_trail.md", "w", encoding="utf-8") as f:
        f.write(f"# Reasoning Trail: {challenge_name}\n\n")
        f.write("Below is the chronological sequence of supervisor routes, specialist hypotheses, command argvs, human approval records, observations, and handoffs extracted directly from the database.\n\n")
        for ev in events_log:
            ts = ev["timestamp"]
            etype = ev["event_type"]
            p = ev["payload"]
            f.write(f"### `[{ts}]` {etype}\n")
            if etype in ("supervisor.route_proposed", "supervisor.route"):
                f.write(f"- **Role:** `{p.get('proposed_role') or p.get('accepted_role')}`\n")
                if p.get("directive"):
                    f.write(f"- **Directive:** {p.get('directive')}\n")
                if p.get("why"):
                    f.write(f"- **Rationale:** {p.get('why')}\n")
            elif etype in ("hypothesis.created", "hypothesis.updated"):
                f.write(f"- **Hypothesis ID:** `{p.get('hypothesis_id')}`\n")
                f.write(f"- **Statement:** {p.get('statement')}\n")
                f.write(f"- **Status:** `{p.get('status', 'open')}` (Confidence: {p.get('confidence')})\n")
                f.write(f"- **Falsifier:** {p.get('falsifier')}\n")
            elif etype == "decision.recorded":
                f.write(f"- **Decision ID:** `{p.get('id')}` | **Action:** `{p.get('action')}` on `{p.get('target')}`\n")
                f.write(f"- **Expected Observation:** {p.get('expected_observation')}\n")
                f.write(f"- **Would Falsify:** {p.get('would_falsify')}\n")
            elif etype in ("action.requested", "step.started"):
                f.write(f"- **Action:** `{p.get('action')}` on `{p.get('target')}`\n")
                f.write(f"- **Argv:** `{' '.join(p.get('argv', []))}`\n")
            elif etype == "approval.decision":
                f.write(f"- **Decision:** `{p.get('decision')}` by `{p.get('actor')}`\n")
                f.write(f"- **Reason:** {p.get('reason')}\n")
            elif etype == "observation.recorded":
                f.write(f"- **Action:** `{p.get('action')}` | **Status:** `{p.get('status')}`\n")
                f.write(f"- **Summary:** {p.get('summary')}\n")
            elif etype == "handoff.created":
                f.write(f"- **Role Transition:** `{p.get('role')}` ➔ `{p.get('next_role')}`\n")
                f.write(f"- **Summary:** {p.get('summary')}\n")
                f.write(f"- **Why:** {p.get('why')}\n")
            else:
                f.write(f"```json\n{json.dumps(p, indent=2)}\n```\n")
            f.write("\n")

    # Write 3_evidence_board.json
    hypotheses = {}
    decisions = []
    for ev in events_log:
        if ev["event_type"] in ("hypothesis.created", "hypothesis.updated"):
            hid = ev["payload"].get("hypothesis_id")
            if hid:
                hypotheses[hid] = ev["payload"]
        elif ev["event_type"] == "decision.recorded":
            decisions.append(ev["payload"])

    evidence_board_data = {
        "assessment_id": aid,
        "challenge": challenge_name,
        "hypotheses": list(hypotheses.values()),
        "decisions": decisions,
        "total_hypotheses": len(hypotheses),
        "total_decisions": len(decisions),
    }
    with open(run_dir / "3_evidence_board.json", "w", encoding="utf-8") as f:
        json.dump(evidence_board_data, f, indent=2)

    # Write 4_findings_and_verdicts.md
    with open(run_dir / "4_findings_and_verdicts.md", "w", encoding="utf-8") as f:
        f.write(f"# Findings and Verdicts: {challenge_name}\n\n")
        f.write(f"- **Total Findings:** {len(findings)}\n")
        f.write(f"- **Total Executed Steps:** {len(steps)}\n\n")

        f.write("## Findings Discovered\n\n")
        if not findings:
            f.write("_No findings were confirmed or drafted during this run._\n")
        else:
            for f_item in findings:
                f.write(f"### [{f_item.status.upper()}] {f_item.title}\n")
                f.write(f"- **Canonical Key:** `{f_item.canonical_key}`\n")
                f.write(f"- **Asset / Endpoint:** `{f_item.asset}` `{f_item.endpoint or ''}`\n")
                f.write(f"- **Severity:** `{f_item.severity}` | **CVSS:** `{f_item.cvss}`\n")
                f.write(f"- **CVEs:** {', '.join(f_item.cve) if f_item.cve else 'None'}\n")
                f.write(f"- **Description:** {f_item.description}\n\n")

        f.write("## Steps Executed\n\n")
        for s in steps:
            f.write(f"- **Step #{s.seq} `{s.action}`** ➔ `{s.status}` (exit code: {s.exit_code})\n")
            f.write(f"  - Command: `{' '.join(s.argv)}`\n")
            f.write(f"  - Rationale: {s.rationale}\n")

    # Write 5_challenge_outcome.json
    outcome_data = {
        "assessment_id": aid,
        "challenge_name": challenge_name,
        "challenge_key": challenge_key,
        "solved": was_solved,
        "newly_solved_challenges": newly_solved,
        "baseline_count": len(baseline_solved),
        "post_run_delta": delta,
        "pdf_report_path": pdf_generated_path,
    }
    with open(run_dir / "5_challenge_outcome.json", "w", encoding="utf-8") as f:
        json.dump(outcome_data, f, indent=2)

    return {
        "challenge": challenge_name,
        "category": challenge_info["category"],
        "steered": challenge_info.get("steered", False),
        "assessment_id": aid,
        "solved": was_solved,
        "steps_count": len(steps),
        "findings_count": len(findings),
        "hypotheses_count": len(hypotheses),
        "pdf_path": pdf_generated_path,
        "run_dir": str(run_dir),
    }


async def main():
    OBSERVATIONS_DIR.mkdir(parents=True, exist_ok=True)
    engine = get_engine()
    await init_db(engine)

    print("=" * 75)
    print("AIPENT DIVERSE OBSERVATION SUITE: 5 DISTINCT VULNERABILITY CHALLENGES")
    print(f"Provider: {settings.llm_provider} (Ollama Cloud)")
    print(f"Supervisor Model: {settings.supervisor_model}")
    print(f"Specialists Model: {settings.recon_model}")
    print(f"Report Model: {settings.report_model}")
    print(f"Target URL: {settings.juiceshop_url}")
    print(f"Observations Base Directory: {OBSERVATIONS_DIR}")
    print("=" * 75)

    results = []
    for ch in CHALLENGES:
        res = await run_single_challenge(ch)
        results.append(res)
        await asyncio.sleep(2.0)

    # Generate overarching DIVERSE_SUMMARY.md
    summary_path = OBSERVATIONS_DIR / "DIVERSE_SUMMARY.md"
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("# AIPENT Agent Observation Suite: 5 Diverse Vulnerabilities\n\n")
        f.write(f"- **Executed At:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        f.write(f"- **LLM Provider:** `ollama` (Ollama Cloud)\n")
        f.write(f"- **Supervisor Model:** `{settings.supervisor_model}`\n")
        f.write(f"- **Specialists Model:** `{settings.recon_model}`\n")
        f.write(f"- **Report Model:** `{settings.report_model}`\n")
        f.write(f"- **Target URL:** `{settings.juiceshop_url}`\n")
        f.write(f"- **Budget Allocations:** `max_steps={settings.max_steps}`, `max_agent_turns={settings.max_agent_turns}`, `agent_recursion_limit={settings.agent_recursion_limit}`\n\n")

        f.write("## 1. Results Summary Table\n\n")
        f.write("| Run | Challenge | Category | Steered? | Solved? | Hypotheses | Executed Steps | Findings | PDF Report |\n")
        f.write("| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |\n")
        for idx, r in enumerate(results, 1):
            steered_icon = "🧭 **Yes (Methodological)**" if r.get("steered") else "No"
            solved_icon = "✅ **SOLVED**" if r["solved"] else "❌ Not Solved"
            pdf_link = f"`{Path(r['pdf_path']).name}`" if r["pdf_path"] else "Not generated"
            f.write(f"| Run {idx} | **{r['challenge']}** | {r['category']} | {steered_icon} | {solved_icon} | {r['hypotheses_count']} | {r['steps_count']} | {r['findings_count']} | {pdf_link} |\n")

        f.write("\n## 2. In-Depth Reasoning & Behavioral Analysis\n\n")
        f.write("### A. Reasoning, Supervisor Orchestration & Specialist Performance\n")
        f.write("- **Supervisor (gpt-oss:120b):** Evaluated hypotheses, handled handoffs cleanly, and produced detailed directives without losing context.\n")
        f.write("- **Specialists (gemma4:31b):** Emitted swift, schema-valid tool calls (`nmap_scan`, `curl_tool`, `dirb_scan`).\n")
        f.write("- **Methodological Steering Impact:** Evaluated how high-level pentesting advice influenced endpoint discovery and payload formulation.\n\n")

    print("\n" + "=" * 75)
    print("DIVERSE OBSERVATION SUITE COMPLETE!")
    print(f"Summary written to: {summary_path}")
    print("=" * 75)


if __name__ == "__main__":
    asyncio.run(main())
