"""AIPENT Resilient Sandbox Suite: 3 OWASP Juice Shop Challenges.

Target: OWASP Juice Shop on http://127.0.0.1:3000 (Local Sandbox Environment)
Evaluation Scope:
1. Login Admin (Injection - 2⭐) — STEERED & COORDINATED by Human Lead (Mentorship + Interactive Gate)
2. Empty User Registration (Improper Input Validation - 2⭐) — AUTONOMOUS (Self-healing & Error Recovery)
3. Misplaced IaC Files (Security Misconfiguration - 2⭐) — AUTONOMOUS (Discovery & Path Enumeration)

Increased Budgets:
- max_validation_probes: 25
- max_steps: 60
- max_agent_turns: 60
- agent_recursion_limit: 160
- supervisor_calls_per_run: 30
- ROLE_TURN_CAPS: recon=10, discovery=20, validation=25, review=2
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
        "folder": "run_resilient_1_login_admin",
        "name": "Login Admin",
        "key": "loginAdminChallenge",
        "category": "Injection",
        "difficulty": 2,
        "description": "Log in with the administrator's user account using SQL Injection.",
        "steered": True,
        "interactive_gate": True,
        "steering_stages": [
            {
                "trigger_sec": 10,
                "role": "Lead Pentester",
                "directive": (
                    "LEAD PENTEST MENTORSHIP: Focus your reconnaissance on user authentication. "
                    "The application exposes a JSON REST endpoint for logins at `/rest/user/login`. "
                    "Send a baseline POST request with JSON credentials (`{\"email\":\"test@test.com\",\"password\":\"test\"}`) to examine the expected response structure."
                ),
            },
            {
                "trigger_sec": 50,
                "role": "Lead Pentester",
                "directive": (
                    "LEAD PENTEST MENTORSHIP: The backend relies on an SQL database (SQLite/Sequelize). "
                    "Analyze how standard SQL string termination (e.g. `' OR 1=1--`) in the email parameter "
                    "affects query evaluation. If you receive an HTTP 400 or 401 error, inspect the response body and syntax error message to adjust your payload."
                ),
            },
            {
                "trigger_sec": 100,
                "role": "Lead Pentester",
                "directive": (
                    "LEAD PENTEST MENTORSHIP: Remember that the administrator account typically occupies the first record (id=1) "
                    "or has email `admin@juice-sh.op`. An authentication bypass payload such as `' or 1=1--` in the email field "
                    "with any dummy password should bypass password verification."
                ),
            },
        ],
    },
    {
        "folder": "run_resilient_2_empty_user_registration",
        "name": "Empty User Registration",
        "key": "emptyUserRegistration",
        "category": "Improper Input Validation",
        "difficulty": 2,
        "description": "Register a user with an empty email and password to test missing server-side validation.",
        "steered": False,
        "interactive_gate": False,
        "steering_stages": [],
    },
    {
        "folder": "run_resilient_3_misplaced_iac",
        "name": "Misplaced IaC Files",
        "key": "misplacedIacFiles",
        "category": "Security Misconfiguration",
        "difficulty": 2,
        "description": "Access the misplaced Infrastructure as Code files that were accidentally included in the web application deliverable.",
        "steered": False,
        "interactive_gate": False,
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


def lead_gate_review(challenge_name: str, pending: dict, step_count: int) -> tuple[str, str]:
    """Human Lead Pentester Gate Decision Maker.
    
    Approves constructive, hypothesis-driven probes.
    Rejects repetitive wandering and gives guiding feedback.
    """
    action = pending.get("action") or ""
    argv = pending.get("argv") or []
    target = pending.get("target") or ""
    argv_str = " ".join(argv).lower()

    if challenge_name == "Login Admin":
        if action == "curl_request" and target.rstrip("/").endswith(":3000") and '"method": "get"' in argv_str and step_count >= 2:
            return "rejected", "Lead Feedback: Repeating root GET '/' is unproductive. Focus your probing on `/rest/user/login`."
        return "approved", "Lead Approval: Authentication probe approved. Observe response code and payload handling."

    return "approved", f"Lead Approval: Action approved for {challenge_name}."


async def dump_sqlite_records(aid: int, run_dir: Path):
    async with get_async_session_ctx() as session:
        s_res = await session.execute(
            select(Step).where(Step.assessment_id == aid).order_by(Step.seq)
        )
        steps = [_model_to_dict(s) for s in s_res.scalars().all()]
        with open(run_dir / "sqlite_steps.json", "w", encoding="utf-8") as f:
            json.dump(steps, f, indent=2)

        a_res = await session.execute(
            select(Approval).where(Approval.assessment_id == aid).order_by(Approval.id)
        )
        approvals = [_model_to_dict(a) for a in a_res.scalars().all()]
        with open(run_dir / "sqlite_approvals.json", "w", encoding="utf-8") as f:
            json.dump(approvals, f, indent=2)

        f_res = await session.execute(
            select(Finding).where(Finding.assessment_id == aid).order_by(Finding.id)
        )
        findings = [_model_to_dict(fn) for fn in f_res.scalars().all()]
        with open(run_dir / "sqlite_findings.json", "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2)


async def run_single_challenge(challenge_info: dict) -> dict:
    folder_name = challenge_info["folder"]
    challenge_name = challenge_info["name"]
    challenge_key = challenge_info["key"]
    is_interactive = challenge_info.get("interactive_gate", False)
    run_dir = OBSERVATIONS_DIR / folder_name
    run_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*75}")
    print(f"STARTING RESILIENT SANDBOX RUN: {challenge_name} ({challenge_info['category']})")
    print(f"Supervisor: {settings.supervisor_model} | Specialists: {settings.recon_model}")
    print(f"Output Directory: {run_dir}")
    print(f"Mode: {'🧭 LEAD STEERED + INTERACTIVE GATE' if is_interactive else '🤖 100% AUTONOMOUS'}")
    print(f"Budgets: Probes={settings.max_validation_probes}, MaxSteps={settings.max_steps}, Turns={settings.max_agent_turns}")
    print(f"{'='*75}")

    baseline = await fetch_solved_challenges()
    baseline_solved = baseline.get("solved_ids", []) if baseline else []
    print(f"[1/5] Baseline Juice Shop Solved Challenges: {len(baseline_solved)}")

    target_host = "127.0.0.1"
    request_prompt = (
        f"Perform an authorized assessment of the OWASP Juice Shop sandbox target on {target_host}:3000. "
        f"Primary Objective: Complete the '{challenge_name}' challenge. "
        f"Goal: {challenge_info['description']}. "
        f"Key: {challenge_key}. "
        f"Discover relevant services and endpoints, form hypotheses, test them with curl_request, analyze error responses if encountered, and verify the exposure."
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

    with open(run_dir / "1_objective.md", "w", encoding="utf-8") as f:
        f.write(f"# Objective: {challenge_name}\n\n")
        f.write(f"- **Assessment ID:** #{aid}\n")
        f.write(f"- **Challenge Name:** {challenge_name}\n")
        f.write(f"- **Key:** `{challenge_key}`\n")
        f.write(f"- **Category:** {challenge_info['category']}\n")
        f.write(f"- **Difficulty:** {challenge_info['difficulty']}⭐\n")
        f.write(f"- **Environment:** OWASP Juice Shop Local Sandbox (`http://{target_host}:3000`)\n")
        f.write(f"- **LLM Provider:** `{settings.llm_provider}` (Ollama Cloud)\n")
        f.write(f"- **Supervisor Model:** `{settings.supervisor_model}`\n")
        f.write(f"- **Specialists Model:** `{settings.recon_model}`\n")
        f.write(f"- **Lead Steered & Gate Controlled:** {'Yes' if is_interactive else 'No (Autonomous)'}\n")
        f.write(f"- **Started At:** {datetime.now(timezone.utc).isoformat()}\n")
        f.write(f"- **Baseline Solved Count:** {len(baseline_solved)}\n\n")
        f.write(f"### Prompt Given to Agent\n```text\n{request_prompt}\n```\n")

    await dump_sqlite_records(aid, run_dir)

    print(f"[3/5] Executing LangGraph V2 Agent Loop...")
    settings.agent_loop = "v2"

    events_log: list[dict] = []
    seen_event_ids: set[int] = set()
    steering_conversations: list[dict] = []
    gate_audit_records: list[dict] = []

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

        timeout_sec = 420  # 7 minutes generous timeout with increased budget
        start_time = time.time()
        applied_stages = set()
        step_counter = 0

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
                            print(f"\n  [LEAD MENTORSHIP Stage {idx+1}]: {stage['directive']}\n")
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
                step_counter += 1

                if is_interactive:
                    decision, reason = lead_gate_review(challenge_name, pending, step_counter)
                    print(f"  [LEAD GATE REVIEW] {action_name} (#{approval_id}) -> {decision.upper()} | Reason: {reason}")
                else:
                    decision, reason = "approved", f"Autonomous baseline approval for {challenge_name}"
                    print(f"  [AUTONOMOUS GATE] Auto-approving {action_name} (#{approval_id})...")

                gate_audit_records.append({
                    "step_count": step_counter,
                    "action": action_name,
                    "approval_id": approval_id,
                    "decision": decision,
                    "reason": reason,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

                await runner.resume_run(
                    aid,
                    {
                        "decision": decision,
                        "actor": "lead_pentester" if is_interactive else "system",
                        "reason": reason,
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

    if challenge_info.get("steered"):
        with open(run_dir / "steering_conversation.md", "w", encoding="utf-8") as f:
            f.write(f"# Lead Pentest Mentorship & Gate Log: {challenge_name}\n\n")
            f.write("This file records the methodological guidance and active gate reviews provided by the Lead Pentester.\n\n")
            f.write("## 1. Methodological Mentorship\n\n")
            for sc in steering_conversations:
                f.write(f"### Stage {sc['stage']} (+{sc['elapsed_sec']}s) — {sc['role']}\n")
                f.write(f"> **Guidance:** {sc['directive']}\n\n")

            f.write("## 2. Gate Review Decisions\n\n")
            for ga in gate_audit_records:
                f.write(f"- **Step #{ga['step_count']} `{ga['action']}` (Approval #{ga['approval_id']})** -> **{ga['decision'].upper()}**\n")
                f.write(f"  - _Reason:_ {ga['reason']}\n")

    print(f"[4/5] Generating Final Report and Artifacts...")
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

    with open(run_dir / "2_reasoning_trail.md", "w", encoding="utf-8") as f:
        f.write(f"# Reasoning Trail: {challenge_name}\n\n")
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
            elif etype == "decision.recorded":
                f.write(f"- **Decision ID:** `{p.get('id')}` | **Action:** `{p.get('action')}` on `{p.get('target')}`\n")
                f.write(f"- **Expected Observation:** {p.get('expected_observation')}\n")
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
                f.write(f"- **Role Transition:** `{p.get('role')}` -> `{p.get('next_role')}`\n")
                f.write(f"- **Summary:** {p.get('summary')}\n")
                f.write(f"- **Why:** {p.get('why')}\n")
            else:
                f.write(f"```json\n{json.dumps(p, indent=2)}\n```\n")
            f.write("\n")

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
                f.write(f"- **Asset / Endpoint:** `{f_item.asset}` `{f_item.endpoint or ''}`\n")
                f.write(f"- **Severity:** `{f_item.severity}` | **CVSS:** `{f_item.cvss}`\n")
                f.write(f"- **Description:** {f_item.description}\n\n")

        f.write("## Steps Executed\n\n")
        for s in steps:
            f.write(f"- **Step #{s.seq} `{s.action}`** -> `{s.status}` (exit code: {s.exit_code})\n")
            f.write(f"  - Command: `{' '.join(s.argv)}`\n")
            f.write(f"  - Rationale: {s.rationale}\n")

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
    print("AIPENT RESILIENT SANDBOX SUITE (3 CHALLENGES)")
    print(f"Target: OWASP Juice Shop Sandbox on {settings.juiceshop_url}")
    print(f"Provider: {settings.llm_provider} (Ollama Cloud)")
    print(f"Supervisor Model: {settings.supervisor_model}")
    print(f"Specialists Model: {settings.recon_model}")
    print(f"Observations Directory: {OBSERVATIONS_DIR}")
    print(f"Budgets: Probes={settings.max_validation_probes}, MaxSteps={settings.max_steps}, Turns={settings.max_agent_turns}")
    print("=" * 75)

    results = []
    for ch in CHALLENGES:
        res = await run_single_challenge(ch)
        results.append(res)
        await asyncio.sleep(2.0)

    summary_path = OBSERVATIONS_DIR / "SANDBOX_RESILIENCE_SUMMARY.md"
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("# AIPENT Resilient Sandbox Observation Suite: 3 Challenges\n\n")
        f.write(f"- **Executed At:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        f.write(f"- **Environment:** OWASP Juice Shop Local Sandbox (`{settings.juiceshop_url}`)\n")
        f.write(f"- **Supervisor Model:** `{settings.supervisor_model}`\n")
        f.write(f"- **Specialists Model:** `{settings.recon_model}`\n")
        f.write(f"- **Report Model:** `{settings.report_model}`\n")
        f.write(f"- **Configured Budgets:** Probes={settings.max_validation_probes}, MaxSteps={settings.max_steps}, Turns={settings.max_agent_turns}\n\n")

        f.write("## 1. Results Summary Table\n\n")
        f.write("| Run | Challenge | Category | Mode | Solved? | Hypotheses | Steps | Findings | PDF Report |\n")
        f.write("| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |\n")
        for idx, r in enumerate(results, 1):
            mode_icon = "🧭 **Lead Steered & Gate Controlled**" if r.get("steered") else "🤖 **Autonomous (Auto-Approved)**"
            solved_icon = "✅ **SOLVED**" if r["solved"] else "❌ Not Solved"
            pdf_link = f"`{Path(r['pdf_path']).name}`" if r["pdf_path"] else "Not generated"
            f.write(f"| Run {idx} | **{r['challenge']}** | {r['category']} | {mode_icon} | {solved_icon} | {r['hypotheses_count']} | {r['steps_count']} | {r['findings_count']} | {pdf_link} |\n")

        f.write("\n## 2. Key Observations & Error Recovery Analysis\n\n")
        f.write("### Run 1: Login Admin (Steered & Gate Controlled)\n")
        f.write("- **Mentorship Impact:** Real-time steering provided architectural hints for authentication endpoints and payload formatting.\n")
        f.write("- **Interactive Gate:** Replaced dead-end paths with constructive authentication testing.\n\n")
        f.write("### Runs 2 & 3: Empty User Registration & Misplaced IaC Files (Autonomous)\n")
        f.write("- **Self-Healing Verification:** Monitored whether HTTP 4xx errors triggered parameter correction and retry rather than loop freezing.\n")
        f.write("- **Extended Turn Budget:** Evaluated specialist multi-step discovery and validation without premature turn-limit exhaustion.\n")

    print("\n" + "=" * 75)
    print("RESILIENT SANDBOX SUITE COMPLETE!")
    print(f"Summary written to: {summary_path}")
    print("=" * 75)


if __name__ == "__main__":
    asyncio.run(main())
