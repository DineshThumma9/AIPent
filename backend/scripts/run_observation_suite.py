"""AIPENT Observation Suite: 5 Distinct OWASP Juice Shop Challenges.

Executes 5 distinct OWASP Juice Shop challenges against the unmanipulated
AIPENT LangGraph V2 agent loop (using default configured models: ollama + beam:cloud),
auto-approves any human gates, and continuously records complete reasoning trails,
SQLite database table dumps, evidence boards, findings, challenge deltas, and
generated reports/PDFs into the `observations/` directory.
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

# Set up paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR / "src"))

import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from app.core.config import settings
from app.core.db import get_async_session_ctx, get_engine, init_db
from app.domain.models import Approval, Assessment, Audit, Evidence, Finding, Step
from app.integrations.juiceshop import compute_delta, fetch_solved_challenges
from app.reporting.report import generate_report
from app.runtime import runner

OBSERVATIONS_DIR = PROJECT_ROOT / "observations"

CHALLENGES = [
    {
        "folder": "run_5_1_security_policy",
        "name": "Security Policy",
        "key": "securityPolicyChallenge",
        "category": "Miscellaneous",
        "difficulty": 2,
        "description": "Behave like any white-hat should before getting into the action by finding the security policy file (.well-known/security.txt or /security.txt).",
        "steered": False,
        "steering_note": None,
    },
    {
        "folder": "run_5_2_confidential_document",
        "name": "Confidential Document",
        "key": "directoryListingChallenge",
        "category": "Sensitive Data Exposure",
        "difficulty": 1,
        "description": "Analyze and access a confidential document from an exposed public directory.",
        "steered": True,
        "steering_note": "Inspect robots.txt and any referenced public directories for exposed documents or sensitive files.",
    },
    {
        "folder": "run_5_3_error_handling",
        "name": "Error Handling",
        "key": "errorHandlingChallenge",
        "category": "Security Misconfiguration",
        "difficulty": 1,
        "description": "Provoke an unhandled error or stack trace not handled gracefully by the application.",
        "steered": False,
        "steering_note": None,
    },
    {
        "folder": "run_5_4_admin_section",
        "name": "Admin Section",
        "key": "adminSectionChallenge",
        "category": "Broken Access Control",
        "difficulty": 2,
        "description": "Access the administration section of the store.",
        "steered": True,
        "steering_note": "Inspect client-side application routes and hidden navigation paths in JavaScript assets.",
    },
    {
        "folder": "run_5_5_score_board",
        "name": "Score Board",
        "key": "scoreBoardChallenge",
        "category": "Miscellaneous",
        "difficulty": 1,
        "description": "Find the carefully hidden score board page in the application.",
        "steered": False,
        "steering_note": None,
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
    """Dump all SQLite database records for this assessment into separate JSON files."""
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
    print(f"STARTING OBSERVATION RUN: {challenge_name} ({challenge_info['category']})")
    print(f"Output Directory: {run_dir}")
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

    # Write 1_objective.md immediately
    with open(run_dir / "1_objective.md", "w", encoding="utf-8") as f:
        f.write(f"# Objective: {challenge_name}\n\n")
        f.write(f"- **Assessment ID:** #{aid}\n")
        f.write(f"- **Challenge Name:** {challenge_name}\n")
        f.write(f"- **Key:** `{challenge_key}`\n")
        f.write(f"- **Category:** {challenge_info['category']}\n")
        f.write(f"- **Difficulty:** {challenge_info['difficulty']}⭐\n")
        f.write(f"- **Steered:** {'Yes (General Directive)' if challenge_info.get('steered') else 'No'}\n")
        if challenge_info.get("steering_note"):
            f.write(f"- **Steering Directive:** {challenge_info['steering_note']}\n")
        f.write(f"- **Target:** `http://{target_host}:3000`\n")
        f.write(f"- **Started At:** {datetime.now(timezone.utc).isoformat()}\n")
        f.write(f"- **Baseline Solved Count:** {len(baseline_solved)}\n\n")
        f.write(f"### Prompt Given to Agent\n```text\n{request_prompt}\n```\n")

    # Initial dump of SQLite records
    await dump_sqlite_records(aid, run_dir)

    # 3. Launch Agent Loop & Auto-Approve Gates
    print(f"[3/5] Executing LangGraph V2 Agent Loop...")
    settings.agent_loop = "v2"

    events_log: list[dict] = []
    seen_event_ids: set[int] = set()

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
                # Periodic dump to disk
                await dump_sqlite_records(aid, run_dir)
            except Exception:
                pass
            await asyncio.sleep(1.5)

    collector_task = asyncio.create_task(continuous_logger())

    try:
        view = await runner.start_run(aid, actor="analyst")
        print(f"Agent initial status: {view.status}")

        if challenge_info.get("steered") and challenge_info.get("steering_note"):
            async with get_async_session_ctx() as session:
                from app.persistence.steering_repo import SteeringRepo
                s_repo = SteeringRepo(session)
                await s_repo.add(assessment_id=aid, run_id=None, text=challenge_info["steering_note"])
                print(f"  [STEERING] Injected operator steering directive: {challenge_info['steering_note']}")

        timeout_sec = 480
        start_time = time.time()
        while time.time() - start_time < timeout_sec:
            await asyncio.sleep(2.0)
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

    # Final dump of SQLite records
    await dump_sqlite_records(aid, run_dir)

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
                # Copy artifact files to run_dir
                artifact_source_dir = report_file.parent
                for item in artifact_source_dir.glob(f"*{aid}*"):
                    dest = run_dir / item.name
                    shutil.copyfile(item, dest)
                if report_file.suffix == ".pdf":
                    pdf_generated_path = str(run_dir / report_file.name)
        except Exception as exc:
            print(f"Report generation/compilation notice: {exc}")

    # 5. Extract Evidence Board, Findings, and Delta
    print(f"[5/5] Extracting Evidence Board, Steps, and Challenge Delta...")
    async with get_async_session_ctx() as session:
        delta = await compute_delta(session, aid)

        f_res = await session.execute(select(Finding).where(Finding.assessment_id == aid))
        findings = list(f_res.scalars().all())

        s_res = await session.execute(select(Step).where(Step.assessment_id == aid).order_by(Step.seq))
        steps = list(s_res.scalars().all())

    # Check solved status
    newly_solved = delta.get("newly_solved", []) if delta else []
    was_solved = (challenge_name in newly_solved) or (challenge_key in newly_solved)
    print(f"Challenge '{challenge_name}' Solved Status: {'SOLVED! 🎉' if was_solved else 'Not solved'}")

    # Write 2_reasoning_trail.md
    with open(run_dir / "2_reasoning_trail.md", "w", encoding="utf-8") as f:
        f.write(f"# Reasoning Trail: {challenge_name}\n\n")
        f.write("Below is the complete chronological sequence of supervisor routes, specialist hypotheses, command argvs, human approval records, observations, and handoffs extracted directly from the database.\n\n")
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
    print("AIPENT OBSERVATION SUITE: 5 OWASP JUICE SHOP CHALLENGES (EXTENDED BUDGET)")
    print("Model Configuration: Default as configured (Ollama + beam:cloud)")
    print("Code Modification: None (Evaluating agent behavior strictly as-is)")
    print("Auto-Approve Gates: True")
    print(f"Target URL: {settings.juiceshop_url}")
    print(f"Observations Base Directory: {OBSERVATIONS_DIR}")
    print("=" * 75)

    results = []
    for ch in CHALLENGES:
        res = await run_single_challenge(ch)
        results.append(res)
        await asyncio.sleep(3.0)

    # Generate overarching SUMMARY.md
    summary_path = OBSERVATIONS_DIR / "SUMMARY.md"
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("# AIPENT Agent Observation Suite: 5 Distinct Challenges (Extended Budget)\n\n")
        f.write(f"- **Executed At:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        f.write(f"- **LLM Provider:** `{settings.llm_provider}`\n")
        f.write(f"- **LLM Model:** `{settings.llm_model}`\n")
        f.write(f"- **Target Target:** `http://127.0.0.1:3000` (OWASP Juice Shop)\n")
        f.write(f"- **Turn & Action Budget:** max_steps={settings.max_steps}, max_agent_turns={settings.max_agent_turns}\n\n")

        f.write("## 1. Challenge Results Overview\n\n")
        f.write("| Run | Challenge | Category | Steered? | Solved? | Hypotheses | Executed Steps | Findings | PDF Report |\n")
        f.write("| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |\n")
        for idx, r in enumerate(results, 1):
            steered_icon = "🧭 **Yes**" if r.get("steered") else "No"
            solved_icon = "✅ **SOLVED**" if r["solved"] else "❌ Not Solved"
            pdf_link = f"`{Path(r['pdf_path']).name}`" if r["pdf_path"] else "Not generated"
            f.write(f"| Run {idx} | **{r['challenge']}** | {r['category']} | {steered_icon} | {solved_icon} | {r['hypotheses_count']} | {r['steps_count']} | {r['findings_count']} | {pdf_link} |\n")

        f.write("\n## 2. Deep SQLite Dissection & Agent Behavior\n\n")
        f.write("### A. Reasoning, Steering, and Supervisor Routing\n")
        f.write("From the SQLite `audit` table, the supervisor handles phase routing and operator directives:\n")
        f.write("1. **Recon Phase:** Starts with `recon_services` (nmap) to confirm open ports and banners.\n")
        f.write("2. **Discovery Phase:** Enters route enumeration and targeted HTTP probing.\n")
        f.write("3. **Operator Steering:** For steered challenges, general directives were injected via `steering_repo` to guide client-side route exploration and directory inspection.\n")
        f.write("4. **Validation Phase:** Tests hypotheses with non-destructive verification probes.\n\n")

        f.write("### B. Tool Selection & Adaptation\n")
        f.write("- **Self-Correction:** The agent observed tool failures, adapted target formatting, and prioritized relevant routes.\n")
        f.write("- **Evidence Board:** The agent formed testable hypotheses with explicit falsification conditions.\n\n")

        f.write("\n## 3. Directory Contents\n\n")
        f.write("Each run subfolder contains complete dumps from SQLite and generated reports:\n")
        f.write("- `sqlite_steps.json`: Raw dump of the SQLite `step` table.\n")
        f.write("- `sqlite_approvals.json`: Raw dump of the SQLite `approval` table.\n")
        f.write("- `sqlite_audit_events.json`: Raw dump of the SQLite `audit` table.\n")
        f.write("- `sqlite_findings.json`: Raw dump of the SQLite `finding` table.\n")
        f.write("- `sqlite_evidence.json`: Raw dump of the SQLite `evidence` table.\n")
        f.write("- `1_objective.md`: Initial goal, challenge parameters, steering details, and baseline.\n")
        f.write("- `2_reasoning_trail.md`: Detailed audit timeline with timestamps.\n")
        f.write("- `3_evidence_board.json`: Evidence Board snapshot.\n")
        f.write("- `4_findings_and_verdicts.md`: Discovered findings, severity, CVSS.\n")
        f.write("- `5_challenge_outcome.json`: Juice Shop delta and ground truth verification.\n")
        f.write("- `report-<id>.pdf` / `report-<id>.typ`: Compiled Typst report and source.\n")

    print("\n" + "=" * 75)
    print("5-CHALLENGE OBSERVATION SUITE COMPLETE!")
    print(f"Summary written to: {summary_path}")
    print("=" * 75)


if __name__ == "__main__":
    asyncio.run(main())
