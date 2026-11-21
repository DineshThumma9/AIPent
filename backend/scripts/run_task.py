#!/usr/bin/env python3
"""Runner script to execute tasks from tasks.py sequentially or individually.

Features:
- Reads tasks and hints from backend/scripts/tasks.py
- Uses AIPENT runtime runner with auto-approval of all human action gates & execution requests
- Injects task hints time to time (step/time-based steering) into the agent loop
- Monitors agent reasoning, supervisor routes, hypotheses, tool actions, observations, and findings
- Tracks Juice Shop challenge solved deltas
- Provides structured behavioral observation summaries without forcing the agent
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
from pathlib import Path

# Add backend/src and backend/scripts to sys.path
SCRIPT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = SCRIPT_DIR.parent
sys.path.insert(0, str(BACKEND_DIR / "src"))
sys.path.insert(0, str(SCRIPT_DIR))

from tasks import task_hints, tasks

from app.core.config import settings
from app.core.db import get_async_session_ctx, init_db
from app.domain.models import Assessment, AssessmentStatus, Audit, Finding, Step
from app.integrations.juiceshop import compute_delta, fetch_solved_challenges
from app.persistence import AssessmentRepo, SteeringRepo
from app.runtime import runner

# Colors for terminal output
BOLD = "\033[1m"
RESET = "\033[0m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
MAGENTA = "\033[35m"
RED = "\033[31m"
BLUE = "\033[34m"
DIM = "\033[2m"


async def run_single_task(task_id: int, timeout_seconds: int = 360) -> dict:
    if task_id not in tasks:
        raise ValueError(f"Task ID {task_id} not found in tasks.py. Available: {list(tasks.keys())}")

    task_desc = tasks[task_id]
    hints = task_hints.get(task_id, [])

    print(f"\n{'='*75}")
    print(f"{BOLD}STARTING TASK {task_id}: {task_desc}{RESET}")
    print(f"{'='*75}")
    print(f"Target: http://127.0.0.1:3000")
    print(f"Available hints ({len(hints)}):")
    for i, h in enumerate(hints, start=1):
        clean_h = " ".join(h.strip().split())
        print(f"  [{i}] {clean_h}")
    print(f"{'-'*75}\n")

    # 1. Baseline
    baseline = await fetch_solved_challenges()
    solved_before = set(baseline.get("solved_ids", [])) if baseline else set()
    print(f"Juice Shop baseline solved challenges: {len(solved_before)}")

    # 2. Create Assessment
    async with get_async_session_ctx() as session:
        repo = AssessmentRepo(session)
        assessment = await repo.create(
            title=f"Task {task_id}: {task_desc[:60]}",
            request=task_desc,
            targets=["127.0.0.1"],
            ports=[3000],
        )
        aid = assessment.id
        print(f"{GREEN}Created Assessment #{aid} for Task {task_id}{RESET}")

    # 3. Launch Agent Loop
    print(f"{CYAN}Starting LangGraph agent loop (unattended auto-approval)...{RESET}")
    await runner.start_run(aid, actor="cli-auto")

    last_audit_id = 0
    seen_hypotheses: set[str] = set()
    hints_injected: set[int] = set()
    start_time = time.time()
    steps_executed = 0

    try:
        while time.time() - start_time < timeout_seconds:
            await asyncio.sleep(1.2)
            view = await runner.get_view(aid)

            # Auto-approve any pending gates
            if view.paused and view.pending:
                pending = view.pending
                gate = pending.get("gate") or pending.get("role") or "action"
                action_name = pending.get("action") or pending.get("role") or "gate"
                print(f"{YELLOW}⚡ Auto-approving gate: {gate.upper()} ({action_name}){RESET}")
                if gate == "plan":
                    proposed = list(pending.get("plan") or [])
                    await runner.resume_run(
                        aid,
                        {
                            "decision": "approved",
                            "actor": "cli-auto",
                            "reason": "auto-approved by task runner",
                            "approval_id": pending.get("approval_id"),
                            "plan": proposed,
                            "feedback": "",
                        },
                    )
                else:
                    await runner.resume_run(
                        aid,
                        {
                            "decision": "approved",
                            "actor": "cli-auto",
                            "reason": "auto-approved by task runner",
                            "approval_id": pending.get("approval_id"),
                        },
                    )
                continue

            # Process new audit events
            async with get_async_session_ctx() as session:
                from sqlmodel import select
                res = await session.execute(
                    select(Audit)
                    .where(Audit.assessment_id == aid, Audit.id > last_audit_id)
                    .order_by(Audit.id.asc())
                )
                events = list(res.scalars().all())

            for ev in events:
                last_audit_id = max(last_audit_id, ev.id or 0)
                payload = ev.payload or {}
                etype = ev.event_type

                if etype == "supervisor.route":
                    role = payload.get("accepted_role", "").upper()
                    directive = payload.get("directive") or payload.get("why") or ""
                    print(f"{MAGENTA}👑 [SUPERVISOR]{RESET} Route ➔ {BOLD}{role}{RESET} {DIM}({str(directive)[:140]}){RESET}")

                elif etype == "hypothesis.created":
                    hid = payload.get("hypothesis_id") or "H"
                    stmt = payload.get("statement") or ""
                    if stmt not in seen_hypotheses:
                        seen_hypotheses.add(stmt)
                        print(f"   {CYAN}💡 Hypothesis ({hid}):{RESET} {stmt}")

                elif etype == "step.started":
                    steps_executed += 1
                    action = payload.get("action")
                    target = payload.get("target") or "target"
                    print(f"   {BLUE}⚡ Action #{steps_executed} started:{RESET} {BOLD}{action}{RESET} on {target}")

                elif etype == "step.finished":
                    action = payload.get("action")
                    code = payload.get("exit_code")
                    dur = payload.get("duration_ms")
                    print(f"   {GREEN}✔ Action #{steps_executed} finished:{RESET} {action} (exit: {code}, {dur}ms)")

                elif etype == "observation.recorded":
                    action = payload.get("action")
                    summary = payload.get("summary") or ""
                    print(f"   {DIM}👀 Obs ({action}): {summary[:200]}...{RESET}")

                elif etype == "finding.created":
                    title_f = payload.get("title") or "New finding"
                    sev = payload.get("severity") or "info"
                    print(f"   {RED}🚨 Finding: [{sev.upper()}] {title_f}{RESET}")

                elif etype == "handoff.created":
                    r = payload.get("role")
                    nr = payload.get("next_role")
                    why = payload.get("why") or ""
                    print(f"   {YELLOW}🤝 Handoff:{RESET} {r} ➔ {nr} ({why[:120]})")

            # Progressive hint injection:
            # Hint 1 injected after step 2 or 40s
            elapsed = time.time() - start_time
            if len(hints) >= 1 and 0 not in hints_injected:
                if steps_executed >= 2 or elapsed >= 40:
                    hints_injected.add(0)
                    hint_text = " ".join(hints[0].strip().split())
                    async with get_async_session_ctx() as session:
                        s_repo = SteeringRepo(session)
                        await s_repo.add(assessment_id=aid, run_id=None, text=f"OPERATOR GUIDANCE / HINT: {hint_text}")
                    print(f"\n{YELLOW}{BOLD}📢 [HINT 1 INJECTED TO AGENT]:{RESET} {hint_text}\n")

            # Hint 2 injected after step 5 or 100s
            if len(hints) >= 2 and 1 not in hints_injected:
                if steps_executed >= 5 or elapsed >= 100:
                    hints_injected.add(1)
                    hint_text = " ".join(hints[1].strip().split())
                    async with get_async_session_ctx() as session:
                        s_repo = SteeringRepo(session)
                        await s_repo.add(assessment_id=aid, run_id=None, text=f"OPERATOR GUIDANCE / HINT: {hint_text}")
                    print(f"\n{YELLOW}{BOLD}📢 [HINT 2 INJECTED TO AGENT]:{RESET} {hint_text}\n")

            # Check if agent has completed naturally
            if not view.running and not view.paused:
                print(f"\n{GREEN}Agent run finished naturally with status: {view.status}{RESET}")
                break
        else:
            print(f"\n{RED}Task {task_id} timed out after {timeout_seconds}s.{RESET}")
            async with get_async_session_ctx() as session:
                a_repo = AssessmentRepo(session)
                a = await a_repo.get(aid)
                if a and a.status == AssessmentStatus.RUNNING.value:
                    from app.core.time import utcnow
                    a.status = AssessmentStatus.FAILED.value
                    a.finished_at = utcnow()
                    await session.commit()

    except Exception as exc:
        print(f"{RED}Exception while running task {task_id}: {exc}{RESET}")

    # 4. Summary & Juice Shop Delta
    print(f"\n{BOLD}{'='*75}")
    print(f"SUMMARY FOR TASK {task_id}: Assessment #{aid}")
    print(f"{'='*75}{RESET}")

    async with get_async_session_ctx() as session:
        delta = await compute_delta(session, aid)
        from sqlmodel import select
        steps = list((await session.execute(select(Step).where(Step.assessment_id == aid).order_by(Step.seq))).scalars().all())
        findings = list((await session.execute(select(Finding).where(Finding.assessment_id == aid))).scalars().all())

    newly_solved = delta.get("newly_solved", []) if delta else []
    print(f"Total Steps Executed: {len(steps)}")
    print(f"Total Findings Detected: {len(findings)}")
    print(f"Newly Solved Challenges: {newly_solved if newly_solved else 'None'}")
    print(f"Hints Injected: {len(hints_injected)}/{len(hints)}")

    print(f"\nFindings breakdown:")
    for f in findings:
        print(f"  - [{f.severity.upper()}] [{f.status}] {f.title} ({f.endpoint or ''})")

    result = {
        "task_id": task_id,
        "task_desc": task_desc,
        "assessment_id": aid,
        "steps_count": len(steps),
        "findings_count": len(findings),
        "newly_solved": newly_solved,
        "hints_injected": len(hints_injected),
    }
    return result


async def main():
    parser = argparse.ArgumentParser(description="Sequential Task Runner for AIPENT")
    parser.add_argument("--task", type=int, default=None, help="Run a specific task ID (1, 2, or 3)")
    parser.add_argument("--tasks", type=str, default=None, help="Comma-separated task IDs (e.g. '2,3')")
    parser.add_argument("--all", action="store_true", help="Run all tasks sequentially (1, 2, 3)")
    parser.add_argument("--timeout", type=int, default=360, help="Timeout in seconds per task")
    args = parser.parse_args()

    await init_db()

    task_list = []
    if args.tasks:
        task_list = [int(t.strip()) for t in args.tasks.split(",") if t.strip()]
    elif args.task:
        task_list = [args.task]
    elif args.all:
        task_list = sorted(tasks.keys())
    else:
        # Default to Task 1
        task_list = [1]

    results = []
    for tid in task_list:
        res = await run_single_task(tid, timeout_seconds=args.timeout)
        results.append(res)
        print(f"\n{BOLD}Completed Task {tid}. Resting briefly before next task...{RESET}\n")
        await asyncio.sleep(3)

    print(f"\n{BOLD}{'='*75}\nALL SCHEDULED TASKS COMPLETED\n{'='*75}{RESET}")
    for r in results:
        print(f"Task {r['task_id']}: Assessment #{r['assessment_id']} | Steps: {r['steps_count']} | Findings: {r['findings_count']} | Solved: {r['newly_solved']}")


if __name__ == "__main__":
    asyncio.run(main())
