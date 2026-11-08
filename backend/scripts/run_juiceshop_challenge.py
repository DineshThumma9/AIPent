"""Juice Shop Challenge Runner for AIPENT Agent.

Selects a challenge from OWASP Juice Shop, sets it as the agent's objective,
runs the assessment loop, and logs the agent's real-time progress and reasoning:
  - Supervisor routing and mission directives
  - Specialist hypotheses, confidence, and falsifiers
  - Action execution, argv, and policy approvals
  - Tool observations returned into the reasoning loop
  - Challenge solved delta (baseline vs post-run)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path

# Add backend/src to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "src"))

import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from app.core.config import settings
from app.core.db import get_async_session_ctx, get_engine, init_db
from app.domain.models import Assessment, Audit, Finding, Step, StepStatus
from app.integrations.juiceshop import compute_delta, fetch_solved_challenges
from app.runtime import runner

# ANSI Color codes for clean terminal output
BOLD = "\033[1m"
RESET = "\033[0m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
MAGENTA = "\033[35m"
RED = "\033[31m"
BLUE = "\033[34m"
DIM = "\033[2m"


async def get_challenges_catalog() -> list[dict]:
    """Fetch all challenges from the live Juice Shop instance."""
    url = f"{settings.juiceshop_url.rstrip('/')}/api/Challenges"
    async with httpx.AsyncClient(timeout=10) as client:
        res = await client.get(url)
        res.raise_for_status()
        data = res.json()
        return data.get("data") or data.get("challenges") or []


def display_challenges(challenges: list[dict]):
    print(f"\n{BOLD}=== OWASP Juice Shop Challenges (1-Star & 2-Star) ==={RESET}")
    for c in challenges:
        if c.get("difficulty", 99) in (1, 2):
            diff = f"{c.get('difficulty')}⭐"
            solved_tag = f"{GREEN}[SOLVED]{RESET}" if c.get("solved") else f"{YELLOW}[OPEN]{RESET}"
            print(f"  {diff} {BOLD}{c.get('name')}{RESET} {solved_tag}")
            print(f"     Key: {c.get('key')} | {c.get('description')}\n")


async def monitor_reasoning(assessment_id: int, stop_event: asyncio.Event):
    """Poll and display audit events representing agent reasoning in real time."""
    seen_ids: set[int] = set()

    while not stop_event.is_set():
        try:
            async with get_async_session_ctx() as session:
                result = await session.execute(
                    select(Audit)
                    .where(Audit.assessment_id == assessment_id)
                    .order_by(Audit.id)
                )
                events = list(result.scalars().all())

            for ev in events:
                if ev.id in seen_ids:
                    continue
                seen_ids.add(ev.id)
                p = ev.payload or {}
                t = ev.event_type

                if t == "supervisor.route_proposed":
                    print(f"\n{MAGENTA}🧠 [SUPERVISOR PROPOSAL]{RESET} Proposing next role: {BOLD}{p.get('proposed_role')}{RESET} (confidence: {p.get('confidence', 0):.2f})")
                    print(f"   {DIM}Rationale:{RESET} {p.get('why')}")
                    if p.get("directive"):
                        print(f"   {YELLOW}Directive:{RESET} {p.get('directive')}")

                elif t == "supervisor.route":
                    print(f"{MAGENTA}🎯 [SUPERVISOR ROUTE ACCEPTED]{RESET} Transitioning to role: {BOLD}{p.get('accepted_role')}{RESET}")

                elif t == "hypothesis.created":
                    print(f"\n{CYAN}💡 [HYPOTHESIS FORMED]{RESET} {BOLD}{p.get('hypothesis_id')}{RESET}: {p.get('statement')}")
                    print(f"   Target: {p.get('asset')} {p.get('endpoint') or ''} | Confidence: {p.get('confidence', 0.5):.2f}")
                    if p.get("falsifier"):
                        print(f"   {DIM}Falsifier:{RESET} {p.get('falsifier')}")

                elif t == "hypothesis.updated":
                    print(f"{CYAN}📝 [HYPOTHESIS UPDATED]{RESET} {BOLD}{p.get('hypothesis_id')}{RESET} -> status: {p.get('status')} | confidence: {p.get('confidence', 0):.2f}")
                    if p.get("note"):
                        print(f"   {DIM}Note:{RESET} {p.get('note')}")

                elif t == "action.requested":
                    print(f"\n{BLUE}⚡ [ACTION PREPARED]{RESET} Tool: {BOLD}{p.get('action')}{RESET} on {p.get('target')}")
                    print(f"   {DIM}Command argv:{RESET} {' '.join(p.get('argv', []))}")

                elif t == "approval.auto_approved":
                    print(f"   {GREEN}✔ Auto-approved by policy{RESET} (Step #{p.get('step_id')})")

                elif t == "step.succeeded":
                    print(f"{GREEN}✔ [STEP SUCCEEDED]{RESET} Step #{p.get('step_id')} ({p.get('action')})")

                elif t == "observation.recorded":
                    print(f"{GREEN}👀 [OBSERVATION FEEDBACK]{RESET} ({p.get('action')}) status: {p.get('status')}")
                    if p.get("summary"):
                        print(f"   {DIM}Observation:{RESET} {p.get('summary')[:300]}")

                elif t == "handoff.created":
                    print(f"\n{YELLOW}🤝 [SPECIALIST HANDOFF]{RESET} Role {BOLD}{p.get('role')}{RESET} -> Recommended next: {BOLD}{p.get('next_role')}{RESET}")
                    print(f"   {DIM}Summary:{RESET} {p.get('summary')}")
                    print(f"   {DIM}Why:{RESET} {p.get('why')} (confidence: {p.get('confidence', 0):.2f})")
                    if p.get("open_questions"):
                        print(f"   {DIM}Open Questions:{RESET} {p.get('open_questions')}")

                elif t == "benchmark.juice_shop_delta":
                    newly = p.get("newly_solved", [])
                    print(f"\n{GREEN}🏆 [JUICE SHOP CHALLENGE DELTA]{RESET} Solved now: {len(newly)} new challenge(s): {newly}")

        except Exception:
            pass

        await asyncio.sleep(1.0)


async def run_challenge_assessment(challenge: dict, loop_version: str = "v2", auto_approve: bool = True):
    print(f"\n{'='*70}")
    print(f"{BOLD}AIPENT AGENT RUN: OWASP Juice Shop Challenge{RESET}")
    print(f"{'='*70}")
    print(f"Target Challenge: {BOLD}{challenge.get('name')}{RESET} ({challenge.get('difficulty')}⭐)")
    print(f"Key: {challenge.get('key')}")
    print(f"Description: {challenge.get('description')}")
    print(f"Target URL: {settings.juiceshop_url}")
    print(f"Agent Loop: {loop_version}")

    # 1. Fetch initial baseline
    print(f"\n{BOLD}[1/4] Taking Juice Shop Baseline...{RESET}")
    baseline = await fetch_solved_challenges()
    if baseline:
        print(f"Baseline Solved Challenges: {len(baseline['solved_ids'])}/{baseline['total']}")
        already_solved = challenge.get("name") in baseline["solved_ids"] or challenge.get("key") in baseline["solved_ids"]
        if already_solved:
            print(f"{YELLOW}Note: This challenge is ALREADY marked solved in the lab environment.{RESET}")
    else:
        print(f"{YELLOW}Warning: Juice Shop unreachable at {settings.juiceshop_url}. Verify service is running.{RESET}")

    # 2. Create Assessment in database
    print(f"\n{BOLD}[2/4] Initializing Assessment...{RESET}")
    settings.agent_loop = loop_version  # type: ignore[assignment]
    target_host = "127.0.0.1"

    request_prompt = (
        f"Perform an assessment of the OWASP Juice Shop target on {target_host}:3000. "
        f"Primary Objective: Complete the '{challenge.get('name')}' challenge. "
        f"Goal: {challenge.get('description')}. "
        f"Key: {challenge.get('key')}. "
        f"Discover relevant services and endpoints, form hypotheses, test them, and verify the exposure."
    )

    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title=f"Juice Shop: {challenge.get('name')}",
            request=request_prompt,
            targets=[target_host],
            ports=[3000],
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)
        aid = assessment.id
        print(f"Created Assessment ID: {aid}")

    # 3. Start Agent Run
    print(f"\n{BOLD}[3/4] Launching AIPENT Agent Loop...{RESET}")
    stop_monitor = asyncio.Event()
    monitor_task = asyncio.create_task(monitor_reasoning(aid, stop_monitor))

    try:
        view = await runner.start_run(aid, actor="analyst")
        print(f"Agent Status: {view.status} | Running: {view.running}")

        # Monitor loop & handle gates
        timeout_seconds = 300
        start_time = time.time()
        while time.time() - start_time < timeout_seconds:
            await asyncio.sleep(2.0)
            view = await runner.get_view(aid)

            if not view.running and not view.paused:
                print(f"\nAgent reached terminal state: {BOLD}{view.status}{RESET}")
                break

            if view.paused and view.pending:
                pending = view.pending
                gate = pending.get("gate", "unknown")
                print(f"\n{YELLOW}⏸ [GATE INTERRUPT]{RESET} Paused at {BOLD}{gate.upper()}{RESET} gate:")
                print(f"   Action: {pending.get('action') or pending.get('role')}")
                if pending.get("argv"):
                    print(f"   Command: {' '.join(pending.get('argv'))}")
                if pending.get("rationale"):
                    print(f"   Rationale: {pending.get('rationale')}")

                if auto_approve:
                    reason = f"Approved for Juice Shop challenge {challenge.get('name')}"
                    print(f"   {GREEN}▶ Resuming with decision: APPROVED{RESET}")
                    await runner.resume_run(aid, {"decision": "approved", "actor": "analyst", "reason": reason})
                else:
                    break

    finally:
        stop_monitor.set()
        await monitor_task

    # 4. Final Evaluation & Delta
    print(f"\n{BOLD}[4/4] Checking Challenge Outcome & Benchmark...{RESET}")
    async with get_async_session_ctx() as session:
        delta = await compute_delta(session, aid)
        if delta:
            print(f"Juice Shop Delta Result:")
            print(f"  Baseline solved: {delta.get('baseline_n')}")
            print(f"  Current solved:  {delta.get('current_n')}")
            print(f"  Newly solved ({delta.get('delta')}): {delta.get('newly_solved')}")

            target_name = challenge.get("name")
            target_key = challenge.get("key")
            if target_name in delta.get("newly_solved", []) or target_key in delta.get("newly_solved", []):
                print(f"\n{GREEN}{BOLD}🎉 SUCCESS! The challenge '{target_name}' was SOLVED during this run!{RESET}")
            else:
                print(f"\n{CYAN}Run complete. Challenge state recorded in audit trail.{RESET}")

        # Summary of findings and hypotheses
        f_res = await session.execute(select(Finding).where(Finding.assessment_id == aid))
        findings = list(f_res.scalars().all())
        print(f"\nFindings Discovered ({len(findings)}):")
        for f in findings:
            print(f"  - [{f.status.upper()}] {f.title} ({f.asset} {f.endpoint or ''})")

        s_res = await session.execute(select(Step).where(Step.assessment_id == aid))
        steps = list(s_res.scalars().all())
        print(f"\nSteps Executed ({len(steps)}):")
        for s in steps:
            print(f"  - Step #{s.seq} {s.action} -> {s.status}")


async def main():
    parser = argparse.ArgumentParser(description="AIPENT Juice Shop Challenge Runner")
    parser.add_argument("--list", action="store_true", help="List available challenges from Juice Shop")
    parser.add_argument("--challenge", type=str, default=None, help="Challenge name or key (e.g. 'Confidential Document')")
    parser.add_argument("--loop", type=str, default="v2", choices=["legacy", "v2"], help="Agent loop version")
    parser.add_argument("--no-auto-approve", action="store_true", help="Pause on human gates rather than auto-approving")
    args = parser.parse_args()

    # Initialize backend DB
    engine = get_engine()
    await init_db(engine)

    try:
        challenges = await get_challenges_catalog()
    except Exception as exc:
        print(f"{RED}Error fetching Juice Shop challenges from {settings.juiceshop_url}: {exc}{RESET}")
        print("Please ensure Juice Shop is running on http://127.0.0.1:3000")
        sys.exit(1)

    if args.list:
        display_challenges(challenges)
        return

    # Select challenge
    target_challenge = None
    if args.challenge:
        query = args.challenge.lower()
        for c in challenges:
            if query in c.get("name", "").lower() or query in c.get("key", "").lower():
                target_challenge = c
                break
        if not target_challenge:
            print(f"{RED}Challenge '{args.challenge}' not found in Juice Shop catalog.{RESET}")
            sys.exit(1)
    else:
        # Default to a 1-star challenge like "Confidential Document" or first unsolved 1-star
        for c in challenges:
            if c.get("difficulty") == 1 and not c.get("solved"):
                target_challenge = c
                break
        if not target_challenge:
            # Fallback to any 1-star challenge
            target_challenge = [c for c in challenges if c.get("difficulty") == 1][0]

    await run_challenge_assessment(
        challenge=target_challenge,
        loop_version=args.loop,
        auto_approve=not args.no_auto_approve,
    )


if __name__ == "__main__":
    asyncio.run(main())
