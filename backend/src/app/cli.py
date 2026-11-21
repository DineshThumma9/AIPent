"""AIPENT Terminal CLI Interface.

Fast, rich terminal client for running authorized security assessments,
monitoring agent reasoning in real-time, deciding approval gates, and
viewing findings and PDF reports.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.prompt import Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from app.core.config import settings
from app.core.db import get_async_session_ctx, get_engine, init_db
from app.domain.models import (
    Approval,
    Assessment,
    AssessmentStatus,
    Audit,
    Decision,
    Finding,
    FindingStatus,
    Severity,
    Step,
)
from app.persistence import AssessmentRepo, FindingRepo, SteeringRepo, StepRepo
from app.reporting.report import generate_report
from app.runtime import runner

APP_HELP = """[bold cyan]AIPENT[/] — Autonomous AI Penetration Testing Engine

Context-aware, evidence-driven security assessments orchestrated by LangGraph multi-agent loops.
Supports interactive human approval gates, automated policy approvals, and client-ready Typst reports.
"""

APP_EPILOG = """[bold cyan]Key Options & Flags (for scan):[/]
  [bold green]-r, --request, -q, --query[/] <str>  Assessment query, objective, or guidance for the agent (e.g. 'Test /rest/products for SQLi')
  [bold green]-y, --auto-approve, --yes[/]         Auto-approve all human action gates & requests (unattended mode)
  [bold green]-s, --quiet, --silent[/]             Quiet mode: record logs in aipent.log without terminal event flood
  [bold green]-p, --ports[/] <str>                 Target ports comma-separated (e.g. '80,443,3000')
  [bold green]-e, --exclude, --exclusions[/] <str> Endpoints or hosts to exclude from scope (e.g. '/admin,/logout')
  [bold green]-t, --title[/] <str>                 Custom assessment title (default: 'VAPT Assessment - <target>')
  [bold green]--timeout[/] <int>                   Maximum run timeout in seconds (default: 900)

[bold cyan]Helpful Examples:[/]
  [dim]# Run an unattended assessment with all requests auto-approved:[/dim]
  [green]aipent scan http://127.0.0.1:3000 -y[/]

  [dim]# Quiet unattended assessment (clean terminal; logs streamed to aipent.log):[/dim]
  [green]aipent scan http://127.0.0.1:3000 -y -s[/]

  [dim]# Pass a specific query / request objective with auto-approval:[/dim]
  [green]aipent scan http://127.0.0.1:3000 -r "Find SQL injection and XSS on search" -y[/]
  [green]aipent scan http://127.0.0.1:3000 -q "Test auth bypass vulnerabilities" --auto-approve[/]

  [dim]# Direct shorthand syntax (without explicit 'scan'):[/dim]
  [green]aipent http://127.0.0.1:3000 -y[/]
  [green]aipent http://127.0.0.1:3000 -r "Check for default credentials" -y[/]

  [dim]# Scan specific ports with scope exclusions:[/dim]
  [green]aipent scan 192.168.1.50 -p 80,443,8080 -e "/admin,/logout" -y[/]

  [dim]# Interactive assessment (prompts for operator approval at critical gates):[/dim]
  [green]aipent scan http://127.0.0.1:3000[/]

  [dim]# Inspect past assessments, findings, and generate reports:[/dim]
  [green]aipent list[/]
  [green]aipent status 1[/]
  [green]aipent steer 1 "Focus on JWT token forgery flaws"[/]
  [green]aipent report 1[/]
"""

SCAN_EPILOG = """[bold cyan]Helpful Examples:[/]
  [dim]# Run against local target with all requests auto-approved (unattended):[/dim]
  [green]aipent scan http://127.0.0.1:3000 -y[/]

  [dim]# Run quiet unattended mode (no terminal spam; full logs in aipent.log):[/dim]
  [green]aipent scan http://127.0.0.1:3000 -y -s[/]

  [dim]# Target a specific vulnerability or query with auto-approval:[/dim]
  [green]aipent scan http://127.0.0.1:3000 -r "Test for SQL injection on search endpoint" -y[/]
  [green]aipent scan http://127.0.0.1:3000 -q "Find OWASP Top 10 vulnerabilities" --auto-approve[/]

  [dim]# Scan specific ports and exclude sensitive paths from scope:[/dim]
  [green]aipent scan 192.168.1.50 -p 80,443,8080 -e "/admin,/logout" -y[/]

  [dim]# Set custom assessment title and extended timeout:[/dim]
  [green]aipent scan http://127.0.0.1:3000 -t "Juice Shop Q4 Audit" --timeout 1800 -y[/]

  [dim]# Interactive mode (prompts for operator approval before executing any tool):[/dim]
  [green]aipent scan http://127.0.0.1:3000[/]
"""


def _normalize_args(argv: list[str]) -> list[str]:
    """Auto-route shorthand targets and flags to `scan`.

    Allows running:
      aipent http://127.0.0.1:3000 -y
      aipent -r "find xss" -y http://127.0.0.1:3000
    without requiring the operator to type `scan`.
    """
    known_commands = {"scan", "list", "status", "report", "steer", "help", "--help", "-h"}
    if argv and argv[0] not in known_commands:
        return ["scan"] + list(argv)
    return list(argv)


class AIPENTTyper(typer.Typer):
    """Custom Typer subclass supporting automatic scan routing and rich formatting."""

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        if args and isinstance(args[0], (list, tuple)):
            normalized = _normalize_args(list(args[0]))
            return super().__call__(normalized, *args[1:], **kwargs)
        if len(sys.argv) > 1:
            known_commands = {"scan", "list", "status", "report", "steer", "help", "--help", "-h"}
            if sys.argv[1] not in known_commands:
                sys.argv.insert(1, "scan")
        return super().__call__(*args, **kwargs)


app = AIPENTTyper(
    name="aipent",
    help=APP_HELP,
    epilog=APP_EPILOG,
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()


def _severity_color(severity: str) -> str:
    s = str(severity).lower()
    if s == "critical":
        return "bold red"
    if s == "high":
        return "red"
    if s == "medium":
        return "yellow"
    if s == "low":
        return "blue"
    return "cyan"


def _status_color(status: str) -> str:
    st = str(status).lower()
    if st == "confirmed":
        return "bold green"
    if st == "suspected":
        return "yellow"
    if st == "false_positive":
        return "dim"
    return "white"


def _curl_batch_requests(argv: list[str]) -> list[tuple[str, str]]:
    """Return (method, path) pairs for a batched curl_request argv."""
    if len(argv) < 3 or argv[0] != "mcp" or argv[1] != "curl_request":
        return []

    try:
        payload = json.loads(argv[2])
    except (TypeError, ValueError):
        return []

    batch = payload.get("batch") if isinstance(payload, dict) else None
    if not isinstance(batch, list):
        return []

    requests: list[tuple[str, str]] = []
    for item in batch:
        if not isinstance(item, dict) or not isinstance(item.get("url"), str):
            return []
        parsed = urlsplit(item["url"])
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        requests.append((str(item.get("method") or "GET").upper(), path))
    return requests


def _argv_preview(argv: list[str], width: int = 60) -> str:
    """One-line summary of an action's argv for the status table."""
    if not argv:
        return "-"
    batch = _curl_batch_requests(argv)
    if batch:
        summary = (
            f"{len(batch)} request{'s' if len(batch) != 1 else ''} · "
            + " · ".join(f"{method} {path}" for method, path in batch)
        )
        return summary[:width]
    return " ".join(argv)[:width]


def _clean_target(raw: str) -> tuple[str, list[int]]:
    """Normalize input URL or host into a clean target host and default ports."""
    target = raw.strip()
    ports: list[int] = []
    if "://" in target:
        parsed = urlsplit(target)
        target = parsed.hostname or target
        if parsed.port:
            ports.append(parsed.port)
        elif parsed.scheme == "https":
            ports.append(443)
        elif parsed.scheme == "http":
            ports.append(80)
    return target, ports


# ---------------------------------------------------------------------------
# Command: scan
# ---------------------------------------------------------------------------


def _print_plan(plan: list[dict], available: dict | None = None) -> None:
    """Render the proposed assessment plan as an editable-looking table."""
    table = Table(show_header=True, header_style="bold cyan", box=box.SIMPLE)
    table.add_column("#", style="dim", width=3)
    table.add_column("Role", style="bold", width=12)
    table.add_column("Action", style="bold cyan", width=20)
    table.add_column("Target", style="white", width=24)
    table.add_column("Rationale", style="italic")
    for index, step in enumerate(plan, start=1):
        table.add_row(
            str(index),
            str(step.get("role", "")),
            str(step.get("action", "")),
            str(step.get("target", "")),
            str(step.get("rationale", ""))[:160],
        )
    console.print(table)
    if available:
        console.print(
            "[dim]Valid actions: "
            + "; ".join(f"{role}={','.join(names)}" for role, names in available.items())
            + "[/dim]"
        )


def _edit_plan(plan: list[dict], available: dict | None = None) -> tuple[list[dict], str]:
    """Interactively edit each step and return (steps, feedback)."""
    edited: list[dict] = []
    console.print("[bold]Edit plan steps. Blank keeps the current value; '-' removes the step.[/]")
    for index, step in enumerate(plan, start=1):
        console.print(f"\n[bold cyan]Step {index}[/]")
        action = Prompt.ask("  Action", default=str(step.get("action", "")))
        if action.strip() == "-":
            continue
        target = Prompt.ask("  Target", default=str(step.get("target", "")))
        rationale = Prompt.ask("  Rationale", default=str(step.get("rationale", "")))
        edited.append(
            {
                "role": step.get("role", "recon"),
                "action": action.strip(),
                "target": target.strip(),
                "rationale": rationale.strip(),
                "enabled": True,
            }
        )

    while Prompt.ask("\nAdd another step?", choices=["y", "n"], default="n") == "y":
        role = Prompt.ask(
            "  Role",
            choices=list((available or {}).keys()) or ["recon", "discovery", "validation", "review"],
            default="discovery",
        )
        action = Prompt.ask("  Action")
        target = Prompt.ask("  Target")
        rationale = Prompt.ask("  Rationale", default="")
        edited.append(
            {
                "role": role,
                "action": action.strip(),
                "target": target.strip(),
                "rationale": rationale.strip(),
                "enabled": True,
            }
        )

    feedback = Prompt.ask(
        "Feedback for every agent (optional; press Enter to skip)", default=""
    )
    return edited, feedback.strip()


@app.command(
    "scan",
    help="Start an authorized security assessment against a target.",
    epilog=SCAN_EPILOG,
)
def scan_cmd(
    target: str = typer.Argument(..., help="Target host, IP, or URL (e.g. 127.0.0.1 or http://127.0.0.1:3000)"),
    ports: Optional[str] = typer.Option(
        None,
        "-p",
        "--ports",
        help="Comma-separated target ports (e.g. '80,443,3000'). Defaults to 3000 or URL port.",
    ),
    title: Optional[str] = typer.Option(
        None,
        "-t",
        "--title",
        help="Custom assessment title (default: 'VAPT Assessment - <target>').",
    ),
    request: str = typer.Option(
        "",
        "-r",
        "--request",
        "-q",
        "--query",
        help="Assessment query, objective, or guidance for the agent (e.g. 'Test for SQL injection on /rest/products/search').",
    ),
    auto_approve: bool = typer.Option(
        False,
        "-y",
        "--auto-approve",
        "--yes",
        "--approve-all",
        help="Auto-approve all human action gates & execution requests without prompting (unattended mode).",
    ),
    quiet: bool = typer.Option(
        False,
        "-s",
        "--quiet",
        "--silent",
        help="Quiet mode: suppress terminal live streaming events (full logs are recorded in backend/data/aipent.log).",
    ),
    exclusions: Optional[str] = typer.Option(
        None,
        "-e",
        "--exclude",
        "--exclusions",
        help="Comma-separated endpoints, paths, or hosts to exclude from scope (e.g. '/admin,/logout').",
    ),
    timeout: int = typer.Option(
        900,
        "--timeout",
        help="Maximum run timeout in seconds (default: 900).",
    ),
):
    """Run an assessment loop from start to finish with live terminal updates."""
    clean_host, url_ports = _clean_target(target)
    final_ports: list[int] = []
    if ports:
        try:
            final_ports = [int(p.strip()) for p in ports.split(",") if p.strip()]
        except ValueError:
            console.print("[bold red]Error:[/] Invalid port format. Use comma-separated integers like '80,443,3000'.")
            raise typer.Exit(1)
    elif url_ports:
        final_ports = url_ports
    else:
        final_ports = [3000]

    final_exclusions: list[str] | None = None
    if exclusions:
        final_exclusions = [x.strip() for x in exclusions.split(",") if x.strip()]

    final_title = title or f"VAPT Assessment - {clean_host}"

    async def _execute():
        await init_db()

        # 1. Create Assessment
        async with get_async_session_ctx() as session:
            repo = AssessmentRepo(session)
            assessment = await repo.create(
                title=final_title,
                request=request,
                targets=[clean_host],
                ports=final_ports,
                exclusions=final_exclusions,
            )
            aid = assessment.id

        from app.agents.run_config import build_run_manifest

        manifest = build_run_manifest(aid)
        role_models = manifest["models"]
        banner = Text.assemble(
            ("🎯 Target: ", "bold cyan"),
            (clean_host, "bold white"),
            (" | Ports: ", "bold cyan"),
            (str(final_ports), "bold white"),
            ("\n📋 Title:  ", "bold cyan"),
            (final_title, "white"),
        )
        if request:
            banner.append("\n❓ Query:  ", style="bold cyan")
            banner.append(request, style="bold yellow")
        if final_exclusions:
            banner.append("\n🚫 Exclude:", style="bold cyan")
            banner.append(", ".join(final_exclusions), style="dim red")
        banner.append("\n🆔 Run ID: ", style="bold cyan")
        banner.append(f"Assessment #{aid}", style="bold green")
        banner.append("\n⚡ Mode:   ", style="bold cyan")
        banner.append(
            "Auto-Approve Enabled (Unattended)" if auto_approve else "Interactive Human Gates",
            style="yellow" if auto_approve else "green",
        )
        banner.append("\n🤖 Models:", style="bold cyan")
        for role, cfg in role_models.items():
            thinking = manifest["thinking"].get(role, "-")
            banner.append(
                f"\n   {role:<12} {cfg['provider']} / {cfg['model']} [{thinking}]",
                style="dim",
            )
        budgets = manifest["budgets"]
        banner.append(
            "\n📊 Limits: "
            f"turns={budgets['role_turn_caps']} · max_turns={budgets['max_agent_turns']} · "
            f"supervisor_calls={budgets['supervisor_calls_per_run']} · "
            f"recursion={budgets['agent_recursion_limit']}",
            style="dim",
        )
        banner.append(
            "\n🧰 Tools: "
            + " · ".join(f"{role}={count}" for role, count in manifest["tool_counts"].items()),
            style="dim",
        )

        if quiet:
            from app.core.log import setup_logging
            setup_logging(stream=False, force=True)
            console.print(
                f"[bold cyan]AIPENT:[/] Assessment [bold green]#{aid}[/] started against [bold white]{clean_host}[/] "
                f"([yellow]{'Auto-Approve' if auto_approve else 'Interactive'}[/]; quiet mode — logs in [dim]{settings.log_path}[/dim])\n"
            )
        else:
            console.print()
            console.print(
                Panel(
                    banner,
                    title="[bold green]AIPENT Autonomous VAPT[/]",
                    box=box.ROUNDED,
                    padding=(1, 2),
                )
            )

        # 2. Start Assessment Run
        await runner.start_run(aid)
        if not quiet:
            console.print("[dim]Starting LangGraph observe-reason-act agent loop...[/]\n")

        # 3. Live Monitoring Loop
        last_audit_id = 0
        seen_hypotheses: set[str] = set()
        seen_findings: set[str] = set()
        start_time = time.time()

        progress: Optional[Progress] = None
        progress_task = None
        if not quiet:
            progress = Progress(
                SpinnerColumn(style="cyan"),
                TextColumn("[bold cyan]{task.description}"),
                BarColumn(bar_width=None),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            )
            progress_task = progress.add_task("Agent starting…", total=None)
            progress.start()
        timed_out = False
        try:
            while time.time() - start_time < timeout:
                await asyncio.sleep(0.6)
                view = await runner.get_view(aid)

                if progress and progress_task is not None:
                    role = (view.active_role or "agent").upper()
                    if view.paused:
                        description = "Waiting for your approval"
                    elif view.running:
                        description = (
                            f"{role} working · {view.steps} action"
                            f"{'' if view.steps == 1 else 's'} · {last_audit_id} events"
                        )
                    else:
                        description = f"Wrapping up · {last_audit_id} events"
                    progress.update(progress_task, description=description)

                # Check new audit events
                async with get_async_session_ctx() as session:
                    from sqlmodel import select
                    stmt = (
                        select(Audit)
                        .where(Audit.assessment_id == aid, Audit.id > last_audit_id)
                        .order_by(Audit.id.asc())
                    )
                    res = await session.execute(stmt)
                    events = list(res.scalars().all())

                for ev in events:
                    last_audit_id = max(last_audit_id, ev.id or 0)
                    if quiet:
                        continue
                    payload = ev.payload or {}
                    etype = ev.event_type
    
                    if etype == "supervisor.route":
                        role = payload.get("accepted_role", "").upper()
                        directive = payload.get("directive") or payload.get("why") or ""
                        console.print(f"[bold magenta]👑 [SUPERVISOR][/] Route ➔ [bold cyan]{role}[/bold cyan] [dim]({directive[:120]})[/dim]")
    
                    elif etype == "hypothesis.created":
                        hid = payload.get("hypothesis_id") or "H"
                        stmt = payload.get("statement") or ""
                        if stmt not in seen_hypotheses:
                            seen_hypotheses.add(stmt)
                            console.print(f"   [cyan]💡 Hypothesis ({hid}):[/cyan] {stmt}")
    
                    elif etype == "step.started":
                        action = payload.get("action")
                        tgt = payload.get("target") or clean_host
                        batch = _curl_batch_requests(payload.get("argv") or [])
                        count = f" ({len(batch)} requests)" if batch else ""
                        console.print(f"   [yellow]⚡ Action queued:[/] [bold]{action}{count}[/] on [bold]{tgt}[/]")
    
                    elif etype == "step.finished":
                        action = payload.get("action")
                        code = payload.get("exit_code")
                        dur = payload.get("duration_ms")
                        dur_str = f" in {dur}ms" if dur else ""
                        batch = _curl_batch_requests(payload.get("argv") or [])
                        count = f" ({len(batch)} requests)" if batch else ""
                        console.print(f"   [green]✔ Action finished:[/] [bold]{action}{count}[/] (exit: {code}{dur_str})")
    
                    elif etype == "finding.created":
                        title_f = payload.get("title") or "New finding"
                        sev = payload.get("severity") or "info"
                        color = _severity_color(sev)
                        if title_f not in seen_findings:
                            seen_findings.add(title_f)
                            console.print(f"   [{color}]🚨 Finding: [{sev.upper()}] {title_f}[/{color}]")
    
                    elif etype == "finding.status_updated":
                        status = payload.get("status") or ""
                        console.print(f"   [bold green]🎯 Verdict:[/] Finding #{payload.get('finding_id')} marked [bold]{status.upper()}[/]")
    
                    elif etype == "report.narrative_generated":
                        count = payload.get("findings_count", 0)
                        console.print(f"[bold blue]📝 Narrative generated by LLM[/] ({count} finding(s) structured & validated)")
    
                    elif etype == "report.narrative_fallback":
                        console.print("[dim yellow]⚠ Narrative fallback triggered; compiling evidence-only report[/]")
    
                    elif etype == "report.generated":
                        path = payload.get("path")
                        console.print(f"[bold green]📄 Final PDF Compiled:[/] [underline]{path}[/underline]")
    
                # Check if paused at an approval gate
                if view.paused and view.pending:
                    if progress:
                        progress.stop()
                    pending = view.pending
                    gate = pending.get("gate") or pending.get("role") or "action"
                    action_name = pending.get("action") or pending.get("role") or "Review Delivery"
                    argv = pending.get("argv") or []
                    rationale = pending.get("rationale") or pending.get("message") or ""

                    if gate == "plan":
                        proposed = list(pending.get("plan") or [])
                        console.print()
                        console.print(
                            Panel(
                                Text(
                                    "The supervisor drafted an assessment plan. Every agent will "
                                    "receive the approved target and rationale before any scan runs.",
                                    style="white",
                                ),
                                title="[bold cyan]Review Proposed Assessment Plan[/]",
                                border_style="cyan",
                                box=box.ROUNDED,
                            )
                        )
                        _print_plan(proposed, pending.get("available_actions"))
                        if pending.get("notes"):
                            console.print(f"[italic dim]Planner notes:[/] {pending['notes']}\n")
                        if pending.get("objective"):
                            console.print(f"[bold]Objective:[/] {pending['objective']}\n")

                        if auto_approve:
                            plan, feedback, decision, reason = (
                                proposed, "", "approved", "auto-approved by -y flag"
                            )
                        else:
                            ans = Prompt.ask(
                                "[bold cyan]Plan[/] ([green]a[/]ccept / [blue]e[/]dit / "
                                "[yellow]f[/]eedback / [red]r[/]eject)",
                                choices=["a", "e", "f", "r"],
                                default="a",
                            )
                            if ans == "r":
                                plan, feedback, decision, reason = (
                                    proposed, "", "rejected", "Rejected via CLI"
                                )
                            elif ans == "e":
                                plan, feedback = _edit_plan(
                                    proposed, pending.get("available_actions")
                                )
                                decision, reason = "approved", "Plan edited and approved via CLI"
                            elif ans == "f":
                                feedback = Prompt.ask("Feedback for every agent", default="")
                                plan, decision, reason = (
                                    proposed, "approved", "Plan accepted with operator feedback"
                                )
                            else:
                                plan, feedback, decision, reason = (
                                    proposed, "", "approved", "Plan accepted via CLI"
                                )

                        console.print(
                            f"[green]▶ Resuming: {decision.capitalize()}[/green]\n"
                        )
                        await runner.resume_run(
                            aid,
                            {
                                "decision": decision,
                                "actor": "operator" if not auto_approve else "cli-auto",
                                "reason": reason,
                                "approval_id": pending.get("approval_id"),
                                "plan": plan,
                                "feedback": feedback,
                            },
                        )
                        if progress and progress_task is not None:
                            progress.start()
                            progress.update(progress_task, description="Resuming the run…")
                        continue

                    batch = _curl_batch_requests(argv)
    
                    console.print()
                    gate_content = Text()
                    gate_content.append("Gate Type:  ", style="bold")
                    gate_content.append(f"{gate.upper()}\n", style="bold yellow")
                    gate_content.append("Action:     ", style="bold")
                    gate_content.append(f"{action_name}\n", style="bold white")
    
                    if batch:
                        gate_content.append("Requests:   ", style="bold")
                        gate_content.append(
                            f"{len(batch)} read-only request"
                            f"{'' if len(batch) == 1 else 's'} · one approval\n",
                            style="bold yellow",
                        )
                        for index, (method, path) in enumerate(batch, start=1):
                            gate_content.append(f"  {index}. ", style="dim")
                            gate_content.append(f"{method:<7}", style="bold cyan")
                            gate_content.append(f"{path}\n", style="white")
                    if argv:
                        gate_content.append("Command:    ", style="bold")
                        gate_content.append(
                            f"{' '.join(argv)}\n",
                            style="dim" if batch else "bold cyan",
                        )
                    if rationale:
                        gate_content.append("Rationale:  ", style="bold")
                        gate_content.append(f"{rationale}\n", style="italic")
    
                    console.print(
                        Panel(
                            gate_content,
                            title="[bold yellow]⏸ Human Action Approval Required[/]",
                            border_style="yellow",
                            box=box.ROUNDED,
                        )
                    )
    
                    if auto_approve:
                        console.print("[green]▶ Auto-approving gate...[/green]\n")
                        await runner.resume_run(
                            aid,
                            {"decision": "approved", "actor": "cli-auto", "reason": "auto-approved by -y flag"},
                        )
                    else:
                        ans = Prompt.ask(
                            "[bold yellow]Decision[/] ([green]y[/]es / [red]n[/]o / [blue]s[/]teer instruction)",
                            choices=["y", "n", "s"],
                            default="y",
                        )
                        if ans == "y":
                            console.print("[green]▶ Resuming: Approved[/green]\n")
                            await runner.resume_run(
                                aid,
                                {"decision": "approved", "actor": "operator", "reason": "Approved via CLI"},
                            )
                        elif ans == "n":
                            console.print("[red]⏹ Resuming: Rejected[/red]\n")
                            await runner.resume_run(
                                aid,
                                {"decision": "rejected", "actor": "operator", "reason": "Rejected via CLI"},
                            )
                        elif ans == "s":
                            note = Prompt.ask("[bold blue]Enter steering guidance for the agent[/]")
                            async with get_async_session_ctx() as s_ctx:
                                s_repo = SteeringRepo(s_ctx)
                                # Preserve None: take_pending() matches the real
                                # run id plus NULL, but never a made-up sentinel.
                                await s_repo.add(
                                    assessment_id=aid,
                                    run_id=view.run_id,
                                    text=note,
                                )
                            console.print(f"[blue]Steering note recorded:[/] [italic]{note}[/italic]")
                            # Prompt for approval after steering
                            sub_dec = Prompt.ask("Proceed with this action now? ([green]y[/]/[red]n[/])", choices=["y", "n"], default="y")
                            dec_str = "approved" if sub_dec == "y" else "rejected"
                            await runner.resume_run(
                                aid,
                                {"decision": dec_str, "actor": "operator", "reason": f"Steered: {note}"},
                            )
    
                    # Resume the live indicator after the blocking prompt.
                    if progress and progress_task is not None:
                        progress.start()
                        progress.update(progress_task, description="Resuming the run…")
    
                # Check if run reached terminal state
                if not view.running and not view.paused:
                    if progress and progress_task is not None:
                        progress.update(
                            progress_task,
                            description=f"Run {view.status} · {last_audit_id} events",
                        )
                    console.print(f"\n[bold green]Assessment completed with status:[/] [bold]{view.status.upper()}[/bold]\n")
                    break
                else:
                    timed_out = False
    
                if time.time() - start_time >= timeout:
                    timed_out = True
                    break
    
        finally:
            if progress:
                progress.stop()

        if timed_out:
            console.print(
                f"[bold yellow]Monitor timed out after {timeout}s.[/] "
                "The agent may still be running in the background; "
                "check `aipent status` or the web desk."
            )

        # 4. Display Final Summary Tables
        await _print_assessment_summary(aid)

    asyncio.run(_execute())


# ---------------------------------------------------------------------------
# Command: list
# ---------------------------------------------------------------------------


@app.command(
    "list",
    help="List all security assessments.",
    epilog="[bold cyan]Helpful Example:[/] [green]aipent list[/]",
)
def list_cmd():
    """Display a formatted table of all assessments in the database."""
    async def _execute():
        await init_db()
        async with get_async_session_ctx() as session:
            from sqlmodel import select
            res = await session.execute(select(Assessment).order_by(Assessment.id.desc()))
            assessments = list(res.scalars().all())

            if not assessments:
                console.print("[dim]No assessments recorded yet. Run 'aipent scan <target>' to start one.[/dim]")
                return

            table = Table(
                title="AIPENT Security Assessments",
                box=box.ROUNDED,
                header_style="bold cyan",
            )
            table.add_column("ID", justify="right", style="bold")
            table.add_column("Title", style="white")
            table.add_column("Targets", style="cyan")
            table.add_column("Ports", style="dim")
            table.add_column("Status", style="yellow")
            table.add_column("Risk Score", justify="center")
            table.add_column("Created", style="dim")

            for a in assessments:
                score_str = f"{a.risk_score:.1f}" if a.risk_score is not None else "-"
                status_style = "bold green" if a.status == "completed" else "bold yellow"
                table.add_row(
                    str(a.id),
                    a.title,
                    ", ".join(a.targets or []),
                    ", ".join(str(p) for p in (a.ports or [])),
                    Text(a.status, style=status_style),
                    score_str,
                    a.created_at.strftime("%Y-%m-%d %H:%M") if a.created_at else "-",
                )

            console.print()
            console.print(table)
            console.print()

    asyncio.run(_execute())


# ---------------------------------------------------------------------------
# Command: status
# ---------------------------------------------------------------------------


@app.command(
    "status",
    help="Show full details, findings, and steps for an assessment.",
    epilog="[bold cyan]Helpful Example:[/] [green]aipent status 1[/]",
)
def status_cmd(
    assessment_id: int = typer.Argument(..., help="Assessment database ID (e.g. 1)"),
):
    """Inspect assessment findings, steps, and gate status."""
    async def _execute():
        await init_db()
        await _print_assessment_summary(assessment_id)

    asyncio.run(_execute())


# ---------------------------------------------------------------------------
# Command: report
# ---------------------------------------------------------------------------


@app.command(
    "report",
    help="Compile and generate the Typst PDF report for an assessment.",
    epilog="[bold cyan]Helpful Example:[/] [green]aipent report 1[/]",
)
def report_cmd(
    assessment_id: int = typer.Argument(..., help="Assessment database ID (e.g. 1)"),
):
    """Compile the client-ready PDF report using Typst."""
    async def _execute():
        await init_db()
        async with get_async_session_ctx() as session:
            assessment = await session.get(Assessment, assessment_id)
            if not assessment:
                console.print(f"[bold red]Error:[/] Assessment #{assessment_id} not found.")
                raise typer.Exit(1)

            try:
                with console.status(
                    f"[bold cyan]Compiling PDF report for Assessment #{assessment_id}…",
                    spinner="dots",
                ):
                    pdf_path = await generate_report(session, assessment_id)
                console.print(
                    Panel(
                        Text.assemble(
                            ("Report Generated Successfully!\n", "bold green"),
                            ("File Path: ", "bold"),
                            (str(pdf_path), "underline cyan"),
                            ("\nSHA-256:   ", "bold"),
                            (assessment.report_sha256 or "", "dim"),
                        ),
                        title="[bold green]Report Output[/]",
                        box=box.ROUNDED,
                    )
                )
            except Exception as exc:
                console.print(f"[bold red]Error generating report:[/] {exc}")
                raise typer.Exit(1)

    asyncio.run(_execute())


# ---------------------------------------------------------------------------
# Command: steer
# ---------------------------------------------------------------------------


@app.command(
    "steer",
    help="Provide an operator steering instruction to the agent.",
    epilog="[bold cyan]Helpful Examples:[/] \n  [green]aipent steer 1 \"Focus on port 8080\"[/]\n  [green]aipent steer 1 \"Check /rest/products for SQL injection\"[/]",
)
def steer_cmd(
    assessment_id: int = typer.Argument(..., help="Assessment database ID (e.g. 1)"),
    instruction: str = typer.Argument(..., help="Guidance or directive for the agent (e.g. 'Focus on port 8080')"),
):
    """Inject operator steering into the agent's reasoning loop."""
    async def _execute():
        await init_db()
        async with get_async_session_ctx() as session:
            assessment = await session.get(Assessment, assessment_id)
            if not assessment:
                console.print(f"[bold red]Error:[/] Assessment #{assessment_id} not found.")
                raise typer.Exit(1)

            repo = SteeringRepo(session)
            # An idle note must stay NULL so the next run consumes it. A
            # sentinel like "cli-manual" never matches the agent's run id.
            note = await repo.add(
                assessment_id=assessment_id,
                run_id=None,
                text=instruction,
            )
            console.print(
                Panel(
                    f"Instruction recorded for Assessment #{assessment_id}:\n[italic cyan]{instruction}[/italic cyan]",
                    title="[bold green]Steering Note Saved[/]",
                    box=box.ROUNDED,
                )
            )

    asyncio.run(_execute())


# ---------------------------------------------------------------------------
# Command: help
# ---------------------------------------------------------------------------


@app.command(
    "help",
    help="Show CLI help or detailed documentation for a specific command.",
    epilog="[bold cyan]Helpful Examples:[/] \n  [green]aipent help[/]\n  [green]aipent help scan[/]",
)
def help_cmd(
    ctx: typer.Context,
    command: Optional[str] = typer.Argument(
        None,
        help="Command to inspect (e.g. 'scan', 'list', 'status', 'report', 'steer')",
    ),
):
    """Display CLI help or command-specific documentation."""
    if command and ctx.parent:
        sub = ctx.parent.command.get_command(ctx.parent, command)
        if sub:
            console.print(sub.get_help(ctx))
            return
        else:
            console.print(
                f"[bold red]Unknown command:[/] '{command}'. Available commands: scan, list, status, report, steer"
            )
            raise typer.Exit(1)
    if ctx.parent:
        console.print(ctx.parent.get_help())


# ---------------------------------------------------------------------------
# Helper: Print Assessment Summary Tables
# ---------------------------------------------------------------------------


async def _print_assessment_summary(aid: int) -> None:
    async with get_async_session_ctx() as session:
        assessment = await session.get(Assessment, aid)
        if not assessment:
            console.print(f"[bold red]Error:[/] Assessment #{aid} not found.")
            return

        f_repo = FindingRepo(session)
        findings = await f_repo.get_all(aid, limit=1000)

        s_repo = StepRepo(session)
        steps = await s_repo.get_all(aid)

    # 1. Findings Table
    console.print(Rule(f"Findings for Assessment #{aid} ({len(findings)} detected)"))
    if findings:
        f_table = Table(box=box.ROUNDED, header_style="bold cyan")
        f_table.add_column("ID", justify="right", style="bold")
        f_table.add_column("Severity", justify="center")
        f_table.add_column("Title", style="white")
        f_table.add_column("Endpoint", style="cyan")
        f_table.add_column("Status", justify="center")
        f_table.add_column("CVEs", style="dim")

        for f in findings:
            cve_str = ", ".join(f.cve) if f.cve else "-"
            f_table.add_row(
                str(f.id),
                Text(f.severity.upper(), style=_severity_color(f.severity)),
                f.title,
                f.endpoint or f.asset,
                Text(f.status.upper(), style=_status_color(f.status)),
                cve_str,
            )
        console.print(f_table)
    else:
        console.print("[dim]No findings recorded for this assessment.[/dim]")

    # 2. Steps Table
    console.print(Rule(f"Execution Steps ({len(steps)} actions)"))
    if steps:
        s_table = Table(box=box.ROUNDED, header_style="bold cyan")
        s_table.add_column("#", justify="right")
        s_table.add_column("Action", style="bold white")
        s_table.add_column("Target", style="cyan")
        s_table.add_column("Status", justify="center")
        s_table.add_column("Exit", justify="right")
        s_table.add_column("Command Preview", style="dim")

        for s in steps:
            status_style = "green" if s.status == "succeeded" else ("yellow" if s.status == "running" else "red")
            cmd_preview = _argv_preview(s.argv)
            s_table.add_row(
                str(s.seq),
                s.action,
                s.target or "-",
                Text(s.status, style=status_style),
                str(s.exit_code) if s.exit_code is not None else "-",
                Text(cmd_preview),
            )
        console.print(s_table)
    else:
        console.print("[dim]No steps recorded.[/dim]")

    # 3. Report Info
    if assessment.report_path:
        console.print(
            Panel(
                f"[bold green]Report PDF:[/] [underline]{assessment.report_path}[/underline]\n"
                f"[dim]SHA-256: {assessment.report_sha256}[/dim]",
                title="Client Delivery",
                box=box.ROUNDED,
            )
        )
    console.print()


def main() -> None:
    app()


if __name__ == "__main__":
    main()
