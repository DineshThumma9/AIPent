"""AIPENT Terminal CLI Interface.

Fast, rich terminal client for running authorized security assessments,
monitoring agent reasoning in real-time, deciding approval gates, and
viewing findings and PDF reports.
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
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

app = typer.Typer(
    name="aipent",
    help="AIPENT — Autonomous AI Penetration Testing Engine",
    no_args_is_help=True,
    add_completion=False,
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


@app.command("scan", help="Start an authorized security assessment against a target.")
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
        help="Custom assessment title.",
    ),
    request: str = typer.Option(
        "",
        "-r",
        "--request",
        help="Assessment objective or special instructions for the agent.",
    ),
    auto_approve: bool = typer.Option(
        False,
        "-y",
        "--auto-approve",
        help="Auto-approve all human action gates without prompting.",
    ),
    timeout: int = typer.Option(
        900,
        "--timeout",
        help="Maximum run timeout in seconds (default 900).",
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
            )
            aid = assessment.id

        console.print()
        console.print(
            Panel(
                Text.assemble(
                    ("🎯 Target: ", "bold cyan"),
                    (clean_host, "bold white"),
                    (" | Ports: ", "bold cyan"),
                    (str(final_ports), "bold white"),
                    ("\n📋 Title:  ", "bold cyan"),
                    (final_title, "white"),
                    ("\n🆔 Run ID: ", "bold cyan"),
                    (f"Assessment #{aid}", "bold green"),
                    ("\n⚡ Mode:   ", "bold cyan"),
                    ("Auto-Approve Enabled" if auto_approve else "Interactive Human Gates", "yellow" if auto_approve else "green"),
                ),
                title="[bold green]AIPENT Autonomous VAPT[/]",
                box=box.ROUNDED,
                padding=(1, 2),
            )
        )

        # 2. Start Assessment Run
        await runner.start_run(aid)
        console.print("[dim]Starting LangGraph observe-reason-act agent loop...[/]\n")

        # 3. Live Monitoring Loop
        last_audit_id = 0
        seen_hypotheses: set[str] = set()
        seen_findings: set[str] = set()
        start_time = time.time()

        while time.time() - start_time < timeout:
            await asyncio.sleep(0.6)
            view = await runner.get_view(aid)

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
                    console.print(f"   [yellow]⚡ Action queued:[/] [bold]{action}[/] on [bold]{tgt}[/]")

                elif etype == "step.finished":
                    action = payload.get("action")
                    code = payload.get("exit_code")
                    dur = payload.get("duration_ms")
                    dur_str = f" in {dur}ms" if dur else ""
                    console.print(f"   [green]✔ Action finished:[/] [bold]{action}[/] (exit: {code}{dur_str})")

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
                pending = view.pending
                gate = pending.get("gate") or pending.get("role") or "action"
                action_name = pending.get("action") or pending.get("role") or "Review Delivery"
                argv = pending.get("argv") or []
                rationale = pending.get("rationale") or pending.get("message") or ""

                console.print()
                gate_content = Text()
                gate_content.append("Gate Type:  ", style="bold")
                gate_content.append(f"{gate.upper()}\n", style="bold yellow")
                gate_content.append("Action:     ", style="bold")
                gate_content.append(f"{action_name}\n", style="bold white")

                if argv:
                    gate_content.append("Command:    ", style="bold")
                    gate_content.append(f"{' '.join(argv)}\n", style="bold cyan")
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
                            await s_repo.add(assessment_id=aid, run_id=view.run_id or "run", text=note)
                        console.print(f"[blue]Steering note recorded:[/] [italic]{note}[/italic]")
                        # Prompt for approval after steering
                        sub_dec = Prompt.ask("Proceed with this action now? ([green]y[/]/[red]n[/])", choices=["y", "n"], default="y")
                        dec_str = "approved" if sub_dec == "y" else "rejected"
                        await runner.resume_run(
                            aid,
                            {"decision": dec_str, "actor": "operator", "reason": f"Steered: {note}"},
                        )

            # Check if run reached terminal state
            if not view.running and not view.paused:
                console.print(f"\n[bold green]Assessment completed with status:[/] [bold]{view.status.upper()}[/bold]\n")
                break

        # 4. Display Final Summary Tables
        await _print_assessment_summary(aid)

    asyncio.run(_execute())


# ---------------------------------------------------------------------------
# Command: list
# ---------------------------------------------------------------------------


@app.command("list", help="List all security assessments.")
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


@app.command("status", help="Show full details, findings, and steps for an assessment.")
def status_cmd(
    assessment_id: int = typer.Argument(..., help="Assessment database ID"),
):
    """Inspect assessment findings, steps, and gate status."""
    async def _execute():
        await init_db()
        await _print_assessment_summary(assessment_id)

    asyncio.run(_execute())


# ---------------------------------------------------------------------------
# Command: report
# ---------------------------------------------------------------------------


@app.command("report", help="Compile and generate the Typst PDF report for an assessment.")
def report_cmd(
    assessment_id: int = typer.Argument(..., help="Assessment database ID"),
):
    """Compile the client-ready PDF report using Typst."""
    async def _execute():
        await init_db()
        async with get_async_session_ctx() as session:
            assessment = await session.get(Assessment, assessment_id)
            if not assessment:
                console.print(f"[bold red]Error:[/] Assessment #{assessment_id} not found.")
                raise typer.Exit(1)

            console.print(f"[dim]Compiling PDF report for Assessment #{assessment_id}...[/dim]")
            try:
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


@app.command("steer", help="Provide an operator steering instruction to the agent.")
def steer_cmd(
    assessment_id: int = typer.Argument(..., help="Assessment database ID"),
    instruction: str = typer.Argument(..., help="Guidance or directive for the agent"),
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
            note = await repo.add(assessment_id=assessment_id, run_id="cli-manual", text=instruction)
            console.print(
                Panel(
                    f"Instruction recorded for Assessment #{assessment_id}:\n[italic cyan]{instruction}[/italic cyan]",
                    title="[bold green]Steering Note Saved[/]",
                    box=box.ROUNDED,
                )
            )

    asyncio.run(_execute())


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
            cmd_preview = " ".join(s.argv)[:60] if s.argv else "-"
            s_table.add_row(
                str(s.seq),
                s.action,
                s.target or "-",
                Text(s.status, style=status_style),
                str(s.exit_code) if s.exit_code is not None else "-",
                cmd_preview,
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


if __name__ == "__main__":
    app()
