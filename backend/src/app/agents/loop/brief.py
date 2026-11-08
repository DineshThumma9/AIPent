"""Deterministic brief rendering for specialists in the V2 loop.

Produces the initial prompt context for a specialist turn from current DB state.
"""

from __future__ import annotations

from typing import Any
from app.agents.loop.contracts import EvidenceBoard
from app.domain.models import Assessment, Finding


def render_brief(
    assessment: Assessment,
    role: str,
    board: EvidenceBoard,
    services: list[Finding],
    candidates: list[Finding],
    steering: list[Any] | None = None,
    supervisor_directive: str | None = None,
) -> str:
    """Build the brief prompt for a specialist role."""
    targets_str = ", ".join(assessment.targets or ["127.0.0.1"])
    ports_str = ", ".join(str(p) for p in (assessment.ports or [])) or "all/default"
    exclusions_str = ", ".join(assessment.exclusions or []) or "none"
    request_str = getattr(assessment, "request", "") or "Discover and validate vulnerabilities within scope."

    sections = [
        "ASSESSMENT",
        f"id={assessment.id} · target={targets_str} · ports={ports_str} · exclusions={exclusions_str}",
        f"request: {request_str!r}",
    ]

    # Evidence board hypotheses
    if board.hypotheses:
        lines = ["\nEVIDENCE BOARD"]
        for h in board.hypotheses[:8]:
            line = f"{h.id} {h.status} confidence={h.confidence:.2f} {h.statement!r}"
            if h.falsifier or h.evidence_ids:
                meta = []
                if h.evidence_ids:
                    meta.append(f"evidence={h.evidence_ids}")
                if h.falsifier:
                    meta.append(f"falsifier={h.falsifier!r}")
                line += f"\n  {' '.join(meta)}"
            lines.append(line)
        sections.append("\n".join(lines))

    # Services
    if services:
        lines = ["\nDISCOVERED SERVICES"]
        for s in services[:10]:
            lines.append(f"- {s.endpoint or s.asset}: {s.title}")
        sections.append("\n".join(lines))

    # Candidate findings
    if candidates:
        lines = ["\nCANDIDATE FINDINGS"]
        for c in candidates[:10]:
            lines.append(f"id={c.id} {c.status} {c.severity} {c.title!r} asset={c.asset} endpoint={c.endpoint}")
        sections.append("\n".join(lines))

    # Open questions from evidence board
    if board.open_questions:
        lines = ["\nOPEN QUESTIONS"]
        for q in board.open_questions[:5]:
            lines.append(f"- {q}")
        sections.append("\n".join(lines))

    # Recent decisions from evidence board
    if board.decisions:
        lines = ["\nRECENT DECISIONS"]
        for d in board.decisions[-4:]:
            lines.append(f"- {d.id} [{d.role}] {d.action} on {d.target}: outcome={d.outcome or 'prepared'}")
        sections.append("\n".join(lines))

    # Supervisor directive
    if supervisor_directive:
        sections.append(f"\nSUPERVISOR DIRECTIVE\n{supervisor_directive}")

    # Operator steering
    if steering:
        notes = [getattr(n, "text", str(n)) for n in steering]
        sections.append("\nOPERATOR STEERING\n" + "\n".join(f"- {n}" for n in notes))

    # Task description by role
    task_map = {
        "recon": (
            "Establish the target surface by discovering open ports and service versions. "
            "Form hypotheses about technologies in play and hand off when the primary service surface is mapped."
        ),
        "discovery": (
            "Explore mapped services for vulnerabilities, misconfigurations, or sensitive endpoints. "
            "Create candidate findings and record falsifiers for validation."
        ),
        "validation": (
            "Test hypotheses with discriminating, non-destructive probes. "
            "Corroborate findings with evidence and record verdicts."
        ),
    }
    role_task = task_map.get(role, "Perform your specialist role and hand off when your objective is achieved.")
    sections.append(f"\nYOUR TASK\n{role_task}")

    return "\n".join(sections)
