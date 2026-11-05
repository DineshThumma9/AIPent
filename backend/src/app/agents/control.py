"""Run-scoped control state chosen by the agent.

The LLM decides which phase it is in and when the assessment is finished.
Python only records those decisions in the append-only audit trail and reads
them back. Keeping control state in the database (rather than in a checkpoint
only) means a restart cannot silently move the agent back to recon.

Every event is scoped by ``run_id`` so a previous run cannot leak its finish or
phase into a new one.
"""

from __future__ import annotations

from sqlmodel import Session, select

from app.domain.models import Audit

PHASES = ("recon", "discovery", "validation")

# The phase label is the agent identity used by the skill allowlists.
PHASE_AGENT = {
    "recon": "recon_agent",
    "discovery": "discovery_agent",
    "validation": "validation_agent",
}


def audit(
    session: Session,
    assessment_id: int,
    event_type: str,
    payload: dict,
    actor: str = "agent",
) -> None:
    session.add(
        Audit(
            assessment_id=assessment_id,
            actor=actor,
            event_type=event_type,
            payload=payload,
        )
    )


def _events(session: Session, assessment_id: int, event_type: str) -> list[Audit]:
    return session.exec(
        select(Audit)
        .where(
            Audit.assessment_id == assessment_id,
            Audit.event_type == event_type,
        )
        .order_by(Audit.id)
    ).all()


def _for_run(events: list[Audit], run_id: str) -> list[dict]:
    return [
        event.payload or {}
        for event in events
        if (event.payload or {}).get("run_id") == run_id
    ]


def current_phase(session: Session, assessment_id: int, run_id: str) -> str:
    """The last phase the agent entered during this run."""
    for payload in reversed(_for_run(_events(session, assessment_id, "phase.advanced"), run_id)):
        phase = str(payload.get("to") or "")
        if phase in PHASES:
            return phase
    return "recon"


def phase_history(session: Session, assessment_id: int, run_id: str) -> list[dict]:
    return _for_run(_events(session, assessment_id, "phase.advanced"), run_id)


def record_phase(
    session: Session,
    assessment_id: int,
    run_id: str,
    to_phase: str,
    reason: str,
    from_phase: str | None = None,
) -> dict:
    if to_phase not in PHASES:
        raise ValueError(f"unknown phase {to_phase!r}; expected one of {PHASES}")
    previous = from_phase or current_phase(session, assessment_id, run_id)
    payload = {
        "run_id": run_id,
        "from": previous,
        "to": to_phase,
        "reason": reason,
    }
    audit(session, assessment_id, "phase.advanced", payload)
    return payload


def record_finish(
    session: Session, assessment_id: int, run_id: str, reason: str
) -> dict:
    payload = {"run_id": run_id, "reason": reason}
    audit(session, assessment_id, "run.finished", payload)
    return payload


def run_finished(session: Session, assessment_id: int, run_id: str) -> bool:
    return bool(_for_run(_events(session, assessment_id, "run.finished"), run_id))


def run_event_count(
    session: Session, assessment_id: int, run_id: str, event_type: str
) -> int:
    return len(_for_run(_events(session, assessment_id, event_type), run_id))
