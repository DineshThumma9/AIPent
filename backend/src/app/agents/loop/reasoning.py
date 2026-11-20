"""Evidence board reasoning and hypothesis management.

Folds append-only audit events into an EvidenceBoard with hypotheses, decisions,
and open questions.
"""

from __future__ import annotations

from typing import Any
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.loop.contracts import (
    DecisionRecord,
    EvidenceBoard,
    Hypothesis,
    Observation,
)
from app.domain.models import Audit, utcnow


def fold_events_into_evidence_board(events: list[Audit]) -> EvidenceBoard:
    """Pure domain function folding a sequence of Audit events into an EvidenceBoard."""
    hypotheses: dict[str, Hypothesis] = {}
    decision_map: dict[str, DecisionRecord] = {}
    decision_order: list[str] = []
    anon_decisions: list[DecisionRecord] = []
    open_questions: list[str] = []

    for event in events:
        payload = event.payload or {}
        if event.event_type == "hypothesis.created":
            try:
                data = dict(payload)
                if not data.get("id"):
                    data["id"] = data.get("hypothesis_id", "H-0")
                if isinstance(data.get("updated_at"), str):
                    data["updated_at"] = datetime.fromisoformat(data["updated_at"])
                elif not data.get("updated_at"):
                    data["updated_at"] = event.ts or utcnow()
                if "created_by" not in data:
                    data["created_by"] = data.get("role", "agent")
                h_id = data.get("hypothesis_id") or data["id"]
                hypotheses[h_id] = Hypothesis(**data)
            except Exception:
                pass
        elif event.event_type == "hypothesis.updated":
            h_id = payload.get("hypothesis_id")
            if h_id and h_id in hypotheses:
                current = hypotheses[h_id]
                updated_fields: dict[str, Any] = {}
                for k in ("status", "confidence", "evidence_ids", "falsifier"):
                    if k in payload:
                        updated_fields[k] = payload[k]
                updated_fields["updated_at"] = event.ts or utcnow()
                hypotheses[h_id] = current.model_copy(update=updated_fields)
        elif event.event_type == "decision.recorded":
            try:
                data = dict(payload)
                if isinstance(data.get("created_at"), str):
                    data["created_at"] = datetime.fromisoformat(data["created_at"])
                elif not data.get("created_at"):
                    data["created_at"] = event.ts or utcnow()
                d_id = data.get("id")
                if d_id and d_id in decision_map:
                    decision_map[d_id] = decision_map[d_id].model_copy(update=data)
                elif d_id:
                    decision_map[d_id] = DecisionRecord(**data)
                    decision_order.append(d_id)
                else:
                    anon_decisions.append(DecisionRecord(**data))
            except Exception:
                pass
        elif event.event_type == "handoff.created":
            open_questions.extend(payload.get("open_questions") or [])

    seen: set[str] = set()
    deduped_questions: list[str] = []
    for q in open_questions:
        if q and q not in seen:
            seen.add(q)
            deduped_questions.append(q)

    final_decisions = [decision_map[d_id] for d_id in decision_order] + anon_decisions

    return EvidenceBoard(
        hypotheses=list(hypotheses.values()),
        decisions=final_decisions,
        open_questions=deduped_questions,
    )


async def build_evidence_board(session: AsyncSession, assessment_id: int) -> EvidenceBoard:
    """Fold audit events into an EvidenceBoard via AuditRepo."""
    from app.persistence.audit_repo import AuditRepo

    return await AuditRepo(session).get_evidence_board(assessment_id)


async def next_hypothesis_id(session: AsyncSession, assessment_id: int) -> str:
    """Generate the next sequential hypothesis id like H-1, H-2 via AuditRepo."""
    from app.persistence.audit_repo import AuditRepo

    return await AuditRepo(session).next_hypothesis_id(assessment_id)


async def record_hypothesis(
    session: AsyncSession,
    assessment_id: int,
    run_id: str,
    role: str,
    statement: str,
    asset: str,
    endpoint: str | None = None,
    falsifier: str = "",
    evidence_ids: list[int] | None = None,
) -> Observation:
    """Record a hypothesis creation audit event and return an Observation."""
    from app.persistence.audit_repo import AuditRepo

    h_id, _ = await AuditRepo(session).record_hypothesis(
        assessment_id=assessment_id,
        run_id=run_id,
        role=role,
        statement=statement,
        asset=asset,
        endpoint=endpoint,
        falsifier=falsifier,
        evidence_ids=evidence_ids,
    )
    await session.commit()

    return Observation(
        ok=True,
        status="succeeded",
        action="record_hypothesis",
        target=asset,
        summary=f"Recorded {h_id}: {statement}",
        next_hint="Test the falsifier before increasing confidence.",
    )


async def update_hypothesis(
    session: AsyncSession,
    assessment_id: int,
    run_id: str,
    role: str,
    hypothesis_id: str,
    status: str,
    confidence: float,
    evidence_ids: list[int] | None = None,
    note: str | None = None,
) -> Observation:
    """Record a hypothesis update audit event and return an Observation."""
    from app.persistence.audit_repo import AuditRepo

    await AuditRepo(session).update_hypothesis(
        assessment_id=assessment_id,
        run_id=run_id,
        role=role,
        hypothesis_id=hypothesis_id,
        status=status,
        confidence=confidence,
        evidence_ids=evidence_ids,
        note=note,
    )
    await session.commit()

    return Observation(
        ok=True,
        status="succeeded",
        action="update_hypothesis",
        target=hypothesis_id,
        summary=f"Updated {hypothesis_id} to status={status}, confidence={confidence:.2f}",
    )
