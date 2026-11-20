from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import col, select

from app.domain.models import Audit, utcnow
from app.persistence.base import BaseRepo

if TYPE_CHECKING:
    from app.agents.loop.contracts import EvidenceBoard

ROLES = ("recon", "discovery", "validation")


class AuditRepo(BaseRepo):
    """All database access for audit events."""

    async def add(
        self,
        assessment_id: int,
        event_type: str,
        payload: dict[str, Any],
        actor: str = "system",
    ) -> Audit:
        audit = Audit(
            assessment_id=assessment_id,
            actor=actor,
            event_type=event_type,
            payload=payload,
        )
        self.session.add(audit)
        await self.session.flush()
        return audit

    async def record_event(
        self,
        assessment_id: int,
        event_type: str,
        payload: dict[str, Any],
        actor: str = "system",
    ) -> Audit:
        """Record an arbitrary audit event."""
        return await self.add(
            assessment_id=assessment_id,
            event_type=event_type,
            payload=payload,
            actor=actor,
        )

    async def record_decision(
        self,
        assessment_id: int,
        run_id: str,
        role: str,
        step_id: int,
        action: str,
        target: str,
        observation: str,
        outcome: str,
        confidence: float = 0.8,
        hypothesis_id: str | None = None,
        evidence_ids: list[int] | None = None,
        expected_observation: str | None = None,
        would_falsify: str | None = None,
        actor: str = "agent",
    ) -> Audit:
        """Record a structured decision.recorded audit event."""
        payload: dict[str, Any] = {
            "id": f"D-{step_id}",
            "run_id": run_id,
            "role": role,
            "action": action,
            "target": target,
            "observation": observation,
            "outcome": outcome,
            "confidence": confidence,
            "hypothesis_id": hypothesis_id,
            "evidence_ids": evidence_ids or [],
            "expected_observation": expected_observation,
            "would_falsify": would_falsify,
        }
        return await self.add(
            assessment_id=assessment_id,
            event_type="decision.recorded",
            payload=payload,
            actor=actor,
        )

    async def get_all_for_assessment(
        self,
        assessment_id: int,
        limit: int = 100,
    ) -> list[Audit]:
        result = await self.session.execute(
            select(Audit)
            .where(Audit.assessment_id == assessment_id)
            .order_by(col(Audit.id).desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def get_for_run(
        self,
        assessment_id: int,
        run_id: str,
    ) -> list[Audit]:
        """Return audit events for a specific run."""
        result = await self.session.execute(
            select(Audit).where(Audit.assessment_id == assessment_id)
        )
        events = list(result.scalars().all())
        return [
            e
            for e in events
            if (e.payload or {}).get("run_id") == run_id
        ]

    async def count_action_queued_for_run(
        self,
        assessment_id: int,
        run_id: str,
    ) -> int:
        result = await self.session.execute(
            select(Audit).where(
                Audit.assessment_id == assessment_id,
                Audit.event_type == "action.queued",
            )
        )
        events = result.scalars().all()
        return sum(
            1 for event in events if (event.payload or {}).get("run_id") == run_id
        )

    async def get_events(
        self,
        assessment_id: int,
        event_types: str | list[str] | tuple[str, ...] | set[str] | None = None,
    ) -> list[Audit]:
        """Fetch audit events for an assessment ordered by id ascending."""
        stmt = select(Audit).where(Audit.assessment_id == assessment_id)
        if isinstance(event_types, str):
            stmt = stmt.where(Audit.event_type == event_types)
        elif isinstance(event_types, (list, tuple, set)):
            stmt = stmt.where(Audit.event_type.in_(list(event_types)))
        stmt = stmt.order_by(Audit.id)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def current_role(self, assessment_id: int, run_id: str) -> str:
        """The last role entered during this run."""
        events = await self.get_events(assessment_id, "role.started")
        for event in reversed(events):
            payload = event.payload or {}
            if payload.get("run_id") == run_id:
                role = str(payload.get("role") or "")
                if role in ROLES:
                    return role
        return "recon"

    async def role_history(
        self,
        assessment_id: int,
        run_id: str,
    ) -> list[dict[str, Any]]:
        """Return role.started payloads for a run."""
        events = await self.get_events(assessment_id, "role.started")
        return [
            event.payload or {}
            for event in events
            if (event.payload or {}).get("run_id") == run_id
        ]

    async def record_role(
        self,
        assessment_id: int,
        run_id: str,
        role: str,
        reason: str,
        from_role: str | None = None,
    ) -> dict[str, Any]:
        """Record transition into a role."""
        if role not in ROLES:
            raise ValueError(f"unknown role {role!r}; expected one of {ROLES}")
        payload = {
            "run_id": run_id,
            "from": from_role,
            "to": role,
            "role": role,
            "reason": reason,
        }
        await self.record_event(
            assessment_id=assessment_id,
            event_type="role.started",
            payload=payload,
            actor="agent",
        )
        return payload

    async def role_event_count(
        self,
        assessment_id: int,
        run_id: str,
        role: str,
        event_type: str,
    ) -> int:
        """Count events of event_type for a specific role and run."""
        events = await self.get_events(assessment_id, event_type)
        return sum(
            1
            for event in events
            if (event.payload or {}).get("run_id") == run_id
            and (event.payload or {}).get("role") == role
        )

    async def record_turn(
        self,
        assessment_id: int,
        run_id: str,
        role: str,
        reason: str = "role turn",
        from_role: str | None = None,
    ) -> int:
        """Record one specialist model invocation and return its turn number."""
        if role not in ROLES:
            raise ValueError(f"unknown role {role!r}; expected one of {ROLES}")
        turn = (
            await self.role_event_count(assessment_id, run_id, role, "role.turn")
            + 1
        )
        await self.record_event(
            assessment_id=assessment_id,
            event_type="role.turn",
            payload={
                "run_id": run_id,
                "role": role,
                "reason": reason,
                "from": from_role,
                "turn": turn,
            },
            actor="agent",
        )
        return turn

    async def record_handoff(
        self,
        assessment_id: int,
        run_id: str,
        role: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Record a handoff created by a role."""
        if role not in ROLES:
            raise ValueError(f"unknown role {role!r}; expected one of {ROLES}")
        body = {
            "run_id": run_id,
            "role": role,
            "summary": str(payload.get("summary") or "")[:1000],
            "decisions": payload.get("decisions") or [],
            "finding_ids": payload.get("finding_ids") or [],
            "step_ids": payload.get("step_ids") or [],
            "next_recommendation": payload.get("next_recommendation") or "review",
            "needs_input": bool(payload.get("needs_input")),
            "question": payload.get("question") or None,
            "open_questions": payload.get("open_questions") or [],
        }
        await self.record_event(
            assessment_id=assessment_id,
            event_type="handoff.created",
            payload=body,
            actor="agent",
        )
        return body

    async def handoff_history(
        self,
        assessment_id: int,
        run_id: str,
        role: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return handoffs for a run, optionally filtered by role."""
        events = await self.get_events(assessment_id, "handoff.created")
        rows = [
            event.payload or {}
            for event in events
            if (event.payload or {}).get("run_id") == run_id
        ]
        if role is not None:
            rows = [row for row in rows if row.get("role") == role]
        return rows

    async def latest_handoff(
        self,
        assessment_id: int,
        run_id: str,
        role: str | None = None,
    ) -> dict[str, Any] | None:
        """Return the most recent handoff for a run."""
        rows = await self.handoff_history(assessment_id, run_id, role)
        return rows[-1] if rows else None

    async def next_hypothesis_id(self, assessment_id: int) -> str:
        """Generate the next sequential hypothesis id like H-1, H-2."""
        events = await self.get_events(assessment_id, "hypothesis.created")
        return f"H-{len(events) + 1}"

    async def record_hypothesis(
        self,
        assessment_id: int,
        run_id: str,
        role: str,
        statement: str,
        asset: str,
        endpoint: str | None = None,
        falsifier: str = "",
        evidence_ids: list[int] | None = None,
    ) -> tuple[str, dict[str, Any]]:
        """Record hypothesis.created audit event and return (hypothesis_id, payload)."""
        h_id = await self.next_hypothesis_id(assessment_id)
        now = utcnow()
        payload = {
            "run_id": run_id,
            "hypothesis_id": h_id,
            "role": role,
            "statement": statement,
            "asset": asset,
            "endpoint": endpoint,
            "falsifier": falsifier,
            "evidence_ids": evidence_ids or [],
            "confidence": 0.5,
            "status": "open",
            "created_by": role,
            "updated_at": now.isoformat(),
        }
        await self.record_event(
            assessment_id=assessment_id,
            event_type="hypothesis.created",
            payload=payload,
            actor="agent",
        )
        return h_id, payload

    async def update_hypothesis(
        self,
        assessment_id: int,
        run_id: str,
        role: str,
        hypothesis_id: str,
        status: str,
        confidence: float,
        evidence_ids: list[int] | None = None,
        note: str | None = None,
    ) -> dict[str, Any]:
        """Record hypothesis.updated audit event and return payload."""
        now = utcnow()
        payload = {
            "run_id": run_id,
            "hypothesis_id": hypothesis_id,
            "role": role,
            "status": status,
            "confidence": confidence,
            "evidence_ids": evidence_ids or [],
            "note": note,
            "updated_at": now.isoformat(),
        }
        await self.record_event(
            assessment_id=assessment_id,
            event_type="hypothesis.updated",
            payload=payload,
            actor="agent",
        )
        return payload

    async def get_evidence_board(self, assessment_id: int) -> EvidenceBoard:
        """Fetch audit events and fold into an EvidenceBoard domain model."""
        from app.agents.loop.reasoning import fold_events_into_evidence_board

        events = await self.get_events(
            assessment_id,
            [
                "hypothesis.created",
                "hypothesis.updated",
                "decision.recorded",
                "handoff.created",
            ],
        )
        return fold_events_into_evidence_board(events)

