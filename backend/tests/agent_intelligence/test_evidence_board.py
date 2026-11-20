"""Tests for folding audit events into the EvidenceBoard domain model."""

from __future__ import annotations

from datetime import datetime
import pytest

from app.domain.models import Audit, utcnow
from app.domain.reasoning import fold_events_into_evidence_board


def test_fold_events_hypotheses_lifecycle():
    ts1 = utcnow()
    event_create = Audit(
        assessment_id=1,
        event_type="hypothesis.created",
        payload={
            "id": "H-1",
            "statement": "Admin panel exposes unauthenticated debug endpoints",
            "asset": "127.0.0.1",
            "endpoint": "http://127.0.0.1/debug",
            "status": "open",
            "confidence": 0.5,
            "falsifier": "Returns 401 or 403 on all probes",
            "created_by": "recon",
            "updated_at": ts1.isoformat(),
        },
        ts=ts1,
    )

    event_update = Audit(
        assessment_id=1,
        event_type="hypothesis.updated",
        payload={
            "hypothesis_id": "H-1",
            "status": "confirmed",
            "confidence": 0.95,
            "evidence_ids": [42, 43],
        },
        ts=utcnow(),
    )

    board = fold_events_into_evidence_board([event_create, event_update])
    assert len(board.hypotheses) == 1
    h = board.hypotheses[0]
    assert h.id == "H-1"
    assert h.statement == "Admin panel exposes unauthenticated debug endpoints"
    assert h.status == "confirmed"
    assert h.confidence == 0.95
    assert h.evidence_ids == [42, 43]
    assert h.falsifier == "Returns 401 or 403 on all probes"


def test_fold_events_decisions_and_open_questions():
    event_dec1 = Audit(
        assessment_id=1,
        event_type="decision.recorded",
        payload={
            "id": "D-1",
            "role": "recon",
            "action": "nmap_scan",
            "target": "127.0.0.1",
            "observation": "Discovered open port 8080",
            "outcome": "succeeded",
            "confidence": 0.9,
        },
    )

    event_dec2 = Audit(
        assessment_id=1,
        event_type="decision.recorded",
        payload={
            "id": "D-2",
            "role": "discovery",
            "action": "nikto_scan",
            "target": "127.0.0.1",
            "observation": "Identified exposed git directory",
            "outcome": "succeeded",
            "confidence": 0.85,
        },
    )

    event_handoff1 = Audit(
        assessment_id=1,
        event_type="handoff.created",
        payload={
            "open_questions": [
                "Does /debug require basic auth?",
                "Is CORS configured permissively?",
            ],
        },
    )

    event_handoff2 = Audit(
        assessment_id=1,
        event_type="handoff.created",
        payload={
            "role": "discovery",
            "summary": "Discovered exposed git directory",
            "recommended_actions": ["Download .git/config"],
            "open_questions": [
                "Does /debug require basic auth?",  # Duplicate question
                "Can credentials be harvested from .git/config?",
            ],
        },
    )

    board = fold_events_into_evidence_board([event_dec1, event_dec2, event_handoff1, event_handoff2])
    assert len(board.decisions) == 2
    assert [d.id for d in board.decisions] == ["D-1", "D-2"]
    assert board.decisions[0].action == "nmap_scan"
    assert board.decisions[1].action == "nikto_scan"

    # Open questions deduplicated preserving order
    assert len(board.open_questions) == 3
    assert board.open_questions == [
        "Does /debug require basic auth?",
        "Is CORS configured permissively?",
        "Can credentials be harvested from .git/config?",
    ]
    assert board.last_handoff is not None
    assert board.last_handoff["role"] == "discovery"
    assert board.last_handoff["summary"] == "Discovered exposed git directory"
    assert board.last_handoff["recommended_actions"] == ["Download .git/config"]


def test_render_brief_includes_prior_handoff():
    from app.agents.brief import render_brief
    from app.domain.models import Assessment
    from app.agents.contracts import EvidenceBoard

    board = EvidenceBoard(
        last_handoff={
            "role": "discovery",
            "summary": "Juice Shop running on port 3000. Found /ftp endpoint with directory listing.",
            "recommended_actions": ["curl_request GET /ftp/acquisitions.md"],
        }
    )
    assessment = Assessment(id=1, targets=["127.0.0.1"], ports=[3000])
    brief = render_brief(
        assessment=assessment,
        role="validation",
        board=board,
        services=[],
        candidates=[],
    )
    assert "PRIOR SPECIALIST HANDOFF (from discovery)" in brief
    assert "Juice Shop running on port 3000" in brief
    assert "curl_request GET /ftp/acquisitions.md" in brief
