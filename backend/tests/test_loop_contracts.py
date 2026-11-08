"""Unit tests for V2 loop contracts (contracts.py)."""

import pytest
from pydantic import ValidationError

from app.agents.loop.contracts import (
    ActionRequest,
    FailureSignal,
    Handoff,
    Observation,
    RouteDecision,
)


def test_handoff_rejects_unknown_role():
    with pytest.raises(ValidationError):
        Handoff(
            summary="Done",
            next_role="exploit",  # type: ignore[arg-type]
            why="test",
            confidence=0.8,
            stop_reason="surface_mapped",
        )


def test_handoff_rejects_invalid_confidence():
    with pytest.raises(ValidationError):
        Handoff(
            summary="Done",
            next_role="recon",
            why="test",
            confidence=1.5,
            stop_reason="surface_mapped",
        )
    with pytest.raises(ValidationError):
        Handoff(
            summary="Done",
            next_role="recon",
            why="test",
            confidence=-0.1,
            stop_reason="surface_mapped",
        )


def test_observation_json_roundtrip():
    obs = Observation(
        ok=True,
        status="succeeded",
        action="recon_services",
        target="127.0.0.1",
        step_id=42,
        summary="Found 2 open ports",
        findings_created=[1, 2],
        evidence_ids=[10, 11],
        artifact={"path": "/data/42.xml", "sha256": "abc123def"},
    )
    raw = obs.model_dump_json()
    loaded = Observation.model_validate_json(raw)
    assert loaded.ok is True
    assert loaded.status == "succeeded"
    assert loaded.step_id == 42
    assert loaded.findings_created == [1, 2]
    assert loaded.artifact == {"path": "/data/42.xml", "sha256": "abc123def"}


def test_action_request_preserves_fields():
    req = ActionRequest(
        tool_call_id="call_123",
        tool_name="recon_services",
        action="recon_services",
        target="127.0.0.1",
        rationale="Initial port scan",
        step_id=10,
        approval_id=5,
        argv=["nmap", "-sV", "-Pn", "127.0.0.1"],
        risk="low",
        requires_approval=False,
        policy_reason="Auto-approved low risk",
        hypothesis_id="H-1",
        evidence_ids=[1, 2],
        expected_observation="Port 80 open",
        would_falsify="All ports closed",
    )
    assert req.argv == ["nmap", "-sV", "-Pn", "127.0.0.1"]
    assert req.requires_approval is False
    assert req.hypothesis_id == "H-1"


def test_route_decision_bounds():
    dec = RouteDecision(
        next_role="recon",
        why="Initial scan needed",
        priority="high",
        confidence=0.9,
    )
    assert dec.next_role == "recon"
    assert dec.overrides_specialist is False

    with pytest.raises(ValidationError):
        RouteDecision(
            next_role="invalid_role",  # type: ignore[arg-type]
            why="test",
            confidence=0.5,
        )


def test_failure_signal_validates_kind():
    sig = FailureSignal(
        role="recon",
        kind="budget_exhausted",
        summary="Recon turn budget reached",
        attempts=8,
    )
    assert sig.kind == "budget_exhausted"
    assert sig.role == "recon"

    with pytest.raises(ValidationError):
        FailureSignal(
            role="recon",
            kind="non_existent_kind",  # type: ignore[arg-type]
            summary="test",
        )
