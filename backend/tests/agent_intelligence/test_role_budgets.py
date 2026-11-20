"""Tests for role turn budgets, supervisor caps, and retry enforcement."""

from __future__ import annotations

import pytest

from app.agents.contracts import RouteDecision
from app.agents.mission_brain import (
    ROLE_TURN_CAPS,
    MissionDigest,
    _retry_allowed,
    _role_has_budget,
    validate_route,
)
from app.core.config import settings


def test_role_turn_caps_values():
    assert ROLE_TURN_CAPS["recon"] == 10
    assert ROLE_TURN_CAPS["discovery"] == 20
    assert ROLE_TURN_CAPS["validation"] == 25
    assert ROLE_TURN_CAPS["review"] == 2


def test_role_has_budget():
    state = {"turns": {"recon": 5, "discovery": 20, "validation": 24}}

    assert _role_has_budget("recon", state) is True
    assert _role_has_budget("discovery", state) is False
    assert _role_has_budget("validation", state) is True

    # Unknown role defaults to cap
    assert _role_has_budget("unknown", {"turns": {"unknown": 10}}) is False


def test_validate_route_enforces_budget_cap():
    state = {"role": "recon", "turns": {"discovery": 20}}  # discovery exhausted
    digest = MissionDigest(assessment_id=1, run_id="run-1", services=[{"id": 1}])
    proposed = RouteDecision(
        next_role="discovery",
        why="Attempting discovery beyond budget",
    )
    decision, rejection = validate_route(proposed, state, digest)
    assert rejection == "role_budget_exhausted"
    assert decision.next_role != "discovery"


def test_supervisor_call_cap(monkeypatch):
    monkeypatch.setattr(settings, "supervisor_calls_per_run", 10)
    state = {"role": "recon", "turns": {}, "supervisor_calls": 10}  # reached cap
    digest = MissionDigest(assessment_id=1, run_id="run-1")
    proposed = RouteDecision(
        next_role="discovery",
        why="Proceeding with discovery",
    )
    decision, rejection = validate_route(proposed, state, digest)
    assert rejection == "supervisor_call_cap"
    # When call cap is reached, fallback route kicks in
    assert decision is not None


def test_retry_limits_enforced(monkeypatch):
    monkeypatch.setattr(settings, "max_role_retries", 3)
    state = {
        "role": "discovery",
        "turns": {"discovery": 2},
        "nudges": 3,  # exhausted retries
    }
    digest = MissionDigest(assessment_id=1, run_id="run-1")

    assert _retry_allowed(state, digest) is False

    proposed = RouteDecision(
        next_role="discovery",
        directive="Try again one more time",
        why="Retrying discovery",
    )
    decision, rejection = validate_route(proposed, state, digest)
    assert rejection == "retry_limit_reached"
