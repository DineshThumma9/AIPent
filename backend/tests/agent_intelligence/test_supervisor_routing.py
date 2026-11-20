"""Tests for supervisor route validation, role transitions, and safety constraints."""

from __future__ import annotations

import pytest

from app.agents.contracts import RouteDecision
from app.agents.mission_brain import (
    MissionDigest,
    deterministic_safe_route,
    validate_route,
)


def test_validate_route_unknown_role():
    state = {"role": "recon", "turns": {}}
    digest = MissionDigest(assessment_id=1, run_id="run-1")
    proposed = RouteDecision.model_construct(
        next_role="non_existent_role",
        why="Invalid role test",
    )
    decision, rejection = validate_route(proposed, state, digest)
    assert rejection == "unknown_role"
    assert decision.next_role in {"recon", "discovery", "validation", "review"}


def test_validate_route_override_without_reason():
    state = {"role": "recon", "turns": {}}
    digest = MissionDigest(assessment_id=1, run_id="run-1")
    proposed = RouteDecision(
        next_role="discovery",
        overrides_specialist=True,
        override_reason="",  # Missing required reason
        why="Overriding specialist",
    )
    decision, rejection = validate_route(proposed, state, digest)
    assert rejection == "missing_override_reason"


def test_validate_route_override_with_reason_accepted():
    state = {"role": "recon", "turns": {}}
    digest = MissionDigest(assessment_id=1, run_id="run-1")
    proposed = RouteDecision(
        next_role="discovery",
        overrides_specialist=True,
        override_reason="Open HTTP port found requiring immediate crawling",
        why="Overriding specialist based on service findings",
    )
    decision, rejection = validate_route(proposed, state, digest)
    assert rejection is None
    assert decision.next_role == "discovery"
    assert decision.overrides_specialist is True


def test_validate_route_validation_without_candidates():
    state = {"role": "discovery", "turns": {"discovery": 1}}
    digest = MissionDigest(assessment_id=1, run_id="run-1", candidates=[])  # Empty candidates
    proposed = RouteDecision(
        next_role="validation",
        why="Proceed to validate",
    )
    decision, rejection = validate_route(proposed, state, digest)
    assert rejection == "validation_without_candidates"
    # Fallback routes safely (e.g. discovery or review)
    assert decision.next_role != "validation"


def test_validate_route_same_role_without_directive():
    state = {"role": "discovery", "turns": {"discovery": 1}}
    digest = MissionDigest(assessment_id=1, run_id="run-1")
    proposed = RouteDecision(
        next_role="discovery",
        why="Run discovery again",
        directive="",  # Missing directive
    )
    decision, rejection = validate_route(proposed, state, digest)
    assert rejection == "same_role_without_directive"


def test_validate_route_same_role_with_directive_accepted():
    state = {"role": "discovery", "turns": {"discovery": 1}, "nudges": 0}
    digest = MissionDigest(assessment_id=1, run_id="run-1")
    proposed = RouteDecision(
        next_role="discovery",
        why="Retry discovery with custom wordlist",
        directive="Run dirb_scan targeting /api/v2 endpoints exclusively",
    )
    decision, rejection = validate_route(proposed, state, digest)
    assert rejection is None
    assert decision.next_role == "discovery"
    assert "dirb_scan targeting /api/v2" in (decision.directive or "")


def test_validate_route_report_ready_without_review():
    state = {"role": "discovery", "turns": {}}
    digest = MissionDigest(assessment_id=1, run_id="run-1")
    proposed = RouteDecision(
        next_role="discovery",
        report_ready=True,  # Invalid when not review
        why="Attempting early report",
    )
    decision, rejection = validate_route(proposed, state, digest)
    assert rejection == "report_ready_without_review"
