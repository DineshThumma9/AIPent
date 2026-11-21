"""Initial plan generation, normalization and run-start manifest tests."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.agents.brief import render_brief
from app.agents.contracts import PlanProposal, PlanStep
from app.agents.mission_brain import (
    _template_plan,
    generate_initial_plan,
    normalize_plan_steps,
)
from app.agents.run_config import build_run_manifest


class _Structured:
    def __init__(self, proposal: PlanProposal):
        self.proposal = proposal

    async def ainvoke(self, *args, **kwargs):
        return self.proposal


class _FakePlanner:
    def __init__(self, proposal: PlanProposal):
        self.proposal = proposal

    def with_structured_output(self, schema):
        assert schema is PlanProposal
        return _Structured(self.proposal)


def test_normalize_plan_steps_validates_and_bounds():
    raw = [
        {"role": "recon", "action": "recon_services", "target": "127.0.0.1", "rationale": "map"},
        {"role": "wizard", "action": "curl_request", "target": "127.0.0.1"},
        {"role": "discovery", "action": "", "target": "127.0.0.1"},
        PlanStep(role="review", action="final_review", target="127.0.0.1", rationale="wrap up"),
    ]
    steps = normalize_plan_steps(raw)
    assert len(steps) == 3
    assert steps[0]["role"] == "recon"
    assert steps[1]["role"] == "recon"  # unknown role falls back
    assert steps[2]["role"] == "review"
    assert steps[0]["enabled"] is True
    assert "valid_action" in steps[0]


def test_normalize_plan_steps_web_target_action_fallback():
    raw = [
        {"role": "recon", "action": "", "target": "http://127.0.0.1:3000", "rationale": "explore endpoints"},
        {"role": "recon", "action": "", "target": "10.0.0.1", "rationale": "port scan host"},
    ]
    steps = normalize_plan_steps(raw)
    assert steps[0]["action"] == "curl_request"
    assert steps[1]["action"] == "nmap_scan"



def test_template_plan_is_generic_and_covers_access_control():
    steps = _template_plan(
        "Broken access control: post feedback in another user's name",
        ["127.0.0.1"],
        [3000],
    )
    actions = [(s["role"], s["action"]) for s in steps]
    assert ("recon", "recon_services") in actions
    assert ("review", "final_review") in actions
    assert all(s["target"] == "127.0.0.1" for s in steps)
    assert len(steps) >= 5
    assert all(s["valid_action"] for s in steps), actions


@pytest.mark.asyncio
async def test_generate_initial_plan_uses_model_and_feedback():
    proposal = PlanProposal(
        steps=[
            PlanStep(
                role="discovery",
                action="curl_request",
                target="127.0.0.1",
                rationale="Probe discovered route",
            )
        ],
        notes="generic approach",
    )
    steps, source, notes = await generate_initial_plan(
        objective="Check auth bypass",
        targets=["127.0.0.1"],
        ports=[3000],
        feedback="Skip directory fuzzing.",
        chat_model=_FakePlanner(proposal),
    )
    assert source == "llm"
    assert steps[0]["action"] == "curl_request"
    assert "Skip directory fuzzing." in notes


@pytest.mark.asyncio
async def test_generate_initial_plan_falls_back_without_model():
    steps, source, _ = await generate_initial_plan(
        objective="SQL injection in login",
        targets=["127.0.0.1"],
        ports=[3000],
        chat_model=object(),  # no with_structured_output -> template fallback
    )
    assert source == "template"
    assert any(s["action"] == "sqlmap_scan" for s in steps)


def test_brief_contains_plan_and_feedback():
    assessment = SimpleNamespace(
        id=7,
        targets=["127.0.0.1"],
        ports=[3000],
        exclusions=[],
        request="Broken access control",
    )
    board = SimpleNamespace(hypotheses=[], open_questions=[], decisions=[])
    text = render_brief(
        assessment=assessment,
        role="validation",
        board=board,
        services=[],
        candidates=[],
        plan=[
            {
                "role": "validation",
                "action": "curl_request",
                "target": "127.0.0.1",
                "rationale": "Confirm forged UserId",
                "enabled": True,
            }
        ],
        feedback="Use the lab account only.",
    )
    assert "APPROVED ASSESSMENT PLAN" in text
    assert "Confirm forged UserId" in text
    assert "Use the lab account only." in text


def test_run_manifest_contains_models_budgets_and_tools():
    manifest = build_run_manifest(42)
    assert manifest["assessment_id"] == 42
    assert "supervisor" in manifest["models"]
    assert manifest["models"]["supervisor"]["provider"]
    for key in ("role_turn_caps", "max_agent_turns", "agent_recursion_limit"):
        assert key in manifest["budgets"]
    assert "curl_request" in manifest["tools"]["validation"]
    assert manifest["tool_counts"]["supervisor"] >= 0
