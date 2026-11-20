"""Unit tests for V2 loop contracts, role tools, models, and observation models."""

import pytest
from pydantic import ValidationError

from app.agents.contracts import (
    ActionRequest,
    FailureSignal,
    Handoff,
    Observation,
    RouteDecision,
)
from app.agents.model import role_model_config
from app.agents.observations import observation_from_step
from app.agents.state import AssessmentState
from app.agents.tool_specs import ROLE_TOOLS
from app.api.schema import DecisionIn
from app.core.config import settings
from app.domain.models import Step, StepStatus


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


def test_route_decision_coerces_structured_directive():
    dec = RouteDecision(
        next_role="discovery",
        why="Test the documented login route",
        directive={
            "url": "http://127.0.0.1:3000/rest/user/login",
            "method": "POST",
            "expect": "HTTP 200 with an authentication token",
        },
    )
    assert isinstance(dec.directive, str)
    assert "rest/user/login" in dec.directive
    assert "HTTP 200" in dec.directive


def test_route_decision_truncates_long_structured_directive():
    dec = RouteDecision(
        next_role="validation",
        why="Long directive test",
        directive={
            "description": "Validate the basket endpoint",
            "steps": [f"step {i}: " + ("x" * 80) for i in range(40)],
        },
    )
    assert isinstance(dec.directive, str)
    assert len(dec.directive) == 1500
    assert dec.directive.endswith("...")
    assert "Validate the basket endpoint" in dec.directive


def test_role_tools_are_unique_and_scoped():
    expected_actions = {
        "recon": {"recon_services"},
        "discovery": {"dirb_scan", "nikto_scan", "zap_baseline"},
        "validation": {"curl_request", "sqlmap_scan", "update_finding_status"},
        "supervisor": set(),
    }
    assert set(ROLE_TOOLS) == {"recon", "discovery", "validation", "supervisor"}
    for role, tools in ROLE_TOOLS.items():
        names = [getattr(tool, "name", "") for tool in tools]
        assert len(names) == len(set(names))
        action_names = {n for n in names if n in expected_actions[role]}
        assert action_names == expected_actions[role]

    assert "record_finding" in {tool.name for tool in ROLE_TOOLS["discovery"]}


def test_assessment_state_declares_steps():
    assert "steps" in AssessmentState.__annotations__


def test_decision_binds_to_a_specific_gate():
    decision = DecisionIn(
        decision="approved",
        approval_id=14,
        step_id=33,
    )
    assert decision.approval_id == 14
    assert decision.step_id == 33


def test_observation_from_step_pure():
    step = Step(
        id=42,
        assessment_id=1,
        action="curl_request",
        status=StepStatus.SUCCEEDED.value,
        target="http://test",
    )
    obs = observation_from_step(step, finding_ids=[10], evidence_ids=[100])
    assert obs.ok is True
    assert obs.action == "curl_request"
    assert obs.findings_created == [10]
    assert obs.evidence_ids == [100]


def test_observation_from_step_failed_pure():
    step = Step(
        id=43,
        assessment_id=1,
        action="sqlmap_scan",
        status=StepStatus.FAILED.value,
        target="http://test",
        error="Connection refused",
    )
    obs = observation_from_step(step)
    assert obs.ok is False
    assert obs.status == "failed"
    assert obs.action == "sqlmap_scan"
    assert "Connection refused" in obs.summary


def test_role_model_config_uses_per_role_overrides(monkeypatch):
    monkeypatch.setattr(settings, "llm_provider", "mistral")
    monkeypatch.setattr(settings, "llm_model", "base-model")
    monkeypatch.setattr(settings, "supervisor_provider", "cerebras")
    monkeypatch.setattr(settings, "supervisor_model", "gpt-oss-120b")
    monkeypatch.setattr(settings, "discovery_provider", None)
    monkeypatch.setattr(settings, "discovery_model", None)

    config = role_model_config()
    assert config["supervisor"] == {
        "provider": "cerebras",
        "model": "gpt-oss-120b",
    }
    assert config["discovery"] == {"provider": "mistral", "model": "base-model"}
    assert set(config) == {"supervisor", "coordinator", "recon", "discovery", "validation", "report"}


def test_nvidia_provider_uses_configured_model(monkeypatch):
    import socket
    from app.agents import model as model_module

    monkeypatch.setenv("NVIDIA_MODEL", "nvidia/test-model")
    monkeypatch.setenv("NVIDIA_API_KEY", "test-key")

    model = model_module._build_model(None, "nvidia")
    assert model.model == "nvidia/test-model"
    assert socket.getaddrinfo is model_module._ipv4_first
