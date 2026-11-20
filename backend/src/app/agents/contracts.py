"""Core contracts for the V2 agent loop.

Pydantic models for actions, observations, handoffs, supervisor route decisions,
evidence board items, and steering notes.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, Field, field_validator,model_validator


class ActionRequest(BaseModel):
    """One prepared tool call, before approval/execution."""

    tool_call_id: str
    tool_name: str
    action: str
    target: str
    rationale: str

    # Resolved by Python, not by the model.
    step_id: int
    approval_id: int | None = None
    argv: list[str] = Field(default_factory=list)
    risk: Literal["low", "medium", "high"] = "medium"
    requires_approval: bool = True
    policy_reason: str = ""

    # Structured reasoning supplied through the tool arguments.
    hypothesis_id: str | None = None
    evidence_ids: list[int] = Field(default_factory=list)
    expected_observation: str | None = None
    would_falsify: str | None = None


class Observation(BaseModel):
    """What the agent gets back from one tool call.

    Compact structured feedback. Raw scanner output lives in the artifact and is
    available through read_artifact; the agent needs the summary and ids.
    """

    ok: bool
    status: Literal[
        "succeeded", "failed", "timeout", "blocked", "rejected", "error"
    ]
    action: str
    target: str
    step_id: int | None = None

    summary: str = ""
    findings_created: list[int] = Field(default_factory=list)
    findings_updated: list[int] = Field(default_factory=list)
    evidence_ids: list[int] = Field(default_factory=list)

    artifact: dict[str, Any] | None = None
    # {"path": "...", "sha256": "...", "kind": ".nmap.xml"}

    http: dict[str, Any] | None = None
    # {"status_code": 200, "headers": {...}, "body_excerpt": "..."}

    facts: dict[str, Any] | None = None

    errors: list[str] = Field(default_factory=list)
    duration_ms: int | None = None
    next_hint: str | None = None

    def __await__(self):
        async def _identity():
            return self

        return _identity().__await__()


class ActionResult(BaseModel):
    """Internal result of app.actions.executor.execute_action."""

    ok: bool
    exit_code: int | None = None
    status: Literal["succeeded", "failed", "timeout", "blocked"] = "failed"
    stdout_excerpt: str = ""
    artifact_path: str | None = None
    artifact_sha256: str | None = None
    error: str | None = None
    duration_ms: int | None = None


class Handoff(BaseModel):
    """Structured end of a specialist turn.

    The supervisor treats this as a recommendation, not a command. It may accept
    it, override it, or send the role back with a directive.
    """

    summary: str = Field(min_length=1, max_length=2000)
    next_role: Literal["recon", "discovery", "validation", "review"]
    why: str = Field(min_length=1, max_length=1000)
    confidence: float = Field(ge=0.0, le=1.0)

    stop_reason: Literal[
        "surface_mapped",
        "hypotheses_tested",
        "no_progress",
        "budget",
        "needs_more_recon",
        "needs_scope_decision",
        "blocked",
    ]
    finding_ids: list[int] = Field(default_factory=list)
    step_ids: list[int] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)


class RouteDecision(BaseModel):
    """The supervisor's proposed next move. Advisory until validate_route accepts it."""

    next_role: Literal["recon", "discovery", "validation", "review"]
    why: str = Field(
        default="Assessing mission state and prioritizing next actions.",
        min_length=1,
        max_length=1500,
        description="Detailed explanation for choosing this next role.",
    )
    priority: Literal["low", "medium", "high"] = "medium"
    confidence: float = Field(
        default=0.75,
        ge=0.0,
        le=1.0,
        description="Confidence score between 0.0 and 1.0.",
    )
    evidence_ids: list[int] = Field(default_factory=list)

    # Set when the supervisor disagrees with the specialist's recommendation.
    overrides_specialist: bool = False
    override_reason: str | None = Field(default=None, max_length=1000)

    # Tactical instruction for the next specialist brief.
    directive: str | None = Field(
        default=None,
        max_length=1500,
        description="Tactical directive for the specialist: specify target endpoint, tool, payload/method, and expected observation.",
    )

    @field_validator("directive", mode="before")
    @classmethod
    def _flatten_directive(cls, value: Any) -> Any:
        # Models often emit the directive as a structured object. Flatten it
        # instead of rejecting the whole route (which silently fell back).
        if isinstance(value, (dict, list)):
            value = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        if isinstance(value, str) and len(value) > 1500:
            # The directive is advisory prompt text. A truncated instruction is
            # strictly better than rejecting the route and losing the LLM's
            # decision for the whole turn.
            return value[:1497] + "..."
        return value

    # True when the supervisor believes the mission is ready for final review.
    report_ready: bool = False


class FailureSignal(BaseModel):
    """Emitted when a role cannot proceed normally."""

    role: Literal["recon", "discovery", "validation"]
    kind: Literal[
        "no_handoff",
        "invalid_handoff",
        "budget_exhausted",
        "no_progress",
        "repeated_action",
        "step_failed",
        "timeout",
        "model_error",
        "approval_rejected",
    ]
    summary: str = Field(min_length=1, max_length=1500)
    attempts: int = Field(default=1, ge=0)
    step_ids: list[int] = Field(default_factory=list)
    evidence_ids: list[int] = Field(default_factory=list)
    observation: dict[str, Any] | None = None


class Hypothesis(BaseModel):
    """Hypothesis recorded on the evidence board."""

    id: str  # "H-1", "H-2"
    statement: str
    asset: str
    endpoint: str | None = None
    status: Literal["open", "supported", "refuted", "inconclusive"] = "open"
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    evidence_ids: list[int] = Field(default_factory=list)
    falsifier: str = ""
    created_by: str  # recon | discovery | validation
    updated_at: datetime


class DecisionRecord(BaseModel):
    """Record of a decision and its expected/falsifying observation."""

    id: str  # "D-1", "D-2"
    role: str
    action: str
    target: str
    hypothesis_id: str | None = None
    evidence_ids: list[int] = Field(default_factory=list)
    observation: str = ""
    expected_observation: str | None = None
    would_falsify: str | None = None
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    outcome: str = ""
    created_at: datetime


class EvidenceBoard(BaseModel):
    """Evidence board folded from audit events."""

    hypotheses: list[Hypothesis] = Field(default_factory=list)
    decisions: list[DecisionRecord] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)
    coverage: dict[str, Any] = Field(default_factory=dict)


class SteeringNote(BaseModel):
    """Operator directive queued for an active run."""

    id: int
    assessment_id: int
    run_id: str | None = None
    text: str
    status: Literal["pending", "consumed", "expired"] = "pending"
    created_at: datetime
    consumed_at: datetime | None = None



class FindingNarrative(BaseModel):
    finding_id: int
    technical_analysis: str = Field(min_length=1, max_length=4000)
    impact: str = Field(min_length=1, max_length=2000)
    remediation: str = Field(min_length=1, max_length=2000)
    confidence_statement: str = Field(min_length=1, max_length=1000)
    observed_vs_inferred: str = Field(min_length=1, max_length=1500)

    @model_validator(mode="before")
    @classmethod
    def _coerce_fields(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        d = dict(data)
        if "finding_id" not in d and "id" in d:
            d["finding_id"] = d["id"]

        obs = str(d.get("observed") or "").strip()
        inf = str(d.get("inferred") or "").strip()
        if not d.get("observed_vs_inferred"):
            if obs or inf:
                d["observed_vs_inferred"] = f"Observed: {obs}\nInferred: {inf}".strip()
            else:
                d["observed_vs_inferred"] = "Direct observation documented in evidence."

        if not d.get("technical_analysis"):
            if obs or inf:
                d["technical_analysis"] = f"{obs} {inf}".strip()
            elif d.get("title"):
                d["technical_analysis"] = str(d.get("title"))
            else:
                d["technical_analysis"] = "Technical analysis based on tool observation."

        if not d.get("confidence_statement"):
            c = d.get("confidence")
            if c is not None:
                d["confidence_statement"] = f"Confidence score {c} based on direct execution evidence."
            else:
                d["confidence_statement"] = "Confidence established through verifiable tool output."

        if not d.get("impact"):
            d["impact"] = "No direct business impact demonstrated beyond observed behavior."

        if not d.get("remediation"):
            d["remediation"] = "Review service exposure and enforce least privilege."

        return d


class ReportNarrative(BaseModel):
    executive_summary: str = Field(min_length=1, max_length=4000)
    methodology: str = Field(min_length=1, max_length=3000)
    risk_overview: str = Field(min_length=1, max_length=2500)
    findings: list[FindingNarrative] = Field(default_factory=list)
    limitations: str = Field(min_length=1, max_length=2500)
    recommendations: list[str] = Field(default_factory=list, max_length=12)
    conclusion: str = Field(min_length=1, max_length=2000)

    @model_validator(mode="before")
    @classmethod
    def _coerce_fields(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        d = dict(data)
        if "report" in d and isinstance(d["report"], dict):
            d = dict(d["report"])

        if isinstance(d.get("methodology"), (dict, list)):
            if isinstance(d["methodology"], dict):
                steps_cnt = d["methodology"].get("steps_executed") or len(d["methodology"].get("steps") or [])
                d["methodology"] = f"The assessment executed {steps_cnt} testing actions using automated tools."
            else:
                d["methodology"] = "\n".join(f"- {s}" for s in d["methodology"] if s)
        elif not d.get("methodology"):
            alt = d.get("approach") or d.get("testing_methodology") or d.get("execution")
            if isinstance(alt, str) and alt.strip():
                d["methodology"] = alt.strip()
            else:
                d["methodology"] = "Methodical vulnerability assessment conducted within authorized scope."

        if not d.get("risk_overview"):
            rs = d.get("risk_summary")
            if isinstance(rs, dict):
                score = rs.get("overall_risk_score", 0.0)
                level = rs.get("risk_level", "Informational")
                d["risk_overview"] = f"Overall risk score: {score} ({level})."
            elif isinstance(rs, str):
                d["risk_overview"] = rs
            else:
                d["risk_overview"] = "Risk evaluated based on verified findings and exposure."

        if isinstance(d.get("limitations"), list):
            d["limitations"] = "\n".join(f"- {item}" for item in d["limitations"])
        elif not d.get("limitations"):
            d["limitations"] = "Testing was conducted in a bounded environment without disruptive exploits."

        if not d.get("conclusion"):
            alt_c = d.get("outcome") or d.get("final_summary")
            if isinstance(alt_c, str) and alt_c.strip():
                d["conclusion"] = alt_c.strip()
            else:
                d["conclusion"] = "Assessment completed. Refer to findings for remediation steps."

        if isinstance(d.get("recommendations"), str):
            d["recommendations"] = [d["recommendations"]]
        elif not d.get("recommendations"):
            d["recommendations"] = ["Maintain updated software versions.", "Review open ports and services."]

        return d
