"""Tool specifications and role toolsets for the V2 loop.

Separates action tools (external commands executed through the graph) from direct
tools (safe in-process reads/writes).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Literal
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from app.agents.loop.contracts import Handoff


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    args_model: type[BaseModel]
    kind: Literal["action", "direct"]
    action: str | None = None
    handler: Callable[..., Any] | None = None
    param_fields: tuple[str, ...] = ()


class ActionReasoning(BaseModel):
    target: str = Field(description="Exactly one target listed in the assessment scope.")
    rationale: str = Field(
        description="Why this action is the cheapest next step and what uncertainty it reduces."
    )
    hypothesis_id: str | None = Field(
        default=None, description="Existing hypothesis id, for example H-2."
    )
    evidence_ids: list[int] = Field(
        default_factory=list, description="Evidence rows that motivated this action."
    )
    expected_observation: str | None = Field(
        default=None,
        description="What result would support the hypothesis, stated before running.",
    )
    would_falsify: str | None = Field(
        default=None,
        description="What result would make you abandon or revise the hypothesis.",
    )


class ReconServicesArgs(ActionReasoning):
    profile: Literal["fast", "deep", "top100", "top1000"] = Field(
        default="fast", description="Nmap profile to execute."
    )
    ports: str | int | list[int] | None = Field(
        default=None, description="Port list or range, e.g. '80,443', '1-1000', or 3000."
    )
    timing: int | None = Field(default=None, ge=1, le=5, description="Nmap timing template (1-5).")
    scripts: list[str] = Field(default_factory=list, description="Optional safe NSE script names.")


class ReadArtifactArgs(BaseModel):
    model_config = {"extra": "ignore"}

    step_id: int = Field(description="Step id whose artifact to inspect.")
    offset: int = Field(default=0, ge=0, description="Character offset from start of artifact to read from.")
    max_chars: int = Field(default=4000, le=8000, description="Max characters to read.")
    search: str | None = Field(default=None, description="Optional substring to search within artifact.")


class ListServicesArgs(BaseModel):
    limit: int = Field(default=50, ge=1, le=200, description="Max services to return.")


class ListFindingsArgs(BaseModel):
    status: str | None = Field(default=None, description="Optional filter by status (suspected, confirmed, false_positive).")
    limit: int = Field(default=50, ge=1, le=200, description="Max findings to return.")


class RecordHypothesisArgs(BaseModel):
    statement: str = Field(description="Clear testable claim about the target surface or vulnerability.")
    asset: str = Field(description="Target host or IP address.")
    endpoint: str | None = Field(default=None, description="Specific URL path, port, or service endpoint.")
    falsifier: str = Field(default="", description="What specific observation would disprove this hypothesis.")
    evidence_ids: list[int] = Field(default_factory=list, description="Evidence IDs supporting this hypothesis.")


class UpdateHypothesisArgs(BaseModel):
    hypothesis_id: str = Field(description="Identifier of hypothesis to update (e.g. 'H-1').")
    status: Literal["open", "supported", "refuted", "inconclusive"] = Field(description="New status.")
    confidence: float = Field(ge=0.0, le=1.0, description="Updated confidence between 0.0 and 1.0.")
    evidence_ids: list[int] = Field(default_factory=list, description="Linked evidence IDs.")
    note: str | None = Field(default=None, description="Explanation for the update.")


class DirbArgs(ActionReasoning):
    path: str = Field(default="/", description="Base path to enumerate.")


class WhatwebArgs(ActionReasoning):
    pass


class HashIdentifyArgs(BaseModel):
    hash_value: str = Field(description="The hash string to identify.")
    source_step_id: int = Field(description="Step ID of artifact where the hash was captured.")


class HashcatArgs(ActionReasoning):
    source_step_id: int = Field(description="Step ID of artifact where the hash was captured.")
    hash_value: str | None = Field(default=None, description="Exact hash string to crack (must exist in source artifact).")
    hash_file: str | None = Field(default=None, description="Optional hash file relative to assessment artifact directory.")
    hash_mode: int = Field(default=0, description="Hashcat hash mode (-m, e.g. 0 for MD5, 100 for SHA-1, 3200 for bcrypt).")
    wordlist: Literal["lab", "rockyou"] = Field(default="lab", description="Allowlisted dictionary to attack with.")
    runtime: int = Field(default=120, ge=10, le=300, description="Max runtime in seconds (10 to 300).")


class NiktoArgs(ActionReasoning):
    pass


class ZapArgs(ActionReasoning):
    pass


class CurlArgs(ActionReasoning):
    path: str = Field(
        default="/",
        description="Path on the scoped target starting with / (e.g. '/api/Users', '/rest/user/login') or full URL.",
    )
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] = Field(
        default="GET",
        description="HTTP method (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS).",
    )
    headers: dict[str, str] = Field(
        default_factory=dict,
        description="Optional request headers dict (e.g. {'Content-Type': 'application/json', 'Authorization': 'Bearer ...'}).",
    )
    body: str | None = Field(
        default=None,
        description="Optional request body string (e.g. JSON string '{\"email\":\"admin@juice-sh.op\",\"password\":\"' or 1=1--\"}').",
    )
    follow_redirects: bool = Field(
        default=True,
        description="Follow HTTP redirects automatically (default true). Set false to capture redirect responses.",
    )
    expected_status: int = Field(default=200, description="Expected HTTP response status code.")
    finding_id: int | None = Field(default=None, description="Candidate finding ID being probed.")



class SqlmapArgs(ActionReasoning):
    parameter: str | None = Field(default=None, description="Optional parameter name to test.")


class UpdateFindingStatusArgs(BaseModel):
    finding_id: int = Field(description="ID of the candidate finding to update.")
    status: Literal["confirmed", "suspected", "false_positive"] = Field(description="New status.")
    reasoning: str = Field(description="Detailed justification based on observed probe evidence.")


class LookupCveArgs(BaseModel):
    cve_id: str | None = Field(default=None, description="Exact CVE identifier (e.g. 'CVE-2023-38606').")
    vendor: str | None = Field(default=None, description="Normalized vendor name (e.g. 'nginx', 'apache').")
    product: str | None = Field(default=None, description="Normalized product name (e.g. 'nginx', 'http_server').")
    version: str | None = Field(default=None, description="Observed version string (e.g. '1.24.0').")
    cpe: str | None = Field(default=None, description="Exact CPE 2.3 criteria if identified by a scanner.")


class EmptyArgs(BaseModel):
    pass


class GetStepsArgs(BaseModel):
    limit: int = Field(default=20, ge=1, le=100)


class GetHandoffsArgs(BaseModel):
    limit: int = Field(default=5, ge=1, le=20)


recon_services_tool = ToolSpec(
    name="recon_services",
    kind="action",
    action="recon_services",
    args_model=ReconServicesArgs,
    description=(
        "Map open TCP ports and service/version banners on one in-scope target. "
        "Choose a profile and port set that fit the current uncertainty. "
        "Returns a compact service summary, finding ids and evidence ids. "
        "Use read_artifact when you need raw Nmap output."
    ),
    param_fields=("profile", "ports", "timing", "scripts"),
)

read_artifact_tool = ToolSpec(
    name="read_artifact",
    kind="direct",
    args_model=ReadArtifactArgs,
    description=(
        "Read a bounded excerpt from a step artifact. Use this only when the "
        "compact observation is insufficient. Prefer a line range or a search term."
    ),
)

list_services_tool = ToolSpec(
    name="list_services",
    kind="direct",
    args_model=ListServicesArgs,
    description="List discovered open ports and services on in-scope targets.",
)

list_findings_tool = ToolSpec(
    name="list_findings",
    kind="direct",
    args_model=ListFindingsArgs,
    description="List candidate or confirmed findings for this assessment.",
)

record_hypothesis_tool = ToolSpec(
    name="record_hypothesis",
    kind="direct",
    args_model=RecordHypothesisArgs,
    description="Record a new hypothesis on the evidence board with an explicit falsifier.",
)

update_hypothesis_tool = ToolSpec(
    name="update_hypothesis",
    kind="direct",
    args_model=UpdateHypothesisArgs,
    description="Update status, confidence, note, or linked evidence for an existing hypothesis.",
)

handoff_tool = ToolSpec(
    name="handoff",
    kind="direct",
    args_model=Handoff,
    description=(
        "End your turn with a structured handoff. Call this when you have no "
        "more useful actions, when the evidence answers the question, or when "
        "another role is better placed to continue. Include what you observed, "
        "what remains open, and the next role."
    ),
)

# Supervisor read-only tool specs
get_mission_digest_tool = ToolSpec(
    name="get_mission_digest",
    kind="direct",
    args_model=EmptyArgs,
    description="Return the compact mission digest: scope, services, candidates, hypotheses, recent steps, handoffs, budgets, steering and failures.",
)

get_steps_tool = ToolSpec(
    name="get_steps",
    kind="direct",
    args_model=GetStepsArgs,
    description="List recent steps with action, target, status, error and linked evidence ids.",
)

get_handoffs_tool = ToolSpec(
    name="get_handoffs",
    kind="direct",
    args_model=GetHandoffsArgs,
    description="List recent specialist handoffs with their recommendation, reason, confidence and open questions.",
)

get_budget_tool = ToolSpec(
    name="get_budget",
    kind="direct",
    args_model=EmptyArgs,
    description="Return per-role turns, remaining budget, elapsed time, supervisor calls and the no-progress counter.",
)


dirb_scan_tool = ToolSpec(
    name="dirb_scan",
    kind="action",
    action="dirb_scan",
    args_model=DirbArgs,
    description=(
        "Enumerate common web paths on one in-scope HTTP service using a fixed "
        "wordlist. Use when content discovery is the missing evidence. "
        "Returns discovered paths as candidate findings."
    ),
    param_fields=("path",),
)

nikto_scan_tool = ToolSpec(
    name="nikto_scan",
    kind="action",
    action="nikto_scan",
    args_model=NiktoArgs,
    description=(
        "Run Nikto web-server checks against one in-scope HTTP service. "
        "Use when server configuration and known-issue checks are relevant. "
        "Returns candidate findings with Nikto evidence."
    ),
    param_fields=(),
)

zap_baseline_tool = ToolSpec(
    name="zap_baseline",
    kind="action",
    action="zap_baseline",
    args_model=ZapArgs,
    description=(
        "Run a passive OWASP ZAP baseline scan against one in-scope HTTP service. "
        "This is a medium-risk action and requires human approval. "
        "Returns ZAP alerts as candidates; they are not confirmations."
    ),
    param_fields=(),
)

curl_request_tool = ToolSpec(
    name="curl_request",
    kind="action",
    action="curl_request",
    args_model=CurlArgs,
    description=(
        "Send one HTTP request via curl-mcp. "
        "Supports all HTTP methods (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD), headers, body payloads, and redirect controls. "
        "Returns status code, response headers, and body excerpt."
    ),
    param_fields=("path", "method", "headers", "body", "expected_status", "follow_redirects", "finding_id"),
)


whatweb_tool = ToolSpec(
    name="whatweb",
    kind="action",
    action="whatweb",
    args_model=WhatwebArgs,
    description=(
        "Run WhatWeb to detect web server technology, CMS, libraries, and response headers "
        "on an in-scope web service. Emits informational findings."
    ),
    param_fields=(),
)

hash_identify_tool = ToolSpec(
    name="hash_identify",
    kind="direct",
    args_model=HashIdentifyArgs,
    description=(
        "Safely identify the hash algorithm (MD5, SHA-1, SHA-256, bcrypt, etc.) and suggested "
        "Hashcat mode for a hash discovered in an assessment artifact. Fast and direct."
    ),
)

hashcat_crack_tool = ToolSpec(
    name="hashcat_crack",
    kind="action",
    action="hashcat_crack",
    args_model=HashcatArgs,
    description=(
        "Perform bounded offline credential cracking using Hashcat against captured hash material "
        "from an assessment artifact. High-risk action requiring human approval. "
        "Recovered credentials are automatically redacted; plaintext passwords are never displayed."
    ),
    param_fields=("source_step_id", "hash_value", "hash_file", "hash_mode", "wordlist", "runtime"),
)

sqlmap_scan_tool = ToolSpec(
    name="sqlmap_scan",
    kind="action",
    action="sqlmap_scan",
    args_model=SqlmapArgs,
    description=(
        "Run a bounded sqlmap check against one in-scope HTTP service. "
        "Use only when evidence specifically points to SQL injection. "
        "This is a high-risk action and requires human approval. "
        "Destructive options are not available."
    ),
    param_fields=("parameter",),
)

update_finding_status_tool = ToolSpec(
    name="update_finding_status",
    kind="direct",
    args_model=UpdateFindingStatusArgs,
    description=(
        "Record a validation verdict for one candidate finding. "
        "confirmed and false_positive require at least one executed curl_request "
        "evidence row linked to the finding. State the observed evidence and "
        "the inference separately."
    ),
)

lookup_cve_tool = ToolSpec(
    name="lookup_cve",
    kind="direct",
    args_model=LookupCveArgs,
    description=(
        "Look up grounded CVE intelligence from the pinned local CVE database (Vulnify). "
        "Provide an exact cve_id or normalized vendor/product/version/cpe. "
        "Returns verified CVSS, CWE, KEV status, EPSS score, and upstream reference URLs. "
        "Free-text search is not supported."
    ),
)


ROLE_TOOL_SPECS: dict[str, list[ToolSpec]] = {
    "recon": [
        recon_services_tool,
        whatweb_tool,
        lookup_cve_tool,
        read_artifact_tool,
        list_services_tool,
        record_hypothesis_tool,
        update_hypothesis_tool,
        handoff_tool,
    ],
    "discovery": [
        curl_request_tool,
        dirb_scan_tool,
        nikto_scan_tool,
        zap_baseline_tool,
        lookup_cve_tool,
        read_artifact_tool,
        list_findings_tool,
        record_hypothesis_tool,
        update_hypothesis_tool,
        handoff_tool,
    ],
    "validation": [
        curl_request_tool,
        sqlmap_scan_tool,
        hash_identify_tool,
        hashcat_crack_tool,
        lookup_cve_tool,
        read_artifact_tool,
        list_findings_tool,
        update_finding_status_tool,
        record_hypothesis_tool,
        update_hypothesis_tool,
        handoff_tool,
    ],
}

ROLE_TOOLS = ROLE_TOOL_SPECS  # compatibility alias

SUPERVISOR_TOOL_SPECS: list[ToolSpec] = [
    get_mission_digest_tool,
    list_services_tool,
    list_findings_tool,
    get_steps_tool,
    get_handoffs_tool,
    get_budget_tool,
]


def lookup_tool(role: str, name: str) -> ToolSpec:
    specs = ROLE_TOOL_SPECS.get(role, [])
    for s in specs:
        if s.name == name:
            return s
    for s in SUPERVISOR_TOOL_SPECS:
        if s.name == name:
            return s
    raise KeyError(f"tool {name!r} not found for role {role!r}")


def is_direct_tool(role: str, name: str) -> bool:
    try:
        spec = lookup_tool(role, name)
        return spec.kind == "direct"
    except KeyError:
        return False


async def raise_if_called(**_kwargs):
    raise RuntimeError("action tools are executed by the loop, not by LangChain")


def _direct_tool(spec: ToolSpec):
    async def _direct_fn(**kwargs):
        if spec.handler:
            return await spec.handler(**kwargs)
        return kwargs

    return tool(
        spec.name,
        description=spec.description,
        args_schema=spec.args_model,
    )(_direct_fn)


def bindable_tools(role: str):
    specs = ROLE_TOOL_SPECS.get(role, [])
    tools = []
    for spec in specs:
        if spec.kind == "action":
            tools.append(
                tool(
                    spec.name,
                    description=spec.description,
                    args_schema=spec.args_model,
                )(raise_if_called)
            )
        else:
            tools.append(_direct_tool(spec))
    return tools
