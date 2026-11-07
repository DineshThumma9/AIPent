"""Closed action catalogue, scope checks and argv resolution.

The LLM never supplies argv. It names an action and a target; this module
resolves the fixed command, so the thing a human approves is exactly the
thing that runs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Literal

from app.adapters import nikto, nmap, zap
from app.adapters.base import FindingDraft
from app.core.config import settings
from app.domain.models import Assessment

ARTIFACT_DIR = settings.artifacts_path


class ScopeError(ValueError):
    """Target is not in the assessment's authorised scope."""


class UnknownAction(ValueError):
    """The plan named an action outside the closed catalogue."""


@dataclass(frozen=True)
class NmapParams:
    profile: Literal["host_discovery", "fast", "service", "full_tcp", "full_service"] = "fast"
    ports: Literal["top100", "top1000", "all"] | list[int] = "top100"
    timing: int = 4


@dataclass(frozen=True)
class ActionSpec:
    name: str
    tool: str
    suffix: str
    output: Literal["stdout", "file"]
    transport: Literal["local", "docker", "mcp", "http"]
    ok_codes: tuple[int, ...]
    build_argv: Callable[[Assessment, str, Path, dict[str, Any] | None], list[str]]
    parse: Callable[[str, str, int], list[FindingDraft]]
    param_hints: dict[str, str] = field(default_factory=dict)


def _web_port(assessment: Assessment) -> int:
    return (assessment.ports or [3000])[0]


def _artifact_dir(assessment_id: int) -> Path:
    directory = ARTIFACT_DIR / str(assessment_id)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _nmap_argv(
    assessment: Assessment, target: str, _output: Path, params: dict[str, Any] | None = None
) -> list[str]:
    p = NmapParams(**(params or {}))
    if p.profile == "host_discovery":
        return nmap.argv(target, [], host_discovery=True)
    if p.profile == "fast":
        return nmap.fast_scan(target, p.ports, timing=p.timing)
    if p.profile == "service":
        return nmap.service_scan(target, p.ports, timing=p.timing)
    if p.profile == "full_tcp":
        return nmap.full_tcp(target, timing=p.timing)
    if p.profile == "full_service":
        return nmap.full_service(target, timing=p.timing)
    return nmap.argv(target, assessment.ports or [3000])


def _nmap_scan_argv(
    assessment: Assessment, target: str, _output: Path, params: dict[str, Any] | None = None
) -> list[str]:
    """Nmap scan with agent-supplied params stored on the step.

    The agent chooses a profile and port set; Python renders the exact argv.
    This resolver is only a fallback when argv is not already set on the step.
    """
    return _nmap_argv(assessment, target, _output, params)


def _nikto_argv(
    assessment: Assessment, target: str, output: Path, params: dict[str, Any] | None = None
) -> list[str]:
    return nikto.argv(target, _web_port(assessment), str(output))


def _zap_argv(
    assessment: Assessment,
    target: str,
    output: Path,
    params: dict[str, Any] | None = None,
) -> list[str]:
    return zap.argv(
        target,
        _web_port(assessment),
        str(output),
        _artifact_dir(assessment.id or 0),
    )


def _sqlmap_argv(
    assessment: Assessment, target: str, _output: Path, params: dict[str, Any] | None = None
) -> list[str]:
    return [
        "sqlmap",
        "-u",
        f"http://{target}:{_web_port(assessment)}/",
        "--batch",
        "--dbs",
    ]


def _dirb_argv(
    assessment: Assessment, target: str, output: Path, params: dict[str, Any] | None = None
) -> list[str]:
    return [
        "dirb",
        f"http://{target}:{_web_port(assessment)}/",
        "/usr/share/wordlists/dirb/common.txt",
        "-S",
        "-o",
        str(output),
    ]


ACTIONS: dict[str, ActionSpec] = {
    "recon_services": ActionSpec(
        name="recon_services",
        tool="nmap",
        suffix=".nmap.xml",
        output="stdout",
        transport="local",
        ok_codes=(0,),
        build_argv=_nmap_argv,
        parse=lambda text, host, _port: nmap.scan(text, host_override=host),
        param_hints={
            "profile": "Scan profile: host_discovery, fast, service, full_tcp, full_service",
            "ports": "Port set: top100, top1000, all, or list of port numbers",
            "timing": "Nmap timing template (0-5, default 4)",
        },
    ),
    "nmap_scan": ActionSpec(
        name="nmap_scan",
        tool="nmap",
        suffix=".nmap.xml",
        output="stdout",
        transport="local",
        ok_codes=(0,),
        build_argv=_nmap_scan_argv,
        parse=lambda text, host, _port: nmap.scan(text, host_override=host),
        param_hints={
            "profile": "Scan profile: host_discovery, fast, service, full_tcp, full_service",
            "ports": "Port set: top100, top1000, all, or list of port numbers",
            "timing": "Nmap timing template (0-5, default 4)",
        },
    ),
    "nikto_scan": ActionSpec(
        name="nikto_scan",
        tool="nikto",
        suffix=".nikto.json",
        output="file",
        transport="local",
        ok_codes=(0,),
        build_argv=_nikto_argv,
        parse=lambda text, host, port: nikto.scan(text, host, port),
    ),
    "zap_baseline": ActionSpec(
        name="zap_baseline",
        tool="zap",
        suffix=".zap.json",
        output="file",
        transport="docker",
        ok_codes=(0, 1, 2),  # baseline exits 1/2 when alerts are present
        build_argv=_zap_argv,
        parse=lambda text, host, port: zap.scan(text, host, port),
    ),
    "sqlmap_scan": ActionSpec(
        name="sqlmap_scan",
        tool="sqlmap",
        suffix=".sqlmap.txt",
        output="file",
        transport="local",
        ok_codes=(0, 1),
        build_argv=_sqlmap_argv,
        parse=lambda _text, _host, _port: [],
    ),
    "dirb_scan": ActionSpec(
        name="dirb_scan",
        tool="dirb",
        suffix=".dirb.txt",
        output="file",
        transport="local",
        ok_codes=(0, 1),
        build_argv=_dirb_argv,
        parse=lambda _text, _host, _port: [],
    ),
    "http_probe": ActionSpec(
        name="http_probe",
        tool="http_probe",
        suffix=".http_probe.json",
        output="file",
        transport="http",
        ok_codes=(0,),
        build_argv=lambda assessment, target, _output, params=None: [
            "http_probe",
            "GET",
            f"http://{target}:{_web_port(assessment)}/",
            "{}",
            "200",
        ],
        parse=lambda _text, _host, _port: [],
    ),
}


def transport_target(target: str) -> str:
    """Map a scope target to its container-visible alias.

    The assessment, findings and report always use the scope target. Only the
    MCP tool argument gets the alias.
    """
    if not settings.mcp_enabled or settings.mcp_transport != "gateway":
        return target

    if target in {"127.0.0.1", "localhost"}:
        return settings.lab_target_alias

    return target


def mcp_tool_call(
    action: str,
    assessment: Assessment,
    target: str,
    params: dict[str, Any] | None = None,
) -> tuple[str, dict[str, Any]]:
    """The single mapping from semantic action to gateway tool and arguments.

    Both the approval descriptor and the live call use this function, so the
    thing a human approves is exactly the thing that runs.
    """
    alias = transport_target(target)
    port = _web_port(assessment)
    if action == "recon_services":
        p = NmapParams(**(params or {}))
        if isinstance(p.ports, list):
            return "nmap_scan", {
                "target": alias,
                "flags": nmap.mcp_flags(ports=p.ports, timing=p.timing),
            }
        return "nmap_scan", {
            "target": alias,
            "flags": nmap.mcp_flags(top_ports=p.ports, timing=p.timing),
        }
    if action == "nikto_scan":
        return "nikto_scan", {"target_url": f"http://{alias}:{port}"}
    if action == "zap_baseline":
        return "zap_baseline", {"target_url": f"http://{alias}:{port}"}
    if action == "sqlmap_scan":
        return "sqlmap_scan", {
            "target_url": f"http://{alias}:{port}",
            "params": "--batch --dbs",
        }
    if action == "dirb_scan":
        return "dirb_scan", {
            "target_url": f"http://{alias}:{port}",
            "wordlist": "/usr/share/wordlists/dirb/common.txt",
        }
    raise UnknownAction(action)


def mcp_command(
    action: str,
    assessment: Assessment,
    target: str,
    params: dict[str, Any] | None = None,
) -> list[str]:
    tool, arguments = mcp_tool_call(action, assessment, target, params=params)
    return ["mcp", tool, json.dumps(arguments, sort_keys=True)]


def get_action(name: str) -> ActionSpec:
    try:
        return ACTIONS[name]
    except KeyError as exc:
        raise UnknownAction(f"action {name!r} is not in the catalogue") from exc


def resolve_argv(
    action: str,
    assessment: Assessment,
    target: str,
    step_id: int,
    params: dict[str, Any] | None = None,
) -> list[str]:
    if settings.mcp_enabled and settings.mcp_transport == "gateway":
        return mcp_command(action, assessment, target, params=params)
    spec = get_action(action)
    output = _artifact_dir(assessment.id or 0) / f"{step_id}{spec.suffix}"
    return spec.build_argv(assessment, target, output, params)


def check_scope(assessment: Assessment, target: str) -> None:
    if target in assessment.exclusions or target not in assessment.targets:
        raise ScopeError(f"{target} is not in scope for assessment {assessment.id}")


def inject_output_path(argv: list[str], output_path: str, spec: ActionSpec) -> list[str]:
    """Ensure agent-supplied argv writes to the artifact output path.

    Different scanners use different flags for their output destination:

    - dirb: ``-o <path>``
    - sqlmap: ``--output-dir <directory>``
    - nikto: ``-output <path>``
    - http_probe: no file flag injected (writes its own artifact)

    Replaces an existing matching flag, or appends one, so the executor
    finds the artifact where it expects it.
    """
    result = list(argv)
    if spec.tool == "dirb":
        try:
            idx = result.index("-o")
            if idx + 1 < len(result):
                result[idx + 1] = output_path
        except ValueError:
            result.extend(["-o", output_path])
    elif spec.tool == "sqlmap":
        output_dir = str(Path(output_path).parent)
        try:
            idx = result.index("--output-dir")
            if idx + 1 < len(result):
                result[idx + 1] = output_dir
        except ValueError:
            result.extend(["--output-dir", output_dir])
    elif spec.tool == "http_probe":
        return result
    else:
        try:
            idx = result.index("-output")
            if idx + 1 < len(result):
                result[idx + 1] = output_path
        except ValueError:
            result.extend(["-output", output_path])
    return result
