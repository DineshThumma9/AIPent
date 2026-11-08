"""Closed action catalogue, scope checks and argv resolution.

The LLM never supplies argv. It names an action and a target; this module
resolves the fixed command, so the thing a human approves is exactly the
thing that runs.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Literal
from urllib.parse import urlsplit

from app.adapters import hashcat, nikto, nmap, whatweb, zap
from app.adapters.base import FindingDraft
from app.core.config import settings
from app.domain.models import Assessment

ARTIFACT_DIR = settings.artifacts_path

BACKEND_DIR = Path(__file__).resolve().parents[3]
WORDLISTS = {
    "lab": BACKEND_DIR / "data" / "wordlists" / "lab.txt",
    "rockyou": Path("/usr/share/wordlists/rockyou.txt"),
}

NMAP_SAFE_SCRIPTS = {
    "http-title",
    "http-headers",
    "http-enum",
    "ssl-cert",
    "ssl-enum-ciphers",
    "smb-os-discovery",
    "smb-enum-shares",
}


class ScopeError(ValueError):
    """Target is not in the assessment's authorised scope."""


class UnknownAction(ValueError):
    """The plan named an action outside the closed catalogue."""


@dataclass(frozen=True)
class NmapParams:
    profile: Literal["host_discovery", "fast", "service", "full_tcp", "full_service"] = "fast"
    ports: Literal["top100", "top1000", "all"] | list[int] = "top100"
    timing: int = 4
    scripts: list[str] = field(default_factory=list)


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
    for s in p.scripts:
        if s not in NMAP_SAFE_SCRIPTS:
            raise ValueError(f"script {s!r} is not in NMAP_SAFE_SCRIPTS allowlist")
    if p.profile == "host_discovery":
        return nmap.argv(target, [], host_discovery=True, scripts=p.scripts)
    if p.profile == "fast":
        return nmap.fast_scan(target, p.ports, timing=p.timing, scripts=p.scripts)
    if p.profile == "service":
        return nmap.service_scan(target, p.ports, timing=p.timing, scripts=p.scripts)
    if p.profile == "full_tcp":
        return nmap.full_tcp(target, timing=p.timing, scripts=p.scripts)
    if p.profile == "full_service":
        return nmap.full_service(target, timing=p.timing, scripts=p.scripts)
    return nmap.argv(target, assessment.ports or [3000], scripts=p.scripts)


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
    # sqlmap writes its report to stdout by default. The action spec is
    # output="stdout", so the executor captures it into the artifact file.
    return [
        "sqlmap",
        "-u",
        f"http://{target}:{_web_port(assessment)}/",
        "--batch",
        "--dbs",
    ]


def _curl_argv(
    assessment: Assessment,
    target: str,
    _output: Path,
    params: dict[str, Any] | None = None,
) -> list[str]:
    """Resolve the approved method/URL/headers for one safe HTTP probe (curl).

    ``params.path`` is restricted to a path on the scoped target so the probe
    cannot be pointed at a different host. ``params.finding_id`` is stored on
    the approval detail, not in argv, so evidence can be linked after the run.
    """
    p = params or {}
    method = str(p.get("method", "GET")).upper()
    if method not in ("GET", "HEAD", "POST"):
        method = "GET"
    path = str(p.get("path") or "/")
    if not path.startswith("/"):
        path = "/" + path
    url = f"http://{target}:{_web_port(assessment)}{path}"
    headers = json.dumps(p.get("headers") or {}, sort_keys=True)
    try:
        expected = int(p.get("expected_status", 200))
    except (TypeError, ValueError):
        expected = 200
    body = str(p.get("body") or "")
    return ["curl_tool", method, url, headers, str(expected), body]


def _whatweb_argv(
    assessment: Assessment, target: str, output: Path, params: dict[str, Any] | None = None
) -> list[str]:
    return [
        "whatweb",
        "--log-json",
        str(output),
        "--no-errors",
        f"http://{target}:{_web_port(assessment)}/",
    ]


def _hashcat_argv(
    assessment: Assessment, target: str, output: Path, params: dict[str, Any] | None = None
) -> list[str]:
    p = params or {}
    mode = p.get("hash_mode", 0)
    runtime = p.get("runtime", 120)
    wordlist_key = p.get("wordlist", "lab")
    wordlist = WORDLISTS.get(wordlist_key, WORDLISTS["lab"])
    input_path = p.get("input_path") or (_artifact_dir(assessment.id or 0) / f"hashcat-input-{p.get('source_step_id', 0)}.txt")
    potfile = _artifact_dir(assessment.id or 0) / "hashcat.potfile"
    return [
        "hashcat",
        "-m",
        str(mode),
        "-a",
        "0",
        "--potfile-path",
        str(potfile),
        "--outfile",
        str(output),
        "--outfile-format",
        "1",
        "--runtime",
        str(runtime),
        "--status",
        "--status-timer",
        "10",
        str(input_path),
        str(wordlist),
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
            "scripts": f"Safe NSE scripts: {', '.join(sorted(NMAP_SAFE_SCRIPTS))}",
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
            "scripts": f"Safe NSE scripts: {', '.join(sorted(NMAP_SAFE_SCRIPTS))}",
        },
    ),
    "nmap_nse": ActionSpec(
        name="nmap_nse",
        tool="nmap",
        suffix=".nmap.xml",
        output="stdout",
        transport="local",
        ok_codes=(0,),
        build_argv=_nmap_argv,
        parse=lambda text, host, _port: nmap.scan(text, host_override=host),
        param_hints={
            "scripts": f"Safe NSE scripts: {', '.join(sorted(NMAP_SAFE_SCRIPTS))}",
        },
    ),
    "whatweb": ActionSpec(
        name="whatweb",
        tool="whatweb",
        suffix=".whatweb.json",
        output="file",
        transport="local",
        ok_codes=(0,),
        build_argv=_whatweb_argv,
        parse=lambda text, host, port: whatweb.scan(text, host, port),
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
        output="stdout",
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
    "curl_tool": ActionSpec(
        name="curl_tool",
        tool="curl",
        suffix=".curl.json",
        output="file",
        transport="http",
        ok_codes=(0,),
        build_argv=_curl_argv,
        parse=lambda _text, _host, _port: [],
    ),
    "hashcat_crack": ActionSpec(
        name="hashcat_crack",
        tool="hashcat",
        suffix=".hashcat.txt",
        output="file",
        transport="local",
        ok_codes=(0, 1),
        build_argv=_hashcat_argv,
        parse=lambda text, host, port: hashcat.scan(text, host, port),
        param_hints={
            "hash_mode": "Hashcat mode (-m), e.g. 0 for MD5, 100 for SHA-1, 3200 for bcrypt",
            "wordlist": "Allowlisted wordlist: lab (default) or rockyou",
            "runtime": "Max cracking time in seconds (10-300, default 120)",
        },
    ),
}


def _clean_host_and_port(target: str, default_port: int) -> tuple[str, int]:
    clean = target.strip()
    if clean.startswith("http://"):
        clean = clean[7:]
    elif clean.startswith("https://"):
        clean = clean[8:]
    clean = clean.split("/")[0]
    port = default_port
    if ":" in clean:
        parts = clean.split(":")
        clean = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            pass
    return clean, port


def transport_target(target: str) -> str:
    """Map a scope target to its container-visible alias.

    The assessment, findings and report always use the scope target. Only the
    MCP tool argument gets the alias.
    """
    if not settings.mcp_enabled or settings.mcp_transport != "gateway":
        return target

    host, _ = _clean_host_and_port(target, 80)
    if host in {"127.0.0.1", "localhost"}:
        return settings.lab_target_alias

    return host


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
    _, parsed_port = _clean_host_and_port(target, _web_port(assessment))
    port = parsed_port
    target_url = f"http://{alias}:{port}"
    if action in {"recon_services", "nmap_scan", "nmap_nse"}:
        p = NmapParams(**(params or {}))
        for s in p.scripts:
            if s not in NMAP_SAFE_SCRIPTS:
                raise ValueError(f"script {s!r} is not in NMAP_SAFE_SCRIPTS allowlist")
        if isinstance(p.ports, list):
            return "nmap_scan", {
                "target": alias,
                "flags": nmap.mcp_flags(ports=p.ports, timing=p.timing, scripts=p.scripts),
            }
        return "nmap_scan", {
            "target": alias,
            "flags": nmap.mcp_flags(top_ports=p.ports, timing=p.timing, scripts=p.scripts),
        }
    if action == "whatweb":
        return "whatweb_scan", {"target_url": target_url}
    if action == "nikto_scan":
        return "nikto_scan", {"target_url": target_url}
    if action == "zap_baseline":
        return "zap_baseline", {"target_url": target_url}
    if action == "sqlmap_scan":
        return "sqlmap_scan", {
            "target_url": target_url,
            "params": "--batch --dbs",
        }
    if action == "dirb_scan":
        return "dirb_scan", {
            "target_url": target_url,
            "wordlist": "/usr/share/wordlists/dirb/common.txt",
        }
    if action == "hashcat_crack":
        p = params or {}
        hash_string = p.get("hash_value") or p.get("hash_string") or target
        hash_type = str(p.get("hash_mode") or "0")
        return "hashcat_crack", {
            "hash_string": hash_string,
            "hash_type": hash_type,
            "wordlist": "/usr/share/wordlists/rockyou.txt",
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
    spec = get_action(action)
    if (
        settings.mcp_enabled
        and settings.mcp_transport == "gateway"
        and spec.transport != "http"
        and action != "hashcat_crack"
    ):
        return mcp_command(action, assessment, target, params=params)
    output = _artifact_dir(assessment.id or 0) / f"{step_id}{spec.suffix}"
    return spec.build_argv(assessment, target, output, params)


_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})


def _normalize_scope_value(value: str) -> str:
    """Case-fold a host and reduce a URL to its hostname."""
    text = value.strip()
    if "://" in text:
        text = urlsplit(text).hostname or text
    return text.rstrip(".").lower()


def _scope_match(target: str, entries: list[str]) -> bool:
    """True when ``target`` equals an entry, a CIDR member, or its loopback alias.

    Scope still fails closed: anything that cannot be parsed or matched is
    rejected. CIDR entries only match IP-literal targets.
    """
    normalized = _normalize_scope_value(target)
    if not normalized:
        return False

    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        address = None

    for entry in entries:
        candidate = _normalize_scope_value(entry)
        if not candidate:
            continue
        if candidate == normalized:
            return True
        if candidate in _LOOPBACK and normalized in _LOOPBACK:
            return True
        if address is not None and "/" in candidate:
            try:
                network = ipaddress.ip_network(candidate, strict=False)
            except ValueError:
                continue
            if address in network:
                return True
    return False


def check_scope(assessment: Assessment, target: str) -> None:
    if _scope_match(target, assessment.exclusions or []):
        raise ScopeError(f"{target} is not in scope for assessment {assessment.id}")
    if not _scope_match(target, assessment.targets or []):
        raise ScopeError(f"{target} is not in scope for assessment {assessment.id}")


def inject_output_path(argv: list[str], output_path: str, spec: ActionSpec) -> list[str]:
    """Ensure agent-supplied argv writes to the artifact output path.

    Different scanners use different flags for their output destination:

    - dirb: ``-o <path>``
    - nikto: ``-output <path>``
    - curl: no file flag injected (writes its own artifact)

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
    elif spec.tool == "curl":
        return result
    elif spec.tool == "whatweb":
        try:
            idx = result.index("--log-json")
            if idx + 1 < len(result):
                result[idx + 1] = output_path
        except ValueError:
            result.extend(["--log-json", output_path])
    elif spec.tool == "hashcat":
        try:
            idx = result.index("--outfile")
            if idx + 1 < len(result):
                result[idx + 1] = output_path
        except ValueError:
            result.extend(["--outfile", output_path])
    else:
        try:
            idx = result.index("-output")
            if idx + 1 < len(result):
                result[idx + 1] = output_path
        except ValueError:
            result.extend(["-output", output_path])
    return result
