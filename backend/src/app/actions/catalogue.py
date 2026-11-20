"""Closed action catalogue, scope checks and argv resolution.

The LLM never supplies argv. It names an action and a target; this module
resolves the fixed command, so the thing a human approves is exactly the
thing that runs.
"""

from __future__ import annotations

import ipaddress
import json
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Literal
from urllib.parse import parse_qsl, urlsplit

from app.adapters import (
    dirb,
    ffuf,
    hashcat,
    katana,
    nikto,
    nmap,
    nuclei,
    sqlmap,
    whatweb,
    zap,
)
from app.adapters.base import FindingDraft
from app.core.config import settings
from app.domain.models import Assessment
import re 

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


_SQLMAP_PARAM_RE = re.compile(r"^[A-Za-z0-9_.\[\]-]{1,64}$")


def _sqlmap_parameter(value: Any) -> str:
    """Return a safe sqlmap parameter name or raise."""
    text = str(value or "").strip()
    if text and not _SQLMAP_PARAM_RE.match(text):
        raise ValueError(
            "sqlmap parameter must be a simple name "
            "(letters, digits, '_', '.', '[', ']', '-')"
        )
    return text


def _sqlmap_endpoint(
    assessment: Assessment,
    target: str,
    params: dict[str, Any] | None,
    *,
    alias: str | None = None,
) -> str:
    """Resolve the exact endpoint sqlmap should test.

    Relative paths are joined to the scoped target. Absolute URLs are only
    accepted when their host is in scope, and are then rebuilt on the scoped
    host so the probe cannot leave scope.
    """
    p = params or {}
    raw = str(p.get("url") or p.get("path") or "").strip()
    if not raw:
        raise ValueError(
            "sqlmap_scan requires a url path, for example /search?q=1"
        )

    host, port = _clean_host_and_port(target, _web_port(assessment))
    scheme = "https" if port in (443, 8443) else "http"
    if target.strip().lower().startswith("https://"):
        scheme = "https"
    if raw.startswith(("http://", "https://")):
        parsed = urlsplit(raw)
        if not parsed.hostname:
            raise ValueError("sqlmap_scan url has no host")
        check_scope(assessment, parsed.hostname)
        if parsed.port and (not assessment.ports or parsed.port in assessment.ports):
            port = parsed.port
        scheme = parsed.scheme or scheme
        raw = parsed.path or "/"
        if parsed.query:
            raw += "?" + parsed.query

    if not raw.startswith("/"):
        raw = "/" + raw

    parameter = _sqlmap_parameter(p.get("parameter"))
    if str(p.get("method") or "GET").upper() == "GET" and parameter:
        parsed_raw = urlsplit(raw)
        query_keys = {
            key for key, _ in parse_qsl(parsed_raw.query, keep_blank_values=True)
        }
        if parameter not in query_keys:
            query = (
                f"{parsed_raw.query}&{parameter}=1"
                if parsed_raw.query
                else f"{parameter}=1"
            )
            raw = f"{parsed_raw.path or '/'}?{query}"

    return f"{scheme}://{alias or host}:{port}{raw}"


def _sqlmap_bounds(params: dict[str, Any] | None) -> tuple[int, int]:
    p = params or {}
    level = min(max(int(p.get("level") or 2), 1), 3)
    risk = min(max(int(p.get("risk") or 1), 1), 2)
    return level, risk


def _sqlmap_argv(
    assessment: Assessment, target: str, _output: Path, params: dict[str, Any] | None = None
) -> list[str]:
    """Build a bounded, targeted sqlmap invocation.

    The model supplies the endpoint and parameter; Python owns every flag, so
    the approved argv is exactly the probe that runs. sqlmap writes its report
    to stdout (the action spec is ``output="stdout"``).
    """
    p = params or {}
    url = _sqlmap_endpoint(assessment, target, p)
    level, risk = _sqlmap_bounds(p)
    argv = [
        "sqlmap",
        "-u",
        url,
        "--batch",
        "--level",
        str(level),
        "--risk",
        str(risk),
        "--timeout",
        "10",
        "--retries",
        "1",
        "--threads",
        "2",
    ]

    parameter = _sqlmap_parameter(p.get("parameter"))
    if parameter:
        argv += ["-p", parameter]

    if str(p.get("method") or "GET").upper() == "POST":
        data = p.get("data")
        if not data:
            raise ValueError("sqlmap_scan POST requires data")
        argv += ["--data", str(data)]
        if str(data).lstrip().startswith("{"):
            argv += ["--headers", "Content-Type: application/json"]

    cookie = p.get("cookie")
    if cookie:
        argv += ["--cookie", str(cookie)]

    return argv


def _curl_request_argv(
    assessment: Assessment,
    target: str,
    output: Path,
    params: dict[str, Any] | None = None,
) -> list[str]:
    tool, arguments = mcp_tool_call("curl_request", assessment, target, params=params)
    return ["mcp", tool, json.dumps(arguments, sort_keys=True)]



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


def _ffuf_argv(
    assessment: Assessment, target: str, output: Path, params: dict[str, Any] | None = None
) -> list[str]:
    p = params or {}
    return ffuf.argv(
        target=target,
        port=_web_port(assessment),
        output_path=str(output),
        wordlist=p.get("wordlist"),
        path=p.get("path") or p.get("endpoint"),
    )


def _katana_argv(
    assessment: Assessment, target: str, output: Path, params: dict[str, Any] | None = None
) -> list[str]:
    p = params or {}
    depth = int(p.get("depth", 3))
    return katana.argv(
        target=target,
        port=_web_port(assessment),
        output_path=str(output),
        depth=depth,
    )


def _nuclei_argv(
    assessment: Assessment, target: str, output: Path, params: dict[str, Any] | None = None
) -> list[str]:
    p = params or {}
    return nuclei.argv(
        target=target,
        port=_web_port(assessment),
        output_path=str(output),
        tags=p.get("tags"),
        severity=p.get("severity"),
    )



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
        parse=lambda text, host, port: sqlmap.scan(text, host, port),
    ),
    "dirb_scan": ActionSpec(
        name="dirb_scan",
        tool="dirb",
        suffix=".dirb.txt",
        output="file",
        transport="local",
        ok_codes=(0, 1),
        build_argv=_dirb_argv,
        parse=lambda text, host, port: dirb.scan(text, host, port),
    ),
    "curl_request": ActionSpec(
        name="curl_request",
        tool="curl_request",
        suffix=".curl.json",
        output="file",
        transport="mcp",
        ok_codes=(0,),
        build_argv=_curl_request_argv,
        parse=lambda _text, _host, _port: [],
        param_hints={
            "method": "HTTP method (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD)",
            "url": "Target URL or path (e.g. /rest/user/login)",
            "headers": "Request headers dictionary",
            "body": "Request body string or JSON",
            "follow_redirects": "Whether to follow HTTP redirects (default true)",
        },
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
    "ffuf_scan": ActionSpec(
        name="ffuf_scan",
        tool="ffuf",
        suffix=".ffuf.json",
        output="file",
        transport="local",
        ok_codes=(0, 1),
        build_argv=_ffuf_argv,
        parse=lambda text, host, port: ffuf.scan(text, host, port),
        param_hints={
            "path": "Base path to fuzz, e.g. /api/FUZZ (defaults to /FUZZ)",
            "wordlist": "Path to wordlist inside container or local environment",
        },
    ),
    "katana_crawl": ActionSpec(
        name="katana_crawl",
        tool="katana",
        suffix=".katana.txt",
        output="file",
        transport="local",
        ok_codes=(0, 1),
        build_argv=_katana_argv,
        parse=lambda text, host, port: katana.scan(text, host, port),
        param_hints={
            "depth": "Crawl depth (default: 3)",
        },
    ),
    "nuclei_scan": ActionSpec(
        name="nuclei_scan",
        tool="nuclei",
        suffix=".nuclei.jsonl",
        output="file",
        transport="local",
        ok_codes=(0, 1),
        build_argv=_nuclei_argv,
        parse=lambda text, host, port: nuclei.scan(text, host, port),
        param_hints={
            "tags": "Template tags to filter by (e.g. cve, xss, misconfig)",
            "severity": "Severity filter (e.g. low, medium, high, critical)",
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
    """Map a scope target to its container-visible host.

    The assessment, findings and report always use the scope target. Only the
    MCP tool argument gets the alias.
    """
    host, _ = _clean_host_and_port(target, 80)
    if not settings.mcp_enabled or settings.mcp_transport != "gateway":
        return host

    if host in {"127.0.0.1", "localhost"}:
        return settings.lab_target_alias

    return host


def _curl_tool_args(
    assessment: Assessment,
    target: str,
    p: dict[str, Any],
    alias: str,
) -> dict[str, Any]:
    """Build the gateway arguments for one curl request."""
    method = str(p.get("method") or "GET").upper()
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        method = "GET"
    raw_url = str(p.get("url") or p.get("path") or "").strip()
    if not raw_url or raw_url == "/":
        # Models sometimes put the full endpoint in `target` and leave
        # `path` at its default. Honour the target's path instead of
        # silently probing the site root.
        parsed_target = urlsplit(target if "://" in target else f"//{target}")
        if parsed_target.path and parsed_target.path != "/":
            raw_url = parsed_target.path
            if parsed_target.query:
                raw_url += "?" + parsed_target.query
    raw_url = raw_url or "/"
    _, port = _clean_host_and_port(target, _web_port(assessment))
    if raw_url.startswith(("http://", "https://")):
        parsed = urlsplit(raw_url)
        if not parsed.hostname:
            raise ValueError("curl_request url has no host")
        check_scope(assessment, parsed.hostname)
        if parsed.port and (not assessment.ports or parsed.port in assessment.ports):
            port = parsed.port
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        url = f"{'https' if port in (443, 8443) else 'http'}://{alias}:{port}{path}"
    else:
        if not raw_url.startswith("/"):
            raw_url = "/" + raw_url
        url = f"{'https' if port in (443, 8443) else 'http'}://{alias}:{port}{raw_url}"
    raw_headers = dict(p.get("headers") or {})
    headers = {str(k).rstrip(": \t"): str(v) for k, v in raw_headers.items()}
    raw_body = p.get("body")
    if isinstance(raw_body, dict):
        body = json.dumps(raw_body)
        if not any(k.lower() == "content-type" for k in headers):
            headers["Content-Type"] = "application/json"
    elif raw_body:
        body = str(raw_body)
        if body.strip().startswith("{") and body.strip().endswith("}") and not any(k.lower() == "content-type" for k in headers):
            headers["Content-Type"] = "application/json"
    else:
        if method in ("POST", "PUT", "PATCH") and any("application/json" in str(v).lower() for v in headers.values()):
            body = "{}"
        else:
            body = None

    tool_args: dict[str, Any] = {
        "url": url,
        "method": method,
        "follow_redirects": bool(p.get("follow_redirects", True)),
    }
    if headers:
        tool_args["headers"] = headers
    if body is not None:
        tool_args["body"] = body
    if "timeout_seconds" in p:
        tool_args["timeout_seconds"] = int(p["timeout_seconds"])
    return tool_args


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
        p = params or {}
        url = _sqlmap_endpoint(assessment, target, p, alias=alias)
        level, risk = _sqlmap_bounds(p)
        flags = [
            "--batch",
            f"--level={level}",
            f"--risk={risk}",
            "--timeout=10",
            "--retries=1",
            "--threads=2",
        ]

        parameter = _sqlmap_parameter(p.get("parameter"))
        if parameter:
            flags += ["-p", parameter]

        if str(p.get("method") or "GET").upper() == "POST":
            data = p.get("data")
            if not data:
                raise ValueError("sqlmap_scan POST requires data")
            flags += ["--data", shlex.quote(str(data))]
            if str(data).lstrip().startswith("{"):
                flags += ["--headers", shlex.quote("Content-Type: application/json")]

        cookie = p.get("cookie")
        if cookie:
            flags += ["--cookie", shlex.quote(str(cookie))]

        return "sqlmap_scan", {"target_url": url, "params": " ".join(flags)}
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
    if action == "curl_request":
        p = params or {}
        batch = p.get("requests") or []
        if batch:
            if len(batch) > 3:
                raise ValueError("curl_request accepts at most 3 batched requests")
            requests: list[dict[str, Any]] = []
            for item in batch:
                if hasattr(item, "model_dump"):
                    item = item.model_dump(exclude_none=True)
                args = _curl_tool_args(assessment, target, item, alias)
                if args["method"] not in {"GET", "HEAD", "OPTIONS"}:
                    raise ValueError(
                        "batched curl_request requests must use GET, HEAD, or OPTIONS"
                    )
                requests.append(args)
            return "curl_request", {"batch": requests}
        return "curl_request", _curl_tool_args(assessment, target, p, alias)
    if action == "ffuf_scan":
        p = params or {}
        raw_path = p.get("path") or p.get("endpoint")
        fuzz_url = ffuf.normalize_fuzz_url(target_url, raw_path)
        tool_args: dict[str, Any] = {"target_url": fuzz_url}
        if p.get("wordlist"):
            tool_args["wordlist"] = p["wordlist"]
        return "ffuf_scan", tool_args
    if action == "katana_crawl":
        p = params or {}
        tool_args = {"target_url": target_url}
        if "depth" in p:
            tool_args["depth"] = int(p["depth"])
        return "katana_crawl", tool_args
    if action == "nuclei_scan":
        p = params or {}
        tool_args = {"target_url": target_url}
        if p.get("tags"):
            tool_args["tags"] = str(p["tags"])
        if p.get("severity"):
            tool_args["severity"] = str(p["severity"])
        return "nuclei_scan", tool_args

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
    elif spec.tool in ("curl", "curl_request"):
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
