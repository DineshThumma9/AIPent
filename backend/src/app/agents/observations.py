"""Observation builder for the V2 loop.

Transforms executed Steps, Evidence, and Findings into compact Observations.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
import re
from typing import Any
import urllib.parse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

logger = logging.getLogger(__name__)

from app.actions.evidence import SQLMAP_PROOF
from app.agents.contracts import ActionRequest, Observation
from app.domain.models import Evidence, Finding, Step, StepStatus
from app.parsers import filter_self_routes, read_sidecar_manifest


def _curl_batch_facts(entry: dict[str, Any]) -> dict[str, Any]:
    """Normalize one result from a batched curl artifact."""
    request = entry.get("request") if isinstance(entry.get("request"), dict) else {}
    result = entry.get("result") if isinstance(entry.get("result"), dict) else {}
    result_request = (
        result.get("request") if isinstance(result.get("request"), dict) else {}
    )
    response = (
        result.get("response") if isinstance(result.get("response"), dict) else {}
    )

    raw_status = response.get("status_code") or result.get("code")
    try:
        status = int(raw_status) if raw_status is not None else None
    except (TypeError, ValueError):
        status = None

    body = response.get("body") or result.get("body") or ""
    excerpt = ""
    json_items: int | None = None
    if isinstance(body, str):
        cleaned = re.sub(
            r"<style[^>]*>[\s\S]*?</style>", "", body, flags=re.IGNORECASE
        )
        excerpt = cleaned[:300]
    elif body:
        excerpt = str(body)[:300]
    try:
        parsed_body = json.loads(body) if isinstance(body, str) else body
        rows = parsed_body.get("data") if isinstance(parsed_body, dict) else None
        if isinstance(rows, list):
            json_items = len(rows)
    except (TypeError, ValueError):
        json_items = None

    error = entry.get("error") or result.get("error_details") or result.get("error")
    if error is None and result.get("ok") is False and status is None:
        error = result.get("message") or "request failed"

    return {
        "index": entry.get("index"),
        "url": str(result_request.get("url") or request.get("url") or ""),
        "method": str(
            result_request.get("method") or request.get("method") or "GET"
        ).upper(),
        "status_code": status,
        "json_items": json_items,
        "body_excerpt": excerpt,
        "error": str(error)[:300] if error else None,
    }


def _is_auth_url(url: str) -> bool:
    """Return True when the request URL targets an authentication endpoint."""
    return any(term in url.lower() for term in ("login", "auth", "token", "session", "register", "signup", "signin", "oauth"))


def _extract_auth_session(
    parsed_body: Any,
    headers: dict[str, Any],
    request_url: str = "",
) -> dict[str, Any] | None:
    """Extract auth token, session identifiers, and user metadata from response.

    Only extracts generic top-level token keys when the request URL targets an
    auth endpoint, to avoid mis-identifying CSRF tokens or reset tokens as JWTs.
    """
    auth_data: dict[str, Any] = {}
    is_auth_endpoint = _is_auth_url(request_url)

    if isinstance(parsed_body, dict):
        # Case A: {"authentication": {"token": "...", "bid": 6, "umail": "..."}}
        # This shape is specific enough to always extract.
        auth_obj = parsed_body.get("authentication")
        if isinstance(auth_obj, dict):
            if "token" in auth_obj and auth_obj["token"]:
                auth_data["token"] = str(auth_obj["token"])
            if "bid" in auth_obj and auth_obj["bid"] is not None:
                auth_data["basket_id"] = auth_obj["bid"]
            if "umail" in auth_obj and auth_obj["umail"]:
                auth_data["email"] = str(auth_obj["umail"])
            if "id" in auth_obj and auth_obj["id"] is not None:
                auth_data["user_id"] = auth_obj["id"]

        # Case B: Top-level token-like keys — only on auth endpoints, and only JWT-shaped values.
        # shortcut: non-JWT bearer tokens (opaque strings) skipped unless on an auth endpoint
        if is_auth_endpoint:
            for tok_key in ("token", "access_token", "jwt", "id_token", "authToken", "bearerToken"):
                val = parsed_body.get(tok_key)
                if isinstance(val, str) and val and val.startswith("eyJ"):
                    auth_data.setdefault("token", val)

        # Case C: Nested in "data" object — same JWT-shape guard
        data_obj = parsed_body.get("data")
        if isinstance(data_obj, dict) and is_auth_endpoint:
            for tok_key in ("token", "access_token", "jwt", "id_token", "authToken"):
                val = data_obj.get(tok_key)
                if isinstance(val, str) and val and val.startswith("eyJ"):
                    auth_data.setdefault("token", val)
            if "bid" in data_obj and data_obj["bid"] is not None:
                auth_data.setdefault("basket_id", data_obj["bid"])
            if "id" in data_obj and data_obj["id"] is not None:
                auth_data.setdefault("user_id", data_obj["id"])
            if "email" in data_obj and data_obj["email"]:
                auth_data.setdefault("email", str(data_obj["email"]))

        # Additional identifiers at top level
        if "bid" in parsed_body and parsed_body["bid"] is not None:
            auth_data.setdefault("basket_id", parsed_body["bid"])
        if "user" in parsed_body and isinstance(parsed_body["user"], dict):
            u = parsed_body["user"]
            if "id" in u and u["id"] is not None:
                auth_data.setdefault("user_id", u["id"])
            if "email" in u and u["email"]:
                auth_data.setdefault("email", str(u["email"]))

    # Check Set-Cookie headers for session cookies — only on auth endpoints
    if is_auth_endpoint and isinstance(headers, dict):
        for k, v in headers.items():
            if str(k).lower() == "set-cookie":
                raw_cookies = v if isinstance(v, list) else [v] if isinstance(v, str) else []
                for header_val in raw_cookies:
                    if not isinstance(header_val, str):
                        continue
                    # Only the first semicolon-separated piece is the cookie name=value pair;
                    # subsequent pieces are attributes like Path=/session, HttpOnly, SameSite.
                    cookie_pair = header_val.split(";")[0].strip()
                    if "=" not in cookie_pair:
                        continue
                    # Skip invalidated/deleted cookies
                    if "deleted" in cookie_pair.lower() or "max-age=0" in header_val.lower():
                        continue
                    cookie_name = cookie_pair.split("=")[0].strip().lower()
                    if any(s in cookie_name for s in ("session", "connect.sid", "jwt", "token", "auth", "sid", "sess")):
                        auth_data.setdefault("cookie", cookie_pair)

    if not auth_data.get("token") and not auth_data.get("cookie"):
        return None

    if "token" in auth_data:
        token_str = auth_data["token"]
        auth_data["token_type"] = "Bearer"
        auth_data["authorization_header"] = f"Bearer {token_str}"

    return auth_data


def _session_file_path(
    assessment_id: int | None,
    output_path: str | Path | None,
) -> Path | None:
    """Resolve the session.json path from absolute output_path or assessment_id."""
    if output_path and Path(output_path).is_absolute():
        return Path(output_path).parent / "session.json"
    if assessment_id:
        try:
            from app.core.config import settings
            return settings.artifacts_path / str(assessment_id) / "session.json"
        except Exception:
            return None
    return None


def _save_session_file(
    assessment_id: int | None,
    output_path: str | Path | None,
    auth_data: dict[str, Any],
) -> str | None:
    if not auth_data:
        return None
    session_file = _session_file_path(assessment_id, output_path)
    if session_file:
        try:
            session_file.parent.mkdir(parents=True, exist_ok=True)
            existing: dict[str, Any] = {}
            if session_file.exists():
                try:
                    existing = json.loads(session_file.read_text(encoding="utf-8"))
                except Exception:
                    existing = {}

            # Clear user-specific identity keys when a new token or cookie credential arrives
            # so multiple accounts or role switches don't inherit previous user/basket IDs.
            new_token = auth_data.get("token")
            new_cookie = auth_data.get("cookie")
            token_changed = bool(new_token and new_token != existing.get("token"))
            cookie_changed = bool(new_cookie and new_cookie != existing.get("cookie"))

            if token_changed or cookie_changed:
                for key in ("user_id", "basket_id", "email"):
                    existing.pop(key, None)
                if token_changed:
                    for key in ("authorization_header", "token_type", "cookie"):
                        existing.pop(key, None)
                if cookie_changed and not new_token:
                    for key in ("token", "authorization_header", "token_type"):
                        existing.pop(key, None)

            existing.update(auth_data)
            session_file.write_text(json.dumps(existing, indent=2), encoding="utf-8")
            return str(session_file)
        except Exception as exc:
            logger.warning("Failed to save session file %s: %s", session_file, exc)
    return None


def _load_session_file(
    assessment_id: int | None,
    output_path: str | Path | None,
) -> dict[str, Any] | None:
    session_file = _session_file_path(assessment_id, output_path)
    if session_file and session_file.exists():
        try:
            return json.loads(session_file.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


def _extract_curl_entities(
    request_url: str,
    headers: dict[str, Any],
    body: Any,
    output_path: str | Path | None = None,
) -> tuple[list[str], list[str], list[str], list[dict[str, Any]]]:
    """Extract candidate routes, file links, JSON keys, and forms using app.parsers."""
    from app.parsers import parse_content, read_sidecar_manifest

    # 1. Check sidecar manifest first if output_path is provided
    if output_path:
        manifest = read_sidecar_manifest(output_path)
        if manifest:
            clean_routes = filter_self_routes(manifest.get("routes", []) or [], request_url)
            return (
                clean_routes,
                manifest.get("files", []) or [],
                manifest.get("keys", []) or [],
                manifest.get("forms", []) or [],
            )

    # 2. Parse content in-memory via app.parsers
    if not isinstance(body, str):
        if isinstance(body, (dict, list)):
            body_str = json.dumps(body)
        else:
            body_str = str(body) if body is not None else ""
    else:
        body_str = body

    ct = ""
    if isinstance(headers, dict):
        for k, v in headers.items():
            if str(k).lower() == "content-type":
                ct = str(v).lower()
                break

    parsed = parse_content(
        content=body_str,
        url=request_url,
        content_type=ct,
        file_path=output_path,
    )
    clean_routes = filter_self_routes(parsed.routes, request_url)
    forms_dict = [f.to_dict() for f in parsed.forms]

    return (
        clean_routes,
        parsed.files,
        parsed.keys,
        forms_dict,
    )


async def _async_observation_from_step(session: AsyncSession, step: Step) -> Observation:
    """Legacy async DB-backed observation loader."""
    # Find all evidence produced for this step
    result = await session.execute(
        select(Evidence).where(Evidence.step_id == step.id)
    )
    evidences = list(result.scalars().all())
    evidence_ids = [e.id for e in evidences if e.id is not None]

    # Find associated findings
    finding_id_set = {e.finding_id for e in evidences if e.finding_id is not None}
    findings: list[Finding] = []
    if finding_id_set:
        f_result = await session.execute(
            select(Finding).where(Finding.id.in_(list(finding_id_set)))
        )
        findings = list(f_result.scalars().all())

    # Distinguish findings created in this step vs updated
    created_ids: list[int] = []
    for f in findings:
        if f.id is not None:
            created_ids.append(f.id)

    return _build_pure_observation(
        step=step,
        finding_ids=created_ids,
        evidence_ids=evidence_ids,
        findings=findings,
    )


def observation_from_step(
    step_or_session: Step | AsyncSession,
    step: Step | None = None,
    *,
    finding_ids: list[int] | None = None,
    evidence_ids: list[int] | None = None,
    findings: list[Finding] | None = None,
) -> Observation | Any:
    """Build a compact Observation from an executed step.

    Can be called synchronously with (step, finding_ids=..., evidence_ids=...)
    with zero database dependencies, or asynchronously with (session, step).
    """
    if (
        isinstance(step_or_session, AsyncSession)
        and step is not None
        and finding_ids is None
        and findings is None
    ):
        return _async_observation_from_step(step_or_session, step)

    actual_step = step if isinstance(step_or_session, AsyncSession) else step_or_session
    if actual_step is None:
        raise ValueError("step is required")

    return _build_pure_observation(
        step=actual_step,
        finding_ids=finding_ids,
        evidence_ids=evidence_ids,
        findings=findings,
    )


def _build_pure_observation(
    step: Step,
    *,
    finding_ids: list[int] | None = None,
    evidence_ids: list[int] | None = None,
    findings: list[Finding] | None = None,
) -> Observation:
    """Pure in-memory observation constructor with zero database queries."""
    created_ids: list[int] = list(finding_ids or [])
    updated_ids: list[int] = []
    evidence_ids = list(evidence_ids or [])
    findings = list(findings or [])

    artifact_info: dict[str, Any] | None = None
    if step.output_path:
        artifact_info = {
            "path": step.output_path,
            "sha256": step.output_sha256 or "",
            "kind": ".nmap.xml" if "nmap" in step.action or "recon" in step.action else ".txt",
        }

    if step.status != StepStatus.SUCCEEDED.value:
        status_map = {
            StepStatus.FAILED.value: "failed",
            StepStatus.TIMEOUT.value: "timeout",
            StepStatus.BLOCKED.value: "blocked",
            StepStatus.REJECTED.value: "rejected",
        }
        obs_status = status_map.get(step.status, "error")
        return Observation(
            ok=False,
            status=obs_status,  # type: ignore[arg-type]
            action=step.action,
            target=step.target,
            step_id=step.id,
            summary=step.error or f"Action {step.action} ended with status {step.status}.",
            findings_created=[],
            findings_updated=[],
            evidence_ids=evidence_ids,
            artifact=artifact_info,
            errors=[step.error] if step.error else [f"status: {step.status}"],
        )

    # For successful recon_services
    if step.action in ("recon_services", "nmap_scan"):
        if findings:
            service_summaries = [f.title for f in findings if f.title]
            port_count = len(findings)
            summary_str = f"{port_count} open port{'s' if port_count != 1 else ''}: {', '.join(service_summaries[:5])}"
            has_http = any("http" in (f.title or "").lower() for f in findings)
            next_hint = (
                "HTTP is present on port(s). Technology fingerprinting or web discovery can discriminate which surface to test first."
                if has_http
                else "Non-HTTP services found. Evaluate open ports for banner info or service discovery."
            )
        else:
            summary_str = f"0 open ports discovered on {step.target}"
            next_hint = "No open ports found. Verify target availability or consider widening port range."

        return Observation(
            ok=True,
            status="succeeded",
            action=step.action,
            target=step.target,
            step_id=step.id,
            summary=summary_str,
            findings_created=created_ids,
            findings_updated=updated_ids,
            evidence_ids=evidence_ids,
            artifact=artifact_info,
            errors=[],
            next_hint=next_hint,
        )

    if step.action == "nikto_scan":
        count = len(findings)
        titles = [f.title for f in findings if f.title][:3]
        summary_str = (
            f"{count} web server finding{'s' if count != 1 else ''} discovered by Nikto: {', '.join(titles)}"
            if count
            else "Nikto scan completed; 0 candidate issues found."
        )
        return Observation(
            ok=True,
            status="succeeded",
            action=step.action,
            target=step.target,
            step_id=step.id,
            summary=summary_str,
            findings_created=created_ids,
            findings_updated=updated_ids,
            evidence_ids=evidence_ids,
            artifact=artifact_info,
            errors=[],
            next_hint="Evaluate candidate findings for validation or probe them directly with curl_request.",
        )

    if step.action == "zap_baseline":
        count = len(findings)
        titles = [f.title for f in findings if f.title][:3]
        summary_str = (
            f"{count} passive ZAP alert{'s' if count != 1 else ''} identified: {', '.join(titles)}"
            if count
            else "OWASP ZAP baseline scan completed with 0 alerts."
        )
        return Observation(
            ok=True,
            status="succeeded",
            action=step.action,
            target=step.target,
            step_id=step.id,
            summary=summary_str,
            findings_created=created_ids,
            findings_updated=updated_ids,
            evidence_ids=evidence_ids,
            artifact=artifact_info,
            errors=[],
            next_hint="ZAP alerts are candidates, not confirmed vulnerabilities. Form a hypothesis and probe with curl_request.",
        )

    if step.action == "dirb_scan":
        count = len(findings)
        endpoints = [f.endpoint or f.title for f in findings if f.endpoint or f.title][:5]
        summary_str = (
            f"{count} web path{'s' if count != 1 else ''} discovered by dirb: {', '.join(endpoints)}"
            if count
            else "dirb scan completed; 0 paths discovered."
        )
        return Observation(
            ok=True,
            status="succeeded",
            action=step.action,
            target=step.target,
            step_id=step.id,
            summary=summary_str,
            findings_created=created_ids,
            findings_updated=updated_ids,
            evidence_ids=evidence_ids,
            artifact=artifact_info,
            errors=[],
            next_hint="Discovered paths may expose sensitive resources or APIs. Test endpoints for access control.",
        )

    if step.action == "ffuf_scan":
        from app.adapters.ffuf import extract_wildcard_lengths

        endpoints = [f.endpoint or f.title for f in findings if f.endpoint or f.title]

        # Inspect raw FFUF output file if available on disk for exact status codes and lengths
        ffuf_items_by_path: dict[str, dict[str, Any]] = {}
        wildcard_lengths: set[int] = set()
        raw_lengths_by_path: dict[str, int] = {}
        out_p = Path(step.output_path) if step.output_path else None
        if out_p and out_p.exists() and out_p.is_file() and out_p.stat().st_size <= 5_000_000:
            try:
                raw_json = json.loads(out_p.read_text(encoding="utf-8", errors="replace"))
                if isinstance(raw_json, dict) and isinstance(raw_json.get("results"), list):
                    raw_results = raw_json["results"]
                    wildcard_lengths = extract_wildcard_lengths(raw_results)

                    for item in raw_results:
                        if isinstance(item, dict):
                            u = str(item.get("url") or "")
                            if "://" in u:
                                p = urllib.parse.urlsplit(u).path or "/"
                            else:
                                p = urllib.parse.urlsplit(u).path if u else ""
                            if not p and isinstance(item.get("input"), dict):
                                fz = item["input"].get("FUZZ", "")
                                p = f"/{fz}" if fz else ""
                            if p:
                                if not p.startswith("/"):
                                    p = f"/{p}"
                                l = int(item.get("length") or 0)
                                raw_lengths_by_path[p] = l
                                if l in wildcard_lengths:
                                    continue
                                ffuf_items_by_path[p] = item
            except Exception:
                pass

        # Discard any endpoints whose raw length matched wildcard fallback lengths
        if raw_lengths_by_path and wildcard_lengths:
            endpoints = [
                ep for ep in endpoints
                if raw_lengths_by_path.get(ep) not in wildcard_lengths
            ]

        # Fallback if findings list is empty but artifact has items
        if not endpoints and ffuf_items_by_path:
            endpoints = list(ffuf_items_by_path.keys())

        count = len(endpoints)
        sensitive = [
            ep
            for ep in endpoints
            if any(
                kw in ep.lower()
                for kw in (
                    "admin",
                    "api",
                    "rest",
                    "swagger",
                    "graphql",
                    "config",
                    "backup",
                    "db",
                    ".git",
                    ".env",
                    "login",
                    "secret",
                    "password",
                )
            )
        ]
        sample = endpoints[:5]

        # Normalize candidates across findings and artifact fallback
        candidates: list[tuple[str, int, int]] = []
        if findings:
            for f in findings:
                ep = f.endpoint or f.title
                if not ep:
                    continue
                # Skip if raw response identified this endpoint as a wildcard SPA response
                if raw_lengths_by_path.get(ep) in wildcard_lengths:
                    continue
                item = ffuf_items_by_path.get(ep)
                if item:
                    st = int(item.get("status") or 200)
                    sz = int(item.get("length") or 0)
                else:
                    m = re.search(r"\(HTTP (\d+)\)", f.title or "")
                    st = int(m.group(1)) if m else 200
                    sz = 0
                candidates.append((ep, st, sz))
        if not candidates and ffuf_items_by_path:
            for ep, item in ffuf_items_by_path.items():
                candidates.append((ep, int(item.get("status") or 200), int(item.get("length") or 0)))

        live_entries: list[tuple[str, int, int]] = []
        error_entries: list[tuple[str, int, int]] = []
        for ep, st, sz in candidates:
            if st in (200, 201, 204, 301, 302, 307, 308, 401, 403):
                live_entries.append((ep, st, sz))
            elif st >= 500:
                error_entries.append((ep, st, sz))

        def _fmt_size(b: int) -> str:
            if b <= 0:
                return "0B"
            if b < 1024:
                return f"{b}B"
            return f"{b / 1024:.1f}KB"

        live_details = [
            f"{ep} (HTTP {st}, {_fmt_size(sz)})" for ep, st, sz in live_entries
        ]

        if count > 0:
            summary_str = (
                f"{count} web endpoint{'s' if count != 1 else ''} discovered by FFUF: {', '.join(sample)}"
            )
            if sensitive:
                summary_str += f" (sensitive: {', '.join(sensitive[:3])})"
            if live_entries:
                summary_str += f" | Live ({len(live_entries)}): {', '.join(live_details[:4])}"
            if error_entries:
                summary_str += f" | {len(error_entries)} endpoint(s) returned HTTP 500"

            sensitive_live = [ep for ep, _, _ in live_entries if ep in sensitive]
            sensitive_errors = [ep for ep, _, _ in error_entries if ep in sensitive]
            if sensitive:
                if sensitive_live:
                    next_hint = (
                        f"FFUF discovered sensitive surfaces ({', '.join(sensitive[:3])}). "
                        f"Live targets: {', '.join(sensitive_live[:3])}. "
                        f"Probe live endpoints with curl_request or inspect sidecar manifest via read_artifact(step_id={step.id}, view='routes')."
                    )
                elif sensitive_errors:
                    live_sample = [ep for ep, _, _ in live_entries[:3]]
                    next_hint = (
                        f"FFUF discovered sensitive surfaces ({', '.join(sensitive[:3])}), but they returned HTTP 500. "
                        f"Active live endpoints: {', '.join(live_sample) if live_sample else 'none'}. "
                        f"Probe live endpoints with curl_request or inspect sidecar manifest via read_artifact(step_id={step.id}, view='routes')."
                    )
                else:
                    live_sample = [ep for ep, _, _ in live_entries[:3]]
                    next_hint = (
                        f"FFUF discovered sensitive surfaces ({', '.join(sensitive[:3])}), but none were directly accessible. "
                        f"Active live endpoints: {', '.join(live_sample) if live_sample else 'none'}. "
                        f"Probe live endpoints with curl_request or inspect sidecar manifest via read_artifact(step_id={step.id}, view='routes')."
                    )
            else:
                live_sample = [ep for ep, _, _ in live_entries[:3]]
                next_hint = (
                    f"FFUF discovered {count} endpoint(s). Live ({len(live_entries)}): {', '.join(live_sample) if live_sample else 'none'}. "
                    f"Probe live routes with curl_request or inspect sidecar manifest via read_artifact(step_id={step.id}, view='routes')."
                )
        else:
            summary_str = "FFUF scan completed; 0 paths discovered."
            next_hint = "FFUF fuzzing completed with 0 matches for the given wordlist."

        return Observation(
            ok=True,
            status="succeeded",
            action=step.action,
            target=step.target,
            step_id=step.id,
            summary=summary_str,
            findings_created=created_ids,
            findings_updated=updated_ids,
            evidence_ids=evidence_ids,
            artifact=artifact_info,
            facts={
                "discovered_endpoints": endpoints,
                "sensitive_endpoints": sensitive,
                "total_discovered": count,
                "live_endpoints": [ep for ep, _, _ in live_entries],
                "live_details": [
                    {"endpoint": ep, "status": st, "length": sz} for ep, st, sz in live_entries
                ],
                "server_errors": [ep for ep, _, _ in error_entries],
                "manifest_routes_hint": f"Call read_artifact(step_id={step.id}, view='routes') for filtered reachable endpoints.",
            },
            errors=[],
            next_hint=next_hint,
        )

    if step.action == "curl_request":
        p_data: dict[str, Any] = {}
        if step.output_path and Path(step.output_path).exists():
            try:
                loaded = json.loads(
                    Path(step.output_path).read_text(
                        encoding="utf-8", errors="replace"
                    )
                )
                if isinstance(loaded, dict):
                    p_data = loaded
            except Exception:
                p_data = {}

        if p_data.get("batch"):
            results = [
                _curl_batch_facts(entry)
                for entry in (p_data.get("results") or [])
                if isinstance(entry, dict)
            ]
            batch_routes: set[str] = set()
            batch_files: set[str] = set()
            manifest = read_sidecar_manifest(step.output_path) if step.output_path else None
            if manifest is not None:
                batch_routes = set(manifest.get("routes") or [])
                batch_files = set(manifest.get("files") or [])
            else:
                for entry in (p_data.get("results") or []):
                    if isinstance(entry, dict):
                        res_obj = entry.get("result") if isinstance(entry.get("result"), dict) else {}
                        resp_obj = res_obj.get("response") if isinstance(res_obj.get("response"), dict) else {}
                        b_url = str(entry.get("request", {}).get("url") or res_obj.get("request", {}).get("url") or "")
                        b_hdrs = resp_obj.get("headers") or {}
                        b_body = resp_obj.get("body") or res_obj.get("body") or ""
                        r_routes, r_files, *_ = _extract_curl_entities(b_url, b_hdrs, b_body)
                        batch_routes.update(r_routes)
                        batch_files.update(r_files)

            parts: list[str] = []
            for item in results:
                label = f"#{item['index']}" if item.get("index") is not None else "#"
                if item.get("error"):
                    parts.append(
                        f"{label} {item['method']} {item['url']} -> error: {item['error']}"
                    )
                else:
                    part = (
                        f"{label} {item['method']} {item['url']} "
                        f"-> HTTP {item.get('status_code')}"
                    )
                    if item.get("json_items") is not None:
                        part += f" ({item['json_items']} items)"
                    parts.append(part)
            summary_str = (
                f"{len(results)} probes: " + "; ".join(parts)
                if results
                else "Curl batch produced no results."
            )
            statuses = [
                item["status_code"]
                for item in results
                if item.get("status_code") is not None
            ]
            if any(item.get("error") for item in results):
                next_hint = "Some batched requests encountered transport errors (connection or network failure)."
            elif any(status >= 500 for status in statuses):
                next_hint = "One or more batched requests returned 5xx server errors."
            elif any(status in (401, 403) for status in statuses):
                next_hint = "One or more batched requests returned 401/403 (authentication/authorization required)."
            elif any(200 <= status < 300 for status in statuses):
                next_hint = "Batched probes yielded 2xx responses. Evaluate response differentials across endpoints."
            else:
                next_hint = "Compare observed results against expected_observation and would_falsify."

            facts_dict: dict[str, Any] = {"batch": True, "results": results}
            if batch_routes:
                facts_dict["extracted_routes"] = sorted(list(batch_routes))[:100]
            if batch_files:
                facts_dict["extracted_files"] = sorted(list(batch_files))[:100]

            return Observation(
                ok=True,
                status="succeeded",
                action=step.action,
                target=step.target,
                step_id=step.id,
                summary=summary_str,
                findings_created=created_ids,
                findings_updated=updated_ids,
                evidence_ids=evidence_ids,
                artifact=artifact_info,
                facts=facts_dict,
                errors=[item["error"] for item in results if item.get("error")],
                next_hint=next_hint,
            )

        http_status = None
        body_excerpt = ""
        body_full = ""
        json_items: int | None = None
        request_url = ""
        headers: dict[str, Any] = {}
        res = p_data.get("curl_result") or p_data.get("probe_result") or {}
        request = p_data.get("request") or {}
        if isinstance(request, dict):
            request_url = str(request.get("url") or "")
        if not request_url and isinstance(res, dict):
            request_url = str(res.get("url") or "")

        # 1. curl-mcp format: { ok, code, status, response: { status_code, headers, body } }
        if "response" in p_data and isinstance(p_data["response"], dict):
            resp = p_data["response"]
            http_status = resp.get("status_code") or p_data.get("code")
            headers = resp.get("headers") or {}
            body_full = resp.get("body") or ""
        # 2. Legacy in-process probe format
        elif "curl_result" in p_data or "probe_result" in p_data:
            http_status = res.get("status_code")
            headers = res.get("headers") or {}
            body_full = res.get("body_preview") or res.get("body") or ""
        else:
            http_status = p_data.get("code") or p_data.get("status_code")
            body_full = p_data.get("body") or ""

        if isinstance(body_full, str):
            # Strip heavy inline styles so directory listings and API responses aren't masked
            cleaned = re.sub(r"<style[^>]*>[\s\S]*?</style>", "", body_full, flags=re.IGNORECASE)
            body_excerpt = cleaned[:1000]
        else:
            body_excerpt = str(body_full)[:1000]

        parsed_body: Any = None
        try:
            parsed_body = (
                json.loads(body_full)
                if isinstance(body_full, str)
                else body_full
            )
            rows = (
                parsed_body.get("data")
                if isinstance(parsed_body, dict)
                else None
            )
            if isinstance(rows, list):
                json_items = len(rows)
        except Exception:
            json_items = None

        auth_data = None
        is_fresh_auth = False
        if http_status in (200, 201):
            auth_data = _extract_auth_session(parsed_body, headers, request_url)
            if auth_data:
                is_fresh_auth = True
                session_path = _save_session_file(step.assessment_id, step.output_path, auth_data)
                if session_path:
                    auth_data["session_file"] = session_path

        if not auth_data:
            existing_auth = _load_session_file(step.assessment_id, step.output_path)
            if existing_auth:
                auth_data = existing_auth

        extracted_routes, extracted_files, json_keys, extracted_forms = _extract_curl_entities(
            request_url=request_url,
            headers=headers,
            body=body_full,
            output_path=step.output_path,
        )

        if is_fresh_auth and http_status in (200, 201) and auth_data:
            user_val = auth_data.get("email") or auth_data.get("user_id")
            user_str = f", user={user_val}" if user_val is not None else ""
            tok_type = "JWT token" if auth_data.get("token") else "session cookie"
            summary_str = f"HTTP {http_status} - Authenticated ({tok_type} obtained{user_str})"
        else:
            status_part = f"HTTP {http_status}" if http_status is not None else "HTTP request succeeded"
            if json_items is not None:
                status_part += f" ({json_items} items)"
            body_part = f" - excerpt: {body_excerpt!r}" if body_excerpt else ""
            summary_str = f"{status_part}{body_part}"

        extra_parts: list[str] = []
        if extracted_routes:
            sample_r = ", ".join(extracted_routes[:8])
            if len(extracted_routes) > 8:
                sample_r += f", ... (+{len(extracted_routes) - 8} more)"
            extra_parts.append(f"extracted {len(extracted_routes)} route(s): [{sample_r}]")
        if extracted_files:
            sample_f = ", ".join(extracted_files[:8])
            if len(extracted_files) > 8:
                sample_f += f", ... (+{len(extracted_files) - 8} more)"
            extra_parts.append(f"extracted {len(extracted_files)} file(s): [{sample_f}]")
        if extracted_forms:
            form_samples = []
            for f in extracted_forms[:3]:
                inps = ", ".join(i.get("name") for i in f.get("inputs", [])[:4] if i.get("name"))
                form_samples.append(f"{f.get('method', 'GET')} {f.get('action')} ({inps})")
            extra_parts.append(f"extracted {len(extracted_forms)} form(s): [{'; '.join(form_samples)}]")
        if extra_parts and not (is_fresh_auth and http_status in (200, 201)):
            summary_str = f"{summary_str} | {' | '.join(extra_parts)}"

        req_method = str(request.get("method") or res.get("method") or "GET").upper()
        if is_fresh_auth and http_status in (200, 201) and auth_data:
            if auth_data.get("token"):
                next_hint = (
                    "Authentication succeeded. Auth credentials obtained in facts['auth']. "
                    "Probe discovered authenticated routes using header 'Authorization: Bearer <token>' "
                    "to test access control and authorization boundaries."
                )
            else:
                cookie_val = auth_data.get("cookie", "")
                next_hint = (
                    "Authentication succeeded. Session cookie obtained in facts['auth']['cookie']. "
                    f"Probe discovered authenticated routes using header 'Cookie: {cookie_val}' "
                    "to test access control and authorization boundaries."
                )
        elif http_status in (401, 403):
            if any(term in request_url.lower() for term in ("login", "auth", "token", "session")):
                next_hint = (
                    f"HTTP {http_status} on auth endpoint: Credentials rejected. "
                    "Target rejected authentication attempt; requires valid credentials, active session token, or bypass."
                )
            else:
                next_hint = f"HTTP {http_status}: Authentication or authorization required. Endpoint denied unauthenticated or unauthorized access."
        elif http_status == 200 and ("<!doctype html" in body_excerpt.lower() or "<html" in body_excerpt.lower()) and req_method in ("POST", "PUT", "PATCH"):
            next_hint = "HTTP 200 returned client-side SPA HTML shell (index.html fallback) instead of an API response. Target router served frontend entrypoint rather than handling the method/route as an API endpoint."
        elif http_status in (400, 422):
            err_msg = ""
            if isinstance(parsed_body, dict):
                err_msg = str(parsed_body.get("message") or parsed_body.get("error") or "")
            if err_msg:
                next_hint = f"HTTP {http_status}: Request rejected by target validation constraint: '{err_msg}'."
            else:
                next_hint = f"HTTP {http_status}: Server rejected request syntax or schema. Target reported invalid or malformed input."
        elif http_status == 404:
            next_hint = "HTTP 404: Endpoint path not found on target. Unmapped route."
        elif http_status == 500 and "Unexpected path" in body_excerpt:
            next_hint = "HTTP 500 with 'Unexpected path': Application routing fault for unmapped route; endpoint does not exist."
        elif http_status == 500:
            next_hint = "HTTP 500: Server raised an unhandled exception. Potential server-side crash or unhandled input error."
        elif json_items is not None and ("search" in request_url or "q=" in request_url):
            next_hint = (
                f"Search endpoint returned {json_items} items. Differential row count "
                "against baseline indicates potential query manipulation or injection (verify before record_finding)."
            )
        elif extracted_routes:
            sample_routes_hint = ", ".join(extracted_routes[:5])
            next_hint = (
                f"Discovered {len(extracted_routes)} client/API routes in response (e.g. {sample_routes_hint}). "
                "Probe these discovered routes to explore exposed application attack surface."
            )
        elif extracted_files:
            sample_files_hint = ", ".join(extracted_files[:5])
            next_hint = (
                f"Discovered {len(extracted_files)} file link(s) (e.g. {sample_files_hint}). "
                "Disclosed files may contain sensitive source, backups, or configuration assets."
            )
        elif extracted_forms:
            next_hint = f"Discovered {len(extracted_forms)} HTML forms. Forms expose input parameters and submission endpoints."
        else:
            next_hint = "Compare observed HTTP status and response against expected_observation and would_falsify."

        facts: dict[str, Any] = {
            "status_code": http_status,
            "headers": headers,
            "body_preview": body_excerpt,
            "json_items": json_items,
            "request_url": request_url,
        }
        if auth_data:
            facts["auth"] = auth_data
        if extracted_routes:
            facts["extracted_routes"] = extracted_routes
        if extracted_files:
            facts["extracted_files"] = extracted_files
        if json_keys:
            facts["keys"] = json_keys
        if extracted_forms:
            facts["extracted_forms"] = extracted_forms

        return Observation(
            ok=True,
            status="succeeded",
            action=step.action,
            target=step.target,
            step_id=step.id,
            summary=summary_str,
            findings_created=created_ids,
            findings_updated=updated_ids,
            evidence_ids=evidence_ids,
            artifact=artifact_info,
            facts=facts,
            errors=[],
            next_hint=next_hint,
        )

    if step.action == "whatweb":
        count = len(findings)
        summary_str = f"WhatWeb scan completed; {count} technology findings recorded."
        return Observation(
            ok=True,
            status="succeeded",
            action=step.action,
            target=step.target,
            step_id=step.id,
            summary=summary_str,
            findings_created=created_ids,
            findings_updated=updated_ids,
            evidence_ids=evidence_ids,
            artifact=artifact_info,
            errors=[],
            next_hint="Technologies detected can be correlated against known CVEs or used to form hypotheses.",
        )

    if step.action == "sslscan":
        count = len(findings)
        summary_str = f"sslscan completed; {count} TLS/SSL protocol/certificate facts identified."
        return Observation(
            ok=True,
            status="succeeded",
            action=step.action,
            target=step.target,
            step_id=step.id,
            summary=summary_str,
            findings_created=created_ids,
            findings_updated=updated_ids,
            evidence_ids=evidence_ids,
            artifact=artifact_info,
            errors=[],
            next_hint="Evaluate deprecated SSL/TLS protocols or certificate validity.",
        )

    if step.action == "hashcat_crack":
        # Strict redaction per §9.1: Plaintext passwords are NEVER returned or stored in observation
        cracked = len(findings) > 0
        summary_str = f"{len(findings)} hash(es) cracked; plaintext redacted." if cracked else "0 hashes cracked; password candidates exhausted."
        return Observation(
            ok=True,
            status="succeeded",
            action=step.action,
            target=step.target,
            step_id=step.id,
            summary=summary_str,
            findings_created=created_ids,
            findings_updated=updated_ids,
            evidence_ids=evidence_ids,
            artifact=artifact_info,
            errors=[],
            next_hint="Assess whether weak credential policy impacts assessment risk.",
        )

    if step.action == "sqlmap_scan":
        text = ""
        if step.output_path:
            path = Path(step.output_path)
            if path.exists():
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    text = ""

        sql_vuln = SQLMAP_PROOF in text.lower()
        server_errors = bool(
            re.search(r"HTTP error codes detected[\s\S]*?\b5\d\d\b", text, re.IGNORECASE)
        )
        if sql_vuln:
            summary_str = "SQL injection confirmed by sqlmap."
            next_hint = (
                "Attach this sqlmap step to the candidate finding as proof, "
                "then record the verdict."
            )
        elif server_errors:
            summary_str = (
                "sqlmap found no injection point at the requested bounds, but "
                "the target returned 5xx to test payloads."
            )
            next_hint = (
                "This negative is inconclusive: escalate level/risk once or test "
                "a different parameter before concluding not injectable."
            )
        else:
            summary_str = "sqlmap scan completed; no SQL injection confirmed."
            next_hint = "Record the negative result or test a different parameter."
        return Observation(
            ok=True,
            status="succeeded",
            action=step.action,
            target=step.target,
            step_id=step.id,
            summary=summary_str,
            findings_created=created_ids,
            findings_updated=updated_ids,
            evidence_ids=evidence_ids,
            artifact=artifact_info,
            errors=[],
            next_hint=next_hint,
        )

    # Generic fallback for any other tool until Phase 2
    return Observation(
        ok=True,
        status="succeeded",
        action=step.action,
        target=step.target,
        step_id=step.id,
        summary=f"Action {step.action} succeeded.",
        findings_created=created_ids,
        findings_updated=updated_ids,
        evidence_ids=evidence_ids,
        artifact=artifact_info,
        errors=[],
    )


def rejection_observation(pending: ActionRequest, reason: str | None = None) -> Observation:
    """Build an observation when an analyst rejects an action at the approval gate."""
    return Observation(
        ok=False,
        status="rejected",
        action=pending.action,
        target=pending.target,
        step_id=pending.step_id,
        summary=f"Analyst rejected {pending.action}: {reason or 'no reason given'}",
        errors=[reason or "rejected by analyst"],
        next_hint=(
            "Do not retry the same command. Choose a safer discriminating observation "
            "or hand off the open question."
        ),
    )


def error_observation(
    action: str, target: str, error: str, step_id: int | None = None
) -> Observation:
    """Build an observation for an internal error during preparation/execution."""
    return Observation(
        ok=False,
        status="error",
        action=action,
        target=target,
        step_id=step_id,
        summary=f"Error executing {action}: {error}",
        errors=[error],
    )
