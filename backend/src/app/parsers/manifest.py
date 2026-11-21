"""Sidecar manifest generator and loader for artifacts at ingestion time."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any
import urllib.parse

from .html_parser import parse_html
from .js_parser import parse_js
from .json_parser import parse_json
from .models import ParsedEntities

logger = logging.getLogger(__name__)


def parse_content(
    content: str,
    url: str = "",
    content_type: str = "",
    file_path: Path | str | None = None,
) -> ParsedEntities:
    """Detect content type and dispatch to HTML, JS, or JSON parser."""
    entities = ParsedEntities()
    if not content or not content.strip():
        return entities

    ct_lower = (content_type or "").lower()
    url_lower = (url or "").lower()
    path_str = str(file_path or "").lower()

    # 1. Check for JavaScript (.js or script bundle or Content-Type)
    if (
        "javascript" in ct_lower
        or "application/x-javascript" in ct_lower
        or url_lower.endswith(".js")
        or path_str.endswith(".js")
    ):
        return parse_js(content, file_path=file_path, base_url=url)

    # 2. Check Content-Type header explicitly when provided
    if "json" in ct_lower:
        return parse_json(content)
    if "html" in ct_lower:
        return parse_html(content, base_url=url)

    # 3. Check for URL / file extension when Content-Type is absent or ambiguous
    if url_lower.endswith(".json") or (path_str.endswith(".json") and not path_str.endswith(".curl.json")):
        return parse_json(content)
    if url_lower.endswith((".html", ".htm")) or path_str.endswith((".html", ".htm")):
        return parse_html(content, base_url=url)

    # 4. Fallback content sniffing: prefer JSON if the payload starts with { or [ and parses
    stripped = content.strip()
    if stripped.startswith(("{", "[")):
        try:
            return parse_json(stripped)
        except Exception:
            pass

    # 5. Check for HTML markup heuristics
    if (
        "<html" in content[:1000].lower()
        or "<!doctype html" in content[:1000].lower()
        or "<table" in content[:1000].lower()
    ):
        return parse_html(content, base_url=url)

    # 6. Fallback markup sweep if content looks like web markup
    if "<" in content[:2000]:
        return parse_html(content, base_url=url)

    return entities


def filter_self_routes(routes: list[str], request_url: str) -> list[str]:
    """Filter out the currently requested URL path, root '/', and empty routes."""
    req_path = ""
    if request_url:
        try:
            parsed = urllib.parse.urlsplit(
                request_url if "://" in request_url else f"//{request_url}"
            )
            raw_path = parsed.path.strip()
            if raw_path:
                req_path = f"/{raw_path.lstrip('/')}".rstrip("/").lower()
        except Exception:
            req_path = ""

    clean: list[str] = []
    for r in routes:
        r_str = str(r).strip()
        if not r_str or r_str in ("/", ""):
            continue
        try:
            r_path = urllib.parse.urlsplit(r_str).path
        except Exception:
            r_path = r_str
        # Discard if it strictly equals the full request URL
        if request_url and r_str.lower().rstrip("/") == request_url.lower().rstrip("/"):
            continue
        # Normalize route path to ensure a leading slash and no trailing slash for comparison
        r_norm = f"/{r_path.lstrip('/')}".rstrip("/").lower()
        if not r_norm or r_norm == "/":
            continue
        # Discard if normalized path strictly equals the current request path
        if req_path and r_norm == req_path:
            continue
        clean.append(r_str)
    return list(dict.fromkeys(clean))


def manifest_path_for_artifact(artifact_path: Path | str) -> Path:
    """Return the companion sidecar manifest path: {artifact_path}.manifest.json."""
    p = Path(artifact_path)
    return p.parent / f"{p.name}.manifest.json"


def create_sidecar_manifest(
    artifact_path: Path | str,
    url: str = "",
    content_type: str = "",
) -> Path | None:
    """Extract entities and write sidecar manifest JSON file alongside artifact."""
    try:
        path = Path(artifact_path)
        if (
            not path.exists()
            or path.is_dir()
            or path.name.endswith(".manifest.json")
            or path.name == "session.json"
            or path.stat().st_size > 5_000_000
        ):
            return None

        content = path.read_text(encoding="utf-8", errors="replace")
        is_curl_artifact = False

        # For curl artifacts, unpack the response body so we only index what the server returned,
        # avoiding circular extraction of the client's own requested URL.
        if path.name.endswith(".json") and not path.name.endswith(".manifest.json"):
            try:
                curl_data = json.loads(content)
                if isinstance(curl_data, dict):
                    # Handle batched curl artifacts
                    if curl_data.get("batch"):
                        entities = ParsedEntities()
                        for entry in curl_data.get("results") or []:
                            if not isinstance(entry, dict):
                                continue
                            req_obj = entry.get("request") if isinstance(entry.get("request"), dict) else {}
                            res_obj = entry.get("result") if isinstance(entry.get("result"), dict) else {}
                            resp_obj = res_obj.get("response") if isinstance(res_obj.get("response"), dict) else {}
                            entry_url = str(req_obj.get("url") or res_obj.get("request", {}).get("url") or "")
                            entry_hdrs = resp_obj.get("headers") or {}
                            entry_ct = ""
                            if isinstance(entry_hdrs, dict):
                                for k, v in entry_hdrs.items():
                                    if str(k).lower() == "content-type":
                                        entry_ct = str(v)
                                        break
                            entry_body = resp_obj.get("body") or res_obj.get("body") or ""
                            entry_body_str = (
                                entry_body
                                if isinstance(entry_body, str)
                                else json.dumps(entry_body)
                            )
                            entry_entities = parse_content(
                                content=entry_body_str,
                                url=entry_url,
                                content_type=entry_ct,
                                file_path=None,  # unpacked body, not the .curl.json envelope
                            )
                            if entry_url:
                                entry_entities.routes = filter_self_routes(
                                    entry_entities.routes, entry_url
                                )
                            entities.merge(entry_entities)

                        manifest_data = entities.to_dict()
                        manifest_data["source_file"] = path.name
                        manifest_data["source_size_bytes"] = path.stat().st_size
                        manifest_data["url"] = url

                        out_path = manifest_path_for_artifact(path)
                        out_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")
                        return out_path
                    elif "response" in curl_data or "curl_result" in curl_data or "probe_result" in curl_data:
                        req_obj = curl_data.get("request") or {}
                        resp_obj = (
                            curl_data.get("response")
                            or curl_data.get("curl_result")
                            or curl_data.get("probe_result")
                            or {}
                        )
                        if not url and isinstance(req_obj, dict):
                            url = str(req_obj.get("url") or "")
                        if not url and isinstance(resp_obj, dict):
                            url = str(resp_obj.get("url") or resp_obj.get("url_probed") or "")
                        if isinstance(resp_obj, dict):
                            resp_body = resp_obj.get("body") or resp_obj.get("body_preview") or ""
                            resp_headers = resp_obj.get("headers") or {}
                            if not content_type and isinstance(resp_headers, dict):
                                for k, v in resp_headers.items():
                                    if str(k).lower() == "content-type":
                                        content_type = str(v)
                                        break
                            content = resp_body if isinstance(resp_body, str) else json.dumps(resp_body)
                            is_curl_artifact = True
            except Exception:
                pass

        entities = parse_content(
            content=content,
            url=url,
            content_type=content_type,
            # Pass file_path only for non-curl files so jsluice reads JS/HTML from disk directly.
            # For unpacked curl response bodies, pass None so jsluice receives content via stdin.
            file_path=None if is_curl_artifact else path,
        )

        # Filter out self-routes and request URLs
        if url:
            entities.routes = filter_self_routes(entities.routes, url)

        manifest_data = entities.to_dict()
        manifest_data["source_file"] = path.name
        manifest_data["source_size_bytes"] = path.stat().st_size
        manifest_data["url"] = url

        out_path = manifest_path_for_artifact(path)
        out_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")
        return out_path
    except Exception as exc:
        logger.warning("Failed to create sidecar manifest for %s: %s", artifact_path, exc)
        return None


def read_sidecar_manifest(artifact_path: Path | str) -> dict[str, Any] | None:
    """Read sidecar manifest if it exists, otherwise return None."""
    try:
        p = manifest_path_for_artifact(artifact_path)
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        pass
    return None
