"""Sidecar manifest generator and loader for artifacts at ingestion time."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from .html_parser import parse_html
from .js_parser import parse_js
from .json_parser import parse_json
from .models import FormEntity, FormField, ParsedEntities

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

    # 1. Check for JSON / OpenAPI
    if "json" in ct_lower or url_lower.endswith(".json") or path_str.endswith(".json"):
        entities = parse_json(content)
        # Also run regex route sweep if no paths were found
        if not entities.routes:
            html_pass = parse_html(content, base_url=url)
            entities.merge(html_pass)
        return entities

    # 2. Check for JavaScript (.js or script bundle)
    if (
        ".js" in url_lower
        or path_str.endswith(".js")
        or "javascript" in ct_lower
        or "application/x-javascript" in ct_lower
    ):
        return parse_js(content, file_path=file_path, base_url=url)

    # 3. Check for HTML
    is_html = (
        "html" in ct_lower
        or url_lower.endswith((".html", ".htm"))
        or path_str.endswith((".html", ".htm"))
        or "<html" in content[:1000].lower()
        or "<!doctype html" in content[:1000].lower()
        or "<table" in content[:1000].lower()
    )
    if is_html:
        return parse_html(content, base_url=url)

    # 4. Fallback: Sniff raw content
    stripped = content.strip()
    if stripped.startswith(("{", "[")):
        try:
            return parse_json(stripped)
        except Exception:
            pass

    # If nothing else matched and content looks like markup or web payload, run HTML/regex sweep
    if "<" in content[:2000]:
        return parse_html(content, base_url=url)

    return entities


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
        if not path.exists() or path.stat().st_size > 5_000_000:
            return None

        content = path.read_text(encoding="utf-8", errors="replace")
        entities = parse_content(
            content=content,
            url=url,
            content_type=content_type,
            file_path=path,
        )

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
