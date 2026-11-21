"""JSON and OpenAPI/Swagger specification parser."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
import urllib.parse

from app.adapters.ffuf import extract_wildcard_lengths
from .models import FormEntity, FormField, ParsedEntities

COMMON_FILE_EXTENSIONS = {
    ".txt",
    ".md",
    ".json",
    ".xml",
    ".html",
    ".htm",
    ".js",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".bak",
    ".backup",
    ".kdbx",
    ".sql",
    ".db",
    ".sqlite",
    ".env",
    ".yml",
    ".yaml",
    ".conf",
    ".ini",
    ".log",
}


def _parse_ffuf_results(results: list[Any], entities: ParsedEntities) -> None:
    """Safely extract reachable routes and files from FFUF scan results."""
    wildcard_lengths = extract_wildcard_lengths(results)

    for item in results:
        if not isinstance(item, dict):
            continue

        status = item.get("status")
        # Keep valid reachable status codes: 2xx, 3xx redirects, 401/403 auth boundaries
        if status not in (200, 201, 204, 301, 302, 307, 308, 401, 403):
            continue

        length = item.get("length", 0)
        # Filter out wildcard SPA fallback responses (e.g. repeated fallback index.html)
        if length in wildcard_lengths:
            continue

        url = str(item.get("url") or "").strip()
        if url:
            try:
                if "://" in url:
                    path = urllib.parse.urlsplit(url).path or "/"
                else:
                    path = urllib.parse.urlsplit(url).path or url
            except Exception:
                path = url
        else:
            inputs = item.get("input", {})
            fuzz_val = inputs.get("FUZZ", "") if isinstance(inputs, dict) else ""
            path = f"/{fuzz_val}" if fuzz_val else "/"

        if not path.startswith("/"):
            path = f"/{path}"

        if not path or path == "/":
            continue

        entities.routes.append(path)

        ext = Path(path).suffix.lower()
        name = Path(path).name.lower()
        if ext in COMMON_FILE_EXTENSIONS or name in COMMON_FILE_EXTENSIONS:
            entities.files.append(path)


def parse_json(json_content: str | dict | list) -> ParsedEntities:
    """Parse JSON content, extracting OpenAPI routes, FFUF scan results, and schema keys."""
    entities = ParsedEntities()

    if isinstance(json_content, (dict, list)):
        data = json_content
    elif isinstance(json_content, str) and json_content.strip():
        try:
            data = json.loads(json_content)
        except Exception:
            return entities
    else:
        return entities

    if isinstance(data, dict):
        # 1. OpenAPI / Swagger Specification Check
        if "paths" in data and isinstance(data["paths"], dict):
            for path_str, path_item in data["paths"].items():
                if not str(path_str).startswith("/"):
                    path_str = f"/{path_str}"
                entities.routes.append(str(path_str))

                if isinstance(path_item, dict):
                    for method_name, op in path_item.items():
                        if method_name.lower() in ("get", "post", "put", "delete", "patch", "options", "head"):
                            fields: list[FormField] = []
                            if isinstance(op, dict):
                                # Parameters list
                                params = op.get("parameters") or []
                                if isinstance(params, list):
                                    for p in params:
                                        if isinstance(p, dict) and "name" in p:
                                            p_name = str(p["name"])
                                            p_type = str(p.get("type") or p.get("in") or "string")
                                            fields.append(FormField(name=p_name, type=p_type))

                                # Request body schema properties
                                req_body = op.get("requestBody") or {}
                                if isinstance(req_body, dict):
                                    content_map = req_body.get("content") or {}
                                    for _, media_obj in content_map.items():
                                        if isinstance(media_obj, dict):
                                            schema = media_obj.get("schema") or {}
                                            props = schema.get("properties") or {}
                                            if isinstance(props, dict):
                                                for prop_name, prop_val in props.items():
                                                    prop_type = (
                                                        prop_val.get("type", "string")
                                                        if isinstance(prop_val, dict)
                                                        else "string"
                                                    )
                                                    fields.append(FormField(name=str(prop_name), type=str(prop_type)))

                            entities.forms.append(
                                FormEntity(
                                    action=str(path_str),
                                    method=method_name.upper(),
                                    inputs=fields,
                                )
                            )

        # 2. FFUF Scanner Output Check
        elif (
            ("commandline" in data or "config" in data)
            and "results" in data
            and isinstance(data["results"], list)
        ):
            _parse_ffuf_results(data["results"], entities)

        # 3. General JSON Object Keys
        entities.keys = list(data.keys())[:50]

        # Check for nested data array
        if "data" in data and isinstance(data["data"], list) and data["data"]:
            first = data["data"][0]
            if isinstance(first, dict):
                entities.keys.extend([f"data.{k}" for k in list(first.keys())[:20]])

    elif isinstance(data, list) and data:
        # Array of objects
        if isinstance(data[0], dict):
            entities.keys = list(data[0].keys())[:50]

    entities.routes = list(dict.fromkeys(entities.routes))[:100]
    entities.files = list(dict.fromkeys(entities.files))[:50]
    entities.keys = list(dict.fromkeys(entities.keys))[:50]

    return entities
