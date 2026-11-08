"""WhatWeb adapter: JSON log parser for web technology identification.

Emits informational findings for detected technologies, web servers, and frameworks.
No vulnerability severity is invented: all findings are INFO unless verified later.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

from app.adapters.base import EvidenceDraft, FindingDraft
from app.domain.models import FindingStatus, Severity


def parse(json_text: str) -> list[dict[str, Any]]:
    """Parse WhatWeb JSON output, supporting both JSON arrays and JSON lines."""
    text = json_text.strip()
    if not text:
        return []

    if text.startswith("["):
        try:
            data = json.loads(text)
            if isinstance(data, list):
                return data
        except json.JSONDecodeError:
            pass

    records: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
            if isinstance(item, dict):
                records.append(item)
            elif isinstance(item, list):
                records.extend(x for x in item if isinstance(x, dict))
        except json.JSONDecodeError:
            continue
    return records


def scan(
    json_text: str,
    host: str,
    port: int,
    host_override: str | None = None,
) -> list[FindingDraft]:
    """Parse WhatWeb JSON output into FindingDraft objects."""
    records = parse(json_text)
    effective_host = host_override or host
    drafts: list[FindingDraft] = []
    seen_keys: set[str] = set()

    for entry in records:
        target_url = entry.get("target") or f"http://{effective_host}:{port}/"
        parsed_url = urlsplit(target_url)
        entry_host = parsed_url.hostname or effective_host
        entry_port = parsed_url.port or port

        plugins = entry.get("plugins") or {}
        if not isinstance(plugins, dict):
            continue

        for plugin_name, details in plugins.items():
            if not isinstance(details, dict):
                continue

            version_str = ""
            if "version" in details and details["version"]:
                vers = details["version"]
                version_str = ", ".join(str(v) for v in vers) if isinstance(vers, list) else str(vers)
            elif "string" in details and details["string"]:
                strings = details["string"]
                version_str = ", ".join(str(s) for s in strings) if isinstance(strings, list) else str(strings)

            clean_plugin = plugin_name.strip()
            title = f"Technology detected: {clean_plugin}"
            if version_str:
                title += f" {version_str}"

            canon_key = f"whatweb:{entry_host}:{entry_port}:{clean_plugin.lower()}"
            if canon_key in seen_keys:
                continue
            seen_keys.add(canon_key)

            excerpt_parts = [clean_plugin]
            if version_str:
                excerpt_parts.append(f"version: {version_str}")
            if "os" in details and details["os"]:
                excerpt_parts.append(f"os: {details['os']}")
            if "module" in details and details["module"]:
                excerpt_parts.append(f"module: {details['module']}")

            drafts.append(
                FindingDraft(
                    canonical_key=canon_key,
                    asset=entry_host,
                    endpoint=f"http://{entry_host}:{entry_port}{parsed_url.path or '/'}",
                    title=title,
                    description=f"WhatWeb detected {clean_plugin} on {target_url}. Details: {', '.join(excerpt_parts)}.",
                    severity=Severity.INFO,
                    confidence=0.8,
                    status=FindingStatus.SUSPECTED,
                    evidence=[
                        EvidenceDraft(
                            locator={
                                "tool": "whatweb",
                                "url": target_url,
                                "plugin": clean_plugin,
                            },
                            excerpt="; ".join(excerpt_parts)[:500],
                        )
                    ],
                )
            )

    return drafts
