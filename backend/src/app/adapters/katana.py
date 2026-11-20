"""katana adapter: parse web crawler and spider output."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

from app.adapters.base import EvidenceDraft, FindingDraft
from app.domain.models import FindingStatus, Origin, Severity

SENSITIVE_KEYWORDS = (
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


def argv(
    target: str,
    port: int,
    output_path: str,
    depth: int = 3,
) -> list[str]:
    """Build katana command-line arguments."""
    if "://" in target:
        parsed = urlsplit(target)
        scheme = parsed.scheme or "http"
        host = parsed.hostname or target
        port = parsed.port or port
    elif ":" in target:
        host, _, target_port = target.partition(":")
        try:
            port = int(target_port)
        except ValueError:
            pass
        scheme = "https" if port in (443, 8443) else "http"
    else:
        host = target
        scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{host}:{port}"

    return [
        "katana",
        "-u",
        url,
        "-d",
        str(depth),
        "-jc",
        "-silent",
        "-o",
        str(output_path),
    ]


def _extract_url_from_line(line: str) -> str | None:
    line = line.strip()
    if not line:
        return None

    if line.startswith("{") and line.endswith("}"):
        try:
            data = json.loads(line)
            if isinstance(data, dict):
                req = data.get("request")
                if isinstance(req, dict) and "endpoint" in req:
                    return str(req["endpoint"])
                if "endpoint" in data:
                    return str(data["endpoint"])
                if "url" in data:
                    return str(data["url"])
        except json.JSONDecodeError:
            pass

    if line.startswith(("http://", "https://", "/")):
        return line

    return None


def scan(text: str, host: str, port: int) -> list[FindingDraft]:
    """Parse katana crawler output (JSONL or raw URLs) and return discovered endpoint drafts."""
    if not text or not text.strip():
        return []

    drafts: list[FindingDraft] = []
    seen_endpoints: set[str] = set()

    for line in text.splitlines():
        extracted = _extract_url_from_line(line)
        if not extracted:
            continue

        if extracted.startswith(("http://", "https://")):
            parsed = urlsplit(extracted)
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
        else:
            path = extracted if extracted.startswith("/") else f"/{extracted}"

        if path in seen_endpoints:
            continue
        seen_endpoints.add(path)

        is_sensitive = any(kw in path.lower() for kw in SENSITIVE_KEYWORDS)
        severity = Severity.LOW if is_sensitive else Severity.INFO

        drafts.append(
            FindingDraft(
                canonical_key=f"katana:{host}:{port}:{path}",
                title=f"Discovered Endpoint (Katana): {path}",
                asset=host,
                endpoint=path,
                severity=severity,
                status=FindingStatus.SUSPECTED,
                confidence=0.8,
                origin=Origin.TOOL,
                description=f"Katana crawler discovered endpoint: {extracted}",
                evidence=[
                    EvidenceDraft(
                        locator={"tool": "katana", "endpoint": path},
                        excerpt=line.strip(),
                    )
                ],
            )
        )

    return drafts
