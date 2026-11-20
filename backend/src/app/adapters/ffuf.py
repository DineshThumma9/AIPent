"""ffuf adapter: parse directory and parameter fuzzing output."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

from app.adapters.base import EvidenceDraft, FindingDraft
from app.domain.models import FindingStatus, Origin, Severity

DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"

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


def normalize_fuzz_url(base_url: str, path: str | None = None) -> str:
    """Ensure the target URL contains the FUZZ keyword."""
    url = base_url.rstrip("/")
    if path:
        clean_path = path if path.startswith("/") else f"/{path}"
        if "FUZZ" not in clean_path:
            clean_path = clean_path.rstrip("/") + "/FUZZ"
        return f"{url}{clean_path}"
    if "FUZZ" not in url:
        return f"{url}/FUZZ"
    return url


def argv(
    target: str,
    port: int,
    output_path: str,
    wordlist: str | None = None,
    path: str | None = None,
) -> list[str]:
    """Build ffuf command-line arguments."""
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}:{port}"
    target_url = normalize_fuzz_url(base_url, path)
    wl = wordlist or DEFAULT_WORDLIST

    return [
        "ffuf",
        "-u",
        target_url,
        "-w",
        wl,
        "-o",
        str(output_path),
        "-of",
        "json",
        "-s",  # silent / clean output
    ]


def scan(text: str, host: str, port: int) -> list[FindingDraft]:
    """Parse ffuf JSON output and extract discovered routes/parameters as findings."""
    if not text or not text.strip():
        return []

    data: dict[str, Any] = {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Check if line-delimited or partial JSON
        return []

    results = data.get("results")
    if not isinstance(results, list):
        return []

    drafts: list[FindingDraft] = []
    seen_endpoints: set[str] = set()

    for item in results:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "").strip()
        status_code = item.get("status", 200)
        length = item.get("length", 0)

        # Extract endpoint path
        if url:
            path = urlsplit(url).path or url
        else:
            inputs = item.get("input", {})
            fuzz_val = inputs.get("FUZZ", "") if isinstance(inputs, dict) else ""
            path = f"/{fuzz_val}" if fuzz_val else "/"

        if not path.startswith("/"):
            path = f"/{path}"

        if path in seen_endpoints:
            continue
        seen_endpoints.add(path)

        is_sensitive = any(kw in path.lower() for kw in SENSITIVE_KEYWORDS)
        severity = Severity.LOW if is_sensitive else Severity.INFO

        drafts.append(
            FindingDraft(
                canonical_key=f"ffuf:{host}:{port}:{path}",
                title=f"Discovered Endpoint (FFUF): {path} (HTTP {status_code})",
                asset=host,
                endpoint=path,
                severity=severity,
                status=FindingStatus.SUSPECTED,
                confidence=0.8,
                origin=Origin.TOOL,
                description=(
                    f"FFUF fuzzing discovered endpoint '{path}' returning HTTP {status_code} "
                    f"(size {length} bytes)."
                ),
                evidence=[
                    EvidenceDraft(
                        locator={"tool": "ffuf", "url": url, "status": status_code, "length": length},
                        excerpt=json.dumps(item),
                    )
                ],
            )
        )

    return drafts
