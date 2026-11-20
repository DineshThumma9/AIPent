"""nuclei adapter: parse template-based vulnerability scan output."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

from app.adapters.base import EvidenceDraft, FindingDraft
from app.domain.models import FindingStatus, Origin, Severity

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def argv(
    target: str,
    port: int,
    output_path: str,
    tags: str | None = None,
    severity: str | None = None,
) -> list[str]:
    """Build nuclei command-line arguments."""
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{target}:{port}"

    args = [
        "nuclei",
        "-u",
        url,
        "-jsonl",
        "-silent",
        "-o",
        str(output_path),
    ]
    if tags:
        args.extend(["-tags", str(tags)])
    if severity:
        args.extend(["-severity", str(severity)])
    return args


def scan(text: str, host: str, port: int) -> list[FindingDraft]:
    """Parse nuclei JSONL output into verified FindingDraft records."""
    if not text or not text.strip():
        return []

    drafts: list[FindingDraft] = []
    seen_keys: set[str] = set()

    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("{") or not line.endswith("}"):
            continue

        try:
            data: dict[str, Any] = json.loads(line)
        except json.JSONDecodeError:
            continue

        if not isinstance(data, dict):
            continue

        template_id = str(data.get("template-id") or data.get("templateID") or "unknown")
        info = data.get("info")
        if not isinstance(info, dict):
            info = {}

        name = str(info.get("name") or template_id)
        description = str(info.get("description") or "")
        raw_sev = str(info.get("severity") or "info").lower()
        severity = _SEVERITY_MAP.get(raw_sev, Severity.INFO)

        classification = info.get("classification")
        if not isinstance(classification, dict):
            classification = {}

        # CVE extraction
        raw_cve = classification.get("cve-id")
        if isinstance(raw_cve, list):
            cve_list = [str(c) for c in raw_cve]
        elif isinstance(raw_cve, str) and raw_cve.strip():
            cve_list = [raw_cve.strip()]
        else:
            cve_list = []

        # CWE extraction
        raw_cwe = classification.get("cwe-id")
        if isinstance(raw_cwe, list):
            cwe_list = [str(c) for c in raw_cwe]
        elif isinstance(raw_cwe, str) and raw_cwe.strip():
            cwe_list = [raw_cwe.strip()]
        else:
            cwe_list = []

        # CVSS score
        cvss: float | None = None
        try:
            raw_cvss = classification.get("cvss-score")
            if raw_cvss is not None:
                cvss = float(raw_cvss)
        except (ValueError, TypeError):
            cvss = None

        matched_at = str(data.get("matched-at") or data.get("matched") or "").strip()
        endpoint: str | None = None
        if matched_at:
            if matched_at.startswith(("http://", "https://")):
                parsed = urlsplit(matched_at)
                endpoint = parsed.path or "/"
                if parsed.query:
                    endpoint = f"{endpoint}?{parsed.query}"
            else:
                endpoint = matched_at if matched_at.startswith("/") else f"/{matched_at}"

        canonical_key = f"nuclei:{host}:{port}:{template_id}:{endpoint or '/'}"
        if canonical_key in seen_keys:
            continue
        seen_keys.add(canonical_key)

        curl_cmd = str(data.get("curl-command") or "").strip()
        excerpt = curl_cmd if curl_cmd else json.dumps(data)

        drafts.append(
            FindingDraft(
                canonical_key=canonical_key,
                title=name,
                asset=host,
                description=description,
                endpoint=endpoint,
                severity=severity,
                status=FindingStatus.CONFIRMED,
                confidence=1.0,
                origin=Origin.TOOL,
                cve=cve_list,
                cwe=cwe_list,
                cvss=cvss,
                evidence=[
                    EvidenceDraft(
                        locator={"tool": "nuclei", "template_id": template_id, "matched_at": matched_at},
                        excerpt=excerpt,
                    )
                ],
            )
        )

    return drafts
