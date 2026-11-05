"""Nikto adapter: fixed argv, typed JSON parse, conservative severity."""

import json
import re
import shutil
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from app.adapters.base import EvidenceDraft, FindingDraft
from app.core.config import settings
from app.domain.models import FindingStatus, Severity

VENDORED = Path(__file__).resolve().parents[3] / "bin" / "nikto" / "program"


class NiktoItem(BaseModel):
    id: str
    msg: str = Field(min_length=1)
    url: str = "/"
    method: str = "GET"


class NiktoReport(BaseModel):
    host: str = ""
    port: int = 0
    vulnerabilities: list[NiktoItem] = Field(default_factory=list)


def command() -> list[str]:
    """A system nikto wins; otherwise use the vendored Perl tree."""
    if settings.nikto_bin:
        return [settings.nikto_bin]
    found = shutil.which("nikto")
    if found:
        return [found]
    script = VENDORED / "nikto.pl"
    if script.exists():
        # -I lets the vendored XML::Writer module resolve without PERL5LIB.
        return ["perl", "-I", str(VENDORED), str(script)]
    return ["nikto"]


def argv(target: str, port: int, output_path: str) -> list[str]:
    return [
        *command(),
        "-h",
        target,
        "-p",
        str(port),
        "-nointeractive",
        "-Format",
        "json",
        "-output",
        output_path,
    ]


def _records(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        if isinstance(payload.get("vulnerabilities"), list):
            return [payload]
        # Older Nikto builds wrap host results in a "host" list.
        if isinstance(payload.get("host"), list):
            return payload["host"]
    raise ValueError("unrecognised Nikto JSON shape")


def parse(text: str) -> list[NiktoItem]:
    payload = json.loads(text)
    items: list[NiktoItem] = []
    for record in _records(payload):
        try:
            report = NiktoReport.model_validate(record)
        except ValidationError as exc:
            raise ValueError(f"invalid Nikto record: {exc}") from exc
        items.extend(report.vulnerabilities)
    return items


def _severity(message: str) -> Severity:
    lowered = message.lower()
    if any(word in lowered for word in ("sql injection", "command injection", "rce")):
        return Severity.HIGH
    if any(
        word in lowered
        for word in ("cross site scripting", "xss", "directory traversal", "file inclusion")
    ):
        return Severity.HIGH
    if any(
        word in lowered
        for word in ("exposed", "backup", "config", "phpinfo", "admin", "default")
    ):
        return Severity.MEDIUM
    if any(word in lowered for word in ("header", "cookie", "missing", "disclosure")):
        return Severity.LOW
    return Severity.INFO


def to_drafts(host: str, port: int, items: list[NiktoItem]) -> list[FindingDraft]:
    drafts: list[FindingDraft] = []
    for item in items:
        clean_msg = re.sub(r"^\[\d+\]\s*", "", item.msg.strip())
        clean_msg = re.sub(r"^/:\s*", "", clean_msg)
        title = clean_msg.split(". ")[0][:160].strip()
        if not title:
            continue
        drafts.append(
            FindingDraft(
                canonical_key=f"web:{title.lower()}:{host}:{port}",
                asset=host,
                endpoint=f"http://{host}:{port}{item.url}",
                title=title,
                description=clean_msg,
                severity=_severity(clean_msg),
                confidence=0.6,
                status=FindingStatus.SUSPECTED,
                evidence=[
                    EvidenceDraft(
                        locator={
                            "tool": "nikto",
                            "id": item.id,
                            "url": item.url,
                            "method": item.method,
                        },
                        excerpt=clean_msg[:600],
                    )
                ],
            )
        )
    return drafts


def scan(text: str, host: str, port: int) -> list[FindingDraft]:
    """Parse either the local JSON file or the Kali MCP's plain text."""
    stripped = text.lstrip()
    items = parse(text) if stripped.startswith(("{", "[")) else parse_text(text)
    for item in items:
        lowered = item.msg.lower()
        if "unable to connect" in lowered or "no web server found" in lowered:
            raise ValueError(f"Nikto could not connect to {host}:{port}")
    return to_drafts(host, port, items)


NOISE = (
    "target ip:",
    "target hostname:",
    "target port:",
    "start time:",
    "end time:",
    "server:",
    "platform:",
    "error: failed to check for updates",
    "no cgi directories found",
    "root page / redirects to",
    "0 item(s) reported",
    "nikto v",
    "host(s) tested",
)


def parse_text(text: str) -> list[NiktoItem]:
    items: list[NiktoItem] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("+"):
            continue
        message = line[1:].strip()
        lowered = message.lower()
        if (
            not message
            or any(lowered.startswith(noise) for noise in NOISE)
            or "requests: " in lowered
            or "host(s) tested" in lowered
        ):
            continue
        item_id = ""
        match = re.match(r"^\[(\d+)\]\s*(.*)$", message)
        if match:
            item_id = match.group(1)
            message = match.group(2).strip()
        items.append(NiktoItem(id=item_id, msg=message, url="/"))
    return items
