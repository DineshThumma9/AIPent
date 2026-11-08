"""Nmap adapter: fixed argv, typed parse, no severity invention."""

import xml.etree.ElementTree as ET
from typing import Literal

from pydantic import BaseModel

from app.adapters.base import EvidenceDraft, FindingDraft
from app.domain.models import Severity

PortState = Literal[
    "open",
    "closed",
    "filtered",
    "unfiltered",
    "open|filtered",
    "closed|filtered",
]


class NmapPort(BaseModel):
    """One <port> element, validated before it reaches the database."""

    host: str
    protocol: str
    port: int
    state: PortState
    service: str | None = None


def argv(
    target: str,
    ports: list[int] | str = "top100",
    timing: int = 4,
    host_discovery: bool = False,
    scripts: list[str] | None = None,
) -> list[str]:
    if host_discovery:
        return ["nmap", "-sn", "-Pn", f"-T{timing}", "-oX", "-", target]
    parts: list[str] = ["nmap", "-sV", "-Pn", f"-T{timing}"]
    if scripts:
        parts.extend(["--script", ",".join(scripts)])
    if ports == "top100":
        parts.extend(["--top-ports", "100"])
    elif ports == "top1000":
        parts.extend(["--top-ports", "1000"])
    elif ports == "all":
        parts.extend(["-p-"])
    else:
        parts.extend(["-p", ",".join(map(str, ports))])
    parts.extend(["-oX", "-", target])
    return parts


def fast_scan(
    target: str,
    ports: list[int] | str = "top100",
    timing: int = 4,
    scripts: list[str] | None = None,
) -> list[str]:
    return argv(target, ports=ports, timing=timing, scripts=scripts)


def service_scan(
    target: str,
    ports: list[int] | str = "top100",
    timing: int = 3,
    scripts: list[str] | None = None,
) -> list[str]:
    return argv(target, ports=ports, timing=timing, scripts=scripts)


def full_tcp(
    target: str,
    timing: int = 4,
    scripts: list[str] | None = None,
) -> list[str]:
    return argv(target, ports="all", timing=timing, scripts=scripts)


def full_service(
    target: str,
    timing: int = 3,
    scripts: list[str] | None = None,
) -> list[str]:
    return argv(target, ports="all", timing=timing, scripts=scripts)


def parse(xml_text: str) -> list[NmapPort]:
    root = ET.fromstring(xml_text)
    records: list[NmapPort] = []
    for host_element in root.iter("host"):
        status = host_element.find("status")
        if status is not None and status.get("state") != "up":
            continue
        address = next(
            (
                node.get("addr")
                for node in host_element.iter("address")
                if node.get("addrtype") in ("ipv4", "ipv6")
            ),
            None,
        )
        if address is None:
            continue
        for port_element in host_element.iter("port"):
            state_element = port_element.find("state")
            service_element = port_element.find("service")
            records.append(
                NmapPort(
                    host=address,
                    protocol=port_element.get("protocol", "tcp"),
                    port=int(port_element.get("portid", "0")),
                    state=state_element.get("state") if state_element is not None else "filtered",
                    service=service_element.get("name") if service_element is not None else None,
                )
            )
    return records


def to_drafts(records: list[NmapPort]) -> list[FindingDraft]:
    drafts: list[FindingDraft] = []
    for record in records:
        if record.state != "open":
            continue
        service = record.service or "unknown"
        drafts.append(
            FindingDraft(
                canonical_key=f"nmap:{record.host}:{record.protocol}/{record.port}",
                asset=record.host,
                endpoint=f"{record.protocol}/{record.port}",
                title=f"Open {record.protocol}/{record.port} ({service})",
                description=(
                    f"nmap reported {record.protocol}/{record.port} open with "
                    f"service {service}."
                ),
                severity=Severity.INFO,
                evidence=[
                    EvidenceDraft(
                        locator={
                            "xpath": (
                                f"//port[@protocol='{record.protocol}']"
                                f"[@portid='{record.port}']"
                            )
                        },
                        excerpt=(
                            f"{record.protocol}/{record.port} {record.state} "
                            f"{record.service or ''}"
                        ).strip(),
                    )
                ],
            )
        )
    return drafts


def mcp_flags(
    ports: list[int] | None = None,
    timing: int = 4,
    top_ports: str | None = None,
    scripts: list[str] | None = None,
) -> str:
    parts = ["-sV", "-Pn", f"-T{timing}"]
    if scripts:
        parts.extend(["--script", ",".join(scripts)])
    if top_ports == "top100":
        parts.extend(["--top-ports", "100"])
    elif top_ports == "top1000":
        parts.extend(["--top-ports", "1000"])
    elif top_ports == "all":
        parts.append("-p-")
    elif ports:
        parts.extend(["-p", ",".join(map(str, ports))])
    parts.extend(["-oX", "-"])
    return " ".join(parts)


def _xml_only(text: str) -> str:
    """Keep only the XML document when a wrapper prints banners or stderr."""
    start = text.find("<nmaprun")
    end = text.rfind("</nmaprun>")
    if start < 0 or end < 0:
        return text
    return text[start : end + len("</nmaprun>")]


def scan(xml_text: str, host_override: str | None = None) -> list[FindingDraft]:
    records = parse(_xml_only(xml_text))
    if host_override:
        for record in records:
            record.host = host_override
    return to_drafts(records)
