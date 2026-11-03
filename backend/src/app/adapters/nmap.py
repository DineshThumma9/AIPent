"""Nmap adapter: fixed argv, typed parse, no severity invention."""

import xml.etree.ElementTree as ET
from typing import Literal

from pydantic import BaseModel

from app.adapters.base import EvidenceDraft, FindingDraft
from app.models import Severity

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


def argv(target: str, ports: list[int]) -> list[str]:
    return [
        "nmap",
        "-sV",
        "-Pn",
        "-T3",
        "-p",
        ",".join(map(str, ports)),
        "-oX",
        "-",
        target,
    ]


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


def scan(xml_text: str) -> list[FindingDraft]:
    return to_drafts(parse(xml_text))
