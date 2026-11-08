"""sslscan adapter: XML parser for TLS/SSL configuration and cipher facts.

Emits findings based on negotiated protocols and certificate validity:
- SSLv2/SSLv3 enabled -> MEDIUM severity
- TLS 1.0/TLS 1.1 enabled -> LOW severity
- Expired / self-signed certificate -> MEDIUM / LOW severity
- Modern TLS (1.2/1.3) and ciphers -> INFO severity
Never invents CVEs.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from app.adapters.base import EvidenceDraft, FindingDraft
from app.domain.models import FindingStatus, Severity


def scan(
    xml_text: str,
    host: str,
    port: int,
    host_override: str | None = None,
) -> list[FindingDraft]:
    """Parse sslscan XML into FindingDraft objects."""
    text = xml_text.strip()
    if not text:
        return []

    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        start = text.find("<document")
        end = text.rfind("</document>")
        if start >= 0 and end >= 0:
            try:
                root = ET.fromstring(text[start : end + len("</document>")])
            except ET.ParseError:
                return []
        else:
            return []

    effective_host = host_override or host
    drafts: list[FindingDraft] = []
    seen_keys: set[str] = set()

    ssltest = root.find("ssltest") if root.tag == "document" else root
    if ssltest is None:
        ssltest = root

    target_host = ssltest.get("host") or effective_host
    target_port_str = ssltest.get("port")
    try:
        target_port = int(target_port_str) if target_port_str else port
    except ValueError:
        target_port = port

    # 1. Parse protocols
    for proto_node in ssltest.iter("protocol"):
        proto_type = (proto_node.get("type") or "").lower()
        version = (proto_node.get("version") or "").lower()
        enabled_val = proto_node.get("enabled", "").lower()
        is_enabled = enabled_val in ("1", "true", "yes")

        proto_label = f"{proto_type} {version}".strip().upper()
        if not is_enabled:
            continue

        if "ssl" in proto_type or version in ("v2", "v3", "2.0", "3.0"):
            fact = f"protocol:{proto_label.lower().replace(' ', '_')}:insecure"
            key = f"sslscan:{target_host}:{target_port}:{fact}"
            if key not in seen_keys:
                seen_keys.add(key)
                drafts.append(
                    FindingDraft(
                        canonical_key=key,
                        asset=target_host,
                        endpoint=f"{target_host}:{target_port}",
                        title=f"Insecure SSL protocol enabled ({proto_label})",
                        description=f"sslscan detected deprecated and insecure {proto_label} enabled on {target_host}:{target_port}.",
                        severity=Severity.MEDIUM,
                        confidence=0.9,
                        status=FindingStatus.CONFIRMED,
                        evidence=[
                            EvidenceDraft(
                                locator={
                                    "tool": "sslscan",
                                    "target": target_host,
                                    "port": target_port,
                                    "fact": fact,
                                },
                                excerpt=f"protocol {proto_label} enabled",
                            )
                        ],
                    )
                )
        elif version in ("v1.0", "v1.1", "1.0", "1.1"):
            fact = f"protocol:{proto_label.lower().replace(' ', '_')}:deprecated"
            key = f"sslscan:{target_host}:{target_port}:{fact}"
            if key not in seen_keys:
                seen_keys.add(key)
                drafts.append(
                    FindingDraft(
                        canonical_key=key,
                        asset=target_host,
                        endpoint=f"{target_host}:{target_port}",
                        title=f"Deprecated TLS protocol enabled ({proto_label})",
                        description=f"sslscan detected deprecated {proto_label} enabled on {target_host}:{target_port}.",
                        severity=Severity.LOW,
                        confidence=0.9,
                        status=FindingStatus.CONFIRMED,
                        evidence=[
                            EvidenceDraft(
                                locator={
                                    "tool": "sslscan",
                                    "target": target_host,
                                    "port": target_port,
                                    "fact": fact,
                                },
                                excerpt=f"protocol {proto_label} enabled",
                            )
                        ],
                    )
                )
        else:
            # Modern TLS (v1.2, v1.3)
            fact = f"protocol:{proto_label.lower().replace(' ', '_')}:supported"
            key = f"sslscan:{target_host}:{target_port}:{fact}"
            if key not in seen_keys:
                seen_keys.add(key)
                drafts.append(
                    FindingDraft(
                        canonical_key=key,
                        asset=target_host,
                        endpoint=f"{target_host}:{target_port}",
                        title=f"Supported TLS protocol ({proto_label})",
                        description=f"sslscan confirmed {proto_label} is supported on {target_host}:{target_port}.",
                        severity=Severity.INFO,
                        confidence=0.95,
                        status=FindingStatus.CONFIRMED,
                        evidence=[
                            EvidenceDraft(
                                locator={
                                    "tool": "sslscan",
                                    "target": target_host,
                                    "port": target_port,
                                    "fact": fact,
                                },
                                excerpt=f"protocol {proto_label} enabled",
                            )
                        ],
                    )
                )

    # 2. Parse certificates
    for cert_node in ssltest.iter("certificate"):
        subject_elem = cert_node.find("subject")
        issuer_elem = cert_node.find("issuer")
        subject = subject_elem.text if subject_elem is not None and subject_elem.text else ""
        issuer = issuer_elem.text if issuer_elem is not None and issuer_elem.text else ""

        # Check expired
        expired_node = cert_node.find(".//expired")
        is_expired = False
        if expired_node is not None and expired_node.text:
            is_expired = expired_node.text.strip().lower() in ("true", "1", "yes")

        if is_expired:
            fact = "cert:expired"
            key = f"sslscan:{target_host}:{target_port}:{fact}"
            if key not in seen_keys:
                seen_keys.add(key)
                drafts.append(
                    FindingDraft(
                        canonical_key=key,
                        asset=target_host,
                        endpoint=f"{target_host}:{target_port}",
                        title=f"Expired SSL/TLS certificate on {target_host}:{target_port}",
                        description=f"The certificate presented by {target_host}:{target_port} is expired. Subject: {subject}.",
                        severity=Severity.MEDIUM,
                        confidence=0.95,
                        status=FindingStatus.CONFIRMED,
                        evidence=[
                            EvidenceDraft(
                                locator={
                                    "tool": "sslscan",
                                    "target": target_host,
                                    "port": target_port,
                                    "fact": fact,
                                },
                                excerpt=f"Certificate expired. Subject: {subject}",
                            )
                        ],
                    )
                )

        # Check self-signed
        self_signed_node = cert_node.find(".//self-signed")
        is_self_signed = False
        if self_signed_node is not None and self_signed_node.text:
            is_self_signed = self_signed_node.text.strip().lower() in ("true", "1", "yes")

        if is_self_signed:
            fact = "cert:self_signed"
            key = f"sslscan:{target_host}:{target_port}:{fact}"
            if key not in seen_keys:
                seen_keys.add(key)
                drafts.append(
                    FindingDraft(
                        canonical_key=key,
                        asset=target_host,
                        endpoint=f"{target_host}:{target_port}",
                        title=f"Self-signed SSL/TLS certificate on {target_host}:{target_port}",
                        description=f"The certificate on {target_host}:{target_port} is self-signed. Subject: {subject}.",
                        severity=Severity.LOW,
                        confidence=0.9,
                        status=FindingStatus.CONFIRMED,
                        evidence=[
                            EvidenceDraft(
                                locator={
                                    "tool": "sslscan",
                                    "target": target_host,
                                    "port": target_port,
                                    "fact": fact,
                                },
                                excerpt=f"Self-signed certificate. Subject: {subject}",
                            )
                        ],
                    )
                )

        # Informational certificate observation
        if subject or issuer:
            fact = "cert:info"
            key = f"sslscan:{target_host}:{target_port}:{fact}"
            if key not in seen_keys:
                seen_keys.add(key)
                drafts.append(
                    FindingDraft(
                        canonical_key=key,
                        asset=target_host,
                        endpoint=f"{target_host}:{target_port}",
                        title=f"SSL/TLS certificate metadata on {target_host}:{target_port}",
                        description=f"Certificate subject: {subject or 'N/A'}, Issuer: {issuer or 'N/A'}.",
                        severity=Severity.INFO,
                        confidence=0.9,
                        status=FindingStatus.CONFIRMED,
                        evidence=[
                            EvidenceDraft(
                                locator={
                                    "tool": "sslscan",
                                    "target": target_host,
                                    "port": target_port,
                                    "fact": fact,
                                },
                                excerpt=f"Subject: {subject}; Issuer: {issuer}",
                            )
                        ],
                    )
                )

    return drafts
