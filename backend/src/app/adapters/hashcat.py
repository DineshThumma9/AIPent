"""Hashcat adapter: parses hashcat output artifacts with strict plaintext redaction.

Only hashes are captured and reported. Plaintext credentials are never stored,
surfaced in observations, or printed in reports.
"""

from __future__ import annotations

from app.adapters.base import EvidenceDraft, FindingDraft
from app.domain.models import FindingStatus, Severity


def scan(
    output_text: str,
    host: str,
    port: int = 0,
    host_override: str | None = None,
) -> list[FindingDraft]:
    """Parse hashcat cracked hash output.

    Assumes --outfile-format 1 (hash only).
    """
    effective_host = host_override or host
    lines = [line.strip() for line in output_text.splitlines() if line.strip()]
    if not lines:
        return []

    # Count unique cracked hashes
    unique_hashes = list(dict.fromkeys(lines))
    cracked_count = len(unique_hashes)

    return [
        FindingDraft(
            canonical_key=f"hashcat:{effective_host}:weak-password-policy",
            asset=effective_host,
            endpoint=effective_host,
            title=f"Weak password policy on {effective_host}",
            description=(
                "Offline cracking recovered at least one credential from the captured hash "
                "material; plaintext is intentionally omitted."
            ),
            severity=Severity.HIGH,
            confidence=0.95,
            status=FindingStatus.CONFIRMED,
            evidence=[
                EvidenceDraft(
                    locator={
                        "tool": "hashcat_crack",
                        "cracked_count": cracked_count,
                    },
                    excerpt=f"{cracked_count} hash(es) cracked; plaintext redacted.",
                )
            ],
        )
    ]
