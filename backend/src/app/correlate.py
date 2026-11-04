"""Cross-tool finding identity.

Adapters report what their tool saw. Correlation gives the *same issue* the
same key so Nikto and ZAP evidence lands on one Finding instead of two. Keys
for unknown issues stay tool-specific: we only merge when the rule is explicit.
"""

import re
from urllib.parse import urlparse

from app.adapters.base import FindingDraft

# Ordered: the first matching family wins.
_RULES: list[tuple[tuple[str, ...], str]] = [
    (("content-security-policy", "content security policy", "csp header"), "csp"),
    (("x-frame-options", "x frame options", "clickjacking"), "x-frame-options"),
    (
        ("x-content-type-options", "x content type options", "mime type"),
        "x-content-type-options",
    ),
    (("strict-transport-security", "hsts"), "hsts"),
    (("server version", "server banner", "server leaks", "server header"), "server-banner"),
    (("directory listing", "directory indexing", "directory traversal"), "directory-listing"),
    (("backup file", "backup", "config file", "configuration file", "exposed"), "exposed-file"),
    (("httponly", "secure flag", "cookie"), "cookie-flags"),
]


def _port(draft: FindingDraft) -> int:
    endpoint = draft.endpoint or ""
    parsed = urlparse(endpoint)
    if parsed.port:
        return parsed.port
    match = re.search(r"(?:tcp|udp)/(\d+)", endpoint)
    return int(match.group(1)) if match else 0


def _title(draft: FindingDraft) -> str:
    return f"{draft.title} {draft.description}".lower()


def canonical_key(draft: FindingDraft) -> str:
    """Return the stable identity used by the unique constraint."""
    title = _title(draft)
    for needles, family in _RULES:
        if any(needle in title for needle in needles):
            return f"web:{family}:{draft.asset}:{_port(draft)}"

    if (draft.endpoint or "").startswith("http"):
        slug = re.sub(r"[^a-z0-9]+", "-", draft.title.lower()).strip("-")[:60]
        return f"web:{slug}:{draft.asset}:{_port(draft)}"

    return draft.canonical_key
