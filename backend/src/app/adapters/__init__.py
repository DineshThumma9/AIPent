"""One module per tool. Each exposes argv/parse/to_drafts and knows nothing
about the database or the LLM."""

from app.adapters import (
    dirb,
    ffuf,
    hashcat,
    katana,
    nikto,
    nmap,
    nuclei,
    sqlmap,
    sslscan,
    whatweb,
    zap,
)

__all__ = [
    "dirb",
    "ffuf",
    "hashcat",
    "katana",
    "nikto",
    "nmap",
    "nuclei",
    "sqlmap",
    "sslscan",
    "whatweb",
    "zap",
]

