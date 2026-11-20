"""HTML DOM parser using BeautifulSoup for deterministic route, form, file, and comment extraction."""

from __future__ import annotations

import re
import urllib.parse
import warnings
from typing import Any

from bs4 import BeautifulSoup, Comment, XMLParsedAsHTMLWarning

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

from .models import FormEntity, FormField, ParsedEntities

INTERESTING_FILE_EXTENSIONS = (
    ".md",
    ".txt",
    ".bak",
    ".zip",
    ".pdf",
    ".kdbx",
    ".json",
    ".yml",
    ".yaml",
    ".pyc",
    ".log",
    ".sql",
    ".conf",
    ".db",
    ".tar",
    ".gz",
    ".env",
    ".swp",
    ".old",
    ".backup",
)

COMMENT_KEYWORD_PATTERNS = re.compile(
    r"(?:password|secret|token|api[_-]?key|admin|debug|todo|endpoint|bearer|credentials?|internal)",
    re.IGNORECASE,
)


def parse_html(html_text: str, base_url: str = "") -> ParsedEntities:
    """Parse HTML content to extract forms, input fields, scripts, links, files, and comments."""
    entities = ParsedEntities()
    if not html_text or not html_text.strip():
        return entities

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=XMLParsedAsHTMLWarning)
            soup = BeautifulSoup(html_text, "html.parser")
    except Exception:
        return entities

    base_path = ""
    if base_url:
        try:
            base_path = urllib.parse.urlparse(base_url).path
        except Exception:
            base_path = ""

    # 1. Forms and Input Fields
    for form in soup.find_all("form"):
        raw_action = form.get("action") or ""
        method = (form.get("method") or "GET").upper()

        action = str(raw_action).strip()
        if not action:
            action = base_path or "/"
        elif action.startswith(("http://", "https://")):
            try:
                action = urllib.parse.urlparse(action).path or "/"
            except Exception:
                pass
        elif not action.startswith("/"):
            action = f"/{action}"

        fields: list[FormField] = []
        for inp in form.find_all(["input", "textarea", "select", "button"]):
            name = inp.get("name") or inp.get("id")
            if not name:
                continue
            inp_type = inp.get("type") or inp.name
            fields.append(FormField(name=str(name).strip(), type=str(inp_type).lower().strip()))

        entities.forms.append(FormEntity(action=action, method=method, inputs=fields))
        if action.startswith("/"):
            entities.routes.append(action)

    # 2. Scripts
    for script in soup.find_all("script"):
        src = script.get("src")
        if src:
            src_clean = str(src).strip()
            if not src_clean.startswith(("http://", "https://", "//")):
                entities.files.append(src_clean)
            elif base_url and base_url in src_clean:
                try:
                    p = urllib.parse.urlparse(src_clean).path
                    if p:
                        entities.files.append(p.lstrip("/"))
                except Exception:
                    pass

    # 3. Links, Directory Listings, and Downloadable Files
    is_dir_listing = any(
        ind in html_text[:2000].lower()
        for ind in [
            "index of",
            "listing directory",
            'id="indexlist"',
            'id="directory"',
            '<table id="indexlist"',
        ]
    )

    for a in soup.find_all("a", href=True):
        href = str(a.get("href", "")).strip()
        if not href or href.startswith(("?", "#", "javascript:", "mailto:")):
            continue

        # Ignore parent directory links in directory listings
        if is_dir_listing or "/ftp" in (base_url or "").lower():
            if href in (".", "..", "./", "../", "/"):
                continue
            if href.lower() in ("parent directory", "parent directory/"):
                continue
            if base_path and href.strip("/") == base_path.strip("/"):
                continue
            clean_href = href[2:] if href.startswith("./") else href
            if not clean_href.startswith(("http://", "https://")):
                entities.files.append(clean_href)
                continue

        # Extract known interesting file extensions
        href_lower = href.lower()
        if any(href_lower.endswith(ext) or f"{ext}?" in href_lower for ext in INTERESTING_FILE_EXTENSIONS):
            clean_file = href
            if clean_file.startswith(("http://", "https://")):
                try:
                    clean_file = urllib.parse.urlparse(clean_file).path
                except Exception:
                    pass
            entities.files.append(clean_file.lstrip("/"))

        # Extract internal API or web routes
        if href.startswith("/"):
            clean_route = href.split("?")[0].split("#")[0].rstrip("/")
            if clean_route and len(clean_route) > 1:
                entities.routes.append(clean_route)

    # 4. Comments (leaked endpoints, secrets, TODOs)
    for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
        c_text = str(comment).strip()
        if not c_text:
            continue
        if COMMENT_KEYWORD_PATTERNS.search(c_text) or "/" in c_text:
            # Check for candidate route in comment
            comment_routes = re.findall(r"""/(?:rest|api|auth|admin|v\d+)[a-zA-Z0-9_\-/\.:]*""", c_text)
            for cr in comment_routes:
                entities.routes.append(cr.rstrip(".,;:'\")"))
            entities.comments.append(c_text[:300])

    # 5. Regex route sweep in raw HTML (for client-side routing configs)
    raw_routes = re.findall(
        r"""["'`]((?:https?://[^"'`\s]+)?/(?:rest|api|auth|oauth|admin|ftp|file|redirect|profile|promotion|assets|v\d+)[a-zA-Z0-9_\-/\.:]*)["'`]""",
        html_text,
    )
    for rr in raw_routes:
        r_str = rr.strip()
        if r_str.startswith(("http://", "https://")):
            try:
                r_str = urllib.parse.urlparse(r_str).path
            except Exception:
                pass
        cleaned = r_str.rstrip(".,;:'\")")
        if len(cleaned) > 2 and cleaned.startswith("/"):
            entities.routes.append(cleaned)

    # Deduplicate while preserving order
    entities.routes = list(dict.fromkeys(entities.routes))[:100]
    entities.files = list(dict.fromkeys(entities.files))[:100]
    entities.comments = list(dict.fromkeys(entities.comments))[:30]

    return entities
