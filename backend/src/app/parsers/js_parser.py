"""JavaScript AST parser wrapping jsluice for endpoint, route, parameter, and secret extraction."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import urllib.parse
from pathlib import Path
from typing import Any

from .models import ParsedEntities

logger = logging.getLogger(__name__)

# Search paths for jsluice binary
JSLUICE_BIN_NAMES = ["jsluice", "/home/dinesh/.local/bin/jsluice", "/usr/local/bin/jsluice"]


def _find_jsluice() -> str | None:
    for name in JSLUICE_BIN_NAMES:
        found = shutil.which(name)
        if found and os.access(found, os.X_OK):
            return found
        if os.path.exists(name) and os.access(name, os.X_OK):
            return name
    return None


def parse_js(
    js_content: str,
    file_path: Path | str | None = None,
    base_url: str = "",
) -> ParsedEntities:
    """Parse JavaScript code using jsluice AST extraction with regex fallback."""
    entities = ParsedEntities()
    if not js_content or not js_content.strip():
        return entities

    jsluice_bin = _find_jsluice()
    if jsluice_bin:
        try:
            # 1. Run jsluice urls
            if file_path and Path(file_path).exists():
                cmd = [jsluice_bin, "urls", str(file_path)]
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
            else:
                cmd = [jsluice_bin, "urls", "-j"]
                proc = subprocess.run(
                    cmd,
                    input=js_content,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )

            if proc.returncode == 0 and proc.stdout:
                for line in proc.stdout.splitlines():
                    line = line.strip()
                    if not line or not line.startswith("{"):
                        continue
                    try:
                        record = json.loads(line)
                        raw_url = record.get("url")
                        if not raw_url:
                            continue
                        url_str = str(raw_url).strip()
                        if url_str.startswith(("http://", "https://")):
                            try:
                                p_u = urllib.parse.urlsplit(url_str)
                                if p_u.fragment:
                                    frag = p_u.fragment.lstrip("/")
                                    url_str = f"/#/{frag}"
                                else:
                                    url_str = p_u.path
                            except Exception:
                                pass

                        cleaned = url_str.rstrip(".,;:'\")")
                        if (
                            cleaned.startswith("/")
                            and len(cleaned) > 2
                            and not cleaned.startswith(("//", "/?"))
                        ):
                            if cleaned.startswith("/#/"):
                                entities.routes.append(cleaned)
                                unhashed = cleaned[2:]
                                if unhashed and unhashed != "/":
                                    entities.routes.append(unhashed)
                            elif not cleaned.startswith("/#"):
                                entities.routes.append(cleaned)
                    except Exception:
                        continue

            # 2. Run jsluice secrets (extract interesting tokens/keys)
            if file_path and Path(file_path).exists():
                cmd_sec = [jsluice_bin, "secrets", str(file_path)]
                proc_sec = subprocess.run(
                    cmd_sec,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
            else:
                cmd_sec = [jsluice_bin, "secrets", "-j"]
                proc_sec = subprocess.run(
                    cmd_sec,
                    input=js_content,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )

            if proc_sec.returncode == 0 and proc_sec.stdout:
                for line in proc_sec.stdout.splitlines():
                    line = line.strip()
                    if not line or not line.startswith("{"):
                        continue
                    try:
                        sec_record = json.loads(line)
                        if "match" in sec_record:
                            entities.secrets.append(str(sec_record["match"])[:100])
                    except Exception:
                        continue
        except Exception as exc:
            logger.warning("jsluice execution failed, falling back to regex: %s", exc)

    # 3. Supplemental Regex Sweep (catches concatenated route fragments and hash routes)
    route_matches = re.findall(
        r"""["'`]((?:https?://[^"'`\s]+)?/(?:rest|api|auth|oauth|admin|ftp|file|redirect|profile|promotion|assets|v\d+|#/[a-zA-Z0-9_\-]+)[a-zA-Z0-9_\-/\.:]*)["'`]""",
        js_content,
    )
    for rm in route_matches:
        r_str = rm.strip()
        if r_str.startswith(("http://", "https://")):
            try:
                p_u = urllib.parse.urlsplit(r_str)
                if p_u.fragment:
                    frag = p_u.fragment.lstrip("/")
                    r_str = f"/#/{frag}"
                else:
                    r_str = p_u.path
            except Exception:
                pass
        cleaned_route = r_str.rstrip(".,;:'\")")
        if len(cleaned_route) > 2 and cleaned_route.startswith("/"):
            if cleaned_route.startswith("/#/"):
                entities.routes.append(cleaned_route)
                unhashed = cleaned_route[2:]
                if unhashed and unhashed != "/":
                    entities.routes.append(unhashed)
            elif not cleaned_route.startswith("/#"):
                entities.routes.append(cleaned_route)

    # 4. Framework Client-Side SPA Route Extraction (Angular, React Router, Vue Router)
    # Extracts router configurations like path: "administration" or path: 'score-board'
    spa_route_matches = re.findall(
        r"""(?:path|redirectTo)\s*:\s*[`'"]([a-zA-Z0-9_\-/\.:]+)[`'"]""",
        js_content,
    )
    IGNORED_SPA_TOKENS = {
        "**", "", "/", "true", "false", "null", "undefined", "string", "number",
        "object", "function", "any", "get", "post", "put", "delete", "none", "auto",
        "parent", "children", "root", "default",
    }
    for sr in spa_route_matches:
        s_clean = sr.strip().strip("/")
        if not s_clean or s_clean.lower() in IGNORED_SPA_TOKENS:
            continue
        if len(s_clean) < 3 or " " in s_clean:
            continue
        entities.routes.append(f"/#/{s_clean}")
        entities.routes.append(f"/{s_clean}")

    # 5. Extract linked chunk/script assets (e.g. main.js, vendor.js, polyfills.js, component chunks)
    script_chunks = re.findall(r"""["']([a-zA-Z0-9_\-\.]+\.(?:js|json|wasm))["']""", js_content[:50000])
    for chunk in script_chunks:
        if not chunk.startswith(("http://", "https://")) and len(chunk) > 3:
            entities.files.append(chunk)

    # Deduplicate
    entities.routes = list(dict.fromkeys(entities.routes))[:100]
    entities.files = list(dict.fromkeys(entities.files))[:50]
    entities.secrets = list(dict.fromkeys(entities.secrets))[:30]

    return entities
