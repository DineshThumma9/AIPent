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
                                url_str = urllib.parse.urlparse(url_str).path
                            except Exception:
                                pass

                        cleaned = url_str.rstrip(".,;:'\")")
                        if (
                            cleaned.startswith("/")
                            and len(cleaned) > 2
                            and not cleaned.startswith(("//", "/#", "/?"))
                        ):
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

    # 3. Supplemental Regex Sweep (catches concatenated route fragments that AST might classify differently)
    route_matches = re.findall(
        r"""["'`]((?:https?://[^"'`\s]+)?/(?:rest|api|auth|oauth|admin|ftp|file|redirect|profile|promotion|assets|v\d+)[a-zA-Z0-9_\-/\.:]*)["'`]""",
        js_content,
    )
    for rm in route_matches:
        r_str = rm.strip()
        if r_str.startswith(("http://", "https://")):
            try:
                r_str = urllib.parse.urlparse(r_str).path
            except Exception:
                pass
        cleaned_route = r_str.rstrip(".,;:'\")")
        if len(cleaned_route) > 2 and cleaned_route.startswith("/"):
            entities.routes.append(cleaned_route)

    # 4. Extract linked chunk/script assets (e.g. main.js, vendor.js, polyfills.js)
    script_chunks = re.findall(r"""["']([a-zA-Z0-9_\-\.]+\.(?:js|json|wasm))["']""", js_content[:20000])
    for chunk in script_chunks:
        if not chunk.startswith(("http://", "https://")) and len(chunk) > 3:
            entities.files.append(chunk)

    # Deduplicate
    entities.routes = list(dict.fromkeys(entities.routes))[:100]
    entities.files = list(dict.fromkeys(entities.files))[:50]
    entities.secrets = list(dict.fromkeys(entities.secrets))[:30]

    return entities
