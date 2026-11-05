"""Standalone SPA Wildcard Fallback Detector.

Detects if a target returns 200 with root HTML for random paths (SPA wildcard fallback).
"""

import asyncio
import sys
import uuid
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


async def check_wildcard(target: str, port: int = 3000, timeout: int = 10) -> dict[str, Any]:
    """Probe random path to detect SPA wildcard fallback."""
    base_url = f"http://{target}:{port}"
    random_path = f"/definitely-random-uuid-404-check-{uuid.uuid4().hex[:12]}"
    url = f"{base_url}{random_path}"

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        try:
            response = await client.get(url)
            is_wildcard = (
                response.status_code == 200 and
                ("<html" in response.text.lower() or "<!doctype html" in response.text.lower())
            )
            return {
                "target": target,
                "port": port,
                "test_url": url,
                "status_code": response.status_code,
                "is_wildcard": is_wildcard,
                "content_type": response.headers.get("content-type", ""),
                "body_preview": response.text[:500],
            }
        except Exception as e:
            return {
                "target": target,
                "port": port,
                "test_url": url,
                "error": str(e),
                "is_wildcard": False,
            }


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Detect SPA wildcard fallback")
    parser.add_argument("target", help="Target host (e.g., 127.0.0.1)")
    parser.add_argument("-p", "--port", type=int, default=3000, help="Target port")
    parser.add_argument("--format", choices=["json", "text"], default="json")
    parser.add_argument("--timeout", type=int, default=10)

    args = parser.parse_args()

    result = asyncio.run(check_wildcard(args.target, args.port, args.timeout))

    if args.format == "json":
        json.dump(result, sys.stdout, indent=2)
    else:
        if result.get("is_wildcard"):
            print(f"WILDCARD DETECTED: {args.target}:{args.port} returns 200 with HTML for random path")
        else:
            print(f"No wildcard: {args.target}:{args.port} returned {result.get('status_code')}")
        sys.exit(0 if result.get("is_wildcard") else 1)