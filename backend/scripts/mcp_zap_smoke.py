"""Direct smoke test for dtkmn/mcp-zap-server. Not part of the app.

It reuses the production guided workflow against the server over streamable
HTTP, so a pass exercises the same parsing the backend uses.
"""

import asyncio
import json
import os
from typing import Any

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from app.integrations.zap_guided import run_zap_baseline
from app.mcp_client import normalise_text

URL = os.getenv("ZAP_MCP_URL", "http://127.0.0.1:7456/mcp")
KEY = os.environ["MCP_API_KEY"]
TARGET = os.getenv("AIPENT_LAB_URL", "http://host.docker.internal:3000")


class DirectGateway:
    """Minimal adapter so the app workflow can talk to dtkmn directly."""

    def __init__(self, session: ClientSession):
        self.session = session

    async def call(self, name: str, arguments: dict[str, Any]) -> str:
        result = await self.session.call_tool(name, arguments)
        text = "\n".join(
            getattr(item, "text", "") for item in result.content
        ).strip()
        if result.is_error:
            raise RuntimeError(text or f"{name} returned an MCP error")
        return normalise_text(text)


async def main() -> None:
    headers = {"X-API-Key": KEY}
    # MCP SDK 2.x: headers go on an httpx2 client, and the transport yields
    # exactly two streams (the old third get_session_id value is gone).
    async with httpx2.AsyncClient(
        headers=headers, timeout=httpx2.Timeout(30, read=600)
    ) as http_client:
        async with streamable_http_client(
            URL, http_client=http_client
        ) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                tools = await session.list_tools()
                names = sorted(tool.name for tool in tools.tools)
                print("tools:", ", ".join(names))
                for name in (
                    "zap_crawl_start",
                    "zap_crawl_status",
                    "zap_passive_scan_wait",
                    "zap_report_generate",
                    "zap_report_read_chunk",
                ):
                    assert name in names, f"missing {name}"

                body, calls = await run_zap_baseline(
                    DirectGateway(session), TARGET, "aipent-smoke-1"
                )

                document = json.loads(body)
                alerts = sum(
                    len(site.get("alerts", []))
                    for site in document.get("site", [])
                )
                print("calls:", ", ".join(call["tool"] for call in calls))
                print("report chars:", len(body))
                print("sites:", len(document.get("site", [])))
                print("alerts:", alerts)


if __name__ == "__main__":
    asyncio.run(main())
