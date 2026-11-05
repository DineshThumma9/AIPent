"""One MCP client for the Docker MCP Gateway.

The gateway is the only transport. The backend never imports a vendor SDK or
speaks to a scanner directly.

The gateway can be started with either wire transport:

* ``--transport=streaming`` -> ``http://127.0.0.1:8812/mcp`` (preferred)
* ``--transport=sse``       -> ``http://127.0.0.1:8812/sse``

The URL selects the client transport, so switching the gateway does not
require a code change.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import AsyncExitStack
from typing import Any

import httpx2
from anyio import BrokenResourceError, ClosedResourceError
from mcp import ClientSession
from mcp.client.sse import sse_client
from mcp.client.streamable_http import streamable_http_client

from app.core.config import settings


class GatewayError(RuntimeError):
    """A gateway call failed, timed out, or returned no text."""


def normalise_text(text: str) -> str:
    """Unwrap JSON string literals returned by Spring AI.

    Kali returns plain text. dtkmn wraps every string result as a JSON string
    literal, so a status message arrives as ``"line\\nline"``. Only unwrap a
    payload that is a JSON string; JSON objects and arrays are left alone.
    """
    stripped = text.strip()
    if len(stripped) >= 2 and stripped[0] == '"' and stripped[-1] == '"':
        try:
            decoded = json.loads(stripped)
        except json.JSONDecodeError:
            return text
        if isinstance(decoded, str):
            return decoded
    return text


def _teardown_noise(exc: BaseException) -> bool:
    """SSE teardown can race its reader task; that is not a tool failure."""
    if isinstance(exc, BaseExceptionGroup):
        return all(_teardown_noise(child) for child in exc.exceptions)
    return isinstance(exc, (BrokenResourceError, ClosedResourceError))


class GatewayClient:
    def __init__(
        self,
        url: str | None = None,
        timeout: int | None = None,
        handshake_timeout: int | None = None,
    ):
        self.url = url or settings.mcp_gateway_url
        self.timeout = timeout or settings.mcp_timeout
        self.handshake_timeout = (
            handshake_timeout or settings.mcp_handshake_timeout
        )
        self._stack = AsyncExitStack()
        self._session: ClientSession | None = None

    async def __aenter__(self) -> "GatewayClient":
        try:
            # A dead gateway must fail the step, not hang the worker forever.
            async with asyncio.timeout(self.handshake_timeout):
                if self.url.rstrip("/").endswith("/sse"):
                    read, write = await self._stack.enter_async_context(
                        sse_client(self.url)
                    )
                else:
                    http_client = await self._stack.enter_async_context(
                        httpx2.AsyncClient(
                            timeout=httpx2.Timeout(
                                self.handshake_timeout, read=self.timeout
                            )
                        )
                    )
                    read, write = await self._stack.enter_async_context(
                        streamable_http_client(
                            self.url, http_client=http_client
                        )
                    )
                self._session = await self._stack.enter_async_context(
                    ClientSession(read, write)
                )
                await self._session.initialize()
        except TimeoutError as exc:
            await self._stack.aclose()
            raise GatewayError(
                f"gateway handshake timed out after {self.handshake_timeout}s"
            ) from exc
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        try:
            await self._stack.aclose()
        except BaseException as teardown:
            # Only hide teardown races when the action itself succeeded.
            if exc_type is None and _teardown_noise(teardown):
                return
            raise

    async def list_tools(self) -> list[str]:
        assert self._session is not None
        result = await self._session.list_tools()
        return sorted(tool.name for tool in result.tools)

    async def call(self, name: str, arguments: dict[str, Any]) -> str:
        assert self._session is not None
        try:
            async with asyncio.timeout(self.timeout):
                result = await self._session.call_tool(name, arguments)
        except TimeoutError as exc:
            raise GatewayError(
                f"{name} timed out after {self.timeout}s"
            ) from exc

        text = "\n".join(
            getattr(item, "text", "")
            for item in (result.content or [])
            if getattr(item, "text", None)
        ).strip()

        if result.is_error:
            raise GatewayError(text or f"{name} returned an MCP error")
        if not text and result.structured_content is not None:
            text = json.dumps(result.structured_content)
        if not text:
            raise GatewayError(f"{name} returned no text")
        return normalise_text(text)
