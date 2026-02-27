"""LEGACY: Content has been merged into bridge.py which is the single source of truth.
This file is kept for backward-compatibility and will be removed by the project owner.
Prefer importing from agentdecompile_cli.bridge.

MCP client for the AgentDecompile server.

Async client that connects to an AgentDecompile MCP server via HTTP
(Streamable HTTP transport at /mcp/message).

Usage:
    async with AgentDecompileMcpClient(host="127.0.0.1", port=8080) as client:
        tools = await client.list_tools()
        result = await client.call_tool("get-functions", {"programPath": "..."})
"""

from __future__ import annotations

import asyncio
import contextlib
import json

from typing import TYPE_CHECKING, Any

from agentdecompile_cli.utils import get_server_start_message, normalize_backend_url

if TYPE_CHECKING:
    from mcp.types import CallToolResult


class ClientError(Exception):
    """Custom exception for client errors."""


class ServerNotRunningError(ClientError):
    """Raised when the AgentDecompile server is not running or unreachable."""


class NotFoundError(ClientError):
    """Raised when a resource or program is not found."""


class AgentDecompileMcpClient:
    """MCP client for the AgentDecompile server.

    Connects via Streamable HTTP and provides async methods for
    list_tools, call_tool, list_resources, read_resource, list_prompts.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        url: str | None = None,
    ):
        """Initialize the client.

        Args:
            host: Server host (used if url is None).
            port: Server port (used if url is None).
            url: Override URL (e.g. http://host:port or http://host:port/mcp/message).
        """
        if url and url.strip():
            self._url = normalize_backend_url(url.strip())
        else:
            base = f"http://{host}:{port}"
            if not base.endswith("/mcp/message"):
                base = f"{base.rstrip('/')}/mcp/message"
            self._url = base
        self._session: Any = None
        self._exit_stack: contextlib.AsyncExitStack | None = None
        self._connected: bool = False

    async def __aenter__(self) -> AgentDecompileMcpClient:
        """Async context manager entry; establishes connection."""
        await self._connect_internal()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit; closes connection."""
        await self._close_internal()

    async def _connect_internal(self) -> None:
        """Establish connection to the AgentDecompile MCP server."""
        from mcp.client.session import ClientSession
        from mcp.client.streamable_http import streamablehttp_client

        self._exit_stack = contextlib.AsyncExitStack()
        await self._exit_stack.__aenter__()

        try:
            read, write, _ = await self._exit_stack.enter_async_context(
                streamablehttp_client(self._url, timeout=5),
            )
            self._session = await self._exit_stack.enter_async_context(
                ClientSession(read, write),
            )
            await self._session.initialize()
            self._connected = True
        except BaseException as e:
            try:
                await self._exit_stack.__aexit__(None, None, None)
            except BaseException:
                pass
            self._exit_stack = None
            self._session = None

            err = str(e)
            is_conn = (
                isinstance(e, (asyncio.TimeoutError, ConnectionError, OSError))
                or any(
                    x in err
                    for x in ["ConnectError", "connection", "ConnectionRefused", "All connection attempts failed"]
                )
            )
            if not is_conn and hasattr(e, "exceptions"):
                is_conn = any(
                    isinstance(sub, (ConnectionError, OSError))
                    or any(
                        x in str(sub)
                        for x in ["ConnectError", "connection", "ConnectionRefused", "All connection attempts failed"]
                    )
                    for sub in e.exceptions  # type: ignore[union-attr]
                )

            if is_conn:
                raise ServerNotRunningError(
                    f"Cannot connect to AgentDecompile server at {self._url}\n\n{get_server_start_message()}",
                ) from e
            if isinstance(e, Exception):
                raise ServerNotRunningError(
                    f"Cannot connect to AgentDecompile server at {self._url}: {e}\n\n{get_server_start_message()}",
                ) from e
            raise

    async def _close_internal(self) -> None:
        """Close connection and release resources."""
        self._connected = False
        self._session = None
        if self._exit_stack is not None:
            try:
                await self._exit_stack.__aexit__(None, None, None)
            except BaseException:
                pass
            self._exit_stack = None

    def _extract_result(self, result: CallToolResult) -> dict[str, Any]:
        """Extract data from MCP CallToolResult; raise on error or not-found."""
        result_dict = result.model_dump()

        if result_dict.get("isError"):
            content = result_dict.get("content", [])
            if content and len(content) > 0:
                c0 = content[0]
                if isinstance(c0, dict):
                    error_text = c0.get("text", "Unknown error")
                    raise ClientError(error_text)
            raise ClientError("Unknown error occurred")

        if "structuredContent" in result_dict:
            structured = result_dict["structuredContent"]
            if structured is None:
                content = result_dict.get("content", [])
                if content and len(content) > 0 and content[0].get("text"):
                    try:
                        return json.loads(content[0]["text"])
                    except (json.JSONDecodeError, KeyError):
                        pass
                raise NotFoundError(
                    "Resource not found. List programs or resources and try again.",
                )
            return structured

        if not result_dict or (isinstance(result_dict, dict) and not result_dict):
            raise NotFoundError(
                "Resource not found. List programs or resources and try again.",
            )

        return result_dict

    async def list_tools(self) -> list[Any]:
        """List tools offered by the server."""
        if not self._connected or self._session is None:
            raise ClientError("Not connected")
        result = await self._session.list_tools()
        return list(result.tools) if result and result.tools else []

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        """Call a tool by name with optional arguments.

        Returns the extracted JSON from the server. The server may return a
        error result: a dict with success=false and an "error" key; check for that
        if you need to handle errors programmatically (the CLI exits non-zero on such results).
        """
        if not self._connected or self._session is None:
            raise ClientError("Not connected")
        result = await self._session.call_tool(name, arguments or {})
        return self._extract_result(result)

    async def list_resources(self) -> list[Any]:
        """List resources offered by the server."""
        if not self._connected or self._session is None:
            raise ClientError("Not connected")
        result = await self._session.list_resources()
        return list(result.resources) if result and result.resources else []

    async def read_resource(self, uri: str) -> Any:
        """Read a resource by URI."""
        if not self._connected or self._session is None:
            raise ClientError("Not connected")
        result = await self._session.read_resource(uri)
        return result

    async def list_prompts(self) -> list[Any]:
        """List prompts offered by the server."""
        if not self._connected or self._session is None:
            raise ClientError("Not connected")
        result = await self._session.list_prompts()
        return list(result.prompts) if result and result.prompts else []
