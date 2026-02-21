"""
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
import json
from typing import TYPE_CHECKING, Any

from agentdecompile_cli.utils import get_server_start_message, normalize_backend_url

if TYPE_CHECKING:
    from mcp.types import CallToolResult


class ClientError(Exception):
    """Custom exception for client errors."""

    pass


class ServerNotRunningError(ClientError):
    """Raised when the AgentDecompile server is not running or unreachable."""

    pass


class NotFoundError(ClientError):
    """Raised when a resource or program is not found."""

    pass


class AgentDecompileMcpClient:
    """
    MCP client for the AgentDecompile server.

    Connects via Streamable HTTP and provides async methods for
    list_tools, call_tool, list_resources, read_resource, list_prompts.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        url: str | None = None,
        api_key: str | None = None,
    ):
        """
        Initialize the client.

        Args:
            host: Server host (used if url is None).
            port: Server port (used if url is None).
            url: Override URL (e.g. http://host:port or http://host:port/mcp/message).
            api_key: Optional X-API-Key header value.
        """
        if url and url.strip():
            self._url = normalize_backend_url(url.strip())
        else:
            base = f"http://{host}:{port}"
            if not base.endswith("/mcp/message"):
                base = f"{base.rstrip('/')}/mcp/message"
            self._url = base
        self._api_key = api_key.strip() if api_key and api_key.strip() else None
        self._session: Any = None
        self._session_cm: Any = None
        self._transport_cm: Any = None
        self._connected: bool = False

    async def __aenter__(self) -> AgentDecompileMcpClient:
        """Async context manager entry; establishes connection."""
        await self._connect_internal()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit; closes connection."""
        await self._close_internal()
        return None

    async def _connect_internal(self) -> None:
        """Establish connection to the AgentDecompile MCP server."""
        from mcp.client.session import ClientSession
        from mcp.client.streamable_http import streamablehttp_client

        headers = None
        if self._api_key:
            headers = {"X-API-Key": self._api_key}

        transport_gen = (
            streamablehttp_client(self._url, headers=headers)
            if headers
            else streamablehttp_client(self._url)
        )
        try:
            read, write, _ = await asyncio.wait_for(
                transport_gen.__aenter__(),
                timeout=5.0,
            )
        except asyncio.TimeoutError:
            try:
                await transport_gen.__aexit__(None, None, None)
            except Exception:
                pass
            raise ServerNotRunningError(
                f"Cannot connect to AgentDecompile server at {self._url}\n\n"
                f"{get_server_start_message()}"
            ) from None
        except (ConnectionError, OSError) as e:
            try:
                await transport_gen.__aexit__(None, None, None)
            except Exception:
                pass
            raise ServerNotRunningError(
                f"Cannot connect to AgentDecompile server at {self._url}\n\n"
                f"{get_server_start_message()}"
            ) from e
        except Exception as e:
            try:
                await transport_gen.__aexit__(None, None, None)
            except Exception:
                pass
            err = str(e)
            if any(
                x in err
                for x in ["ConnectError", "connection", "ConnectionRefused"]
            ):
                raise ServerNotRunningError(
                    f"Cannot connect to AgentDecompile server at {self._url}\n\n"
                    f"{get_server_start_message()}"
                ) from e
            raise ServerNotRunningError(
                f"Cannot connect to AgentDecompile server at {self._url}: {e}\n\n"
                f"{get_server_start_message()}"
            ) from e

        self._transport_cm = transport_gen
        self._session_cm = ClientSession(read, write)
        self._session = await self._session_cm.__aenter__()
        await self._session.initialize()
        self._connected = True

    async def _close_internal(self) -> None:
        """Close connection and release resources."""
        if self._session_cm is not None and self._connected:
            self._connected = False
            try:
                await self._session_cm.__aexit__(None, None, None)
            except Exception:
                pass
            self._session_cm = None
            self._session = None
        if self._transport_cm is not None:
            try:
                await self._transport_cm.__aexit__(None, None, None)
            except Exception:
                pass
            self._transport_cm = None

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
                    "Resource not found. List programs or resources and try again."
                )
            return structured

        if not result_dict or (isinstance(result_dict, dict) and not result_dict):
            raise NotFoundError(
                "Resource not found. List programs or resources and try again."
            )

        return result_dict

    async def list_tools(self) -> list[Any]:
        """List tools offered by the server."""
        if not self._connected or self._session is None:
            raise ClientError("Not connected")
        result = await self._session.list_tools()
        return list(result.tools) if result and result.tools else []

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        """Call a tool by name with optional arguments."""
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
