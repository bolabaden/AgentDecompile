"""
Stdio to HTTP MCP bridge using official MCP SDK Server abstraction.

Provides a proper MCP Server that forwards all requests to AgentDecompile's StreamableHTTP endpoint.
Uses the MCP SDK's stdio transport and Pydantic serialization - no manual JSON-RPC handling.

The bridge acts as a transparent proxy - all tool calls, resources, and prompts are
forwarded to the Java AgentDecompile backend running on localhost.
"""

from __future__ import annotations

import asyncio
import sys
from collections import deque
from typing import TYPE_CHECKING, Any, Iterable

try:
    from anyio import BrokenResourceError, ClosedResourceError
except ImportError:
    # Fallback when anyio is unavailable - use distinct classes so except
    # (BrokenResourceError, ClosedResourceError) does not shadow except Exception
    class _PlaceholderConnectionError(Exception):  # noqa: B903
        """Placeholder; never raised when anyio is not available."""

    BrokenResourceError = _PlaceholderConnectionError
    ClosedResourceError = _PlaceholderConnectionError

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.shared.message import SessionMessage
from mcp.types import (
    JSONRPCMessage,
    JSONRPCNotification,
    TextContent,
)

from agentdecompile_cli.utils import get_server_start_message, normalize_backend_url


class ClientError(Exception):
    """Custom exception for client errors."""

    pass


class ServerNotRunningError(ClientError):
    """Raised when the backend is not running or unreachable."""

    pass


# Timeout for initial transport connect (separate from long-running operation timeouts)
CONNECT_TIMEOUT = 5.0


def _is_jsonrpc_request(msg: SessionMessage) -> bool:
    """True if message is a JSON-RPC request (has method and id)."""
    m = getattr(msg, "message", None)
    if m is None:
        return False
    return getattr(m, "method", None) is not None and getattr(m, "id", None) is not None


def _is_jsonrpc_response_with_id_zero(msg: SessionMessage) -> bool:
    """True if message is a JSON-RPC response (has result or error) with id 0."""
    m = getattr(msg, "message", None)
    if m is None:
        return False
    mid = getattr(m, "id", None)
    if mid != 0:
        return False
    return getattr(m, "result", None) is not None or getattr(m, "error", None) is not None


def _session_message_with_id(msg: SessionMessage, new_id: int | str) -> SessionMessage:
    """Return a new SessionMessage with the same content but response id set to new_id."""
    m = msg.message
    if not hasattr(m, "model_copy"):
        return msg
    new_msg = m.model_copy(update={"id": new_id})
    return SessionMessage(message=new_msg, metadata=msg.metadata)


class _IdFixReadStream:
    """
    Wraps the stdio read stream and records JSON-RPC request ids so responses
    with id:0 can be rewritten to match (see _IdFixWriteStream).
    """

    def __init__(self, read_stream: Any, request_ids: deque[int | str]) -> None:
        self._read = read_stream
        self._request_ids = request_ids

    def __aiter__(self) -> Any:
        return self

    async def __anext__(self) -> SessionMessage | Exception:
        item = await self._read.__anext__()
        if isinstance(item, SessionMessage) and _is_jsonrpc_request(item):
            rid = getattr(item.message, "id", None)
            if rid is not None:
                self._request_ids.append(rid)
        return item


class _IdFixWriteStream:
    """
    Wraps the stdio write stream and rewrites any JSON-RPC response with id:0
    to use the corresponding client request id (FIFO), so strict clients like
    Cursor accept the response instead of "unknown message ID".
    """

    def __init__(self, write_stream: Any, request_ids: deque[int | str]) -> None:
        self._write = write_stream
        self._request_ids = request_ids

    async def send(self, msg: SessionMessage | Exception) -> None:
        if isinstance(msg, SessionMessage) and _is_jsonrpc_response_with_id_zero(msg):
            if self._request_ids:
                new_id = self._request_ids.popleft()
                msg = _session_message_with_id(msg, new_id)
        await self._write.send(msg)

    async def aclose(self) -> None:
        if hasattr(self._write, "aclose"):
            await self._write.aclose()

if TYPE_CHECKING:
    from mcp.server.lowlevel.helper_types import ReadResourceContents
    from mcp.server.lowlevel.server import (
        CombinationContent,
        StructuredContent,
        UnstructuredContent,
    )
    from mcp.types import (
        CallToolResult,
        Prompt,
        Resource,
        Tool,
    )
    from pydantic import AnyUrl


class JsonEnvelopeStream:
    """
    Wraps the MCP stream to handle parsing errors gracefully.
    The stream yields SessionMessage objects or Exception objects.
    When the MCP SDK fails to parse a log message as JSON-RPC, it creates an Exception.
    We catch those exceptions and convert them to valid SessionMessage objects.
    """

    def __init__(self, original_stream):
        self.original_stream = original_stream

    async def __aenter__(self):
        # If original stream supports context manager, enter it
        if hasattr(self.original_stream, "__aenter__"):
            return await self.original_stream.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        # If original stream supports context manager, exit it
        if hasattr(self.original_stream, "__aexit__"):
            return await self.original_stream.__aexit__(exc_type, exc_val, exc_tb)
        return None

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            item = await self.original_stream.__anext__()
        except StopAsyncIteration:
            raise

        # The stream yields SessionMessage | Exception
        # If it's an Exception (parsing error from log message), convert it to a valid SessionMessage
        if isinstance(item, Exception):
            # Extract the log message from the exception
            error_msg = str(item)
            # Create a valid JSON-RPC notification message for the log
            # Use a notification (no id) so it doesn't break request/response flow
            notification = JSONRPCNotification(
                jsonrpc="2.0",
                method="_log",
                params={"message": error_msg},
            )
            return SessionMessage(JSONRPCMessage(notification))

        # If it's already a SessionMessage, pass it through unchanged
        return item

    async def aclose(self):
        """Close the stream if it supports it."""
        if hasattr(self.original_stream, "aclose"):
            await self.original_stream.aclose()


class AgentDecompileStdioBridge:
    """
    MCP Server that bridges stdio to AgentDecompile's StreamableHTTP endpoint.

    Acts as a transparent proxy - forwards all MCP requests to the AgentDecompile backend
    and returns responses.
    """

    def __init__(self, backend: int | str, api_key: str | None = None):
        """
        Initialize the stdio bridge.

        Args:
            backend: AgentDecompile server port (int) or URL (str) to connect to
            api_key: Optional API key sent as X-API-Key header
        """
        if isinstance(backend, int):
            self.port: int | None = backend
            self.url: str = f"http://localhost:{backend}/mcp/message"
        else:
            self.port = None
            self.url = normalize_backend_url(backend)

        self._streamable_http_headers: dict[str, str] | None = None
        if api_key is not None and api_key.strip():
            self._streamable_http_headers = {"X-API-Key": api_key}

        self.server: Server = Server("AgentDecompile")
        self.backend_session: ClientSession | None = None
        self._current_json_stream: JsonEnvelopeStream | None = None
        self._transport_cm: Any = None

        self._register_handlers()

    async def _ensure_backend_connected(self) -> ClientSession:
        """Ensure backend session is connected."""
        if self.backend_session is None:
            raise RuntimeError("Backend session not initialized - connection lost")
        return self.backend_session

    def _register_handlers(self):
        """Register MCP protocol handlers that forward to AgentDecompile backend."""

        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            try:
                await self._ensure_backend_connected()
                result = await self.backend_session.list_tools()  # type: ignore
                return result.tools if result else []
            except RuntimeError:
                return []
            except Exception as e:
                sys.stderr.write(f"ERROR: list_tools failed: {e.__class__.__name__}: {e}\n")
                return []

        @self.server.call_tool()
        async def call_tool(
            name: str,
            arguments: dict[str, Any],
        ) -> (
            UnstructuredContent
            | StructuredContent
            | CombinationContent
            | CallToolResult
        ):
            try:
                await self._ensure_backend_connected()
                session = self.backend_session
                if session is None:
                    return [TextContent(type="text", text="Error: Backend session not initialized")]
                result = await session.call_tool(name, arguments)
                if result is None:
                    return [TextContent(type="text", text=f"Error: Tool '{name}' returned no result")]
                return result.content
            except RuntimeError as e:
                return [TextContent(type="text", text=f"Error: Backend connection lost: {e}")]
            except Exception as e:
                sys.stderr.write(f"ERROR: call_tool {name} failed: {e.__class__.__name__}: {e}\n")
                return [TextContent(type="text", text=f"Error: {e.__class__.__name__}: {e}")]

        @self.server.list_resources()
        async def list_resources() -> list[Resource]:
            try:
                await self._ensure_backend_connected()
                result = await self.backend_session.list_resources()  # type: ignore
                return result.resources if result else []
            except RuntimeError:
                return []
            except Exception as e:
                sys.stderr.write(f"ERROR: list_resources failed: {e.__class__.__name__}: {e}\n")
                return []

        @self.server.read_resource()
        async def read_resource(
            uri: AnyUrl,
        ) -> str | bytes | Iterable[ReadResourceContents]:
            try:
                await self._ensure_backend_connected()
                result = await self.backend_session.read_resource(uri)  # type: ignore
                if result is None or not result.contents:
                    return ""
                content = result.contents[0]
                if hasattr(content, "text") and content.text:  # pyright: ignore[reportAttributeAccessIssue]
                    return content.text  # pyright: ignore[reportAttributeAccessIssue]
                if hasattr(content, "blob") and content.blob:  # pyright: ignore[reportAttributeAccessIssue]
                    return content.blob  # pyright: ignore[reportAttributeAccessIssue]
                return ""
            except RuntimeError:
                return ""
            except Exception as e:
                sys.stderr.write(f"ERROR: read_resource failed for URI {uri}: {e.__class__.__name__}: {e}\n")
                return ""

        @self.server.list_prompts()
        async def list_prompts() -> list[Prompt]:
            try:
                await self._ensure_backend_connected()
                result = await self.backend_session.list_prompts()  # type: ignore
                return result.prompts if result else []
            except RuntimeError:
                return []
            except Exception as e:
                sys.stderr.write(f"ERROR: list_prompts failed: {e.__class__.__name__}: {e}\n")
                return []

    async def run(self):
        """
        Run the stdio bridge.

        Connects to AgentDecompile backend via StreamableHTTP, initializes the session,
        then exposes the MCP server via stdio transport.
        """
        sys.stderr.write(f"Connecting to AgentDecompile backend at {self.url}...\n")

        if self._streamable_http_headers:
            transport_gen = streamablehttp_client(self.url, headers=self._streamable_http_headers)
        else:
            transport_gen = streamablehttp_client(self.url)
        try:
            read_stream, write_stream, get_session_id = await asyncio.wait_for(
                transport_gen.__aenter__(),
                timeout=CONNECT_TIMEOUT,
            )
        except asyncio.TimeoutError:
            try:
                await transport_gen.__aexit__(None, None, None)
            except Exception:
                pass
            raise ServerNotRunningError(
                f"Cannot connect to AgentDecompile backend at {self.url}\n\n{get_server_start_message()}"
            ) from None
        except (ConnectionError, OSError) as e:
            try:
                await transport_gen.__aexit__(None, None, None)
            except Exception:
                pass
            raise ServerNotRunningError(
                f"Cannot connect to AgentDecompile backend at {self.url}\n\n{get_server_start_message()}"
            ) from e
        except Exception as e:
            try:
                await transport_gen.__aexit__(None, None, None)
            except Exception:
                pass
            error_msg = str(e)
            if any(
                x in error_msg
                for x in ["ConnectError", "connection", "ConnectionRefused"]
            ):
                raise ServerNotRunningError(
                    f"Cannot connect to AgentDecompile backend at {self.url}\n\n"
                    f"{get_server_start_message()}"
                ) from e
            raise ServerNotRunningError(
                f"Cannot connect to AgentDecompile backend at {self.url}: {e}\n\n"
                f"{get_server_start_message()}"
            ) from e

        self._transport_cm = transport_gen
        session_cm = None
        try:
            json_stream = JsonEnvelopeStream(read_stream)
            self._current_json_stream = json_stream

            async with json_stream:
                session_cm = ClientSession(json_stream, write_stream)  # pyright: ignore[reportArgumentType]
                self.backend_session = await session_cm.__aenter__()
                sys.stderr.write("Initializing AgentDecompile backend session...\n")
                init_result = await self.backend_session.initialize()
                sys.stderr.write(f"Connected to {init_result.serverInfo.name} v{init_result.serverInfo.version}\n")
                sys.stderr.write("Bridge ready - stdio transport active\n")
                try:
                    async with stdio_server() as (stdio_read, stdio_write):
                        request_ids: deque[int | str] = deque()
                        read_fix = _IdFixReadStream(stdio_read, request_ids)
                        write_fix = _IdFixWriteStream(stdio_write, request_ids)
                        await self.server.run(
                            read_fix,  # pyright: ignore[reportArgumentType]
                            write_fix,  # pyright: ignore[reportArgumentType]
                            self.server.create_initialization_options(),
                        )
                except ClosedResourceError:
                    sys.stderr.write("Client disconnected\n")
                except BrokenResourceError:
                    sys.stderr.write("Client connection broken - disconnecting\n")
                except Exception:
                    raise
        finally:
            self.backend_session = None
            if session_cm is not None:
                try:
                    await session_cm.__aexit__(None, None, None)
                except Exception:
                    pass
            if self._current_json_stream is not None:
                try:
                    await self._current_json_stream.aclose()
                except Exception:
                    pass
                self._current_json_stream = None
            if getattr(self, "_transport_cm", None) is not None:
                try:
                    await self._transport_cm.__aexit__(None, None, None)
                except Exception:
                    pass
                self._transport_cm = None

    def stop(self):
        """Stop the bridge and cleanup resources."""
        if self._current_json_stream is not None:
            try:
                pass
            except Exception:
                pass
            self._current_json_stream = None
