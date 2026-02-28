"""Compatibility module mirrored in bridge.py as the primary implementation.
This file is kept for backward-compatibility.
Prefer importing from agentdecompile_cli.bridge.

Stdio to HTTP MCP bridge using official MCP SDK Server abstraction.

Provides a proper MCP Server that forwards all requests to AgentDecompile's StreamableHTTP endpoint.
Uses the MCP SDK's stdio transport and Pydantic serialization - no manual JSON-RPC handling.

The bridge acts as a transparent proxy - all tool calls, resources, and prompts are
forwarded to the Python AgentDecompile backend running on localhost.

1:1 with Python MCP server: endpoint POST http://{host}:{port}/mcp/message (streamable HTTP);
tool names, parameter names (camelCase), and resource URIs match src/agentdecompile_cli/mcp_server exactly.
"""

from __future__ import annotations

import asyncio
import contextlib
import sys

from collections import deque
from collections.abc import Iterable
from types import TracebackType
from typing import TYPE_CHECKING, Any

try:
    from anyio import BrokenResourceError, ClosedResourceError
except ImportError:
    # Fallback when anyio is unavailable - use distinct classes so except
    # (BrokenResourceError, ClosedResourceError) does not shadow except Exception
    class _PlaceholderConnectionError(Exception):  # noqa: B903
        """Placeholder; never raised when anyio is not available."""

    BrokenResourceError = _PlaceholderConnectionError
    ClosedResourceError = _PlaceholderConnectionError

from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from httpx import AsyncClient
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.shared.message import SessionMessage
from mcp.types import (
    JSONRPCMessage,
    JSONRPCNotification,
    LoggingCapability,
    ServerCapabilities,
    TextContent,
)

from agentdecompile_cli.utils import get_server_start_message, normalize_backend_url

if TYPE_CHECKING:
    from contextlib import _AsyncGeneratorContextManager


class ClientError(Exception):
    """Custom exception for client errors."""


class ServerNotRunningError(ClientError):
    """Raised when the backend is not running or unreachable."""


# Timeout for initial transport connect (separate from long-running operation timeouts)
CONNECT_TIMEOUT = 5.0
# Timeout for backend operations (tool calls, list_resources, etc.)
BACKEND_OP_TIMEOUT = 90.0


def _canonical_streamable_http_url(url: str) -> str:
    """Return canonical MCP streamable HTTP endpoint URL with trailing slash."""
    return f"{url}/" if url.endswith("/mcp/message") else url


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
    """Wraps the stdio read stream and records JSON-RPC request ids so responses
    with id:0 can be rewritten to match (see _IdFixWriteStream).

    Implements async context manager protocol (delegates to underlying stream)
    since MCP session._receive_loop uses async with on the read stream.
    """

    def __init__(
        self,
        read_stream: MemoryObjectReceiveStream[SessionMessage | Exception],
        request_ids: deque[int | str],
    ) -> None:
        self._read: MemoryObjectReceiveStream[SessionMessage | Exception] = read_stream
        self._request_ids: deque[int | str] = request_ids

    async def __aenter__(self) -> _IdFixReadStream:
        if hasattr(self._read, "__aenter__"):
            await self._read.__aenter__()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if hasattr(self._read, "__aexit__"):
            await self._read.__aexit__(exc_type, exc_val, exc_tb)

    def __aiter__(self) -> _IdFixReadStream:
        return self

    async def __anext__(self) -> SessionMessage | Exception:
        item: SessionMessage | Exception = await self._read.__anext__()
        if isinstance(item, SessionMessage) and _is_jsonrpc_request(item):
            rid = getattr(item.message, "id", None)
            if rid is not None:
                self._request_ids.append(rid)
        return item


class _IdFixWriteStream:
    """Wraps the stdio write stream.

    Rewrites any JSON-RPC response with id:0 to use the corresponding client
    request id (FIFO), so strict clients like Cursor accept the response
    instead of "unknown message ID".
    """

    def __init__(
        self,
        write_stream: MemoryObjectSendStream[SessionMessage | Exception],
        request_ids: deque[int | str],
    ) -> None:
        self._write: MemoryObjectSendStream[SessionMessage | Exception] = write_stream
        self._request_ids: deque[int | str] = request_ids

    async def send(
        self,
        msg: SessionMessage | Exception,
    ) -> None:
        if isinstance(msg, SessionMessage) and _is_jsonrpc_response_with_id_zero(msg):
            if self._request_ids:
                new_id: int | str = self._request_ids.popleft()
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
    """Wraps the MCP stream to handle parsing errors gracefully.
    The stream yields SessionMessage objects or Exception objects.
    When the MCP SDK fails to parse a log message as JSON-RPC, it creates an Exception.
    We catch those exceptions and convert them to valid SessionMessage objects.
    """

    def __init__(
        self,
        original_stream: MemoryObjectReceiveStream[SessionMessage | Exception],
    ) -> None:
        self.original_stream: MemoryObjectReceiveStream[SessionMessage | Exception] = original_stream

    async def __aenter__(self) -> JsonEnvelopeStream | MemoryObjectReceiveStream[SessionMessage | Exception]:
        # If original stream supports context manager, enter it
        if hasattr(self.original_stream, "__aenter__"):
            return await self.original_stream.__aenter__()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> bool | None:
        # If original stream supports context manager, exit it
        if hasattr(self.original_stream, "__aexit__"):
            return await self.original_stream.__aexit__(exc_type, exc_val, exc_tb)
        return None

    def __aiter__(self) -> JsonEnvelopeStream:
        return self

    async def __anext__(self) -> SessionMessage | Exception:
        try:
            item: SessionMessage | Exception = await self.original_stream.__anext__()
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
    """MCP Server that bridges stdio to AgentDecompile's Python StreamableHTTP endpoint.

    Acts as a transparent proxy - forwards all MCP requests to the Python AgentDecompile backend
    and returns responses.
    """

    def __init__(self, backend: int | str):
        """Initialize the stdio bridge.

        Args:
            backend: AgentDecompile server port (int) or URL (str) to connect to
        """
        if isinstance(backend, int):
            self.port: int | None = backend
            self.url: str = f"http://localhost:{backend}/mcp/message"
        else:
            self.port = None
            self.url = normalize_backend_url(backend)

        self._streamable_http_headers: dict[str, str] | None = None

        self.server: Server = Server("AgentDecompile")
        self._backend_connect_lock: asyncio.Lock = asyncio.Lock()
        self._backend_exit_stack: contextlib.AsyncExitStack | None = None
        self._backend_session: ClientSession | None = None
        self._backend_connected: bool = False

        self._register_handlers()

    async def _reset_backend_session(self) -> None:
        """Close and clear any existing backend session state."""
        self._backend_connected = False
        self._backend_session = None
        if self._backend_exit_stack is not None:
            try:
                await self._backend_exit_stack.__aexit__(None, None, None)
            except Exception:
                pass
            self._backend_exit_stack = None

    async def _ensure_backend_session(self) -> ClientSession:
        """Ensure there is a live backend MCP session and return it."""
        if self._backend_connected and self._backend_session is not None:
            return self._backend_session

        async with self._backend_connect_lock:
            if self._backend_connected and self._backend_session is not None:
                return self._backend_session

            await self._reset_backend_session()

            try:
                exit_stack = contextlib.AsyncExitStack()
                await exit_stack.__aenter__()

                client = AsyncClient(
                    headers={} if self._streamable_http_headers is None else self._streamable_http_headers,
                    timeout=BACKEND_OP_TIMEOUT,
                )
                read_stream, write_stream, _ = await asyncio.wait_for(
                    exit_stack.enter_async_context(
                        streamable_http_client(
                            url=_canonical_streamable_http_url(self.url),
                            http_client=client,
                        ),
                    ),
                    timeout=CONNECT_TIMEOUT,
                )

                json_stream = JsonEnvelopeStream(read_stream)
                session = await exit_stack.enter_async_context(ClientSession(json_stream, write_stream))
                await session.initialize()

                self._backend_exit_stack = exit_stack
                self._backend_session = session
                self._backend_connected = True
                return session
            except asyncio.TimeoutError:
                await self._reset_backend_session()
                raise ServerNotRunningError(f"Cannot connect to AgentDecompile backend at {self.url}\n\n{get_server_start_message()}") from None
            except (ConnectionError, OSError) as e:
                await self._reset_backend_session()
                raise ServerNotRunningError(f"Cannot connect to AgentDecompile backend at {self.url}\n\n{get_server_start_message()}") from e
            except Exception as e:
                await self._reset_backend_session()
                err = str(e)
                if any(x in err for x in ["ConnectError", "connection", "ConnectionRefused"]):
                    raise ServerNotRunningError(f"Cannot connect to AgentDecompile backend at {self.url}\n\n{get_server_start_message()}") from e
                raise ServerNotRunningError(f"Cannot connect to AgentDecompile backend at {self.url}: {e}\n\n{get_server_start_message()}") from e

    @contextlib.asynccontextmanager
    async def _with_backend_session(self, _op_name: str):
        """Context manager over a persistent backend MCP session.

        Reuses a single initialized session for all requests so server-side
        session context (open program/project state) survives across commands.
        """
        session = await self._ensure_backend_session()
        try:
            yield session
        except Exception:
            await self._reset_backend_session()
            raise

    def _register_handlers(self):
        """Register MCP protocol handlers that forward to AgentDecompile backend."""

        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            try:
                async with self._with_backend_session("list_tools") as session:
                    result = await session.list_tools()
                    return [] if result is None else result.tools
            except RuntimeError:
                return []
            except Exception as e:
                sys.stderr.write(f"ERROR: list_tools failed: {e.__class__.__name__}: {e}\n")
                return []

        @self.server.call_tool()
        async def call_tool(
            name: str,
            arguments: dict[str, Any],
        ) -> UnstructuredContent | StructuredContent | CombinationContent | CallToolResult:  # pyright: ignore[reportInvalidTypeForm]
            try:
                async with self._with_backend_session("call_tool") as session:
                    result = await asyncio.wait_for(
                        session.call_tool(name, arguments),
                        timeout=BACKEND_OP_TIMEOUT,
                    )
                    return [TextContent(type="text", text=f"Error: Tool '{name}' returned no result")] if result is None else result.content
            except RuntimeError as e:
                return [TextContent(type="text", text=f"Error: Backend connection lost: {e}")]
            except Exception as e:
                sys.stderr.write(f"ERROR: call_tool {name} failed: {e.__class__.__name__}: {e}\n")
                return [TextContent(type="text", text=f"Error: {e.__class__.__name__}: {e}")]

        @self.server.list_resources()
        async def list_resources() -> list[Resource]:
            try:
                async with self._with_backend_session("list_resources") as session:
                    result = await session.list_resources()
                    return [] if result is None else result.resources
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
                async with self._with_backend_session("read_resource") as session:
                    result = await session.read_resource(uri)
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
                async with self._with_backend_session("list_prompts") as session:
                    result = await session.list_prompts()
                    return [] if result is None else result.prompts
            except RuntimeError:
                return []
            except Exception as e:
                sys.stderr.write(f"ERROR: list_prompts failed: {e.__class__.__name__}: {e}\n")
                return []

    def _create_initialization_options(self):
        """Create MCP initialization options with explicit logging capability."""
        options = self.server.create_initialization_options()
        capabilities = getattr(options, "capabilities", None)
        if capabilities is None:
            capabilities = ServerCapabilities()

        if getattr(capabilities, "logging", None) is None:
            capabilities = capabilities.model_copy(update={"logging": LoggingCapability()})

        return options.model_copy(update={"capabilities": capabilities})

    async def run(self):
        """Run the stdio bridge.

        Starts the MCP server on stdio immediately. Connects to the AgentDecompile
        backend lazily on first tool/resource/prompt request to avoid MCP streamable
        HTTP race conditions during the initialize handshake.
        """
        sys.stderr.write("Bridge ready - stdio transport active\n")
        try:
            async with stdio_server() as (stdio_read, stdio_write):
                # Pass raw streams - _IdFix wrappers cause MCP SDK async context manager errors
                await self.server.run(
                    stdio_read,  # pyright: ignore[reportArgumentType]
                    stdio_write,  # pyright: ignore[reportArgumentType]
                    self._create_initialization_options(),
                )
        except ClosedResourceError:
            sys.stderr.write("Client disconnected\n")
        except BrokenResourceError:
            sys.stderr.write("Client connection broken - disconnecting\n")
        except Exception:
            raise
        finally:
            await self._reset_backend_session()

    def stop(self):
        """Stop the bridge and cleanup resources."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        loop.create_task(self._reset_backend_session())
