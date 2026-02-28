"""Bridge, HTTP client, and MCP session patch for AgentDecompile.

Merged from:
  - mcp_session_patch.py  (_apply_mcp_session_fix)
  - client.py             (AgentDecompileMcpClient and exceptions)
  - stdio_bridge.py       (AgentDecompileStdioBridge and helpers)

The MCP session fix is applied once at import time.
AgentDecompileMcpClient provides an async HTTP client to an existing server.
AgentDecompileStdioBridge proxies stdio MCP transport to the HTTP backend.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib.util
import json
import sys

from collections import deque
from collections.abc import Iterable
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING, Any

try:
    from anyio import BrokenResourceError, ClosedResourceError
except ImportError:

    class _PlaceholderConnectionError(Exception):  # noqa: B903
        """Placeholder; never raised when anyio is not available."""

    BrokenResourceError = _PlaceholderConnectionError  # type: ignore[assignment,misc]
    ClosedResourceError = _PlaceholderConnectionError  # type: ignore[assignment,misc]

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
    TextContent,
)

from agentdecompile_cli.executor import get_server_start_message, normalize_backend_url

if TYPE_CHECKING:
    from contextlib import _AsyncGeneratorContextManager

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


# ---------------------------------------------------------------------------
# MCP session patch  (formerly mcp_session_patch.py)
# ---------------------------------------------------------------------------


def _apply_mcp_session_fix() -> None:
    """Patch installed MCP session.py to use list() for _response_streams iteration.

    The MCP Python SDK's BaseSession._receive_loop iterates over
    self._response_streams.items() in its finally block. Concurrent coroutines
    can modify this dict (via send_request's finally block calling .pop()),
    causing RuntimeError: dictionary changed size during iteration.
    Industry-standard fix: use list(self._response_streams.items()) to iterate
    over a snapshot.

    This patches the installed mcp package's source file on disk before import.
    No monkeypatching - we edit the installed source once.
    """
    try:
        spec = importlib.util.find_spec("mcp")
        if not spec or not spec.origin:
            return
        session_path = Path(spec.origin).parent / "shared" / "session.py"
        if not session_path.exists():
            return
        content = session_path.read_text(encoding="utf-8")
        old = "for id, stream in self._response_streams.items():"
        new = "for id, stream in list(self._response_streams.items()):"
        if old in content and new not in content:
            session_path.write_text(content.replace(old, new), encoding="utf-8")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ClientError(Exception):
    """Custom exception for client errors."""


class ServerNotRunningError(ClientError):
    """Raised when the AgentDecompile server is not running or unreachable."""


class NotFoundError(ClientError):
    """Raised when a resource or program is not found."""


# ---------------------------------------------------------------------------
# AgentDecompileMcpClient  (formerly client.py)
# ---------------------------------------------------------------------------


class AgentDecompileMcpClient:
    """MCP client for the AgentDecompile server.

    Connects via Streamable HTTP and provides async methods for
    list_tools, call_tool, list_resources, read_resource, list_prompts.

    Usage::

        async with AgentDecompileMcpClient(host="127.0.0.1", port=8080) as client:
            tools = await client.list_tools()
            result = await client.call_tool("get-functions", {"programPath": "..."})
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
        """Establish connection to the AgentDecompile MCP server.

        Uses ``contextlib.AsyncExitStack`` to manage the transport and session
        context managers.  This guarantees that anyio task-groups spawned inside
        ``streamablehttp_client`` are always cancelled and cleaned up in the
        *same task* that entered them – avoiding the ``RuntimeError: Attempted
        to exit cancel scope in a different task`` that occurred when we
        manually called ``__aenter__``/``__aexit__`` with ``asyncio.wait_for``.

        The ``timeout`` parameter of ``streamablehttp_client`` (passed straight
        to the underlying ``httpx.AsyncClient``) replaces the old
        ``asyncio.wait_for`` wrapper so the connection still fails fast when
        the backend is unreachable.
        """
        from mcp.client.session import ClientSession as _ClientSession
        from mcp.client.streamable_http import streamablehttp_client

        self._exit_stack = contextlib.AsyncExitStack()
        await self._exit_stack.__aenter__()

        try:
            read, write, _ = await self._exit_stack.enter_async_context(
                streamablehttp_client(self._url, timeout=5),
            )
            self._session = await self._exit_stack.enter_async_context(
                _ClientSession(read, write),
            )
            await self._session.initialize()
            self._connected = True
        except BaseException as e:
            # Deterministically tear down every entered CM so the anyio
            # task-group and its cancel-scope are exited in the correct task.
            try:
                await self._exit_stack.__aexit__(None, None, None)
            except BaseException:
                pass  # cleanup errors must not mask the original exception
            self._exit_stack = None
            self._session = None

            # Re-raise as ServerNotRunningError for known connectivity issues.
            err = str(e)
            is_conn = (
                isinstance(e, (asyncio.TimeoutError, ConnectionError, OSError))
                or any(
                    x in err
                    for x in [
                        "ConnectError",
                        "connection",
                        "ConnectionRefused",
                        "All connection attempts failed",
                    ]
                )
            )
            if not is_conn and hasattr(e, "exceptions"):
                is_conn = any(
                    isinstance(sub, (ConnectionError, OSError))
                    or any(
                        x in str(sub)
                        for x in [
                            "ConnectError",
                            "connection",
                            "ConnectionRefused",
                            "All connection attempts failed",
                        ]
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
            raise  # re-raise KeyboardInterrupt / SystemExit as-is

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

    def _extract_result(self, result: Any) -> dict[str, Any]:
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


# ---------------------------------------------------------------------------
# Stdio bridge helpers  (formerly stdio_bridge.py)
# ---------------------------------------------------------------------------

# Timeout for initial transport connect (separate from long-running operation timeouts)
CONNECT_TIMEOUT = 5.0
# Timeout for backend operations (tool calls, list_resources, etc.)
BACKEND_OP_TIMEOUT = 90.0


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
        if hasattr(self.original_stream, "__aenter__"):
            return await self.original_stream.__aenter__()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> bool | None:
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

        if isinstance(item, Exception):
            error_msg = str(item)
            notification = JSONRPCNotification(
                jsonrpc="2.0",
                method="_log",
                params={"message": error_msg},
            )
            return SessionMessage(JSONRPCMessage(notification))

        return item

    async def aclose(self):
        """Close the stream if it supports it."""
        if hasattr(self.original_stream, "aclose"):
            await self.original_stream.aclose()


# ---------------------------------------------------------------------------
# AgentDecompileStdioBridge  (main bridge class, formerly stdio_bridge.py)
# ---------------------------------------------------------------------------


class AgentDecompileStdioBridge:
    """MCP Server that bridges stdio to AgentDecompile's Python StreamableHTTP endpoint.

    Acts as a transparent proxy - forwards all MCP requests to the Python AgentDecompile
    backend and returns responses.
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
                            url=self.url,
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
                raise ServerNotRunningError(
                    f"Cannot connect to AgentDecompile backend at {self.url}\n\n{get_server_start_message()}",
                ) from None
            except (ConnectionError, OSError) as e:
                await self._reset_backend_session()
                raise ServerNotRunningError(
                    f"Cannot connect to AgentDecompile backend at {self.url}\n\n{get_server_start_message()}",
                ) from e
            except Exception as e:
                await self._reset_backend_session()
                err = str(e)
                if any(x in err for x in ["ConnectError", "connection", "ConnectionRefused"]):
                    raise ServerNotRunningError(
                        f"Cannot connect to AgentDecompile backend at {self.url}\n\n{get_server_start_message()}",
                    ) from e
                raise ServerNotRunningError(
                    f"Cannot connect to AgentDecompile backend at {self.url}: {e}\n\n{get_server_start_message()}",
                ) from e

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
        async def list_tools() -> list[Tool]:  # type: ignore[name-defined]
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
        ) -> UnstructuredContent | StructuredContent | CombinationContent | CallToolResult:  # type: ignore[name-defined]  # pyright: ignore[reportInvalidTypeForm]
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
        async def list_resources() -> list[Resource]:  # type: ignore[name-defined]
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
            uri: AnyUrl,  # type: ignore[name-defined]
        ) -> str | bytes | Iterable[ReadResourceContents]:  # type: ignore[name-defined]  # pyright: ignore[reportInvalidTypeForm]
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
        async def list_prompts() -> list[Prompt]:  # type: ignore[name-defined]
            try:
                async with self._with_backend_session("list_prompts") as session:
                    result = await session.list_prompts()
                    return [] if result is None else result.prompts
            except RuntimeError:
                return []
            except Exception as e:
                sys.stderr.write(f"ERROR: list_prompts failed: {e.__class__.__name__}: {e}\n")
                return []

    async def run(self):
        """Run the stdio bridge.

        Starts the MCP server on stdio immediately. Connects to the AgentDecompile
        backend lazily on first tool/resource/prompt request to avoid MCP streamable
        HTTP race conditions during the initialize handshake.
        """
        sys.stderr.write("Bridge ready - stdio transport active\n")
        try:
            async with stdio_server() as (stdio_read, stdio_write):
                await self.server.run(
                    stdio_read,  # pyright: ignore[reportArgumentType]
                    stdio_write,  # pyright: ignore[reportArgumentType]
                    self.server.create_initialization_options(),
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
