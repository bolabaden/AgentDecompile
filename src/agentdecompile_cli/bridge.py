"""Bridge, HTTP client, and MCP session patch for AgentDecompile.

Merged from:
  - mcp_session_patch.py  (_apply_mcp_session_fix)
  - client.py             (AgentDecompileMcpClient and exceptions)
  - stdio_bridge.py       (AgentDecompileStdioBridge and helpers)

The MCP session fix is applied once at import time.
AgentDecompileMcpClient provides an async HTTP client to an existing server.
AgentDecompileStdioBridge proxies stdio MCP transport to the HTTP backend.

**Bridge Architecture (v5 – raw httpx)**:
The stdio bridge NO LONGER uses the MCP Python SDK's ``streamable_http_client``
or ``ClientSession`` for backend communication.  Those classes rely on anyio
task groups internally, and their cancel scopes are incompatible with asyncio
Tasks spawned by ``Server.run()`` for request handling.  Instead the bridge
makes plain httpx POST requests carrying JSON-RPC payloads, parses JSON or SSE
responses, and tracks the ``Mcp-Session-Id`` header manually.  This eliminates
all anyio cancel-scope lifetime issues.
"""

from __future__ import annotations

import asyncio
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
from httpx import AsyncClient, Timeout
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.shared.message import SessionMessage
from mcp.types import (
    CallToolResult,
    JSONRPCMessage,
    JSONRPCNotification,
    LoggingCapability,
    ServerCapabilities,
    TextContent,
    Tool,
)

from agentdecompile_cli.executor import get_server_start_message, normalize_backend_url
from agentdecompile_cli.registry import resolve_tool_name

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
# RawMcpHttpBackend – plain httpx JSON-RPC client (no anyio / no MCP SDK client)
# ---------------------------------------------------------------------------

MCP_PROTOCOL_VERSION = "2025-03-26"

# Timeout for initial transport connect
CONNECT_TIMEOUT = 10.0
# Timeout for backend operations (tool calls, list_resources, etc.)
BACKEND_OP_TIMEOUT = 120.0


class RawMcpHttpBackend:
    """Speaks the MCP Streamable-HTTP transport using plain httpx.

    This intentionally avoids ``streamable_http_client`` and ``ClientSession``
    which rely on anyio task groups.  Instead it makes ordinary HTTP POST
    requests, parses JSON or SSE responses, and tracks ``Mcp-Session-Id``.

    Safe to call from **any** asyncio task — no anyio cancel scopes are created.
    """

    def __init__(self, url: str, *, connect_timeout: float = CONNECT_TIMEOUT, op_timeout: float = BACKEND_OP_TIMEOUT):
        self._url = url if url.endswith("/") else f"{url}/"
        self._session_id: str | None = None
        self._request_counter = 0
        self._initialized = False
        self._client = AsyncClient(
            timeout=Timeout(op_timeout, connect=connect_timeout),
            follow_redirects=True,
        )

    # -- helpers -------------------------------------------------------------

    def _next_id(self) -> int:
        self._request_counter += 1
        return self._request_counter

    def _headers(self) -> dict[str, str]:
        h: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self._session_id:
            h["Mcp-Session-Id"] = self._session_id
        return h

    @staticmethod
    def _parse_sse_data(text: str) -> dict[str, Any] | None:
        """Extract the last ``data:`` payload from an SSE stream.

        MCP Streamable HTTP may return multiple SSE events; the final one
        with ``"result"`` or ``"error"`` is the JSON-RPC response.
        """
        last_payload: dict[str, Any] | None = None
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("data:"):
                raw = stripped[len("data:"):].strip()
                if raw:
                    try:
                        parsed = json.loads(raw)
                        if isinstance(parsed, dict):
                            last_payload = parsed
                    except json.JSONDecodeError:
                        continue
        return last_payload

    async def _post(self, body: dict[str, Any]) -> dict[str, Any]:
        """POST a JSON-RPC envelope and return the parsed response dict."""
        resp = await self._client.post(self._url, json=body, headers=self._headers())

        # Capture session id.
        sid = resp.headers.get("mcp-session-id") or resp.headers.get("Mcp-Session-Id")
        if sid:
            self._session_id = sid

        resp.raise_for_status()

        ct = (resp.headers.get("content-type") or "").lower()
        if "text/event-stream" in ct:
            parsed = self._parse_sse_data(resp.text)
            if parsed is not None:
                return parsed
            # Fallback: try parsing whole body as JSON.
            try:
                return resp.json()  # type: ignore[return-value]
            except Exception:
                return {"error": {"code": -32600, "message": f"Unparseable SSE response ({len(resp.text)} bytes)"}}
        return resp.json()  # type: ignore[return-value]

    async def _notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        """Send a JSON-RPC notification (no id, no response expected)."""
        body: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params:
            body["params"] = params
        try:
            await self._client.post(self._url, json=body, headers=self._headers())
        except Exception:
            pass  # notifications are fire-and-forget

    async def _request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Send a JSON-RPC request and return the ``result`` dict."""
        rid = self._next_id()
        body: dict[str, Any] = {"jsonrpc": "2.0", "method": method, "id": rid}
        if params is not None:
            body["params"] = params
        response = await self._post(body)

        if "error" in response:
            err = response["error"]
            msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
            raise ClientError(f"JSON-RPC error: {msg}")
        return response.get("result", response)

    # -- public API ----------------------------------------------------------

    async def initialize(self) -> dict[str, Any]:
        """Send ``initialize`` + ``notifications/initialized``."""
        result = await self._request("initialize", {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "AgentDecompile-Bridge", "version": "1.0.0"},
        })
        await self._notify("notifications/initialized")
        self._initialized = True
        return result

    async def list_tools(self) -> list[dict[str, Any]]:
        """Return the raw tool list from ``tools/list``."""
        result = await self._request("tools/list")
        return result.get("tools", []) if isinstance(result, dict) else []

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        """Call a tool and return the raw result dict."""
        return await self._request("tools/call", {"name": name, "arguments": arguments or {}})

    async def list_resources(self) -> list[dict[str, Any]]:
        result = await self._request("resources/list")
        return result.get("resources", []) if isinstance(result, dict) else []

    async def read_resource(self, uri: str) -> dict[str, Any]:
        return await self._request("resources/read", {"uri": uri})

    async def list_prompts(self) -> list[dict[str, Any]]:
        result = await self._request("prompts/list")
        return result.get("prompts", []) if isinstance(result, dict) else []

    async def close(self) -> None:
        """Close the underlying httpx client."""
        try:
            await self._client.aclose()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# AgentDecompileMcpClient  (formerly client.py)
# ---------------------------------------------------------------------------


class AgentDecompileMcpClient:
    """MCP client for the AgentDecompile server.

    Uses ``RawMcpHttpBackend`` (plain httpx) instead of the MCP SDK's
    ``streamable_http_client`` / ``ClientSession`` to avoid anyio cancel-scope
    crashes.

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
        self._backend: RawMcpHttpBackend | None = None
        self._connected: bool = False

    async def __aenter__(self) -> AgentDecompileMcpClient:
        """Async context manager entry; establishes connection."""
        await self._connect_internal()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit; closes connection."""
        await self._close_internal()

    async def _connect_internal(self) -> None:
        """Connect to the backend using plain httpx."""
        self._backend = RawMcpHttpBackend(self._url)
        try:
            await self._backend.initialize()
            self._connected = True
        except Exception as e:
            if self._backend:
                await self._backend.close()
            self._backend = None
            err = str(e)
            is_conn = isinstance(e, (asyncio.TimeoutError, ConnectionError, OSError)) or any(
                x in err for x in ["ConnectError", "connection", "ConnectionRefused", "ConnectTimeout"]
            )
            if is_conn:
                raise ServerNotRunningError(
                    f"Cannot connect to AgentDecompile server at {self._url}\n\n{get_server_start_message()}",
                ) from e
            raise ServerNotRunningError(
                f"Cannot connect to AgentDecompile server at {self._url}: {e}\n\n{get_server_start_message()}",
            ) from e

    async def _close_internal(self) -> None:
        """Close connection and release resources."""
        self._connected = False
        if self._backend:
            await self._backend.close()
            self._backend = None

    def _extract_result(self, result: Any) -> dict[str, Any]:
        """Extract data from raw result dict; raise on error or not-found."""
        if isinstance(result, dict):
            result_dict = result
        elif hasattr(result, "model_dump"):
            result_dict = result.model_dump()
        else:
            result_dict = dict(result) if result else {}

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
        if not self._connected or self._backend is None:
            raise ClientError("Not connected")
        return await self._backend.list_tools()

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        """Call a tool by name with optional arguments."""
        if not self._connected or self._backend is None:
            raise ClientError("Not connected")
        result = await self._backend.call_tool(name, arguments or {})
        return self._extract_result(result)

    async def list_resources(self) -> list[Any]:
        """List resources offered by the server."""
        if not self._connected or self._backend is None:
            raise ClientError("Not connected")
        return await self._backend.list_resources()

    async def read_resource(self, uri: str) -> Any:
        """Read a resource by URI."""
        if not self._connected or self._backend is None:
            raise ClientError("Not connected")
        return await self._backend.read_resource(uri)

    async def list_prompts(self) -> list[Any]:
        """List prompts offered by the server."""
        if not self._connected or self._backend is None:
            raise ClientError("Not connected")
        return await self._backend.list_prompts()


# ---------------------------------------------------------------------------
# Stdio bridge helpers  (formerly stdio_bridge.py)
# ---------------------------------------------------------------------------


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
# AgentDecompileStdioBridge  (main bridge class)
# ---------------------------------------------------------------------------


class AgentDecompileStdioBridge:
    """MCP Server that bridges stdio to AgentDecompile's Python StreamableHTTP endpoint.

    Uses ``RawMcpHttpBackend`` (plain httpx POST requests) for all backend
    communication.  This avoids anyio cancel-scope crashes that occur with the
    MCP SDK's ``streamable_http_client`` / ``ClientSession`` when called from
    handler tasks spawned by ``Server.run()``.
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

        self.server: Server = Server("AgentDecompile")
        self._backend: RawMcpHttpBackend | None = None
        self._backend_lock = asyncio.Lock()

        self._register_handlers()

    async def _ensure_backend(self) -> RawMcpHttpBackend:
        """Return (or lazily create) the backend connection.

        Uses an ``asyncio.Lock`` so only one handler initializes the backend.
        Subsequent callers get the cached instance.
        """
        if self._backend is not None and self._backend._initialized:
            return self._backend

        async with self._backend_lock:
            # Double-check after acquiring lock.
            if self._backend is not None and self._backend._initialized:
                return self._backend

            # Close stale client if any.
            if self._backend is not None:
                await self._backend.close()

            backend = RawMcpHttpBackend(self.url)
            await backend.initialize()
            self._backend = backend
            sys.stderr.write(f"Backend session established to {self.url}\n")
            return backend

    async def _backend_request(self, method: str, *args: Any, **kwargs: Any) -> Any:
        """Convenience: ensure backend, call *method*, retry once on connection errors."""
        last_exc: Exception | None = None
        for attempt in range(2):
            try:
                backend = await self._ensure_backend()
                func = getattr(backend, method)
                return await func(*args, **kwargs)
            except Exception as exc:
                last_exc = exc
                if attempt == 0 and self._is_connection_error(exc):
                    sys.stderr.write(
                        f"Backend connection error on {method}, reconnecting... "
                        f"({type(exc).__name__}: {exc})\n",
                    )
                    # Invalidate the session so _ensure_backend creates a fresh one.
                    if self._backend is not None:
                        await self._backend.close()
                    self._backend = None
                    continue
                break
        raise last_exc  # type: ignore[misc]

    @staticmethod
    def _is_connection_error(exc: BaseException) -> bool:
        """Return True if *exc* is a transport/connection failure."""
        if isinstance(exc, (ConnectionError, OSError, asyncio.TimeoutError)):
            return True
        if isinstance(exc, (BrokenResourceError, ClosedResourceError)):
            return True
        err_str = str(exc)
        return any(
            kw in err_str
            for kw in (
                "ConnectError",
                "ConnectTimeout",
                "ConnectionRefused",
                "BrokenResource",
                "ClosedResource",
                "connection reset",
                "Timed out",
                "TimeoutException",
            )
        )

    @staticmethod
    def _raw_tool_to_mcp(raw: dict[str, Any]) -> Tool:
        """Convert a raw tool dict from the backend to an MCP ``Tool`` object."""
        return Tool.model_validate(raw)

    def _register_handlers(self):
        """Register MCP protocol handlers that forward to AgentDecompile backend."""

        @self.server.list_tools()
        async def list_tools() -> list[Tool]:  # type: ignore[name-defined]
            try:
                raw_tools: list[dict[str, Any]] = await self._backend_request("list_tools")
                advertised: list[Tool] = []
                for raw in raw_tools:
                    try:
                        tool = self._raw_tool_to_mcp(raw)
                    except Exception:
                        continue  # skip non-parseable tools

                    # Normalize name via registry.
                    resolved = resolve_tool_name(tool.name)
                    canonical = resolved if resolved is not None else tool.name
                    if canonical != tool.name:
                        try:
                            tool = tool.model_copy(update={"name": canonical})
                        except Exception:
                            pass
                    advertised.append(tool)
                return advertised
            except Exception as e:
                sys.stderr.write(f"ERROR: list_tools failed: {e.__class__.__name__}: {e}\n")
                return []

        @self.server.call_tool()
        async def call_tool(
            name: str,
            arguments: dict[str, Any],
        ) -> UnstructuredContent | StructuredContent | CombinationContent | CallToolResult:  # type: ignore[name-defined]  # pyright: ignore[reportInvalidTypeForm]
            backend_name = resolve_tool_name(name) if isinstance(name, str) else None
            if backend_name is None:
                backend_name = name

            try:
                raw_result: dict[str, Any] = await self._backend_request("call_tool", backend_name, arguments)
                # raw_result is the JSON-RPC "result" value which should be
                # a CallToolResult-shaped dict: {content: [...], isError: bool}
                return CallToolResult.model_validate(raw_result)
            except ClientError as exc:
                sys.stderr.write(f"ERROR: call_tool {name}: {exc}\n")
                return CallToolResult(
                    content=[TextContent(type="text", text=f"Error: {exc}")],
                    isError=True,
                )
            except Exception as exc:
                sys.stderr.write(f"ERROR: call_tool {name} failed: {type(exc).__name__}: {exc}\n")
                return CallToolResult(
                    content=[TextContent(type="text", text=f"Error: {type(exc).__name__}: {exc}")],
                    isError=True,
                )

        @self.server.list_resources()
        async def list_resources() -> list[Resource]:  # type: ignore[name-defined]
            try:
                from mcp.types import Resource as _Resource

                raw: list[dict[str, Any]] = await self._backend_request("list_resources")
                return [_Resource.model_validate(r) for r in raw]
            except Exception as e:
                sys.stderr.write(f"ERROR: list_resources failed: {e.__class__.__name__}: {e}\n")
                return []

        @self.server.read_resource()
        async def read_resource(
            uri: AnyUrl,  # type: ignore[name-defined]
        ) -> str | bytes | Iterable[ReadResourceContents]:  # type: ignore[name-defined]  # pyright: ignore[reportInvalidTypeForm]
            try:
                raw: dict[str, Any] = await self._backend_request("read_resource", str(uri))
                contents = raw.get("contents", [])
                if contents:
                    c0 = contents[0] if isinstance(contents, list) else contents
                    if isinstance(c0, dict):
                        return c0.get("text", c0.get("blob", ""))
                return ""
            except Exception as e:
                sys.stderr.write(f"ERROR: read_resource failed for URI {uri}: {e.__class__.__name__}: {e}\n")
                return ""

        @self.server.list_prompts()
        async def list_prompts() -> list[Prompt]:  # type: ignore[name-defined]
            try:
                from mcp.types import Prompt as _Prompt

                raw: list[dict[str, Any]] = await self._backend_request("list_prompts")
                return [_Prompt.model_validate(p) for p in raw]
            except Exception as e:
                sys.stderr.write(f"ERROR: list_prompts failed: {e.__class__.__name__}: {e}\n")
                return []

    def _create_initialization_options(self):
        """Create MCP initialization options with explicit logging capability.

        Some MCP clients attempt to set the server log level during/after
        initialize and expect `capabilities.logging` to be present.
        """
        options = self.server.create_initialization_options()
        capabilities = getattr(options, "capabilities", None)
        if capabilities is None:
            capabilities = ServerCapabilities()

        if getattr(capabilities, "logging", None) is None:
            capabilities = capabilities.model_copy(update={"logging": LoggingCapability()})

        return options.model_copy(update={"capabilities": capabilities})

    async def run(self):
        """Run the stdio bridge.

        The backend connection is established lazily on the first handler
        request.  All backend communication uses ``RawMcpHttpBackend`` (plain
        httpx POST) so no anyio cancel scopes are involved.
        """
        sys.stderr.write("Bridge ready - stdio transport active\n")

        try:
            async with stdio_server() as (stdio_read, stdio_write):
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
            if self._backend:
                await self._backend.close()

    def stop(self):
        """Stop the bridge and cleanup resources."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        if self._backend:
            loop.create_task(self._backend.close())
