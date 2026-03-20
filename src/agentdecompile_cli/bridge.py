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
import os
import sys

from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from mcp.server.models import InitializationOptions

try:
    from anyio import BrokenResourceError, ClosedResourceError
except ImportError:

    class _PlaceholderConnectionError(Exception):  # noqa: B903
        """Placeholder; never raised when anyio is not available."""

    BrokenResourceError = _PlaceholderConnectionError  # type: ignore[assignment,misc]
    ClosedResourceError = _PlaceholderConnectionError  # type: ignore[assignment,misc]

from httpx import AsyncClient, HTTPStatusError, Timeout
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
from agentdecompile_cli.mcp_server.session_context import get_current_mcp_session_id
from agentdecompile_cli.registry import resolve_tool_name

if TYPE_CHECKING:
    from collections import deque
    from collections.abc import Iterable
    from types import TracebackType

    from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
    from mcp.server.lowlevel.helper_types import ReadResourceContents
    from mcp.server.lowlevel.server import (
        CombinationContent,
        StructuredContent,
        UnstructuredContent,
    )
    from mcp.types import (
        GetPromptResult,
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

MCP_PROTOCOL_VERSION: str = "2025-03-26"

# Timeout for initial transport connect
CONNECT_TIMEOUT: float = 10.0
# Timeout for backend operations (tool calls, list_resources, etc.)
BACKEND_OP_TIMEOUT: float = 120.0

_TRANSPORT_ERROR_KEYWORDS: tuple[str, ...] = (
    "BrokenResource",
    "ClosedResource",
    "ConnectError",
    "connection reset",
    "ConnectionRefused",
    "ConnectTimeout",
    "Timed out",
    "TimeoutException",
)


def _is_transport_connection_error(exc: BaseException) -> bool:
    """Return True if *exc* is likely a backend transport/connection failure."""
    if isinstance(exc, (ConnectionError, OSError, asyncio.TimeoutError)):
        return True
    if isinstance(exc, (BrokenResourceError, ClosedResourceError)):
        return True
    err_str = str(exc)
    return any(keyword in err_str for keyword in _TRANSPORT_ERROR_KEYWORDS)


# Cookie name for MCP session (persistent cookie jar); must match server/proxy.
_MCP_SESSION_COOKIE_NAME = "mcp_session_id"


class RawMcpHttpBackend:
    """Speaks the MCP Streamable-HTTP transport using plain httpx.

    This intentionally avoids ``streamable_http_client`` and ``ClientSession``
    which rely on anyio task groups.  Instead it makes ordinary HTTP POST
    requests, parses JSON or SSE responses, and tracks ``Mcp-Session-Id``.

    Safe to call from **any** asyncio task — no anyio cancel scopes are created.
    """

    def __init__(
        self,
        url: str,
        *,
        connect_timeout: float = CONNECT_TIMEOUT,
        op_timeout: float = BACKEND_OP_TIMEOUT,
        extra_headers: dict[str, str] | None = None,
        cookie_file: Path | None = None,
    ) -> None:
        self._url: str = url.rstrip("/")
        self._session_id: str | None = None
        self._request_counter: int = 0
        self._initialized: bool = False
        self._extra_headers: dict[str, str] = dict(extra_headers or {})
        self._cookie_file: Path | None = cookie_file
        self._client: AsyncClient = AsyncClient(
            timeout=Timeout(op_timeout, connect=connect_timeout),
            follow_redirects=True,
        )

    # -- helpers -------------------------------------------------------------

    def _next_id(self) -> int:
        self._request_counter += 1
        return self._request_counter

    def _load_cookie_from_file(self) -> str | None:
        """Load mcp_session_id from persistent cookie file; return value or None."""
        if not self._cookie_file or not self._cookie_file.exists():
            return None
        try:
            data = json.loads(self._cookie_file.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                val = data.get(_MCP_SESSION_COOKIE_NAME)
                if isinstance(val, str) and val.strip():
                    return val.strip()
        except Exception:
            pass
        return None

    def _save_cookie_to_file(self, value: str) -> None:
        """Persist mcp_session_id to cookie file (HttpOnly-style; we only store the value)."""
        if not self._cookie_file:
            return
        try:
            self._cookie_file.parent.mkdir(parents=True, exist_ok=True)
            self._cookie_file.write_text(
                json.dumps({_MCP_SESSION_COOKIE_NAME: value}, indent=2),
                encoding="utf-8",
            )
        except Exception:
            pass

    def _save_session_cookie_from_response(self, resp: Any) -> None:
        """If response has Set-Cookie mcp_session_id, persist to cookie file."""
        if not self._cookie_file:
            return
        set_cookie: str | None = resp.headers.get("set-cookie") or resp.headers.get("Set-Cookie")
        if not set_cookie:
            return
        prefix = _MCP_SESSION_COOKIE_NAME + "="
        idx = set_cookie.find(prefix)
        if idx >= 0:
            rest = set_cookie[idx + len(prefix) :]
            end = rest.find(";")
            cookie_val = (rest[: end].strip() if end >= 0 else rest.strip()).strip('"')
            if cookie_val:
                self._save_cookie_to_file(cookie_val)

    def _headers(self) -> dict[str, str]:
        h: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        h.update(self._extra_headers)
        # Always send a session ID so servers that require it (e.g. behind some proxies) accept the request.
        # Use "default" when we have none yet; server may return a new one in response headers.
        h["Mcp-Session-Id"] = self._session_id or "default"
        # Persistent cookie jar: send session cookie if present so server can use cookie-based session.
        if self._cookie_file:
            cookie_val = self._load_cookie_from_file()
            if cookie_val:
                h["Cookie"] = f"{_MCP_SESSION_COOKIE_NAME}={cookie_val}"
        return h

    @staticmethod
    def _parse_sse_data(text: str) -> dict[str, Any] | None:
        """Extract the last ``data:`` payload from an SSE stream.

        MCP Streamable HTTP may return multiple SSE events; the final one
        with ``"result"`` or ``"error"`` is the JSON-RPC response.

        Optimized to find the last data line without processing all lines
        when only the final result matters.
        """
        # Find the last "data:" line more efficiently by working backwards
        lines = text.splitlines()
        for line in reversed(lines):
            stripped = line.strip()
            if stripped.startswith("data:"):
                raw = stripped[5:].strip()  # len("data:") = 5
                if raw:
                    try:
                        parsed = json.loads(raw)
                        if isinstance(parsed, dict):
                            return parsed
                    except json.JSONDecodeError:
                        continue
        return None

    async def _post(self, body: dict[str, Any]) -> dict[str, Any]:
        """POST a JSON-RPC envelope and return the parsed response dict."""
        had_session_id = bool(self._session_id)
        try:
            resp = await self._client.post(self._url, json=body, headers=self._headers())
        except Exception:
            # Retry once with a trailing slash for backends that strictly require it.
            retry_url = f"{self._url}/"
            resp = await self._client.post(retry_url, json=body, headers=self._headers())

        # Capture session id from response so subsequent requests reuse the same session
        sid = resp.headers.get("mcp-session-id") or resp.headers.get("Mcp-Session-Id")
        if sid:
            self._session_id = sid
        self._save_session_cookie_from_response(resp)

        # Some servers expose /mcp but not /mcp/message; retry without /message on 404
        if resp.status_code == 404 and self._url.endswith("/mcp/message/"):
            retry_url = self._url.rstrip("/")
            resp = await self._client.post(retry_url, json=body, headers=self._headers())
            sid = resp.headers.get("mcp-session-id") or resp.headers.get("Mcp-Session-Id")
            if sid:
                self._session_id = sid
            self._save_session_cookie_from_response(resp)

        # On 400, retry once without session id (stale id can cause server to reject)
        if resp.status_code == 400 and had_session_id:
            self._session_id = None
            resp = await self._client.post(self._url, json=body, headers=self._headers())
            sid = resp.headers.get("mcp-session-id") or resp.headers.get("Mcp-Session-Id")
            if sid:
                self._session_id = sid
            self._save_session_cookie_from_response(resp)

        try:
            resp.raise_for_status()
        except HTTPStatusError as e:
            body_str = e.response.text or ""
            try:
                data = e.response.json()
                if isinstance(data, dict) and "error" in data:
                    err = data["error"]
                    body_str = err.get("message", str(err)) if isinstance(err, dict) else str(err)
                elif isinstance(data, dict) and "message" in data:
                    body_str = str(data["message"])
            except Exception:
                pass
            if len(body_str) > 500:
                body_str = body_str[:500] + "..."
            raise ClientError(
                f"Client error '{e.response.status_code} {e.response.reason_phrase}' for url {e.request.url}: {body_str}",
            ) from e

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

    async def _notify(
        self,
        method: str,
        params: dict[str, Any] | None = None,
    ) -> None:
        """Send a JSON-RPC notification (no id, no response expected)."""
        body: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params:
            body["params"] = params
        try:
            await self._client.post(self._url, json=body, headers=self._headers())
        except Exception:
            pass  # notifications are fire-and-forget

    async def _request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
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

    async def _request_list(
        self,
        method: str,
        key: str,
    ) -> list[dict[str, Any]]:
        """Call a list-style RPC method and safely extract ``key`` from its result."""
        result = await self._request(method)
        if not isinstance(result, dict):
            return []
        items = result.get(key, [])
        return items if isinstance(items, list) else []

    # -- public API ----------------------------------------------------------

    async def initialize(self) -> dict[str, Any]:
        """Send ``initialize`` + ``notifications/initialized``."""
        result = await self._request(
            "initialize",
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "AgentDecompile-Bridge", "version": "1.0.0"},
            },
        )
        await self._notify("notifications/initialized")
        self._initialized = True
        # Log server identity so the user can see backend name/version at startup.
        if isinstance(result, dict):
            info = result.get("serverInfo", {}) or {}
            name = info.get("name", "")
            version = info.get("version", "")
            proto = result.get("protocolVersion", "")
            parts = []
            if name:
                parts.append(name)
            if version:
                parts.append(f"v{version}")
            if proto:
                parts.append(f"(protocol {proto})")
            if parts:
                sys.stderr.write(f"Backend: {' '.join(parts)}\n")
        return result

    async def list_tools(self) -> list[dict[str, Any]]:
        """Return the raw tool list from ``tools/list``."""
        return await self._request_list("tools/list", "tools")

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Call a tool and return the raw result dict."""
        return await self._request("tools/call", {"name": name, "arguments": arguments or {}})

    async def list_resources(self) -> list[dict[str, Any]]:
        return await self._request_list("resources/list", "resources")

    async def read_resource(self, uri: str) -> dict[str, Any]:
        return await self._request("resources/read", {"uri": uri})

    async def list_prompts(self) -> list[dict[str, Any]]:
        return await self._request_list("prompts/list", "prompts")

    async def get_prompt(
        self,
        name: str,
        arguments: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Return the prompt result from prompts/get."""
        return await self._request("prompts/get", {"name": name, "arguments": arguments or {}})

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
            result = await client.call_tool(Tool.GET_FUNCTIONS.value, {"programPath": "..."})
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        url: str | None = None,
        extra_headers: dict[str, str] | None = None,
        cookie_file: Path | None = None,
    ):
        """Initialize the client.

        Args:
        ----
            host: Server host (used if url is None).
            port: Server port (used if url is None).
            url: Override URL (e.g. http://host:port or http://host:port/mcp/message).
            cookie_file: Optional path to persist MCP session cookie (for cookie-based session reuse).
        """
        if url and url.strip():
            self._url = normalize_backend_url(url.strip())
        else:
            base = f"http://{host}:{port}"
            if not base.endswith("/mcp/message"):
                base = f"{base.rstrip('/')}/mcp/message"
            self._url = base
        self._extra_headers = dict(extra_headers or {})
        self._cookie_file: Path | None = cookie_file
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
        self._backend = RawMcpHttpBackend(
            self._url,
            extra_headers=self._extra_headers,
            cookie_file=self._cookie_file,
        )
        try:
            await self._backend.initialize()
            self._connected = True
        except Exception as e:
            if self._backend is not None:
                await self._backend.close()
            self._backend = None
            msg_prefix = f"Cannot connect to AgentDecompile server at {self._url}"
            if self._is_connection_error(e):
                msg = f"{msg_prefix}\n\n{get_server_start_message()}"
            else:
                msg = f"{msg_prefix}: {e}\n\n{get_server_start_message()}"
            raise ServerNotRunningError(msg) from e

    async def _close_internal(self) -> None:
        """Close connection and release resources."""
        self._connected = False
        if self._backend is not None:
            await self._backend.close()
            self._backend = None

    @staticmethod
    def _is_connection_error(exc: BaseException) -> bool:
        """Return True if *exc* is a transport/connection failure."""
        return _is_transport_connection_error(exc)

    def _require_connected_backend(self) -> RawMcpHttpBackend:
        """Return the active backend when connected, else raise a client error."""
        backend = self._backend
        if not self._connected or backend is None:
            raise ClientError("Not connected")
        return backend

    def get_session_id(self) -> str | None:
        """Return the current MCP session id from the last response (for CLI persistence across invocations)."""
        if self._backend is None:
            return None
        return getattr(self._backend, "_session_id", None) or None

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
        return await self._require_connected_backend().list_tools()

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Call a tool by name with optional arguments."""
        result = await self._require_connected_backend().call_tool(name, arguments or {})
        return self._extract_result(result)

    async def list_resources(self) -> list[Any]:
        """List resources offered by the server."""
        return await self._require_connected_backend().list_resources()

    async def read_resource(self, uri: str) -> Any:
        """Read a resource by URI."""
        return await self._require_connected_backend().read_resource(uri)

    async def list_prompts(self) -> list[Any]:
        """List prompts offered by the server."""
        return await self._require_connected_backend().list_prompts()


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


# The MCP SDK sometimes sends responses with id:0 instead of the request's id.
# We record request ids as they go out and rewrite response id to the matching
# request id so the client can correlate responses with requests.
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
        self._backends: dict[str, RawMcpHttpBackend] = {}
        self._backend_locks: dict[str, asyncio.Lock] = {}
        self._backend_map_lock = asyncio.Lock()
        self._streamable_http_headers: dict[str, dict[str, str]] = {}

        self._register_handlers()

    def _set_streamable_http_headers(self, session_id: str, headers: dict[str, str]) -> None:
        """Store forwarded HTTP headers for one frontend session."""
        if headers:
            self._streamable_http_headers[session_id] = dict(headers)
        else:
            self._streamable_http_headers.pop(session_id, None)

    def _get_streamable_http_headers(self, session_id: str) -> dict[str, str]:
        """Return forwarded HTTP headers for one frontend session."""
        return dict(self._streamable_http_headers.get(session_id, {}))

    @staticmethod
    def _proxy_project_path_headers() -> dict[str, str]:
        """Build X-AgentDecompile-Project-Path from proxy env so backend uses configured project.

        When agentdecompile-proxy runs with AGENTDECOMPILE_PROJECT_PATH and optionally
        AGENTDECOMPILE_PROJECT_NAME, these are sent to the backend so debug-info and
        open-project use the right .gpr path instead of the backend default (e.g. my_project.gpr).
        Enables multiple proxy sessions to target different projects via env.
        """
        path_val: str = os.environ.get("AGENTDECOMPILE_PROJECT_PATH", "").strip() or os.environ.get("AGENT_DECOMPILE_PROJECT_PATH", "").strip() or ""
        if not path_val.strip():
            return {}
        path: Path = Path(path_val.strip()).expanduser()
        if path.suffix.lower() == ".gpr":
            return {"X-AgentDecompile-Project-Path": path.as_posix()}
        name_val: str = os.environ.get("AGENTDECOMPILE_PROJECT_NAME", "").strip() or os.environ.get("AGENT_DECOMPILE_PROJECT_NAME", "").strip() or ""
        name: str = name_val.strip() or "my_project"
        if not name.lower().strip().endswith(".gpr"):
            name = f"{name.strip()}.gpr"
        return {"X-AgentDecompile-Project-Path": (path / name).as_posix()}

    def _current_frontend_session_id(self) -> str:
        sid: str = get_current_mcp_session_id()
        if sid and sid != "default":
            return sid

        # Fallback: derive from MCP SDK request context. Some transport paths
        # may not propagate the custom contextvar but still carry a stable
        # per-client session object in request_context.
        try:
            ctx = self.server.request_context
            session = getattr(ctx, "session", None)
            if session is not None:
                for attr in ("session_id", "id", "_session_id", "client_id"):
                    value = getattr(session, attr, None)
                    if value:
                        return str(value)
                return f"sdk-session:{id(session)}"
        except Exception:
            pass

        return sid or "default"

    async def _get_backend_lock(self, session_id: str) -> asyncio.Lock:
        async with self._backend_map_lock:
            lock: asyncio.Lock | None = self._backend_locks.get(session_id)
            if lock is None:
                lock = asyncio.Lock()
                self._backend_locks[session_id] = lock
            return lock

    async def _ensure_backend(self, session_id: str | None = None) -> RawMcpHttpBackend:
        """Return (or lazily create) the backend connection for one frontend session.
        Per-session lock prevents concurrent requests from opening duplicate connections.
        """
        sid: str = session_id or self._current_frontend_session_id()
        backend: RawMcpHttpBackend | None = self._backends.get(sid)
        if backend is not None and backend._initialized:
            return backend

        lock: asyncio.Lock = await self._get_backend_lock(sid)
        async with lock:
            backend = self._backends.get(sid)
            if backend is not None and backend._initialized:
                return backend

            if backend is not None:
                await backend.close()

            merged_headers: dict[str, str] = {
                **self._get_streamable_http_headers(sid),
                **self._proxy_project_path_headers(),
            }
            backend = RawMcpHttpBackend(self.url, extra_headers=merged_headers)
            await backend.initialize()
            self._backends[sid] = backend
            sys.stderr.write(f"Backend session established to {self.url} (frontend session: {sid})\n")

            # Auto-open shared server if CLI credentials are available.
            await self._auto_open_shared_server(backend)

            return backend

    async def _auto_open_shared_server(self, backend: RawMcpHttpBackend) -> None:
        """Auto-open a shared Ghidra server connection if CLI credentials are in env vars.

        Shared-server host/auth values should be supplied via environment
        variables (``AGENT_DECOMPILE_GHIDRA_SERVER_HOST``,
        ``AGENT_DECOMPILE_GHIDRA_SERVER_PORT``,
        ``AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME``,
        ``AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD``, and optionally
        ``AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY``). This method reads them and calls ``open-project`` on the remote
        backend so that tools like ``list-project-files`` work immediately
        without requiring a manual ``open-project`` call.
        """
        server_host: str = (
            os.environ.get("AGENT_DECOMPILE_SERVER_HOST", "").strip()
            or os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_HOST", "").strip()
            or os.environ.get("AGENTDECOMPILE_HTTP_GHIDRA_SERVER_HOST", "").strip()
            or os.environ.get("AGENTDECOMPILE_SERVER_HOST", "").strip()
            or os.environ.get("AGENTDECOMPILE_GHIDRA_SERVER_HOST", "").strip()
            or ""
        ).strip()
        if not server_host.strip():
            sys.stderr.write(
                "[auto-open] No shared server host found in env. Checked: AGENT_DECOMPILE_SERVER_HOST, AGENT_DECOMPILE_GHIDRA_SERVER_HOST, AGENTDECOMPILE_SERVER_HOST, AGENTDECOMPILE_GHIDRA_SERVER_HOST\n"
            )
            return  # No shared server configured – nothing to auto-open.

        server_port: str = (
            os.environ.get("AGENT_DECOMPILE_SERVER_PORT", "").strip()
            or os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_PORT", "").strip()
            or os.environ.get("AGENTDECOMPILE_HTTP_GHIDRA_SERVER_PORT", "").strip()
            or os.environ.get("AGENTDECOMPILE_SERVER_PORT", "").strip()
            or os.environ.get("AGENTDECOMPILE_GHIDRA_SERVER_PORT", "").strip()
            or "13100"
        ).strip()
        server_username: str = (
            os.environ.get("AGENT_DECOMPILE_SERVER_USERNAME", "").strip()
            or os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME", "").strip()
            or os.environ.get("AGENTDECOMPILE_SERVER_USERNAME", "").strip()
            or os.environ.get("AGENTDECOMPILE_GHIDRA_SERVER_USERNAME", "").strip()
            or ""
        ).strip()
        server_password: str = (
            os.environ.get("AGENT_DECOMPILE_SERVER_PASSWORD", "").strip()
            or os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD", "").strip()
            or os.environ.get("AGENTDECOMPILE_SERVER_PASSWORD", "").strip()
            or os.environ.get("AGENTDECOMPILE_GHIDRA_SERVER_PASSWORD", "").strip()
            or ""
        ).strip()
        repository: str = (
            os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY", "").strip()
            or os.environ.get("AGENTDECOMPILE_HTTP_GHIDRA_SERVER_REPOSITORY", "").strip()
            or os.environ.get("AGENTDECOMPILE_GHIDRA_SERVER_REPOSITORY", "").strip()
            or os.environ.get("AGENT_DECOMPILE_REPOSITORY", "").strip()
            or os.environ.get("AGENTDECOMPILE_REPOSITORY", "").strip()
            or ""
        ).strip()
        sys.stderr.write(
            f"[auto-open] Resolved env: host={server_host!r}, port={server_port!r}, username={'(set)' if server_username else '(not set)'}, password={'(set)' if server_password else '(not set)'}, repository={repository!r}\n"
        )

        open_args: dict[str, Any] = {
            "server_host": server_host,
            "server_port": int(server_port) if server_port.isdigit() else 13100,
        }
        if server_username.strip():
            open_args["server_username"] = server_username
        if server_password:
            open_args["server_password"] = server_password
        if repository.strip():
            open_args["path"] = repository

        # Log the exact args being sent (redact password)
        _log_args: dict[str, Any] = {k: ("***" if "password" in k.lower() else v) for k, v in open_args.items()}
        sys.stderr.write(f"[auto-open] Calling connect-shared-project with args: {_log_args}\n")
        sys.stderr.write(f"Auto-opening shared server {server_host}:{open_args['server_port']}{(' repo=' + repository) if repository else ''} ...\n")

        try:
            result: dict[str, Any] = await backend.call_tool("connect-shared-project", open_args)
            # Log a structured summary of the result.
            if isinstance(result, dict):
                content: list[dict[str, Any]] = result.get("content", [])
                is_error = result.get("isError", False)
                if is_error:
                    text_parts: list[str] = [c.get("text", "") for c in content if isinstance(c, dict) and c.get("type") == "text"]
                    sys.stderr.write(f"Auto-open FAILED: {' '.join(text_parts)}\n")
                else:
                    # Parse the embedded JSON to get structured fields.
                    data: dict[str, Any] = {}
                    for c in content:
                        if isinstance(c, dict) and c.get("type") == "text":
                            try:
                                data = json.loads(c["text"])
                            except (json.JSONDecodeError, KeyError):
                                pass
                            break
                    if data:
                        repo = data.get("repository", "")
                        avail_repos = data.get("availableRepositories", [])
                        prog_count = data.get("programCount", 0)
                        programs = data.get("programs", [])
                        server_connected = data.get("serverConnected", False)
                        checked_out = data.get("checkedOutProgram")
                        sys.stderr.write(
                            f"Auto-open OK: connected={server_connected}, repo={repo!r}, availableRepositories={avail_repos}, programs={prog_count}\n",
                        )
                        if programs:
                            prog_paths = [p.get("path", p.get("name", str(p))) for p in programs[:20]]
                            sys.stderr.write(f"  programs: {prog_paths}\n")
                            if len(programs) > 20:
                                sys.stderr.write(f"  ... and {len(programs) - 20} more\n")
                        if checked_out:
                            sys.stderr.write(f"  checked-out: {checked_out}\n")
                    else:
                        text_parts = [c.get("text", "") for c in content if isinstance(c, dict) and c.get("type") == "text"]
                        sys.stderr.write(f"Auto-open OK: {' '.join(text_parts)[:300]}\n")
            else:
                sys.stderr.write(f"Auto-open returned: {str(result)[:200]}\n")
        except Exception as exc:
            # Non-fatal – tools still work, user can call open manually.
            sys.stderr.write(f"Auto-open failed (non-fatal): {type(exc).__name__}: {exc}\n")

    async def _reset_backend_session(self, session_id: str | None = None) -> None:
        """Reset backend session(s).

        If ``session_id`` is provided, only that frontend-mapped backend session
        is reset. Otherwise all backend sessions are reset.
        """
        if session_id is not None and session_id.strip():
            sid: str = session_id.strip() or "default"
            backend: RawMcpHttpBackend | None = self._backends.pop(sid, None)
            self._backend_locks.pop(sid, None)
            self._streamable_http_headers.pop(sid, None)
            if backend is not None:
                await backend.close()
            return

        backends: list[RawMcpHttpBackend] = list(self._backends.values())
        self._backends.clear()
        self._backend_locks.clear()
        self._streamable_http_headers.clear()
        for backend in backends:
            await backend.close()

    async def _backend_request(self, method: str, *args: Any, **kwargs: Any) -> Any:
        """Ensure backend for current session, call *method*, retry once on connection errors by resetting session."""
        last_exc: Exception | None = None
        session_id: str = self._current_frontend_session_id()
        for attempt in range(2):
            try:
                backend: RawMcpHttpBackend = await self._ensure_backend(session_id)
                func: Callable[[Any, Any], Any] = getattr(backend, method)
                return await func(*args, **kwargs)
            except Exception as exc:
                last_exc = exc
                if attempt == 0 and self._is_connection_error(exc):
                    msg = f"Backend connection error on {method}, reconnecting... ({type(exc).__name__}: {exc}) [frontend session: {session_id}]"
                    sys.stderr.write(msg + "\n")
                    # Invalidate this session's backend so next _ensure_backend creates a fresh connection
                    await self._reset_backend_session(session_id)
                    continue
                break
        raise last_exc  # type: ignore[misc]

    @staticmethod
    def _is_connection_error(exc: BaseException) -> bool:
        """Return True if *exc* is a transport/connection failure."""
        return _is_transport_connection_error(exc)

    @staticmethod
    def _raw_tool_to_mcp(raw: dict[str, Any]) -> Tool:
        """Convert a raw tool dict from the backend to an MCP ``Tool`` object."""
        return Tool.model_validate(raw)

    async def _handle_list_tools(self) -> list[Tool]:
        """Handle MCP list_tools request by forwarding to backend."""
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
            sys.stderr.write(f"Tools advertised: {len(advertised)}\n")
            return advertised
        except Exception as e:
            msg = f"ERROR: list_tools failed: {e.__class__.__name__}: {e}"
            sys.stderr.write(msg + "\n")
            return []

    async def _handle_call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
    ) -> UnstructuredContent | StructuredContent | CombinationContent | CallToolResult:  # pyright: ignore[reportInvalidTypeForm]
        """Handle MCP call_tool request by forwarding to backend."""
        backend_name = resolve_tool_name(name) if isinstance(name, str) else None
        if backend_name is None:
            backend_name = name

        try:
            call_args: dict[str, Any] = dict(arguments or {})
            call_args.setdefault("format", "markdown")
            raw_result: dict[str, Any] = await self._backend_request("call_tool", backend_name, call_args)
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

    async def _handle_list_resources(self) -> list[Resource]:
        """Handle MCP list_resources request by forwarding to backend."""
        try:
            from mcp.types import Resource as _Resource

            raw: list[dict[str, Any]] = await self._backend_request("list_resources")
            resources = [_Resource.model_validate(r) for r in raw]
            sys.stderr.write(f"Resources available: {len(resources)}\n")
            return resources
        except Exception as e:
            sys.stderr.write(f"ERROR: list_resources failed: {e.__class__.__name__}: {e}\n")
            return []

    async def _handle_read_resource(
        self,
        uri: AnyUrl,
    ) -> str | bytes | Iterable[ReadResourceContents]:
        """Handle MCP read_resource request by forwarding to backend."""
        try:
            raw: dict[str, Any] = await self._backend_request("read_resource", str(uri))
            contents = raw.get("contents", [])
            if contents:
                c0 = contents[0] if isinstance(contents, list) else contents
                if isinstance(c0, dict):
                    return c0.get("text", c0.get("blob", ""))
            return ""
        except Exception as e:
            msg = f"ERROR: read_resource failed for URI {uri}: {e.__class__.__name__}: {e}"
            sys.stderr.write(msg + "\n")
            return ""

    async def _handle_list_prompts(self) -> list[Prompt]:
        """Handle MCP list_prompts request by forwarding to backend."""
        try:
            from mcp.types import Prompt as _Prompt

            raw: list[dict[str, Any]] = await self._backend_request("list_prompts")
            prompts = [_Prompt.model_validate(p) for p in raw]
            sys.stderr.write(f"Prompts available: {len(prompts)}\n")
            return prompts
        except Exception as e:
            msg = f"ERROR: list_prompts failed: {e.__class__.__name__}: {e}"
            sys.stderr.write(msg + "\n")
            return []

    async def _handle_get_prompt(self, name: str, arguments: dict[str, str] | None) -> GetPromptResult:
        """Handle MCP get_prompt request by forwarding to backend."""
        from mcp.types import GetPromptResult as _GetPromptResult

        try:
            raw: dict[str, Any] = await self._backend_request("get_prompt", {"name": name, "arguments": arguments})
            return _GetPromptResult.model_validate(raw)
        except Exception as e:
            msg = f"ERROR: get_prompt failed for {name}: {e.__class__.__name__}: {e}"
            sys.stderr.write(msg + "\n")
            raise

    def _register_handlers(self):
        """Register MCP protocol handlers that forward to AgentDecompile backend."""

        @self.server.list_tools()
        async def list_tools() -> list[Tool]:  # type: ignore[name-defined]
            return await self._handle_list_tools()

        @self.server.call_tool()
        async def call_tool(
            name: str,
            arguments: dict[str, Any],
        ) -> UnstructuredContent | StructuredContent | CombinationContent | CallToolResult:  # type: ignore[name-defined]  # pyright: ignore[reportInvalidTypeForm]
            return await self._handle_call_tool(name, arguments)

        @self.server.list_resources()
        async def list_resources() -> list[Resource]:  # type: ignore[name-defined]
            return await self._handle_list_resources()

        @self.server.read_resource()
        async def read_resource(
            uri: AnyUrl,  # type: ignore[name-defined]
        ) -> str | bytes | Iterable[ReadResourceContents]:  # type: ignore[name-defined]  # pyright: ignore[reportInvalidTypeForm]
            return await self._handle_read_resource(uri)

        @self.server.list_prompts()
        async def list_prompts() -> list[Prompt]:  # type: ignore[name-defined]
            return await self._handle_list_prompts()

        @self.server.get_prompt()
        async def get_prompt(name: str, arguments: dict[str, str] | None) -> GetPromptResult:  # type: ignore[name-defined]
            return await self._handle_get_prompt(name, arguments)

    def _create_initialization_options(self):
        """Create MCP initialization options with explicit logging capability.

        Some MCP clients attempt to set the server log level during/after
        initialize and expect `capabilities.logging` to be present.
        """
        options: InitializationOptions = self.server.create_initialization_options()
        capabilities: ServerCapabilities | None = getattr(options, "capabilities", None)
        if capabilities is None:
            capabilities = ServerCapabilities()

        if hasattr(capabilities, "logging") and capabilities.logging is None:
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
            await self._reset_backend_session()

    def stop(self):
        """Stop the bridge and cleanup resources."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        loop.create_task(self._reset_backend_session())
