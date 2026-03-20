"""Local MCP proxy server for forwarding to a remote MCP backend.

This server exposes a local streamable HTTP MCP endpoint and forwards all
tools/resources/prompts to another MCP server (e.g. agentdecompile-server).
It does not require PyGhidra or local JVM startup; use agentdecompile-proxy
when the backend runs elsewhere. Session state is kept locally and bridged
via stdio/HTTP to the backend.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import threading
import time

from typing import Callable
from contextlib import AbstractContextManager
from contextvars import Token
from typing import TYPE_CHECKING, Any, Awaitable

import uvicorn

from fastapi import FastAPI
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from pydantic import BaseModel
from starlette.types import Message

from agentdecompile_cli.bridge import AgentDecompileStdioBridge
from agentdecompile_cli.mcp_server.auth import AuthMiddleware
from agentdecompile_cli.mcp_server.server import _validate_session_id
from agentdecompile_cli.mcp_server.session_context import CURRENT_MCP_SESSION_ID, SESSION_CONTEXTS
from agentdecompile_cli.registry import Tool

if TYPE_CHECKING:
    from agentdecompile_cli.mcp_server.auth import AuthConfig

logger = logging.getLogger(__name__)

# Cookie name for MCP session (allowlist only this cookie when forwarding to backend).
_MCP_SESSION_COOKIE_NAME = "mcp_session_id"


def _parse_mcp_session_cookie_from_scope(scope: dict[str, Any]) -> str | None:
    """Parse Cookie header and return the value for mcp_session_id, or None."""
    if scope.get("type") != "http":
        return None
    for key_b, value_b in scope.get("headers", []):
        if key_b.decode("latin1").lower() == "cookie":
            cookie_header = value_b.decode("latin1")
            prefix = _MCP_SESSION_COOKIE_NAME + "="
            for part in cookie_header.split(";"):
                part = part.strip()
                if part.startswith(prefix):
                    return part[len(prefix) :].strip().strip('"')
            return None
    return None


def _proxy_mcp_post_openapi_extra() -> dict[str, Any]:
    return {
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "required": ["jsonrpc", "id", "method"],
                        "properties": {
                            "jsonrpc": {"type": "string", "example": "2.0"},
                            "id": {
                                "oneOf": [
                                    {"type": "integer", "example": 1},
                                    {"type": "string", "example": "req-1"},
                                ],
                            },
                            "method": {
                                "type": "string",
                                "enum": [
                                    "initialize",
                                    "tools/list",
                                    "tools/call",
                                    "resources/list",
                                    "resources/read",
                                ],
                            },
                            "params": {"type": "object", "additionalProperties": True},
                        },
                        "additionalProperties": True,
                    },
                    "examples": {
                        "initialize": {
                            "summary": "Initialize a proxied MCP session",
                            "value": {
                                "jsonrpc": "2.0",
                                "id": 1,
                                "method": "initialize",
                                "params": {
                                    "protocolVersion": "2025-11-25",
                                    "capabilities": {},
                                    "clientInfo": {"name": "proxy-docs-client", "version": "1.0"},
                                },
                            },
                        },
                        "tools_call": {
                            "summary": "Forward tool invocation to backend",
                            "value": {
                                "jsonrpc": "2.0",
                                "id": 2,
                                "method": "tools/call",
                                "params": {
                                    "name": Tool.OPEN_PROJECT.value,
                                    "arguments": {
                                        "path": "/K1/k1_win_gog_swkotor.exe",
                                        "format": "json",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
    }


class ProxyServerConfig(BaseModel):
    """Configuration for a local MCP proxy server."""

    name: str = "AgentDecompile"
    version: str = "1.1.0"
    host: str = "127.0.0.1"
    port: int = 8080
    backend_url: str
    tls_certfile: str | None = None
    """Path to TLS certificate file (PEM). Enables HTTPS when combined with tls_keyfile."""
    tls_keyfile: str | None = None
    """Path to TLS private key file (PEM). Enables HTTPS when combined with tls_certfile."""


class AgentDecompileMcpProxyServer:
    """Run a local MCP server that proxies requests to a remote MCP server."""

    def __init__(self, config: ProxyServerConfig, auth_config: AuthConfig | None = None):
        self.config: ProxyServerConfig = config
        self.auth_config: AuthConfig | None = auth_config
        self.app: FastAPI = FastAPI(
            title=self.config.name,
            version=self.config.version,
            description=(
                "AgentDecompile MCP proxy server — forwards MCP tool calls to a remote backend. MCP endpoint: `POST /mcp` (streamable-HTTP) or `POST /mcp/message` (SSE)."
            ),
            docs_url="/docs",
            redoc_url="/redoc",
            openapi_url="/openapi.json",
        )
        self._bridge: AgentDecompileStdioBridge = AgentDecompileStdioBridge(self.config.backend_url)
        self._session_manager: StreamableHTTPSessionManager = StreamableHTTPSessionManager(
            app=self._bridge.server,
            json_response=True,
            stateless=False,
        )
        self._session_manager_cm: AbstractContextManager[StreamableHTTPSessionManager, bool | None] | None = None
        self._running: bool = False
        self._server_thread: threading.Thread | None = None
        self._uvicorn_server: uvicorn.Server | None = None

        self._setup_routes()

    _MCP_PATHS: frozenset[str] = frozenset({"/mcp", "/mcp/message"})

    @staticmethod
    async def _mcp_openapi_stub() -> dict[str, Any]:
        """Schema-only MCP route stub for OpenAPI visibility."""
        return {
            "detail": "MCP proxy requests are handled by the outer transport middleware before FastAPI routing.",
        }

    def _setup_routes(self) -> None:
        """Register FastAPI routes: startup/shutdown for MCP session manager and bridge, health, API info, and MCP path stubs."""

        @self.app.on_event("startup")
        async def _startup_session_manager() -> AbstractContextManager[StreamableHTTPSessionManager] | None:
            # Bridge uses StreamableHTTPSessionManager; enter its context so MCP sessions can be created
            self._session_manager_cm = self._session_manager.run()
            await self._session_manager_cm.__aenter__()
            SESSION_CONTEXTS.start_reaper()

        @self.app.on_event("shutdown")
        async def _shutdown_session_manager() -> None:
            SESSION_CONTEXTS.stop_reaper()
            if self._session_manager_cm is not None:
                await self._session_manager_cm.__aexit__(None, None, None)
                self._session_manager_cm = None
            await self._bridge._reset_backend_session()

        @self.app.get("/health", tags=["meta"])
        async def health_check() -> dict[str, Any]:
            return {
                "status": "healthy" if self._running else "starting",
                "server": self.config.name,
                "version": self.config.version,
                "mode": "proxy",
                "backend": self.config.backend_url,
            }

        @self.app.get("/.well-known/oauth-authorization-server", tags=["meta"], include_in_schema=False)
        async def oauth_authorization_server_discovery() -> dict[str, Any]:
            """RFC 8414 discovery: this server does not provide OAuth 2.0 authorization; return minimal doc to avoid 404 probes."""
            return {
                "issuer": "",
                "authorization_endpoint": "",
                "token_endpoint": "",
                "response_types_supported": [],
                "scopes_supported": [],
            }

        @self.app.get("/", tags=["meta"])
        async def api_info() -> dict[str, Any]:
            """API index — links to interactive documentation and transport endpoints."""
            return {
                "server": self.config.name,
                "version": self.config.version,
                "mode": "proxy",
                "backend": self.config.backend_url,
                "docs": {
                    "swagger_ui": "/docs",
                    "redoc": "/redoc",
                    "openapi_json": "/openapi.json",
                },
                "mcp": {
                    "streamable_http": "/mcp",
                    "sse_message": "/mcp/message",
                    "protocol": "Model Context Protocol (MCP) — JSON-RPC 2.0 over HTTP",
                },
                "health": "/health",
            }

        @self.app.get("/api/reference", tags=["reference"])
        async def api_reference() -> dict[str, Any]:
            """Proxy-specific MCP docs and forwarded auth headers."""
            return {
                "documentation": {
                    "openapi": "/openapi.json",
                    "swagger_ui": "/docs",
                    "redoc": "/redoc",
                },
                "transport": {
                    "canonical": "/mcp",
                    "compatibility": "/mcp/message",
                    "backend": self.config.backend_url,
                },
                "forwarded_headers": [
                    "authorization",
                    "x-ghidra-server-host",
                    "x-ghidra-server-port",
                    "x-ghidra-repository",
                    "x-agent-server-username",
                    "x-agent-server-password",
                    "x-agent-server-repository",
                ],
                "shared_server_http_mapping": {
                    "request_url": "Use the proxy MCP URL itself, typically http://host:port/mcp",
                    "env_to_headers": {
                        "AGENT_DECOMPILE_GHIDRA_SERVER_HOST": ["X-Ghidra-Server-Host"],
                        "AGENT_DECOMPILE_GHIDRA_SERVER_PORT": ["X-Ghidra-Server-Port"],
                        "AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY": ["X-Ghidra-Repository", "X-Agent-Server-Repository"],
                        "AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME": ["Authorization", "X-Agent-Server-Username"],
                        "AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD": ["Authorization", "X-Agent-Server-Password"],
                        "AGENTDECOMPILE_AUTO_MATCH_PROPAGATE": ["X-AgentDecompile-Auto-Match-Propagate"],
                        "AGENTDECOMPILE_AUTO_MATCH_TARGET_PATHS": ["X-AgentDecompile-Auto-Match-Target-Paths"],
                    },
                    "transport_headers": {
                        "content-type": "application/json",
                        "accept": "application/json, text/event-stream",
                        "mcp-session-id": "Send on follow-up requests after the proxy returns it",
                    },
                    "precedence": {
                        "credentials": ["authorization", "x-agent-server-username/x-agent-server-password"],
                        "repository": ["x-ghidra-repository", "x-agent-server-repository"],
                    },
                },
                "notes": [
                    "Proxy mode does not run local PyGhidra analysis.",
                    "MCP sessions are local to the proxy and bridged to backend sessions.",
                    "Prefer /mcp for new clients; /mcp/message remains compatibility-only.",
                ],
            }

        @self.app.get("/api", tags=["meta"], include_in_schema=False)
        async def legacy_api_info() -> dict[str, Any]:
            """Backward-compatible alias for the API index."""
            return await api_info()

        for method in ("GET", "POST", "DELETE"):
            self.app.add_api_route(
                "/mcp",
                self._mcp_openapi_stub,
                methods=[method],
                tags=["mcp"],
                summary="MCP Streamable HTTP proxy endpoint",
                description=(
                    "Canonical MCP streamable-HTTP proxy endpoint. Use POST for JSON-RPC methods and forward all calls to the configured backend URL. Runtime traffic is intercepted by the outer MCP middleware before FastAPI routing."
                ),
                operation_id=f"proxy_mcp_streamable_{method.lower()}",
                openapi_extra=_proxy_mcp_post_openapi_extra() if method == "POST" else None,
                include_in_schema=True,
            )
            self.app.add_api_route(
                "/mcp/message",
                self._mcp_openapi_stub,
                methods=[method],
                tags=["mcp"],
                summary="MCP message compatibility proxy endpoint",
                description=(
                    "Compatibility MCP proxy endpoint for clients that target /mcp/message. Prefer /mcp for new integrations. Runtime traffic is intercepted by the outer MCP middleware before FastAPI routing."
                ),
                operation_id=f"proxy_mcp_message_{method.lower()}",
                openapi_extra=_proxy_mcp_post_openapi_extra() if method == "POST" else None,
                include_in_schema=True,
            )

        mcp_handle = self._session_manager.handle_request

        def _forwardable_shared_headers(scope: dict[str, Any]) -> dict[str, str]:
            forwarded: dict[str, str] = {}
            if scope.get("type") != "http":
                return forwarded

            allowed_headers: set[str] = {
                "authorization",
                "mcp-session-id",
                "x-ghidra-server-host",
                "x-ghidra-server-port",
                "x-ghidra-repository",
                "x-agent-server-username",
                "x-agent-server-password",
                "x-agent-server-repository",
                "x-agentdecompile-auto-match-propagate",
                "x-agentdecompile-auto-match-target-paths",
            }
            key_b: bytes
            value_b: bytes
            for key_b, value_b in scope.get("headers", []):
                key = key_b.decode("latin1").lower()
                if key in allowed_headers:
                    forwarded[key_b.decode("latin1")] = value_b.decode("latin1").strip()
            # Forward only the MCP session cookie (allowlist) so backend receives session id via cookie.
            cookie_sid = _parse_mcp_session_cookie_from_scope(scope)
            if cookie_sid:
                forwarded["Cookie"] = f"{_MCP_SESSION_COOKIE_NAME}={cookie_sid}"
            return forwarded

        async def _mcp_asgi(scope: dict[str, Any], receive: Callable[[], Awaitable[Message]], send: Callable[[Message], Awaitable[None]]) -> None:
            session_id: str = "default"
            user_agent: str = ""
            remote_addr: str = ""
            if scope.get("type") == "http":
                key_b: bytes
                value_b: bytes
                for key_b, value_b in scope.get("headers", []):
                    header_name = key_b.decode("latin1").lower()
                    if header_name == "mcp-session-id":
                        value = value_b.decode("latin1").strip()
                        if value:
                            session_id = value
                    elif header_name == "user-agent":
                        user_agent = value_b.decode("latin1", errors="replace")
                client_info = scope.get("client")
                if client_info:
                    remote_addr = str(client_info[0]) if isinstance(client_info, (list, tuple)) else ""
                # Resolution order: header (already set) → cookie → default.
                if session_id == "default":
                    cookie_sid = _parse_mcp_session_cookie_from_scope(scope)
                    if cookie_sid:
                        session_id = cookie_sid
                session_id = _validate_session_id(session_id)

            self._bridge._set_streamable_http_headers(session_id, _forwardable_shared_headers(scope))

            pre_sessions: set[str] = set(session_manager._server_instances.keys())

            token: Token[str] = CURRENT_MCP_SESSION_ID.set(session_id)
            try:
                await mcp_handle(scope, receive, send)
            finally:
                CURRENT_MCP_SESSION_ID.reset(token)

            post_sessions: set[str] = set(session_manager._server_instances.keys())
            new_sids = post_sessions - pre_sessions
            if new_sids and (user_agent or remote_addr):
                fingerprint = SESSION_CONTEXTS.compute_client_fingerprint(
                    user_agent=user_agent,
                    remote_addr=remote_addr,
                )
                for new_sid in new_sids:
                    SESSION_CONTEXTS.bind_fingerprint(new_sid, fingerprint)
            removed_sids = pre_sessions - post_sessions
            for gone_sid in removed_sids:
                SESSION_CONTEXTS.evict_to_grace(gone_sid)

        # Optionally wrap with auth (experimental, off by default).
        mcp_app: Callable[[dict[str, Any], Any, Any], Awaitable[None]] = _mcp_asgi
        if self.auth_config is not None:
            mcp_app = AuthMiddleware(_mcp_asgi, self.auth_config)

        inner_app = self.app
        mcp_paths = self._MCP_PATHS
        session_manager = self._session_manager

        class _MCPRoutingMiddleware:
            """ASGI middleware: route /mcp and /mcp/message to MCP handler.

            Handles stale ``mcp-session-id`` headers with grace-period
            awareness so the SDK creates a fresh session while preserving
            session state for reconnecting clients.
            """

            @staticmethod
            def _handle_stale_session(scope: dict[str, Any]) -> dict[str, Any]:
                raw_headers: list[tuple[bytes, bytes]] = scope.get("headers", [])
                for key_b, value_b in raw_headers:
                    if key_b.lower() == b"mcp-session-id":
                        sid = value_b.decode("latin1", errors="replace").strip()
                        if sid and sid not in session_manager._server_instances:
                            cleaned = [(k, v) for k, v in raw_headers if k.lower() != b"mcp-session-id"]
                            return {**scope, "headers": cleaned}
                        break
                return scope

            async def __call__(self, scope: dict[str, Any], receive: Callable[[], Awaitable[Message]], send: Callable[[Message], Awaitable[None]]) -> None:
                if scope.get("type") == "http":
                    path = (scope.get("path") or "").rstrip("/") or "/"
                    if path in mcp_paths:
                        scope = self._handle_stale_session(scope)
                        rewritten: dict[str, Any] = {**scope, "path": "/"}
                        await mcp_app(rewritten, receive, send)
                        return
                await inner_app(scope, receive, send)

        self.app = _MCPRoutingMiddleware()  # type: ignore[assignment]

    def _is_port_available(self, host: str, port: int) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind((host, int(port)))
                return True
        except OSError:
            return False

    def _find_free_port(self, host: str) -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((host, 0))
            return int(sock.getsockname()[1])

    def _is_server_ready(self) -> bool:
        if not self._running:
            return False

        try:
            import httpx

            scheme = "https" if (self.config.tls_certfile and self.config.tls_keyfile) else "http"
            with httpx.Client(verify=False) as client:  # noqa: S501 (local readiness probe)
                response = client.get(
                    f"{scheme}://{self.config.host}:{self.config.port}/health",
                    timeout=1.0,
                )
                return response.status_code == 200
        except Exception:
            return False

    def _run_server(self) -> None:
        import uvicorn

        uvicorn_kwargs: dict[str, Any] = {
            "app": self.app,
            "host": self.config.host,
            "port": self.config.port,
            "log_level": "info",
        }
        if self.config.tls_certfile and self.config.tls_keyfile:
            uvicorn_kwargs["ssl_certfile"] = self.config.tls_certfile
            uvicorn_kwargs["ssl_keyfile"] = self.config.tls_keyfile
        uvicorn_config = uvicorn.Config(**uvicorn_kwargs)
        self._uvicorn_server = uvicorn.Server(uvicorn_config)

        try:
            asyncio.run(self._uvicorn_server.serve())
        except Exception as e:
            logger.error("Proxy server error: %s", e)
        finally:
            self._running = False

    def start(self) -> int:
        if self._running:
            logger.warning("Proxy server is already running")
            return self.config.port

        if not self._is_port_available(self.config.host, self.config.port):
            requested_port = self.config.port
            self.config.port = self._find_free_port(self.config.host)
            logger.warning(
                "Port %s is in use on %s; falling back to free port %s",
                requested_port,
                self.config.host,
                self.config.port,
            )

        self._running = True
        self._server_thread = threading.Thread(target=self._run_server, daemon=True)
        self._server_thread.start()

        timeout = 10.0
        start_time = time.time()
        while not self._is_server_ready():
            if time.time() - start_time > timeout:
                raise RuntimeError("Proxy server failed to start within timeout")
            time.sleep(0.1)

        logger.info("MCP proxy server started on %s:%s", self.config.host, self.config.port)
        return self.config.port

    def stop(self) -> None:
        if not self._running:
            return

        self._running = False

        if self._uvicorn_server is not None:
            self._uvicorn_server.should_exit = True

        if self._server_thread is not None and self._server_thread.is_alive():
            self._server_thread.join(timeout=5.0)

        try:
            asyncio.run(self._bridge._reset_backend_session())
        except RuntimeError:
            pass
