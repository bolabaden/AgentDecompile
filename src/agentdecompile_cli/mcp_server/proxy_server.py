"""Local MCP proxy server for forwarding to a remote MCP backend.

This server exposes a local streamable HTTP MCP endpoint and forwards all
tools/resources/prompts to another MCP server. It does not require PyGhidra
or local JVM startup.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import threading
import time

from typing import Any

from fastapi import FastAPI
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from pydantic import BaseModel
from agentdecompile_cli.bridge import AgentDecompileStdioBridge
from agentdecompile_cli.mcp_server.auth import AuthConfig, AuthMiddleware
from agentdecompile_cli.mcp_server.session_context import CURRENT_MCP_SESSION_ID

logger = logging.getLogger(__name__)


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
        self.app: FastAPI = FastAPI(title=self.config.name, version=self.config.version)
        self._bridge: AgentDecompileStdioBridge = AgentDecompileStdioBridge(self.config.backend_url)
        self._session_manager: StreamableHTTPSessionManager = StreamableHTTPSessionManager(
            app=self._bridge.server,
            json_response=True,
            stateless=True,
        )
        self._session_manager_cm: Any | None = None
        self._running: bool = False
        self._server_thread: threading.Thread | None = None
        self._uvicorn_server: Any | None = None

        self._setup_routes()

    _MCP_PATHS: frozenset[str] = frozenset({"/mcp", "/mcp/message"})

    def _setup_routes(self) -> None:
        @self.app.on_event("startup")
        async def _startup_session_manager() -> None:
            self._session_manager_cm = self._session_manager.run()
            await self._session_manager_cm.__aenter__()

        @self.app.on_event("shutdown")
        async def _shutdown_session_manager() -> None:
            if self._session_manager_cm is not None:
                await self._session_manager_cm.__aexit__(None, None, None)
                self._session_manager_cm = None
            await self._bridge._reset_backend_session()

        @self.app.get("/health")
        async def health_check() -> dict[str, Any]:
            return {
                "status": "healthy" if self._running else "starting",
                "server": self.config.name,
                "version": self.config.version,
                "mode": "proxy",
                "backend": self.config.backend_url,
            }

        mcp_handle = self._session_manager.handle_request

        async def _mcp_asgi(scope: dict[str, Any], receive: Any, send: Any) -> None:
            session_id = "default"
            if scope.get("type") == "http":
                for key_b, value_b in scope.get("headers", []):
                    key_b: bytes
                    value_b: bytes
                    if key_b.decode("latin1").lower() == "mcp-session-id":
                        value = value_b.decode("latin1").strip()
                        if value:
                            session_id = value
                        break
            token = CURRENT_MCP_SESSION_ID.set(session_id)
            try:
                await mcp_handle(scope, receive, send)
            finally:
                CURRENT_MCP_SESSION_ID.reset(token)

        # Optionally wrap with auth (experimental, off by default).
        mcp_app: Any = _mcp_asgi
        if self.auth_config is not None:
            mcp_app = AuthMiddleware(_mcp_asgi, self.auth_config)

        inner_app = self.app
        mcp_paths = self._MCP_PATHS

        class _MCPRoutingMiddleware:
            """ASGI middleware: route /mcp and /mcp/message to MCP handler."""

            async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
                if scope.get("type") == "http":
                    path = (scope.get("path") or "").rstrip("/") or "/"
                    if path in mcp_paths:
                        rewritten = dict(scope, path="/")
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
