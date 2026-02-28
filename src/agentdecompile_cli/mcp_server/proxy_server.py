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
from agentdecompile_cli.mcp_server.session_context import CURRENT_MCP_SESSION_ID

logger = logging.getLogger(__name__)


class ProxyServerConfig(BaseModel):
    """Configuration for a local MCP proxy server."""

    name: str = "AgentDecompile"
    version: str = "1.1.0"
    host: str = "127.0.0.1"
    port: int = 8080
    backend_url: str


class AgentDecompileMcpProxyServer:
    """Run a local MCP server that proxies requests to a remote MCP server."""

    def __init__(self, config: ProxyServerConfig):
        self.config: ProxyServerConfig = config
        self.app: FastAPI = FastAPI(title=self.config.name, version=self.config.version)
        self._bridge: AgentDecompileStdioBridge = AgentDecompileStdioBridge(self.config.backend_url)
        self._session_manager: StreamableHTTPSessionManager = StreamableHTTPSessionManager(
            app=self._bridge.server,
            json_response=True,
            stateless=False,
        )
        self._session_manager_cm: Any | None = None
        self._running: bool = False
        self._server_thread: threading.Thread | None = None
        self._uvicorn_server: Any | None = None

        self._setup_routes()

    def _setup_routes(self) -> None:
        class _SessionContextASGI:
            def __init__(self, inner_app: Any):
                self._inner_app: Any = inner_app

            async def __call__(self, scope, receive, send):
                session_id = "default"
                if scope.get("type") == "http":
                    key_b: bytes
                    value_b: bytes
                    for key_b, value_b in scope.get("headers", []):
                        if key_b.decode("latin1").lower() == "mcp-session-id":
                            value = value_b.decode("latin1").strip()
                            if value:
                                session_id = value
                            break

                token = CURRENT_MCP_SESSION_ID.set(session_id)
                try:
                    await self._inner_app(scope, receive, send)
                finally:
                    CURRENT_MCP_SESSION_ID.reset(token)

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

        mcp_asgi = _SessionContextASGI(self._session_manager.handle_request)
        self.app.mount("/mcp/message", mcp_asgi)
        self.app.mount("/mcp/message/", mcp_asgi)

        @self.app.get("/health")
        async def health_check() -> dict[str, Any]:
            return {
                "status": "healthy" if self._running else "starting",
                "server": self.config.name,
                "version": self.config.version,
                "mode": "proxy",
                "backend": self.config.backend_url,
            }

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

            with httpx.Client() as client:
                response = client.get(f"http://{self.config.host}:{self.config.port}/health", timeout=1.0)
                return response.status_code == 200
        except Exception:
            return False

    def _run_server(self) -> None:
        import uvicorn

        uvicorn_config = uvicorn.Config(
            app=self.app,
            host=self.config.host,
            port=self.config.port,
            log_level="info",
        )
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
