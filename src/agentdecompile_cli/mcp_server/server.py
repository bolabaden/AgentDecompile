"""Python MCP Server implementation.

This module provides a complete MCP server implementation using the Python MCP SDK,
maintaining 1:1 API compatibility.
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import time

from typing import Any

from fastapi import FastAPI, Request
from mcp import types
from mcp.server import Server, Server as MCPServer
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from pydantic import BaseModel

from agentdecompile_cli.launcher import ProgramInfo, ProjectManager
from agentdecompile_cli.mcp_server.resource_providers import ResourceProviderManager
from agentdecompile_cli.mcp_server.session_context import CURRENT_MCP_SESSION_ID
from agentdecompile_cli.mcp_server.tool_providers import UnifiedToolProviderManager
from agentdecompile_cli.mcp_utils.debug_logger import DebugLogger

logger = logging.getLogger(__name__)


class ServerConfig(BaseModel):
    """Configuration for the MCP server."""

    name: str = "AgentDecompile"
    version: str = "1.1.0"
    host: str = "127.0.0.1"
    port: int = 8080
    keep_alive_interval: int = 30


class PythonMcpServer:
    """Python MCP Server implementation.

    Provides MCP interface running entirely in Python
    using PyGhidra for Ghidra integration.
    """

    def __init__(
        self,
        config: ServerConfig | None = None,
    ) -> None:
        self.config: ServerConfig = ServerConfig() if config is None else config
        self.app: FastAPI = FastAPI(title=self.config.name, version=self.config.version)

        # Core components
        self.project_manager: ProjectManager | None = None
        self.program_info: ProgramInfo | None = None

        # MCP server components
        self.mcp_server: MCPServer = self._create_mcp_server()
        self.tool_providers: UnifiedToolProviderManager = UnifiedToolProviderManager()
        self.tool_providers.register_all_providers()
        self.resource_providers: ResourceProviderManager = ResourceProviderManager()

        # Server state
        self._running: bool = False
        self._shutdown_event: threading.Event = threading.Event()
        self._server_thread: threading.Thread | None = None
        self._session_manager = StreamableHTTPSessionManager(
            app=self.mcp_server,
            json_response=True,
            stateless=False,
        )
        self._session_manager_cm = None

        # Setup routes
        self._setup_routes()

    def _create_mcp_server(self) -> MCPServer:
        """Create the MCP server instance."""
        server = Server(name=self.config.name, version=self.config.version)

        @server.list_tools()
        async def list_tools() -> list[types.Tool]:
            """List all available MCP tools."""
            return self.tool_providers.list_tools()

        @server.call_tool(validate_input=False)
        async def call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
            """Call a tool by name with arguments.

            Input validation is disabled because we normalize all parameter names
            (any case/separator variant accepted) before dispatch.  The MCP SDK's
            jsonschema validation would reject valid aliased params.
            """
            return await self.tool_providers.call_tool(name, arguments, self.program_info)

        @server.list_resources()
        async def list_resources() -> list[types.Resource]:
            """List all available MCP resources."""
            return self.resource_providers.list_resources()

        @server.read_resource()
        async def read_resource(uri: str) -> str:
            """Read a resource by URI."""
            return await self.resource_providers.read_resource(uri, self.program_info)

        return server

    def _setup_routes(self) -> None:
        """Setup FastAPI routes for MCP communication."""

        class _SessionContextASGI:
            def __init__(self, inner_app):
                self._inner_app = inner_app

            async def __call__(self, scope, receive, send):
                session_id = "default"
                if scope.get("type") == "http":
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

        self.app.mount("/mcp/message", _SessionContextASGI(self._session_manager.handle_request))

        @self.app.get("/health")
        async def health_check() -> dict[str, Any]:
            """Health check endpoint."""
            return {
                "status": "healthy" if self._running else "starting",
                "server": self.config.name,
                "version": self.config.version,
                "programs": (1 if self.program_info and self.program_info.program else 0),
            }

    def set_project_manager(
        self,
        project_manager: ProjectManager,
    ) -> None:
        """Set the project manager for program lifecycle management."""
        self.project_manager = project_manager

    def set_program_info(
        self,
        program_info: ProgramInfo,
    ) -> None:
        """Set the program info for tool access."""
        self.program_info = program_info
        self.tool_providers.set_program_info(program_info)
        self.resource_providers.set_program_info(program_info)

    def set_ghidra_project(self, project: Any) -> None:
        """Store the GhidraProject so providers can use it for checkout."""
        self.tool_providers.set_ghidra_project(project)

    def program_opened(self, program_path: str) -> None:
        """Notify providers that a program was opened."""
        self.tool_providers.program_opened(program_path)
        self.resource_providers.program_opened(program_path)

    def program_closed(self, program_path: str) -> None:
        """Notify providers that a program was closed."""
        self.tool_providers.program_closed(program_path)
        self.resource_providers.program_closed(program_path)

    def start(self) -> int:
        """Start the MCP server.

        Returns the port the server is running on.
        """
        if self._running:
            logger.warning("Server is already running")
            return self.config.port

        self._running = True
        self._shutdown_event.clear()

        # Enable debug logging if configured
        debug_env = os.getenv("AGENT_DECOMPILE_DEBUG", "").lower()
        if debug_env in ("true", "1", "yes", "on"):
            DebugLogger.set_debug_enabled(True)
            DebugLogger.debug(self, "Debug logging enabled")

        DebugLogger.debug_tool_execution(self, "server_startup", "START", f"Starting server on {self.config.host}:{self.config.port}")

        # Start server in background thread
        self._server_thread = threading.Thread(target=self._run_server, daemon=True)
        self._server_thread.start()

        # Wait for server to be ready
        timeout = 10.0
        start_time = time.time()
        while not self._is_server_ready():
            if time.time() - start_time > timeout:
                raise RuntimeError("Server failed to start within timeout")
            time.sleep(0.1)

        logger.info(f"MCP server started on {self.config.host}:{self.config.port}")
        DebugLogger.debug_tool_execution(self, "server_startup", "SUCCESS", f"Server ready on port {self.config.port}")
        return self.config.port

    def _run_server(self) -> None:
        """Run the FastAPI server in a background thread."""
        import uvicorn

        config = uvicorn.Config(app=self.app, host=self.config.host, port=self.config.port, log_level="info")
        server = uvicorn.Server(config)

        try:
            # Run server until shutdown
            asyncio.run(server.serve())
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            self._running = False

    def _is_server_ready(self) -> bool:
        """Check if the server is ready to accept connections."""
        if not self._running:
            return False

        try:
            import httpx

            with httpx.Client() as client:
                response = client.get(f"http://{self.config.host}:{self.config.port}/health", timeout=1.0)
                return response.status_code == 200
        except Exception:
            return False

    def stop(self) -> None:
        """Stop the MCP server."""
        if not self._running:
            return

        logger.info("Stopping MCP server...")
        self._running = False
        self._shutdown_event.set()

        # Cleanup providers
        if self.tool_providers is None:
            logger.warning("Tool providers are not set! Cannot cleanup!")
        else:
            self.tool_providers.cleanup()

        if self.resource_providers is None:
            logger.warning("Resource providers are not set! Cannot cleanup!")
        else:
            self.resource_providers.cleanup()

        # Stop the server thread
        if self._server_thread is not None and self._server_thread.is_alive():
            # For uvicorn, we need to send shutdown signal
            try:
                import os
                import signal

                os.kill(os.getpid(), signal.SIGTERM)
            except Exception:
                pass

            self._server_thread.join(timeout=5.0)

        logger.info("MCP server stopped")

    def is_running(self) -> bool:
        """Check if the server is running."""
        return self._running and self._is_server_ready()
