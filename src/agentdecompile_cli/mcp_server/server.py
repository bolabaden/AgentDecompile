"""Python MCP Server implementation.

This module provides a complete MCP server implementation using the Python MCP SDK,
maintaining 1:1 API compatibility.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import threading
import time

from typing import Any

from fastapi import FastAPI
from mcp import types
from mcp.server import Server, Server as MCPServer
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from pydantic import BaseModel

from agentdecompile_cli.launcher import ProgramInfo, ProjectManager
from agentdecompile_cli.mcp_server.auth import (
    CURRENT_AUTH_CONTEXT,
    AuthConfig,
    AuthContext,
    AuthMiddleware,
    get_current_auth_context,
    parse_basic_auth,
)
from agentdecompile_cli.mcp_server.resource_providers import ResourceProviderManager
from agentdecompile_cli.mcp_server.session_context import CURRENT_MCP_SESSION_ID, SESSION_CONTEXTS
from agentdecompile_cli.mcp_server.tool_providers import UnifiedToolProviderManager
from agentdecompile_cli.mcp_utils.debug_logger import DebugLogger

logger = logging.getLogger(__name__)
_TRUTHY_ENV_VALUES: frozenset[str] = frozenset({"true", "1", "yes", "on"})


def _auth_context_from_scope_headers(
    scope: dict[str, Any],
    auth_config: AuthConfig | None,
) -> AuthContext | None:
    """Derive best-effort shared-server defaults from MCP HTTP headers.

    This enables direct HTTP MCP clients to send the same accessor-style
    headers used by editor configs without requiring AuthMiddleware to be
    explicitly enabled. When AuthMiddleware is active, its context takes
    precedence and this helper is ignored.
    """
    if scope.get("type") != "http":
        return None

    auth_header = ""
    target_host = ""
    target_port_str = ""
    target_repo = ""
    agent_username = ""
    agent_password = ""
    agent_repo = ""

    for key_b, value_b in scope.get("headers", []):
        key = key_b.decode("latin1").lower()
        val = value_b.decode("latin1").strip()
        if key == "authorization":
            auth_header = val
        elif key == "x-ghidra-server-host":
            target_host = val
        elif key == "x-ghidra-server-port":
            target_port_str = val
        elif key == "x-ghidra-repository":
            target_repo = val
        elif key == "x-agent-server-username":
            agent_username = val
        elif key == "x-agent-server-password":
            agent_password = val
        elif key == "x-agent-server-repository":
            agent_repo = val

    if not target_repo and agent_repo:
        target_repo = agent_repo

    username = ""
    password = ""
    if auth_header.lower().startswith("basic "):
        try:
            username, password = parse_basic_auth(auth_header)
        except ValueError:
            logger.debug("Ignoring malformed Basic auth header while deriving request auth context")
    if not username and agent_username:
        username = agent_username
        password = agent_password

    try:
        server_port = int(target_port_str)
    except (TypeError, ValueError):
        server_port = auth_config.default_server_port if auth_config is not None else 13100

    server_host = target_host or ((auth_config.default_server_host or "") if auth_config is not None else "")
    repository = target_repo or ((auth_config.default_repository or "") if auth_config is not None else "")

    if not any([server_host, username, password, repository]):
        return None

    return AuthContext(
        username=username,
        password=password,
        server_host=server_host or None,
        server_port=server_port,
        repository=repository or None,
    )


class ServerConfig(BaseModel):
    """Configuration for the MCP server."""

    name: str = "AgentDecompile"
    version: str = "1.1.0"
    host: str = "127.0.0.1"
    port: int = 8080
    keep_alive_interval: int = 30
    tls_certfile: str | None = None
    """Path to TLS certificate file (PEM). Enables HTTPS when combined with tls_keyfile."""
    tls_keyfile: str | None = None
    """Path to TLS private key file (PEM). Enables HTTPS when combined with tls_certfile."""


class PythonMcpServer:
    """Python MCP Server implementation.

    Provides MCP interface running entirely in Python
    using PyGhidra for Ghidra integration.
    """

    def __init__(
        self,
        config: ServerConfig | None = None,
        auth_config: AuthConfig | None = None,
    ) -> None:
        self.config: ServerConfig = ServerConfig() if config is None else config
        self.auth_config: AuthConfig | None = auth_config
        self.app: FastAPI = FastAPI(
            title=self.config.name,
            version=self.config.version,
            description=(
                "AgentDecompile MCP server — exposes Ghidra reverse-engineering capabilities "
                "as Model Context Protocol tools for AI agents. "
                "MCP endpoint: `POST /mcp` (streamable-HTTP) or `POST /mcp/message` (SSE)."
            ),
            docs_url="/api/docs",
            redoc_url="/api/redoc",
            openapi_url="/api/openapi.json",
        )

        # Core components
        self.project_manager: ProjectManager | None = None
        self.program_info: ProgramInfo | None = None

        # MCP server components
        self.mcp_server: MCPServer = self._create_mcp_server()
        self.tool_providers: UnifiedToolProviderManager = UnifiedToolProviderManager()
        self.tool_providers.register_all_providers()
        self.resource_providers: ResourceProviderManager = ResourceProviderManager()

        # Keep server.program_info in sync when providers update it (e.g. checkout).
        self.tool_providers._on_program_info_changed = self._on_provider_program_info_changed

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
            call_args: dict[str, Any] = dict(arguments or {})
            call_args.setdefault("format", "markdown")
            # Don't pass the server's program_info here.  server.set_program_info()
            # already cascades to the manager at startup.  Passing a stale copy on
            # every call would revert updates made by tools (e.g. checkout from a
            # shared repository).  The manager tracks the latest program_info itself.
            return await self.tool_providers.call_tool(name, call_args)

        @server.list_resources()
        async def list_resources() -> list[types.Resource]:
            """List all available MCP resources."""
            return self.resource_providers.list_resources()

        @server.read_resource()  # pyright: ignore[reportArgumentType]
        async def read_resource(uri: str) -> str:
            """Read a resource by URI."""
            try:
                logger.info(f"MCP read_resource called with URI: {uri}")
                result = await self.resource_providers.read_resource(uri, self.program_info)
                logger.info(f"MCP read_resource succeeded for {uri}, returning {len(result)} bytes")
                return result
            except Exception as e:
                logger.error(f"MCP read_resource failed for {uri}: {e.__class__.__name__}: {e}", exc_info=True)
                # Return empty JSON object for failed resources instead of propagating exception
                # This prevents MCP protocol errors while still indicating failure
                return json.dumps({"error": f"{e.__class__.__name__}: {e}", "uri": str(uri), "status": "failed"})

        @server.list_prompts()
        async def list_prompts() -> list[types.Prompt]:
            """List all available MCP prompts."""
            # No prompts are currently implemented, return empty list
            return []

        return server

    # Paths that the MCP session handler should serve.
    _MCP_PATHS: frozenset[str] = frozenset({"/", "/mcp", "/mcp/message"})

    def _setup_routes(self) -> None:
        """Setup FastAPI routes for MCP communication.

        Uses an outer ASGI middleware to intercept ``/mcp`` and
        ``/mcp/message`` *before* Starlette's router so that all HTTP
        methods (POST, GET, DELETE) arrive at the MCP session handler
        with ``path="/"`` as the SDK expects.  Every other path
        (``/docs``, ``/redoc``, ``/openapi.json``, ``/health``) falls
        through to FastAPI's normal router.
        """

        @self.app.on_event("startup")
        async def _startup_session_manager() -> None:
            self._session_manager_cm = self._session_manager.run()
            await self._session_manager_cm.__aenter__()
            SESSION_CONTEXTS.start_reaper()

        @self.app.on_event("shutdown")
        async def _shutdown_session_manager() -> None:
            SESSION_CONTEXTS.stop_reaper()
            if self._session_manager_cm is not None:
                await self._session_manager_cm.__aexit__(None, None, None)  # pyright: ignore[reportGeneralTypeIssues]
                self._session_manager_cm = None

        @self.app.get("/health", tags=["meta"])
        async def health_check() -> dict[str, Any]:
            """Health check endpoint."""
            return {
                "status": "healthy" if self._running else "starting",
                "server": self.config.name,
                "version": self.config.version,
                "programs": (1 if self.program_info and self.program_info.program else 0),
                "sessions": SESSION_CONTEXTS.stats(),
            }

        @self.app.get("/api", tags=["meta"])
        async def api_info() -> dict[str, Any]:
            """API index — links to interactive documentation and transport endpoints."""
            return {
                "server": self.config.name,
                "version": self.config.version,
                "docs": {
                    "swagger_ui": "/api/docs",
                    "redoc": "/api/redoc",
                    "openapi_json": "/api/openapi.json",
                },
                "mcp": {
                    "streamable_http": "/mcp",
                    "sse_message": "/mcp/message",
                    "protocol": "Model Context Protocol (MCP) — JSON-RPC 2.0 over HTTP",
                },
                "health": "/health",
            }

        # Build the innermost ASGI handler: session-context → MCP SDK
        mcp_handle = self._session_manager.handle_request

        async def _mcp_asgi(scope: dict[str, Any], receive: Any, send: Any) -> None:
            """Propagate MCP session ID into ContextVar, bind fingerprint, then delegate."""
            session_id = "default"
            user_agent = ""
            remote_addr = ""
            if scope.get("type") == "http":
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

            # Capture which sessions exist before the SDK handles the request.
            pre_sessions = set(session_manager._server_instances.keys())

            auth_token = None
            if get_current_auth_context() is None:
                header_auth_ctx = _auth_context_from_scope_headers(scope, self.auth_config)
                if header_auth_ctx is not None:
                    auth_token = CURRENT_AUTH_CONTEXT.set(header_auth_ctx)

            token = CURRENT_MCP_SESSION_ID.set(session_id)
            try:
                await mcp_handle(scope, receive, send)
            finally:
                CURRENT_MCP_SESSION_ID.reset(token)
                if auth_token is not None:
                    CURRENT_AUTH_CONTEXT.reset(auth_token)

            # After the SDK processes the request, detect newly created sessions
            # and bind the client fingerprint for reconnection support.
            post_sessions = set(session_manager._server_instances.keys())
            new_sids = post_sessions - pre_sessions
            if new_sids and (user_agent or remote_addr):
                fingerprint = SESSION_CONTEXTS.compute_client_fingerprint(
                    user_agent=user_agent, remote_addr=remote_addr,
                )
                for new_sid in new_sids:
                    SESSION_CONTEXTS.bind_fingerprint(new_sid, fingerprint)

            # Detect sessions that disappeared (crashed/terminated) and evict to grace.
            removed_sids = pre_sessions - post_sessions
            for gone_sid in removed_sids:
                SESSION_CONTEXTS.evict_to_grace(gone_sid)

        # Optionally wrap with auth (experimental, off by default).
        mcp_app: Any = _mcp_asgi
        if self.auth_config is not None:
            mcp_app = AuthMiddleware(_mcp_asgi, self.auth_config)

        # Wrap the entire FastAPI app with an outer middleware that
        # intercepts MCP paths before Starlette's router sees them.
        inner_app = self.app  # the FastAPI ASGI app itself
        mcp_paths = self._MCP_PATHS
        session_manager = self._session_manager

        class _MCPRoutingMiddleware:
            """ASGI middleware: route /mcp and /mcp/message to the MCP handler.

            Before forwarding a request, this middleware validates the
            ``mcp-session-id`` header against the session manager's live
            session registry.  If the header references an expired or
            unknown session (e.g. after a server restart), the header is
            stripped so the SDK creates a fresh session.  When that new
            session is created, the grace-period context (if any) is
            migrated into it — preserving program state across brief
            client disconnections.
            """

            @staticmethod
            def _handle_stale_session(scope: dict[str, Any]) -> dict[str, Any]:
                """Handle a stale or unknown mcp-session-id.

                If the session is in the grace-period store, it will be
                reclaimed when the SDK creates the replacement session
                (handled in ``_mcp_asgi`` post-hook).  Either way, strip
                the stale header so the SDK creates a fresh transport.
                """
                raw_headers: list[tuple[bytes, bytes]] = scope.get("headers", [])
                for key_b, value_b in raw_headers:
                    if key_b.lower() == b"mcp-session-id":
                        sid = value_b.decode("latin1", errors="replace").strip()
                        if sid and sid not in session_manager._server_instances:
                            in_grace = sid in SESSION_CONTEXTS._grace
                            cleaned = [(k, v) for k, v in raw_headers if k.lower() != b"mcp-session-id"]
                            if in_grace:
                                logger.info(
                                    "Session %s not in SDK but in grace period — "
                                    "stripping header; state will be reclaimed on new session.",
                                    sid[:12],
                                )
                            else:
                                logger.info(
                                    "Stripped stale mcp-session-id %s — a new session will be created.",
                                    sid[:12],
                                )
                            return {**scope, "headers": cleaned}
                        break
                return scope

            async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
                if scope.get("type") == "http":
                    path = (scope.get("path") or "").rstrip("/") or "/"
                    if path in mcp_paths:
                        scope = self._handle_stale_session(scope)
                        rewritten = {**scope, "path": "/"}
                        await mcp_app(rewritten, receive, send)
                        return
                await inner_app(scope, receive, send)

        # Replace self.app so uvicorn serves the middleware-wrapped version.
        self.app = _MCPRoutingMiddleware()  # type: ignore[assignment]

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

    def _on_provider_program_info_changed(self, program_info: ProgramInfo) -> None:
        """Callback fired by the tool-provider manager when program_info changes.

        Keeps the server-level copy in sync so that resource providers and any
        other server-level consumers see the latest program.
        """
        self.program_info = program_info
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

    @staticmethod
    def _is_truthy_env(value: str | None) -> bool:
        if value is None:
            return False
        return value.strip().lower() in _TRUTHY_ENV_VALUES

    @staticmethod
    def _cleanup_provider(provider: Any, provider_name: str) -> None:
        """Run provider cleanup when available; log if provider is not set."""
        if provider is None:
            logger.warning("%s are not set! Cannot cleanup!", provider_name)
            return
        provider.cleanup()

    def start(self) -> int:
        """Start the MCP server.

        Returns the port the server is running on.
        """
        if self._running:
            logger.warning("Server is already running")
            return self.config.port

        if not self._is_port_available(self.config.host, self.config.port):
            raise RuntimeError(
                f"Port {self.config.port} on {self.config.host} is already in use. Use --port to specify a different port, or stop the other process.",
            )

        self._running = True
        self._shutdown_event.clear()

        # Enable debug logging if configured
        if self._is_truthy_env(os.getenv("AGENT_DECOMPILE_DEBUG")):
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

        logger.info("MCP server started on %s:%s", self.config.host, self.config.port)
        DebugLogger.debug_tool_execution(self, "server_startup", "SUCCESS", f"Server ready on port {self.config.port}")
        return self.config.port

    def _is_port_available(self, host: str, port: int) -> bool:
        """Return True when host:port can be bound by this process."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind((host, int(port)))
                return True
        except OSError:
            return False

    def _run_server(self) -> None:
        """Run the FastAPI server in a background thread."""
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
        config = uvicorn.Config(**uvicorn_kwargs)
        server = uvicorn.Server(config)

        try:
            # Run server until shutdown
            asyncio.run(server.serve())
        except Exception as e:
            logger.error("Server error: %s", e)
        finally:
            self._running = False

    def _is_server_ready(self) -> bool:
        """Check if the server is ready to accept connections."""
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

    def stop(self) -> None:
        """Stop the MCP server."""
        if not self._running:
            return

        logger.info("Stopping MCP server...")
        self._running = False
        self._shutdown_event.set()
        SESSION_CONTEXTS.stop_reaper()

        # Cleanup providers
        self._cleanup_provider(self.tool_providers, "Tool providers")
        self._cleanup_provider(self.resource_providers, "Resource providers")

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
