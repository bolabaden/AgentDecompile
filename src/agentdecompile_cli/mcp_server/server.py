"""Python MCP Server implementation (FastAPI + Streamable HTTP).

This module wires the MCP Python SDK (Server, StreamableHTTPSessionManager) to FastAPI
so that AgentDecompile can be reached over HTTP (e.g. by the stdio bridge or external clients).
Flow: HTTP request → StreamableHTTPSessionManager handles MCP protocol → server routes
tools/list, tools/call, resources/*, prompts/* → ToolProviderManager / ResourceProviderManager.
Session and auth context are set per-request so tools and resources see the correct
program/session. Standalone server entry point is launcher.start() (see launcher.py).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import socket
import threading
import time

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any

from fastapi import FastAPI
from mcp.server import Server, Server as MCPServer
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from pydantic import BaseModel

from agentdecompile_cli.mcp_server import prompt_providers
from agentdecompile_cli.mcp_server.auth import (
    CURRENT_AUTH_CONTEXT,
    AuthContext,
    AuthMiddleware,
    get_current_auth_context,
    parse_basic_auth,
)
from agentdecompile_cli.mcp_server.resource_providers import ResourceProviderManager
from agentdecompile_cli.mcp_server.session_context import (
    CURRENT_MCP_SESSION_ID,
    CURRENT_REQUEST_AUTO_MATCH_PROPAGATE,
    CURRENT_REQUEST_AUTO_MATCH_TARGET_PATHS,
    CURRENT_REQUEST_PROJECT_PATH_OVERRIDE,
    SESSION_CONTEXTS,
)
from agentdecompile_cli.mcp_server.tool_providers import UnifiedToolProviderManager
from agentdecompile_cli.mcp_utils.debug_logger import DebugLogger
from agentdecompile_cli.registry import ADVERTISED_TOOLS, TOOLS, TOOL_ALIASES, Tool, get_tool_params

if TYPE_CHECKING:
    from contextvars import Token

    from mcp import types
    from mcp.server import Server as MCPServer

    from agentdecompile_cli.launcher import ProgramInfo
    from agentdecompile_cli.project_manager import ProjectManager
    from agentdecompile_cli.mcp_server.auth import (
        AuthConfig,
    )

logger = logging.getLogger(__name__)
_TRUTHY_ENV_VALUES: frozenset[str] = frozenset({"true", "1", "yes", "on"})


def _safe_list(value: Any) -> list[Any]:
    """Ensure value is a list for JSON/response building; return empty list if not."""
    return value if isinstance(value, list) else []


def _build_tool_alias_index() -> dict[str, list[str]]:
    """Build canonical tool name → sorted list of alias names for the /tool-reference payload."""
    alias_index: dict[str, list[str]] = {canonical: [] for canonical in TOOLS}
    for alias_name, canonical_name in TOOL_ALIASES.items():
        if canonical_name not in alias_index:
            alias_index[canonical_name] = []
        if alias_name != canonical_name:
            alias_index[canonical_name].append(alias_name)
    for canonical_name, aliases in alias_index.items():
        alias_index[canonical_name] = sorted(set(aliases))
    return alias_index


def _build_tool_reference_payload() -> dict[str, Any]:
    alias_index = _build_tool_alias_index()
    canonical_tools: list[dict[str, Any]] = []
    for canonical_name in sorted(TOOLS):
        params = [str(param) for param in get_tool_params(canonical_name)]
        canonical_tools.append(
            {
                "name": canonical_name,
                "advertised": canonical_name in ADVERTISED_TOOLS,
                "parameters": params,
                "aliases": alias_index.get(canonical_name, []),
            },
        )

    return {
        "summary": {
            "canonical_tool_count": len(TOOLS),
            "advertised_tool_count": len(ADVERTISED_TOOLS),
            "alias_count": sum(len(item["aliases"]) for item in canonical_tools),
        },
        "transport": {
            "canonical_endpoint": "/mcp",
            "compatibility_endpoint": "/mcp/message",
            "notes": [
                "Use /mcp as the canonical MCP streamable-HTTP route.",
                "Use /mcp/message only for compatibility with clients that hardcode that path.",
                "Standalone CLI calls are session-isolated; use tool-seq to keep state in one session.",
            ],
        },
        "shared_server_headers": {
            "authorization": "Basic <base64(username:password)>",
            "x-ghidra-server-host": "Shared Ghidra server host",
            "x-ghidra-server-port": "Shared Ghidra server port (usually 13100)",
            "x-ghidra-repository": "Shared repository name",
            "x-agent-server-username": "Optional username alias header",
            "x-agent-server-password": "Optional password alias header",
            "x-agent-server-repository": "Optional repository alias header",
        },
        "shared_server_http_mapping": {
            "request_url": {
                "env": "AGENT_DECOMPILE_MCP_SERVER_URL",
                "usage": "Request URL itself, typically http://host:port/mcp",
            },
            "env_to_headers": {
                "AGENT_DECOMPILE_GHIDRA_SERVER_HOST": ["X-Ghidra-Server-Host"],
                "AGENT_DECOMPILE_GHIDRA_SERVER_PORT": ["X-Ghidra-Server-Port"],
                "AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY": ["X-Ghidra-Repository", "X-Agent-Server-Repository"],
                "AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME": ["Authorization", "X-Agent-Server-Username"],
                "AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD": ["Authorization", "X-Agent-Server-Password"],
            },
            "transport_headers": {
                "content-type": "application/json",
                "accept": "application/json, text/event-stream",
                "mcp-session-id": "Send on follow-up requests after the server returns it",
            },
            "precedence": {
                "credentials": ["Authorization", "X-Agent-Server-Username/X-Agent-Server-Password"],
                "repository": ["X-Ghidra-Repository", "X-Agent-Server-Repository"],
            },
        },
        "environment_variables": {
            "shared_server": [
                "AGENT_DECOMPILE_GHIDRA_SERVER_HOST",
                "AGENT_DECOMPILE_GHIDRA_SERVER_PORT",
                "AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME",
                "AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD",
                "AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY",
            ],
            "local_project": [
                "AGENT_DECOMPILE_PROJECT_PATH",
                "AGENT_DECOMPILE_PROJECT_NAME",
            ],
            "tool_advertisement": [
                "AGENTDECOMPILE_ENABLE_TOOLS",
                "AGENTDECOMPILE_DISABLE_TOOLS",
                "AGENTDECOMPILE_ENABLE_LEGACY_TOOLS",
                "AGENTDECOMPILE_SHOW_LEGACY_TOOLS",
            ],
        },
        "canonical_tools": canonical_tools,
    }


def _mcp_post_openapi_extra() -> dict[str, Any]:
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
                                    "prompts/list",
                                ],
                            },
                            "params": {"type": "object", "additionalProperties": True},
                        },
                        "additionalProperties": True,
                    },
                    "examples": {
                        "initialize": {
                            "summary": "Initialize MCP session",
                            "value": {
                                "jsonrpc": "2.0",
                                "id": 1,
                                "method": "initialize",
                                "params": {
                                    "protocolVersion": "2025-11-25",
                                    "capabilities": {},
                                    "clientInfo": {"name": "docs-client", "version": "1.0"},
                                },
                            },
                        },
                        "tools_list": {
                            "summary": "List currently advertised tools",
                            "value": {
                                "jsonrpc": "2.0",
                                "id": 2,
                                "method": "tools/list",
                                "params": {},
                            },
                        },
                        "tools_call_open_project_shared": {
                            "summary": "Open a shared-server program",
                            "value": {
                                "jsonrpc": "2.0",
                                "id": 3,
                                "method": "tools/call",
                                "params": {
                                    "name": Tool.OPEN.value,
                                    "arguments": {
                                        "path": "/K1/k1_win_gog_swkotor.exe",
                                        "serverHost": "<ghidra-host>",
                                        "serverPort": 13100,
                                        "serverUsername": "<username>",
                                        "serverPassword": "<password>",
                                        "format": "json",
                                    },
                                },
                            },
                        },
                        "tools_call_references": {
                            "summary": "Get references to WinMain",
                            "value": {
                                "jsonrpc": "2.0",
                                "id": 4,
                                "method": "tools/call",
                                "params": {
                                    "name": Tool.GET_REFERENCES.value,
                                    "arguments": {
                                        "programPath": "/K1/k1_win_gog_swkotor.exe",
                                        "target": "WinMain",
                                        "direction": "to",
                                        "limit": 25,
                                        "format": "json",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        "responses": {
            "200": {
                "description": "JSON-RPC response envelope. Tool-level failures may appear as semantic errors in successful MCP responses.",
                "content": {
                    "application/json": {
                        "examples": {
                            "success": {
                                "summary": "Successful JSON-RPC result",
                                "value": {
                                    "jsonrpc": "2.0",
                                    "id": 2,
                                    "result": {"tools": [{"name": Tool.OPEN.value}]},
                                },
                            },
                            "error": {
                                "summary": "JSON-RPC transport or validation error",
                                "value": {
                                    "jsonrpc": "2.0",
                                    "id": 3,
                                    "error": {
                                        "code": -32602,
                                        "message": "Invalid params",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
    }


# Session cookie name (no hyphen); used for cookie-based session id (header wins over cookie).
_MCP_SESSION_COOKIE_NAME = "mcp_session_id"
# Allow "default" or a single token: alphanumeric, hyphen, underscore, 1–128 chars (MCP visible ASCII).
_SESSION_ID_VALID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,128}$")


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


def _validate_session_id(value: str) -> str:
    """Return value if it is a valid session id; otherwise return 'default'.

    Allows literal 'default' or a token matching [a-zA-Z0-9_-]{1,128}.
    Rejects empty, newlines, path-like, or overlength to avoid injection.
    """
    if not value or "\n" in value or "\r" in value or "/" in value or "\\" in value:
        return "default"
    if value == "default":
        return value
    if _SESSION_ID_VALID_RE.match(value):
        return value
    return "default"


def _make_session_cookie_header(session_id: str, secure: bool) -> tuple[bytes, bytes]:
    """Build Set-Cookie header value for mcp_session_id (HttpOnly, SameSite=Lax)."""
    # Path=/; HttpOnly; SameSite=Lax; optionally Secure (only over TLS or SESSION_COOKIE_SECURE)
    value = f"{_MCP_SESSION_COOKIE_NAME}={session_id}; Path=/; HttpOnly; SameSite=Lax"
    if secure:
        value += "; Secure"
    return (b"set-cookie", value.encode("latin1"))


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

    auth_header: str = ""
    target_host: str = ""
    target_port_str: str = ""
    target_repo: str = ""
    agent_username: str = ""
    agent_password: str = ""
    agent_repo: str = ""

    key_b: bytes
    value_b: bytes
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

    username: str = ""
    password: str = ""
    if auth_header.lower().startswith("basic "):
        try:
            username, password = parse_basic_auth(auth_header)
        except ValueError:
            logger.debug("Ignoring malformed Basic auth header while deriving request auth context")
    if not username and agent_username:
        username = agent_username
        password = agent_password

    try:
        server_port: int = int(target_port_str)
    except (TypeError, ValueError):
        server_port = auth_config.default_server_port if auth_config is not None else 13100

    server_host: str = target_host or ((auth_config.default_server_host or "") if auth_config is not None else "")
    repository: str = target_repo or ((auth_config.default_repository or "") if auth_config is not None else "")

    if not any((server_host, username, password, repository)):
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
            description=("AgentDecompile MCP server — exposes Ghidra reverse-engineering capabilities as Model Context Protocol tools for AI agents. MCP endpoint: `POST /mcp` (streamable-HTTP) or `POST /mcp/message` (SSE)."),
            docs_url="/docs",
            redoc_url="/redoc",
            openapi_url="/openapi.json",
        )

        # Core components
        self.project_manager: ProjectManager | None = None
        self.program_info: ProgramInfo | None = None

        # MCP server components
        self.mcp_server: MCPServer = self._create_mcp_server()
        self.tool_providers: UnifiedToolProviderManager = UnifiedToolProviderManager()
        self.tool_providers.register_all_providers()
        self.resource_providers: ResourceProviderManager = ResourceProviderManager()
        self.resource_providers.set_tool_provider_manager(self.tool_providers)

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
        self._session_manager_cm: Any | None = None

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
                logger.info("MCP read_resource called with URI: %s", uri)
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
            return prompt_providers.list_prompts()

        return server

    # Paths that the MCP session handler should serve.
    _MCP_PATHS: frozenset[str] = frozenset({"/mcp", "/mcp/message"})

    @staticmethod
    async def _mcp_openapi_stub() -> dict[str, Any]:
        """Schema-only MCP route stub.

        Runtime requests are intercepted by the outer ASGI middleware before
        FastAPI routing, but these explicit route registrations keep `/mcp`
        and `/mcp/message` visible in the generated OpenAPI schema.
        """
        return {
            "detail": "MCP requests are handled by the outer transport middleware before FastAPI routing.",
        }

    def _setup_routes(self) -> None:
        """Setup FastAPI routes for MCP communication.

        Uses an outer ASGI middleware to intercept ``/mcp`` and ``/mcp/message`` *before*
        Starlette's router so that all HTTP methods (POST, GET, DELETE) arrive at
        the MCP session handler with ``path="/"`` as the SDK expects.
        
        Every other path (``/docs``, ``/redoc``, ``/openapi.json``, ``/health``) falls
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
            """Comprehensive MCP usage, auth, and tool reference summary."""
            return {
                "documentation": {
                    "openapi": "/openapi.json",
                    "swagger_ui": "/docs",
                    "redoc": "/redoc",
                    "tool_reference": "/api/tool-reference",
                    "usage_examples": "/api/usage-examples",
                },
                "transport": {
                    "canonical": "/mcp",
                    "compatibility": "/mcp/message",
                    "json_rpc_methods": [
                        "initialize",
                        "tools/list",
                        "tools/call",
                        "resources/list",
                        "resources/read",
                        "prompts/list",
                    ],
                },
                "auth_and_shared_project": {
                    "headers": {
                        "authorization": "Basic <base64(username:password)>",
                        "x-ghidra-server-host": "Shared Ghidra host",
                        "x-ghidra-server-port": "Shared Ghidra port",
                        "x-ghidra-repository": "Shared repository name",
                        "x-agent-server-username": "Accepted username alias header",
                        "x-agent-server-password": "Accepted password alias header",
                        "x-agent-server-repository": "Accepted repository alias header",
                    },
                    "env": {
                        "mcp_server_url": "AGENT_DECOMPILE_MCP_SERVER_URL (request URL, not a header)",
                        "host": "AGENT_DECOMPILE_GHIDRA_SERVER_HOST",
                        "port": "AGENT_DECOMPILE_GHIDRA_SERVER_PORT",
                        "username": "AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME",
                        "password": "AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD",
                        "repository": "AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY",
                    },
                    "transport_headers": {
                        "content-type": "application/json",
                        "accept": "application/json, text/event-stream",
                        "mcp-session-id": "Send on follow-up requests after the server returns it",
                    },
                    "precedence": {
                        "credentials": ["authorization", "x-agent-server-username/x-agent-server-password"],
                        "repository": ["x-ghidra-repository", "x-agent-server-repository"],
                    },
                },
                "session_behavior": {
                    "cli": "Standalone CLI invocations are stateless across commands.",
                    "tool_seq": "Use tool-seq to keep open/import/query steps in one MCP session.",
                },
            }

        @self.app.get("/api/tool-reference", tags=["reference"])
        async def tool_reference() -> dict[str, Any]:
            """List canonical tools, advertised subset, parameters, and aliases."""
            return _build_tool_reference_payload()

        @self.app.get("/api/usage-examples", tags=["reference"])
        async def usage_examples() -> dict[str, Any]:
            """Curated command and payload examples for common local and shared workflows."""
            return {
                "local": {
                    "start_server": "uv run agentdecompile-server -t streamable-http --host 127.0.0.1 --port 8080 --project-path ./agentdecompile_projects",
                    "list_tools": "uv run agentdecompile-cli --mcp-server-url http://127.0.0.1:8080/mcp tool --list-tools",
                    "tool_seq": f'uv run agentdecompile-cli --mcp-server-url http://127.0.0.1:8080/mcp tool-seq \'[{{"name":"{Tool.OPEN.value}","arguments":{{"path":"tests/fixtures/test_x86_64"}}}},{{"name":"{Tool.LIST_FUNCTIONS.value}","arguments":{{"programPath":"test_x86_64","limit":5}}}}]\'',
                },
                "shared": {
                    "open": "uv run agentdecompile-cli --mcp-server-url http://host:port/mcp open --server_host $Env:AGENT_DECOMPILE_GHIDRA_SERVER_HOST --server_port $Env:AGENT_DECOMPILE_GHIDRA_SERVER_PORT --server_username $Env:AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME --server_password $Env:AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD /K1/k1_win_gog_swkotor.exe",
                    "raw_tool": '{"jsonrpc":"2.0","id":101,"method":"tools/call","params":{"name":"get-references","arguments":{"programPath":"/K1/k1_win_gog_swkotor.exe","target":"WinMain","direction":"to","limit":25,"format":"json"}}}',
                },
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
                summary="MCP Streamable HTTP endpoint",
                description=(
                    "Canonical MCP streamable-HTTP endpoint. "
                    "Use POST for JSON-RPC methods such as initialize, tools/list, tools/call, "
                    "resources/list, and resources/read. Runtime traffic is intercepted "
                    "by the outer MCP middleware before FastAPI routing. "
                    "For complete tool contracts and aliases, see /api/tool-reference and /api/usage-examples."
                ),
                operation_id=f"mcp_streamable_{method.lower()}",
                openapi_extra=_mcp_post_openapi_extra() if method == "POST" else None,
                include_in_schema=True,
            )
            self.app.add_api_route(
                "/mcp/message",
                self._mcp_openapi_stub,
                methods=[method],
                tags=["mcp"],
                summary="MCP message compatibility endpoint",
                description=(
                    "Compatibility MCP endpoint for clients that target /mcp/message. Prefer /mcp for new integrations. Runtime traffic is intercepted by the outer MCP middleware before FastAPI routing."
                ),
                operation_id=f"mcp_message_{method.lower()}",
                openapi_extra=_mcp_post_openapi_extra() if method == "POST" else None,
                include_in_schema=True,
            )

        # Build the innermost ASGI handler: session-context → MCP SDK
        mcp_handle = self._session_manager.handle_request

        async def _mcp_asgi(scope: dict[str, Any], receive: Any, send: Any) -> None:
            """Propagate MCP session ID into ContextVar, bind fingerprint, then delegate."""
            # When no session id is provided (no mcp-session-id header, no session cookie),
            # use the single default session so multiple requests (e.g. sequential CLI
            # invocations) reuse the same session without the client persisting a session id.
            session_id: str = "default"
            user_agent: str = ""
            remote_addr: str = ""
            project_path_override: str | None = None
            auto_match_propagate: str | None = None
            auto_match_target_paths: str | None = None
            request_scheme: str = "http"
            if scope.get("type") == "http":
                request_scheme = scope.get("scheme", "http")
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
                    elif header_name == "x-agentdecompile-project-path":
                        raw = value_b.decode("latin1").strip()
                        project_path_override = raw.replace("\\", "/") if raw else None
                    elif header_name == "x-agentdecompile-auto-match-propagate":
                        auto_match_propagate = value_b.decode("latin1").strip() or None
                    elif header_name == "x-agentdecompile-auto-match-target-paths":
                        auto_match_target_paths = value_b.decode("latin1").strip() or None
                client_info: tuple[int, int] | None = scope.get("client")
                if client_info:
                    remote_addr = str(client_info[0]) if isinstance(client_info, (list, tuple)) else ""
                # Resolution order: header (already set) → cookie → default. If no header, try cookie.
                if session_id == "default":
                    cookie_sid = _parse_mcp_session_cookie_from_scope(scope)
                    if cookie_sid:
                        session_id = cookie_sid
                session_id = _validate_session_id(session_id)

            # Capture which sessions exist before the SDK handles the request.
            pre_sessions: set[str] = set(session_manager._server_instances.keys())

            # Set context vars so tool/resource handlers see this request's session (and optional auth)
            auth_token: Token[AuthContext | None] | None = None
            if get_current_auth_context() is None:
                header_auth_ctx = _auth_context_from_scope_headers(scope, self.auth_config)
                if header_auth_ctx is not None:
                    auth_token = CURRENT_AUTH_CONTEXT.set(header_auth_ctx)

            token: Token[str] = CURRENT_MCP_SESSION_ID.set(session_id)
            project_path_token: Token[str | None] | None = None
            auto_match_propagate_token: Token[str | None] | None = None
            auto_match_target_paths_token: Token[str | None] | None = None
            if project_path_override:
                project_path_token = CURRENT_REQUEST_PROJECT_PATH_OVERRIDE.set(project_path_override)
            if auto_match_propagate is not None:
                auto_match_propagate_token = CURRENT_REQUEST_AUTO_MATCH_PROPAGATE.set(auto_match_propagate)
            if auto_match_target_paths is not None:
                auto_match_target_paths_token = CURRENT_REQUEST_AUTO_MATCH_TARGET_PATHS.set(auto_match_target_paths)

            # Inject mcp-session-id in response so CLI can persist and resend it (two-command session persistence)
            session_id_for_response: str = session_id
            response_start_sent: list[bool] = [False]

            # Secure cookie only over TLS or when SESSION_COOKIE_SECURE is set (e.g. behind TLS terminator).
            cookie_secure: bool = (
                request_scheme == "https"
                or os.environ.get("SESSION_COOKIE_SECURE", "").lower() in ("1", "true", "yes")
            )

            async def send_wrapper(message: dict[str, Any]) -> None:
                if message.get("type") == "http.response.start" and not response_start_sent[0]:
                    response_start_sent[0] = True
                    headers: list[tuple[bytes, bytes]] = list(message.get("headers", []))
                    key_lower = b"mcp-session-id"
                    existing_sid: bytes | None = None
                    for k, v in headers:
                        if k.lower() == key_lower:
                            existing_sid = v
                            break
                    # Prefer SDK-provided session ID (e.g. new UUID) so client can resend it; else echo request id
                    headers = [(k, v) for k, v in headers if k.lower() != key_lower]
                    headers.append(
                        (key_lower, (existing_sid if existing_sid else session_id_for_response.encode("latin1")))
                    )
                    # Set-Cookie for session so clients (e.g. browser or CLI with cookie jar) can resend it.
                    if session_id_for_response != "default":
                        headers.append(_make_session_cookie_header(session_id_for_response, cookie_secure))
                    message = {**message, "headers": headers}
                await send(message)

            try:
                await mcp_handle(scope, receive, send_wrapper)  # pyright: ignore[reportArgumentType]
            finally:
                CURRENT_MCP_SESSION_ID.reset(token)
                if project_path_token is not None:
                    CURRENT_REQUEST_PROJECT_PATH_OVERRIDE.reset(project_path_token)
                if auto_match_propagate_token is not None:
                    CURRENT_REQUEST_AUTO_MATCH_PROPAGATE.reset(auto_match_propagate_token)
                if auto_match_target_paths_token is not None:
                    CURRENT_REQUEST_AUTO_MATCH_TARGET_PATHS.reset(auto_match_target_paths_token)
                if auth_token is not None:
                    CURRENT_AUTH_CONTEXT.reset(auth_token)

            # After the SDK processes the request, detect newly created sessions
            # and bind the client fingerprint for reconnection support.
            post_sessions: set[str] = set(session_manager._server_instances.keys())
            new_sids: set[str] = post_sessions - pre_sessions
            if new_sids and (user_agent or remote_addr):
                fingerprint: str = SESSION_CONTEXTS.compute_client_fingerprint(
                    user_agent=user_agent,
                    remote_addr=remote_addr,
                )
                for new_sid in new_sids:
                    SESSION_CONTEXTS.bind_fingerprint(new_sid, fingerprint)

            # Detect sessions that disappeared (crashed/terminated) and evict to grace.
            removed_sids: set[str] = pre_sessions - post_sessions
            for gone_sid in removed_sids:
                SESSION_CONTEXTS.evict_to_grace(gone_sid)

        # Optionally wrap with auth (experimental, off by default).
        mcp_app: Callable[[dict[str, Any], Any, Any], Awaitable[None]] = _mcp_asgi
        if self.auth_config is not None:
            mcp_app = AuthMiddleware(_mcp_asgi, self.auth_config)

        # Wrap the entire FastAPI app with an outer middleware that
        # intercepts MCP paths before Starlette's router sees them.
        inner_app: FastAPI = self.app  # the FastAPI ASGI app itself
        mcp_paths: frozenset[str] = self._MCP_PATHS
        session_manager: StreamableHTTPSessionManager = self._session_manager

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
                key_b: bytes
                value_b: bytes
                for key_b, value_b in raw_headers:
                    if key_b.lower() == b"mcp-session-id":
                        sid = value_b.decode("latin1", errors="replace").strip()
                        if sid and sid not in session_manager._server_instances:
                            in_grace = sid in SESSION_CONTEXTS._grace
                            cleaned = [(k, v) for k, v in raw_headers if k.lower() != b"mcp-session-id"]
                            if in_grace:
                                logger.info(
                                    "Session %s not in SDK but in grace period — stripping header; state will be reclaimed on new session.",
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

            async def __call__(
                self,
                scope: dict[str, Any],
                receive: Any,
                send: Any,
            ) -> None:
                if scope.get("type") == "http":
                    path = (scope.get("path") or "").rstrip("/") or "/"
                    if path in mcp_paths:
                        scope = self._handle_stale_session(scope)
                        rewritten: dict[str, Any] = {**scope, "path": "/"}
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

    def set_runtime_context(self, runtime_context: dict[str, Any]) -> None:
        """Set server startup/runtime context for resources and diagnostics."""
        self.resource_providers.set_runtime_context(runtime_context)

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
