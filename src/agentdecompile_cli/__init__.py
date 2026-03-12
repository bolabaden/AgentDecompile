"""AgentDecompile CLI - stdio MCP bridge for AgentDecompile Ghidra extension.

This package provides a command-line interface that bridges stdio MCP transport
to AgentDecompile's StreamableHTTP server, enabling seamless integration with Claude CLI.
Programmatic use: AgentDecompileMcpClient for async HTTP access to an existing server.

Package layout:
  - bridge: HTTP client (AgentDecompileMcpClient), stdio bridge, MCP session fix.
  - registry: Tool names (Tool enum), normalization, TOOLS, TOOL_PARAMS, resource URIs.
  - executor: run_async(), get_client(), error handling, backend URL resolution.
  - launcher: PyGhidra init, ProjectManager, AgentDecompileLauncher (see launcher.py).
  - mcp_server: FastMCP server, ToolProviderManager, providers/*, resources, prompts.

Tool and resource names: use agentdecompile_cli.registry (TOOLS, RESOURCE_URIS,
build_tool_payload, get_tool_params, resolve_tool_name_enum).
"""

try:
    from ._version import version as __version__
except ImportError:
    # Fallback version if not installed or in development without git tags
    __version__ = "0.0.0.dev0"

from agentdecompile_cli.bridge import (
    AgentDecompileMcpClient,
    ClientError,
    NotFoundError,
    ServerNotRunningError,
)
from agentdecompile_cli.registry import (
    RESOURCE_URI_DEBUG_INFO,
    RESOURCE_URI_PROGRAMS,
    RESOURCE_URI_STATIC_ANALYSIS,
    RESOURCE_URIS,
    ResourceUri,
    Tool,
    ToolName,
    TOOLS,
    TOOL_PARAMS,
    build_tool_payload,
    get_tool_params,
    resolve_tool_name_enum,
    to_camel_case_key,
)
from agentdecompile_cli.executor import (
    get_client,
    get_server_start_message,
    handle_command_error,
    handle_noisy_mcp_errors,
    run_async,
    show_connection_error,
)

__all__ = [
    "RESOURCE_URIS",
    "RESOURCE_URI_DEBUG_INFO",
    "RESOURCE_URI_PROGRAMS",
    "RESOURCE_URI_STATIC_ANALYSIS",
    "TOOLS",
    "TOOL_PARAMS",
    "AgentDecompileMcpClient",
    "ClientError",
    "NotFoundError",
    "ResourceUri",
    "ServerNotRunningError",
    "Tool",
    "ToolName",
    "__version__",
    "build_tool_payload",
    "get_client",
    "get_server_start_message",
    "get_tool_params",
    "handle_command_error",
    "handle_noisy_mcp_errors",
    "resolve_tool_name_enum",
    "run_async",
    "show_connection_error",
    "to_camel_case_key",
]
