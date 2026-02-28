"""AgentDecompile CLI - stdio MCP bridge for AgentDecompile Ghidra extension.

This package provides a command-line interface that bridges stdio MCP transport
to AgentDecompile's StreamableHTTP server, enabling seamless integration with Claude CLI.
Programmatic use: AgentDecompileMcpClient for async HTTP access to an existing server.

Tool and resource names: use agentdecompile_cli.tools_schema (TOOLS,
RESOURCE_URIS, build_tool_payload, RESOURCE_URI_*).
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
    TOOLS,
    TOOL_PARAMS,
    build_tool_payload,
    get_tool_params,
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
    "ServerNotRunningError",
    "__version__",
    "build_tool_payload",
    "get_client",
    "get_server_start_message",
    "get_tool_params",
    "handle_command_error",
    "handle_noisy_mcp_errors",
    "run_async",
    "show_connection_error",
    "to_camel_case_key",
]
