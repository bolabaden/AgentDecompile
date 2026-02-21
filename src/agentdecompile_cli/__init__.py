"""
AgentDecompile CLI - stdio MCP bridge for AgentDecompile Ghidra extension.

This package provides a command-line interface that bridges stdio MCP transport
to AgentDecompile's StreamableHTTP server, enabling seamless integration with Claude CLI.
Programmatic use: AgentDecompileMcpClient for async HTTP access to an existing server.
"""

try:
    from ._version import version as __version__
except ImportError:
    # Fallback version if not installed or in development without git tags
    __version__ = "0.0.0.dev0"

from agentdecompile_cli.client import (
    AgentDecompileMcpClient,
    ClientError,
    NotFoundError,
    ServerNotRunningError,
)
from agentdecompile_cli.utils import (
    get_client,
    get_server_start_message,
    handle_command_error,
    handle_noisy_mcp_errors,
    run_async,
    show_connection_error,
)

__all__ = [
    "__version__",
    "AgentDecompileMcpClient",
    "ClientError",
    "NotFoundError",
    "ServerNotRunningError",
    "get_client",
    "get_server_start_message",
    "handle_command_error",
    "handle_noisy_mcp_errors",
    "run_async",
    "show_connection_error",
]
