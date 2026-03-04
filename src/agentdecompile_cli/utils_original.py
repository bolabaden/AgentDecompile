"""Legacy utility compatibility exports.

The canonical implementations live in ``agentdecompile_cli.executor``.
This module preserves old import paths without duplicating logic.
"""

from __future__ import annotations

from agentdecompile_cli.executor import (
    build_backend_url,
    format_output,
    get_client,
    get_server_start_message,
    handle_command_error,
    handle_noisy_mcp_errors,
    normalize_backend_url,
    resolve_backend_url,
    run_async,
    show_connection_error,
)

__all__ = [
    "build_backend_url",
    "format_output",
    "get_client",
    "get_server_start_message",
    "handle_command_error",
    "handle_noisy_mcp_errors",
    "normalize_backend_url",
    "resolve_backend_url",
    "run_async",
    "show_connection_error",
]
