"""Backward-compatible MCP client exports.

The canonical implementation lives in ``agentdecompile_cli.bridge``.
This module remains import-stable for legacy code.
"""

from __future__ import annotations

from agentdecompile_cli.bridge import (
    AgentDecompileMcpClient,
    ClientError,
    NotFoundError,
    ServerNotRunningError,
)

__all__ = [
    "AgentDecompileMcpClient",
    "ClientError",
    "NotFoundError",
    "ServerNotRunningError",
]
