"""Shared CLI utilities."""

from __future__ import annotations

import asyncio
import json as _json
import os
import sys

from typing import Any
from urllib.parse import urlparse, urlunparse


def get_server_start_message() -> str:
    """Return the standardized server start message."""
    return (
        "Please start the server first.\n\n"
        "Connect to an existing AgentDecompile MCP server:\n\n"
        "  mcp-agentdecompile --server-url http://host:port\n"
        "  mcp-agentdecompile --host 127.0.0.1 --port 8080\n"
        "  AGENT_DECOMPILE_MCP_SERVER_URL=http://host:port mcp-agentdecompile\n"
        "  AGENT_DECOMPILE_SERVER_HOST=host AGENT_DECOMPILE_SERVER_PORT=8080 mcp-agentdecompile\n\n"
        "Or run Ghidra with AgentDecompile enabled and use the URL from File > Edit Tool Options > AgentDecompile."
    )


def build_backend_url(host: str, port: int, use_tls: bool = False) -> str:
    """Build MCP backend URL from host and port (for connect mode)."""
    scheme = "https" if use_tls else "http"
    return f"{scheme}://{host}:{port}"


def normalize_backend_url(value: str) -> str:
    """Normalize a backend URL or host[:port] into a full MCP message endpoint URL."""
    raw = value.strip()
    if not raw:
        raise ValueError("Backend URL cannot be empty")
    if "://" not in raw:
        raw = f"http://{raw}"
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(
            f"Unsupported URL scheme '{parsed.scheme}'. Use http:// or https://.",
        )
    if not parsed.netloc:
        raise ValueError("Backend URL must include a host")
    path = parsed.path or ""
    if not path or path == "/":
        path = "/mcp/message"
    elif not path.endswith("/mcp/message"):
        path = f"{path.rstrip('/')}/mcp/message"
    return urlunparse(parsed._replace(path=path))


def resolve_backend_url(
    server_url: str | None,
    host: str | None,
    port: int | None,
    env_url_keys: tuple[str, ...] = (
        "AGENT_DECOMPILE_MCP_SERVER_URL",
        "AGENT_DECOMPILE_SERVER_URL",
    ),
    env_host_key: str = "AGENT_DECOMPILE_SERVER_HOST",
    env_port_key: str = "AGENT_DECOMPILE_SERVER_PORT",
    default_host: str = "127.0.0.1",
    default_port: int = 8080,
) -> str | None:
    """Resolve backend URL for connect mode.

    Priority: explicit server_url > env URL > host+port (cli or env).
    Returns None if no connect-mode option is set.
    """
    if server_url and server_url.strip():
        return server_url.strip()
    for key in env_url_keys:
        val = os.getenv(key)
        if val and val.strip():
            return val.strip()
    h = host or os.getenv(env_host_key)
    p = port
    if p is None:
        try:
            p = int(os.getenv(env_port_key, "") or default_port)
        except ValueError:
            p = default_port
    if h is not None and h.strip():
        return build_backend_url(h.strip(), p)
    if os.getenv(env_port_key) is not None:
        return build_backend_url(default_host, p)
    return None


def format_output(data: Any, fmt: str, verbose: bool = False) -> str:
    """Format data for human-readable output.

    fmt: 'json' | 'table' | 'text'
    """
    if fmt == "json":
        return _json.dumps(data, indent=2)
    if fmt == "text":
        if isinstance(data, dict):
            return "\n".join(f"{k}: {v}" for k, v in data.items())
        if isinstance(data, list):
            return "\n".join(f"- {item}" for item in data)
        return str(data)
    if fmt == "table":
        if isinstance(data, list) and data and isinstance(data[0], dict):
            headers = list(data[0].keys())
            lines = [" | ".join(headers), "-" * (len(headers) * 10)]
            for item in data:
                row = [str(item.get(h, "")) for h in headers]
                lines.append(" | ".join(row))
            return "\n".join(lines)
        return str(data)
    return str(data)


def handle_noisy_mcp_errors(error_msg: str) -> bool:
    """Check if error_msg contains noisy MCP/async cleanup patterns and handle them.

    Returns True if the error was handled (was noisy), False otherwise.
    """
    noisy_patterns: list[str] = [
        "aclose()",
        "anyio.WouldBlock",
        "async_generator",
        "asynchronous generator is already running",
        "Attempted to exit cancel scope",
        "CancelledError: Cancelled by cancel scope",
        "Exception Group",
        "GeneratorExit",
        "unhandled errors in a TaskGroup",
    ]
    if not any(pattern in error_msg for pattern in noisy_patterns):
        return False
    if "ServerNotRunningError" in error_msg or "Cannot connect" in error_msg:
        for line in error_msg.split("\n"):
            line = line.strip()
            if "Cannot connect" in line or "AgentDecompile" in line:
                sys.stderr.write(f"Error: {line}\n")
                return True
    if any(p in error_msg.lower() for p in ["connection", "connect", "refused", "failed"]):
        show_connection_error()
        return True
    sys.stderr.write(
        "Error: An error occurred. Please ensure the AgentDecompile backend is running.\n",
    )
    return True


def show_connection_error() -> None:
    """Display a standardized connection error message to stderr."""
    sys.stderr.write(
        f"Error: Cannot connect to AgentDecompile backend.\n\n{get_server_start_message()}\n",
    )


def run_async(coro: Any) -> Any:
    """Run an async coroutine."""
    return asyncio.run(coro)


def handle_command_error(error: BaseException) -> None:
    """Handle CLI errors and display user-friendly messages to stderr."""
    error_msg = str(error)
    if (
        isinstance(error, (ConnectionRefusedError, ConnectionError, OSError))
        or "all connection attempts failed" in error_msg.lower()
        or "ConnectError" in error_msg
        or "connection refused" in error_msg.lower()
    ):
        show_connection_error()
        return
    if isinstance(error, asyncio.exceptions.CancelledError):
        show_connection_error()
        return
    if handle_noisy_mcp_errors(error_msg):
        return
    if type(error).__name__ == "ServerNotRunningError":
        sys.stderr.write(f"Error: {error}\n")
        return
    if type(error).__name__ == "ClientError":
        sys.stderr.write(f"Error: {error}\n")
        return
    sys.stderr.write(f"Error: {error_msg}\n")


def get_client(
    host: str = "127.0.0.1",
    port: int = 8080,
    url: str | None = None,
    api_key: str | None = None,
) -> Any:
    """Create and return an AgentDecompileMcpClient instance (not connected)."""
    from agentdecompile_cli.client import AgentDecompileMcpClient

    return AgentDecompileMcpClient(
        host=host,
        port=port,
        url=url,
        api_key=api_key,
    )
