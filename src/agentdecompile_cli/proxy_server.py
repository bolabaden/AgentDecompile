#!/usr/bin/env python3
"""Proxy MCP server for AgentDecompile.

Runs as a stdio MCP server that forwards all tool calls to a remote MCP backend.
This allows running a local MCP server that connects to a remote AgentDecompile instance.

Usage:
    python -m agentdecompile_cli.proxy_server --backend http://170.9.241.140:8080/

Environment variables:
    AGENT_DECOMPILE_BACKEND_URL: Remote MCP backend URL (e.g., http://170.9.241.140:8080/)
    AGENT_DECOMPILE_GHIDRA_SERVER_HOST: Ghidra server hostname
    AGENT_DECOMPILE_GHIDRA_SERVER_PORT: Ghidra server port
    AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME: Ghidra server username
    AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD: Ghidra server password
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

from agentdecompile_cli.bridge import _apply_mcp_session_fix

# Apply MCP SDK fix before any ClientSession use
_apply_mcp_session_fix()

from agentdecompile_cli.bridge import AgentDecompileStdioBridge


def main():
    """Start the proxy MCP server."""
    parser = argparse.ArgumentParser(
        description="Proxy MCP server that forwards to a remote AgentDecompile backend"
    )
    parser.add_argument(
        "--backend",
        default=os.getenv("AGENT_DECOMPILE_BACKEND_URL", "http://127.0.0.1:8080/"),
        help="Remote MCP backend URL (default: $AGENT_DECOMPILE_BACKEND_URL or http://127.0.0.1:8080/)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )
    args = parser.parse_args()

    if args.verbose:
        sys.stderr.write(f"Starting proxy MCP server forwarding to {args.backend}\n")

    # Create and run the bridge
    bridge = AgentDecompileStdioBridge(args.backend)
    
    try:
        asyncio.run(bridge.run())
    except KeyboardInterrupt:
        sys.stderr.write("Proxy server interrupted\n")
    except Exception as e:
        sys.stderr.write(f"Proxy server error: {e}\n")
        raise


if __name__ == "__main__":
    main()
