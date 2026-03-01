#!/usr/bin/env python3
"""Local proxy server entrypoint for AgentDecompile.

Supports:
- stdio mode: MCP stdio bridge to remote backend
- http mode: local streamable-http MCP endpoint forwarding to remote backend
"""

from __future__ import annotations

import argparse
import os
import sys
import time

from agentdecompile_cli.bridge import AgentDecompileStdioBridge
from agentdecompile_cli.executor import normalize_backend_url
from agentdecompile_cli.mcp_server.proxy_server import AgentDecompileMcpProxyServer, ProxyServerConfig


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AgentDecompile local proxy server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  agentdecompile-proxy --backend http://170.9.241.140:8080/\n"
            "  agentdecompile-proxy --backend http://170.9.241.140:8080/ --http --port 8081"
        ),
    )
    parser.add_argument("--backend", default=None, help="Remote MCP backend base URL")
    parser.add_argument("--backend-url", default=None, help="Alias of --backend (equivalent to AGENT_DECOMPILE_BACKEND_URL)")
    parser.add_argument("--mcp-server-url", default=None, help="Fallback backend URL (equivalent to AGENT_DECOMPILE_MCP_SERVER_URL)")
    parser.add_argument("--server-host", default=None, help="Shared Ghidra server host (equivalent to AGENT_DECOMPILE_SERVER_HOST)")
    parser.add_argument("--server-port", type=int, default=None, help="Shared Ghidra server port (equivalent to AGENT_DECOMPILE_SERVER_PORT)")
    parser.add_argument("--server-username", default=None, help="Shared Ghidra server username (equivalent to AGENT_DECOMPILE_SERVER_USERNAME)")
    parser.add_argument("--server-password", default=None, help="Shared Ghidra server password (equivalent to AGENT_DECOMPILE_SERVER_PASSWORD)")
    parser.add_argument("--ghidra-server-repository", default=None, help="Shared Ghidra repository (equivalent to AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY)")
    parser.add_argument("--http", action="store_true", help="Run streamable-http proxy mode")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host for HTTP mode")
    parser.add_argument("--port", type=int, default=8081, help="Bind port for HTTP mode")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose startup logs")
    return parser


def main() -> None:
    args: argparse.Namespace = _build_parser().parse_args()
    backend_raw: str = (
        args.backend
        or args.backend_url
        or args.mcp_server_url
        or os.getenv("AGENT_DECOMPILE_BACKEND_URL")
        or os.getenv("AGENT_DECOMPILE_MCP_SERVER_URL")
        or "http://127.0.0.1:8080"
    )
    backend_url: str = normalize_backend_url(backend_raw)

    if args.server_host:
        os.environ["AGENT_DECOMPILE_SERVER_HOST"] = str(args.server_host)
    if args.server_port is not None:
        os.environ["AGENT_DECOMPILE_SERVER_PORT"] = str(args.server_port)
    if args.server_username:
        os.environ["AGENT_DECOMPILE_SERVER_USERNAME"] = str(args.server_username)
    if args.server_password:
        os.environ["AGENT_DECOMPILE_SERVER_PASSWORD"] = str(args.server_password)
    if args.ghidra_server_repository:
        os.environ["AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY"] = str(args.ghidra_server_repository)

    if args.verbose:
        sys.stderr.write(f"Proxy backend: {backend_url}\n")

    if args.http:
        proxy_server: AgentDecompileMcpProxyServer = AgentDecompileMcpProxyServer(
            ProxyServerConfig(host=args.host, port=args.port, backend_url=backend_url),
        )
        try:
            started_port: int = proxy_server.start()
            sys.stderr.write(f"AgentDecompile proxy server running at http://{args.host}:{started_port}/mcp/message\n")
            sys.stderr.write(f"Forwarding requests to backend {backend_url}\n")
            sys.stderr.write("Press Ctrl+C to stop.\n")
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            sys.stderr.write("\nShutdown complete\n")
        finally:
            proxy_server.stop()
        return

    bridge: AgentDecompileStdioBridge = AgentDecompileStdioBridge(backend_url)
    try:
        import asyncio

        asyncio.run(bridge.run())
    except KeyboardInterrupt:
        sys.stderr.write("\nShutdown complete\n")


if __name__ == "__main__":
    main()
