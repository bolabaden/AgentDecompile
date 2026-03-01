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
    parser.add_argument(
        "--backend",
        default=os.getenv("AGENT_DECOMPILE_BACKEND_URL", "http://127.0.0.1:8080"),
        help="Remote MCP backend base URL",
    )
    parser.add_argument("--http", action="store_true", help="Run streamable-http proxy mode")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host for HTTP mode")
    parser.add_argument("--port", type=int, default=8081, help="Bind port for HTTP mode")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose startup logs")
    return parser


def main() -> None:
    args = _build_parser().parse_args()
    backend_url = normalize_backend_url(args.backend)

    if args.verbose:
        sys.stderr.write(f"Proxy backend: {backend_url}\n")

    if args.http:
        proxy_server = AgentDecompileMcpProxyServer(
            ProxyServerConfig(host=args.host, port=args.port, backend_url=backend_url),
        )
        try:
            started_port = proxy_server.start()
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

    bridge = AgentDecompileStdioBridge(backend_url)
    try:
        import asyncio

        asyncio.run(bridge.run())
    except KeyboardInterrupt:
        sys.stderr.write("\nShutdown complete\n")


if __name__ == "__main__":
    main()
