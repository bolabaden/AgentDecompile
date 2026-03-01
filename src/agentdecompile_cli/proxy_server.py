#!/usr/bin/env python3
"""Proxy MCP server for AgentDecompile.

Runs as either:
1. A stdio MCP server for MCP clients (Claude, etc.)
2. An HTTP server that clients can POST JSON-RPC to

This allows running a local MCP server that connects to a remote AgentDecompile instance.

Usage (stdio):
    python -m agentdecompile_cli.proxy_server --backend http://170.9.241.140:8080/

Usage (HTTP on port 8081):
    python -m agentdecompile_cli.proxy_server --backend http://170.9.241.140:8080/ --http --port 8081

Environment variables:
    AGENT_DECOMPILE_BACKEND_URL: Remote MCP backend URL (e.g., http://170.9.241.140:8080/)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from typing import Any

from agentdecompile_cli.bridge import _apply_mcp_session_fix

# Apply MCP SDK fix before any ClientSession use
_apply_mcp_session_fix()

from agentdecompile_cli.bridge import RawMcpHttpBackend
from agentdecompile_cli.executor import normalize_backend_url


async def run_http_server(backend_url: str, host: str, port: int) -> None:
    """Run HTTP server mode using Starlette."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route
    import uvicorn
    
    # Normalize URL to include MCP endpoint
    normalized_url = normalize_backend_url(backend_url)
    # Create backend connection
    backend = RawMcpHttpBackend(normalized_url)
    await backend.initialize()
    
    async def handle_request(request) -> JSONResponse:
        """Handle JSON-RPC request."""
        try:
            body = await request.json()
            method = body.get("method", "")
            params = body.get("params", {})
            req_id = body.get("id")
            
            # Route based on method
            if method == "tools/listTools":
                result = await backend.list_tools()
            elif method == "tools/callTool":
                tool_name = params.get("name", "")
                arguments = params.get("arguments", {})
                result = await backend.call_tool(tool_name, arguments)
            elif method == "resources/list":
                result = await backend.list_resources()
            elif method == "resources/read":
                uri = params.get("uir", "")
                result = await backend.read_resource(uri)
            else:
                return JSONResponse(
                    {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown method: {method}"}},
                    status_code=400,
                )
            
            # Return success response
            return JSONResponse({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": result,
            })
            
        except Exception as e:
            return JSONResponse({
                "jsonrpc": "2.0",
                "id": req_id or -1,
                "error": {"code": -1, "message": str(e)}
            }, status_code=500)
    
    # Create Starlette app
    routes = [
        Route("/", handle_request, methods=["POST"]),
        Route("/mcp/message", handle_request, methods=["POST"]),
    ]
    
    app = Starlette(routes=routes)
    
    print(f"HTTP proxy server listening on {host}:{port}", file=sys.stderr)
    
    # Run server
    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="info",
    )
    server = uvicorn.Server(config)
    
    try:
        await server.serve()
    finally:
        await backend.close()


async def run_stdio_server(backend_url: str) -> None:
    """Run stdio MCP server mode."""
    from agentdecompile_cli.bridge import AgentDecompileStdioBridge
    
    bridge = AgentDecompileStdioBridge(backend_url)
    await bridge.run()


def main():
    """Start the proxy server."""
    parser = argparse.ArgumentParser(
        description="Proxy MCP server that forwards to a remote AgentDecompile backend",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Stdio mode (for MCP clients like Claude)
  agentdecompile-proxy --backend http://170.9.241.140:8080/
  
  # HTTP mode (for direct HTTP connections)
  agentdecompile-proxy --backend http://170.9.241.140:8080/ --http --port 8081
        """
    )
    parser.add_argument(
        "--backend",
        default=os.getenv("AGENT_DECOMPILE_BACKEND_URL", "http://127.0.0.1:8080/"),
        help="Remote MCP backend URL (default: $AGENT_DECOMPILE_BACKEND_URL or http://127.0.0.1:8080/)",
    )
    parser.add_argument(
        "--http",
        action="store_true",
        help="Run in HTTP mode instead of stdio",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8081,
        help="Port for HTTP mode (default: 8081)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host for HTTP mode (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )
    args = parser.parse_args()

    if args.verbose:
        sys.stderr.write(f"Proxy backend: {args.backend}\n")
        if args.http:
            sys.stderr.write(f"Proxy mode: HTTP on {args.host}:{args.port}\n")
        else:
            sys.stderr.write(f"Proxy mode: stdio\n")

    try:
        if args.http:
            # HTTP mode
            asyncio.run(run_http_server(args.backend, args.host, args.port))
        else:
            # Stdio mode
            asyncio.run(run_stdio_server(args.backend))
    except KeyboardInterrupt:
        sys.stderr.write("Proxy interrupted\n")
    except Exception as e:
        sys.stderr.write(f"Proxy error: {e}\n")
        raise


if __name__ == "__main__":
    main()
