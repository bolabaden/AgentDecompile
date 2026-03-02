from __future__ import annotations

import json
import socket
import threading

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from collections.abc import Generator
from typing import Any

import pytest

from agentdecompile_cli.bridge import RawMcpHttpBackend


class _MockMcpHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send_json(self, payload: dict[str, Any], *, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("mcp-session-id", "mock-session-1")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
        body = json.loads(raw)

        method = body.get("method")
        rid = body.get("id")

        if rid is None:
            self.send_response(202)
            self.send_header("mcp-session-id", "mock-session-1")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if method == "initialize":
            self._send_json(
                {
                    "jsonrpc": "2.0",
                    "id": rid,
                    "result": {
                        "protocolVersion": "2025-03-26",
                        "serverInfo": {"name": "MockBackend", "version": "0.1.0"},
                        "capabilities": {"tools": {}},
                    },
                }
            )
            return

        if method == "tools/list":
            self._send_json(
                {
                    "jsonrpc": "2.0",
                    "id": rid,
                    "result": {
                        "tools": [
                            {
                                "name": "manage-files",
                                "description": "Manage files",
                                "inputSchema": {"type": "object", "properties": {"mode": {"type": "string"}}},
                            },
                            {
                                "name": "list-project-files",
                                "description": "List project files",
                                "inputSchema": {"type": "object", "properties": {}},
                            },
                        ]
                    },
                }
            )
            return

        if method == "tools/call":
            params = body.get("params", {})
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})
            self._send_json(
                {
                    "jsonrpc": "2.0",
                    "id": rid,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(
                                    {
                                        "success": True,
                                        "tool": tool_name,
                                        "arguments": arguments,
                                        "files": ["/project/file1.bin", "/project/file2.gpr"],
                                    }
                                ),
                            }
                        ],
                        "isError": False,
                    },
                }
            )
            return

        self._send_json({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "Method not found"}})

    def log_message(self, format: str, *args: object) -> None:
        return


@pytest.fixture()
def mock_mcp_server() -> Generator[tuple[ThreadingHTTPServer, int], None, None]:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]

    server = ThreadingHTTPServer(("127.0.0.1", port), _MockMcpHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


@pytest.mark.asyncio
async def test_raw_backend_initialize_list_and_call(mock_mcp_server: tuple[ThreadingHTTPServer, int]) -> None:
    _, port = mock_mcp_server
    backend = RawMcpHttpBackend(f"http://127.0.0.1:{port}/mcp/message")
    try:
        init = await backend.initialize()
        assert init["serverInfo"]["name"] == "MockBackend"

        tools = await backend.list_tools()
        assert isinstance(tools, list)
        assert len(tools) == 2
        names = {t["name"] for t in tools}
        assert "manage-files" in names
        assert "list-project-files" in names

        result = await backend.call_tool("manage-files", {"mode": "list"})
        assert "content" in result
        content = result["content"]
        assert isinstance(content, list)
        payload = json.loads(content[0]["text"])
        assert payload["success"] is True
        assert payload["tool"] == "manage-files"
        assert payload["arguments"]["mode"] == "list"
    finally:
        await backend.close()


@pytest.mark.asyncio
async def test_raw_backend_raises_on_rpc_error(mock_mcp_server: tuple[ThreadingHTTPServer, int], monkeypatch: pytest.MonkeyPatch) -> None:
    _, port = mock_mcp_server
    backend = RawMcpHttpBackend(f"http://127.0.0.1:{port}/mcp/message")

    async def _fake_post(body: dict[str, Any]) -> dict[str, Any]:
        return {"error": {"code": -32601, "message": "boom"}}

    monkeypatch.setattr(backend, "_post", _fake_post)

    try:
        with pytest.raises(Exception):
            await backend.list_tools()
    finally:
        await backend.close()
