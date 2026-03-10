from __future__ import annotations

import json

from typing import Any

import httpx


def extract_text_content(response: dict[str, Any]) -> str:
    """Extract concatenated text blocks from an MCP JSON-RPC response."""
    result = response.get("result", {})
    content = result.get("content", result.get("contents", []))
    texts: list[str] = []
    for item in content:
        if isinstance(item, dict) and item.get("type") == "text":
            texts.append(item.get("text", ""))
        elif isinstance(item, dict) and "text" in item:
            texts.append(item.get("text", ""))
    return "\n".join(text for text in texts if text)


def extract_json_content(response: dict[str, Any]) -> dict[str, Any]:
    """Extract text blocks and parse them as JSON."""
    return json.loads(extract_text_content(response))


def find_project_file(files: list[dict[str, Any]], *, name: str | None = None, path_suffix: str | None = None) -> dict[str, Any] | None:
    """Return the first project file entry matching a name or path suffix."""
    for item in files:
        item_name = str(item.get("name") or "")
        item_path = str(item.get("path") or "")
        if name and item_name == name:
            return item
        if path_suffix and item_path.endswith(path_suffix):
            return item
    return None


class JsonRpcMcpSession:
    """Thin synchronous MCP JSON-RPC client for live E2E tests."""

    def __init__(
        self,
        base_url: str,
        *,
        endpoint: str = "/mcp/message",
        timeout: float = 30.0,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.client = httpx.Client(base_url=base_url, timeout=timeout)
        self.endpoint = endpoint
        self.timeout = timeout
        self.extra_headers = dict(extra_headers or {})
        self.session_id = ""
        self._next_request_id = 1
        self.initialize()

    def close(self) -> None:
        self.client.close()

    def __enter__(self) -> JsonRpcMcpSession:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _request_id(self) -> int:
        request_id = self._next_request_id
        self._next_request_id += 1
        return request_id

    def _headers(self, *, include_session: bool = True, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            **self.extra_headers,
            **(extra or {}),
        }
        if include_session and self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        return headers

    def post_jsonrpc(
        self,
        method: str,
        params: dict[str, Any],
        *,
        request_id: int | None = None,
        include_session: bool = True,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        payload = {
            "jsonrpc": "2.0",
            "id": request_id if request_id is not None else self._request_id(),
            "method": method,
            "params": params,
        }
        response = self.client.post(
            self.endpoint,
            json=payload,
            headers=self._headers(include_session=include_session, extra=extra_headers),
            timeout=self.timeout,
        )
        assert response.status_code == 200, (
            f"{method} returned HTTP {response.status_code}: {response.text}"
        )
        return response.json()

    def initialize(self) -> dict[str, Any]:
        response = self.client.post(
            self.endpoint,
            json={
                "jsonrpc": "2.0",
                "id": self._request_id(),
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "pytest-e2e-lifecycle", "version": "1.0"},
                },
            },
            headers=self._headers(include_session=False),
            timeout=self.timeout,
        )
        assert response.status_code == 200, response.text
        self.session_id = response.headers.get("mcp-session-id", "")
        return response.json()

    def call_tool(self, name: str, arguments: dict[str, Any], *, request_id: int | None = None) -> dict[str, Any]:
        return self.post_jsonrpc(
            "tools/call",
            {"name": name, "arguments": arguments},
            request_id=request_id,
        )

    def call_tool_json(self, name: str, arguments: dict[str, Any], *, request_id: int | None = None) -> dict[str, Any]:
        merged_arguments = dict(arguments)
        merged_arguments.setdefault("format", "json")
        return extract_json_content(self.call_tool(name, merged_arguments, request_id=request_id))

    def list_tools(self, *, request_id: int | None = None) -> list[dict[str, Any]]:
        response = self.post_jsonrpc("tools/list", {}, request_id=request_id)
        return response["result"]["tools"]

    def read_resource(self, uri: str, *, request_id: int | None = None) -> dict[str, Any]:
        return self.post_jsonrpc("resources/read", {"uri": uri}, request_id=request_id)
