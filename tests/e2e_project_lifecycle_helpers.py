from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time

from dataclasses import dataclass
from pathlib import Path
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


def extract_resource_json_content(response: dict[str, Any]) -> dict[str, Any]:
    """Extract text blocks from a resources/read response and parse them as JSON."""
    result = response.get("result", {})
    content = result.get("contents", result.get("content", []))
    texts: list[str] = []
    for item in content:
        if isinstance(item, dict) and item.get("type") == "text":
            texts.append(item.get("text", ""))
        elif isinstance(item, dict) and "text" in item:
            texts.append(item.get("text", ""))
    return json.loads("\n".join(text for text in texts if text))


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


def get_local_ghidra_runtime() -> Path | None:
    """Return the configured local Ghidra install path if it exists."""
    ghidra_dir = os.environ.get("GHIDRA_INSTALL_DIR", "").strip()
    if not ghidra_dir:
        return None

    ghidra_path = Path(ghidra_dir)
    if not ghidra_path.exists():
        return None

    return ghidra_path


def find_free_port() -> int:
    """Return an available localhost TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def build_local_server_env(project_path: Path) -> dict[str, str]:
    """Return a clean environment for running a local subprocess MCP server."""
    env = os.environ.copy()
    for key in [
        "AGENT_DECOMPILE_BACKEND_URL",
        "AGENT_DECOMPILE_MCP_SERVER_URL",
        "AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME",
        "AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD",
        "AGENT_DECOMPILE_GHIDRA_SERVER_HOST",
        "AGENT_DECOMPILE_GHIDRA_SERVER_PORT",
        "AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY",
        "AGENTDECOMPILE_SERVER_HOST",
        "AGENTDECOMPILE_SERVER_PORT",
        "AGENTDECOMPILE_SERVER_USERNAME",
        "AGENTDECOMPILE_SERVER_PASSWORD",
        "AGENTDECOMPILE_SERVER_REPOSITORY",
    ]:
        env.pop(key, None)
    env["AGENT_DECOMPILE_PROJECT_PATH"] = str(project_path)
    env["PYTHONUNBUFFERED"] = "1"
    return env


def wait_for_server(base_url: str, process: subprocess.Popen[str], timeout: float = 120.0) -> None:
    """Poll the health endpoint until the subprocess server is ready."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate(timeout=5)
            raise AssertionError(
                "Local subprocess server exited before becoming healthy. "
                f"stdout={stdout[-800:]} stderr={stderr[-800:]}"
            )
        try:
            health_response = httpx.get(f"{base_url}/health", timeout=1.0)
            if health_response.status_code == 200:
                return
        except (httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout):
            time.sleep(1)
            continue
        time.sleep(1)

    process.terminate()
    try:
        stdout, stderr = process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate(timeout=10)
    raise AssertionError(
        "Local subprocess server did not become ready within timeout. "
        f"stdout={stdout[-800:]} stderr={stderr[-800:]}"
    )


@dataclass
class LocalServerHandle:
    key: str
    base_url: str
    project_path: Path
    process: subprocess.Popen[str]

    def stop(self) -> None:
        self.process.terminate()
        try:
            self.process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.communicate(timeout=10)


class LocalServerPool:
    """Cache local subprocess MCP servers for grouped live test reuse."""

    def __init__(self, repo_root: Path, *, default_timeout: float = 120.0) -> None:
        self.repo_root = repo_root
        self.default_timeout = default_timeout
        self._handles: dict[str, LocalServerHandle] = {}

    def get_or_start(
        self,
        key: str,
        *,
        project_path: Path,
        project_name: str,
        host: str = "127.0.0.1",
        timeout: float | None = None,
    ) -> LocalServerHandle:
        existing = self._handles.get(key)
        if existing is not None and existing.process.poll() is None:
            return existing

        project_path.mkdir(parents=True, exist_ok=True)
        port = find_free_port()
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "agentdecompile_cli.server",
                "-t",
                "streamable-http",
                "--host",
                host,
                "--port",
                str(port),
                "--project-path",
                str(project_path),
                "--project-name",
                project_name,
            ],
            cwd=str(self.repo_root),
            env=build_local_server_env(project_path),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        base_url = f"http://{host}:{port}"
        wait_for_server(base_url, process, timeout=self.default_timeout if timeout is None else timeout)
        handle = LocalServerHandle(
            key=key,
            base_url=base_url,
            project_path=project_path,
            process=process,
        )
        self._handles[key] = handle
        return handle

    def close_all(self) -> None:
        for handle in reversed(list(self._handles.values())):
            if handle.process.poll() is None:
                handle.stop()
        self._handles.clear()


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

    def list_resources(self, *, request_id: int | None = None) -> list[dict[str, Any]]:
        response = self.post_jsonrpc("resources/list", {}, request_id=request_id)
        return response["result"]["resources"]

    def read_resource(self, uri: str, *, request_id: int | None = None) -> dict[str, Any]:
        return self.post_jsonrpc("resources/read", {"uri": uri}, request_id=request_id)

    def read_resource_json(self, uri: str, *, request_id: int | None = None) -> dict[str, Any]:
        return extract_resource_json_content(self.read_resource(uri, request_id=request_id))
