from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import shutil
import sys
import time

from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO

import httpx


_JFR_JCMD_PID_RE = re.compile(r"Use jcmd\s+(\d+)\s+JFR\.dump\s+name=")


def resolve_java_home() -> Path | None:
    """Return a usable JAVA_HOME containing the JVM shared library."""
    candidates: list[Path] = []

    java_home_raw = os.environ.get("JAVA_HOME", "").strip()
    if java_home_raw:
        candidates.append(Path(java_home_raw))

    java_exe = shutil.which("java")
    if java_exe:
        candidates.append(Path(java_exe).resolve().parent.parent)

    seen: set[str] = set()
    for candidate in candidates:
        normalized = str(candidate).rstrip("\\/")
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        home = Path(normalized)
        if (home / "bin" / "server" / "jvm.dll").exists():
            return home
        if (home / "lib" / "server" / "libjvm.so").exists():
            return home
        if (home / "lib" / "jli" / "libjli.dylib").exists():
            return home
    return None


def resolve_jcmd() -> Path | None:
    """Return the jcmd executable when available."""
    jcmd = shutil.which("jcmd")
    if jcmd:
        return Path(jcmd).resolve()

    java_home = resolve_java_home()
    if java_home is None:
        return None

    suffix = ".exe" if sys.platform == "win32" else ""
    candidate = java_home / "bin" / f"jcmd{suffix}"
    if candidate.exists():
        return candidate
    return None


def start_jfr_recording(process_id: int, recording_path: Path, *, name: str = "agentdecompile-tests") -> None:
    """Start a JFR recording on an already-running JVM via jcmd."""
    jcmd = resolve_jcmd()
    if jcmd is None:
        raise AssertionError("jcmd is not available; Java 21 tooling is required for the profiled E2E fixture")

    recording_path.parent.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        [
            str(jcmd),
            str(process_id),
            "JFR.start",
            f"name={name}",
            "settings=profile",
            "disk=true",
            "dumponexit=true",
            f"filename={recording_path}",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise AssertionError(f"Failed to start JFR recording for PID {process_id}: {detail}")


def dump_jfr_recording(process_id: int, recording_path: Path, *, name: str = "agentdecompile-tests") -> Path:
    """Dump an active JFR recording to disk via jcmd."""
    jcmd = resolve_jcmd()
    if jcmd is None:
        raise AssertionError("jcmd is not available; Java 21 tooling is required for the profiled E2E fixture")

    recording_path.parent.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        [
            str(jcmd),
            str(process_id),
            "JFR.dump",
            f"name={name}",
            f"filename={recording_path}",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise AssertionError(f"Failed to dump JFR recording for PID {process_id}: {detail}")
    if not recording_path.exists():
        raise AssertionError(f"Expected JFR dump at {recording_path}")
    return recording_path


def extract_jfr_jcmd_pid(log_path: Path) -> int:
    """Return the JVM PID advertised in the startup JFR log line."""
    if not log_path.exists():
        raise AssertionError(f"Expected server log at {log_path}")
    text = log_path.read_text(encoding="utf-8", errors="replace")
    match = _JFR_JCMD_PID_RE.search(text)
    if match is None:
        raise AssertionError(f"Could not find JFR jcmd PID in {log_path}")
    return int(match.group(1))


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


def build_local_server_env(project_path: Path, *, extra_env: dict[str, str] | None = None) -> dict[str, str]:
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

    resolved_java_home = resolve_java_home()
    if resolved_java_home is not None:
        java_home = str(resolved_java_home)
        env["JAVA_HOME"] = java_home
        env.setdefault("JAVA_HOME_OVERRIDE", java_home)
        java_bin = str(resolved_java_home / "bin")
        current_path = str(env.get("PATH", ""))
        path_parts = [part for part in current_path.split(os.pathsep) if part]
        normalized_parts = {part.rstrip("\\/").lower() for part in path_parts}
        if java_bin.rstrip("\\/").lower() not in normalized_parts:
            env["PATH"] = os.pathsep.join([java_bin, *path_parts])

    env["AGENT_DECOMPILE_PROJECT_PATH"] = str(project_path)
    env["PYTHONUNBUFFERED"] = "1"
    if extra_env:
        env.update({key: str(value) for key, value in extra_env.items()})
    return env


def _tail_text(path: Path | None, *, max_chars: int = 800) -> str:
    if path is None or not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")[-max_chars:]


def wait_for_server(base_url: str, process: subprocess.Popen[str], timeout: float = 120.0, log_path: Path | None = None) -> None:
    """Poll the health endpoint until the subprocess server is ready."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate(timeout=5)
            stdout_tail = (stdout or "")[-800:]
            stderr_tail = (stderr or "")[-800:]
            log_tail = _tail_text(log_path)
            raise AssertionError(
                "Local subprocess server exited before becoming healthy. "
                f"stdout={stdout_tail} stderr={stderr_tail} log_tail={log_tail}"
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
    stdout_tail = (stdout or "")[-800:]
    stderr_tail = (stderr or "")[-800:]
    log_tail = _tail_text(log_path)
    raise AssertionError(
        "Local subprocess server did not become ready within timeout. "
        f"stdout={stdout_tail} stderr={stderr_tail} log_tail={log_tail}"
    )


@dataclass
class LocalServerHandle:
    key: str
    base_url: str
    project_path: Path
    process: subprocess.Popen[str]
    log_path: Path | None = None
    _log_handle: TextIO | None = None

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.communicate(timeout=10)
        if self._log_handle is not None:
            self._log_handle.close()
            self._log_handle = None


class LocalServerPool:
    """Cache local subprocess MCP servers for grouped live test reuse."""

    def __init__(self, repo_root: Path, *, default_timeout: float = 120.0) -> None:
        self.repo_root: Path = repo_root
        self.default_timeout: float = default_timeout
        self._handles: dict[str, LocalServerHandle] = {}

    def get_or_start(
        self,
        key: str,
        *,
        project_path: Path,
        project_name: str,
        host: str = "127.0.0.1",
        timeout: float | None = None,
        extra_env: dict[str, str] | None = None,
        log_path: Path | None = None,
    ) -> LocalServerHandle:
        existing = self._handles.get(key)
        if existing is not None and existing.process.poll() is None:
            return existing

        project_path.mkdir(parents=True, exist_ok=True)
        port = find_free_port()
        log_handle: TextIO | None = None
        stdout_target: Any = subprocess.PIPE
        stderr_target: Any = subprocess.PIPE
        if log_path is not None:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_handle = log_path.open("w", encoding="utf-8")
            stdout_target = log_handle
            stderr_target = subprocess.STDOUT
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
            env=build_local_server_env(project_path, extra_env=extra_env),
            stdout=stdout_target,
            stderr=stderr_target,
            text=True,
        )
        base_url = f"http://{host}:{port}"
        wait_for_server(base_url, process, timeout=self.default_timeout if timeout is None else timeout, log_path=log_path)
        handle = LocalServerHandle(
            key=key,
            base_url=base_url,
            project_path=project_path,
            process=process,
            log_path=log_path,
            _log_handle=log_handle,
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
        self.client: httpx.Client = httpx.Client(base_url=base_url, timeout=timeout)
        self.endpoint: str = endpoint
        self.timeout: float = timeout
        self.extra_headers: dict[str, str] = dict(extra_headers or {})
        self.session_id: str = ""
        self._next_request_id: int = 1
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
