from __future__ import annotations

import os
import socket
import subprocess
import sys
import time

from contextlib import contextmanager
from pathlib import Path
from typing import Generator

import httpx
import pytest

from tests.e2e_project_lifecycle_helpers import JsonRpcMcpSession, find_project_file
from tests.helpers import create_minimal_binary


pytestmark = [pytest.mark.e2e, pytest.mark.slow]


@pytest.fixture
def local_http_session(isolated_workspace: Path) -> Generator[JsonRpcMcpSession, None, None]:
    with _running_local_server_context(isolated_workspace) as base_url:
        with JsonRpcMcpSession(base_url) as session:
            yield session


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _server_env(project_path: Path) -> dict[str, str]:
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


def _wait_for_server(base_url: str, process: subprocess.Popen[str], timeout: float = 120.0) -> None:
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


@contextmanager
def _running_local_server_context(isolated_workspace: Path) -> Generator[str, None, None]:
    port = _find_free_port()
    project_path = isolated_workspace / "runtime_project"
    project_path.mkdir(parents=True, exist_ok=True)
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "agentdecompile_cli.server",
            "-t",
            "streamable-http",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--project-path",
            str(project_path),
            "--project-name",
            "pytest-lifecycle",
        ],
        cwd=str(Path(__file__).resolve().parents[1]),
        env=_server_env(project_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    base_url = f"http://127.0.0.1:{port}"
    _wait_for_server(base_url, process)
    try:
        yield base_url
    finally:
        process.terminate()
        try:
            process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=10)


def _make_named_binary(workspace: Path, name: str) -> Path:
    binary_path = workspace / name
    create_minimal_binary(binary_path)
    return binary_path


class TestLocalProjectLifecycle:
    def test_open_local_binary_sets_current_program_and_lists_project_entry(self, local_http_session: JsonRpcMcpSession, test_binary: Path):
        open_payload = local_http_session.call_tool_json("open-project", {"path": str(test_binary)})
        assert open_payload["operation"] == "import"
        assert open_payload["filesImported"] == 1
        assert len(open_payload["importedPrograms"]) == 1
        assert open_payload["importedPrograms"][0]["path"] == str(test_binary)

        current_payload = local_http_session.call_tool_json("get-current-program", {})
        assert current_payload["loaded"] is True
        assert current_payload["name"] == test_binary.name
        assert current_payload["programPath"].endswith(test_binary.name)
        assert current_payload["functionCount"] >= 0

        listing_payload = local_http_session.call_tool_json("list-project-files", {})
        assert listing_payload["count"] >= 1
        assert listing_payload.get("source") != "shared-server-session"
        assert find_project_file(listing_payload["files"], name=test_binary.name) is not None

    def test_opening_project_domain_path_reopens_local_program(self, local_http_session: JsonRpcMcpSession, test_binary: Path):
        local_http_session.call_tool_json("open-project", {"path": str(test_binary)})
        listing_payload = local_http_session.call_tool_json("list-project-files", {})
        listed_program = find_project_file(listing_payload["files"], name=test_binary.name)
        assert listed_program is not None

        reopen_payload = local_http_session.call_tool_json("open-project", {"path": listed_program["path"]})
        assert reopen_payload["action"] == "open"
        assert reopen_payload["mode"] == "project-domain"
        assert reopen_payload["path"].endswith(test_binary.name)

        current_payload = local_http_session.call_tool_json("get-current-program", {})
        assert current_payload["loaded"] is True
        assert current_payload["programPath"].endswith(test_binary.name)

    def test_opening_second_local_binary_replaces_active_program_and_preserves_listing(self, local_http_session: JsonRpcMcpSession, isolated_workspace: Path):
        first_binary = _make_named_binary(isolated_workspace, "first_local.bin")
        second_binary = _make_named_binary(isolated_workspace, "second_local.bin")

        first_open = local_http_session.call_tool_json("open-project", {"path": str(first_binary)})
        second_open = local_http_session.call_tool_json("open-project", {"path": str(second_binary)})

        assert first_open["filesImported"] == 1
        assert second_open["filesImported"] == 1

        current_payload = local_http_session.call_tool_json("get-current-program", {})
        assert current_payload["loaded"] is True
        assert current_payload["name"] == second_binary.name
        assert current_payload["programPath"].endswith(second_binary.name)

        listing_payload = local_http_session.call_tool_json("list-project-files", {})
        assert find_project_file(listing_payload["files"], name=first_binary.name) is not None
        assert find_project_file(listing_payload["files"], name=second_binary.name) is not None

    def test_local_sync_project_uses_local_save_modes_after_open(self, local_http_session: JsonRpcMcpSession, test_binary: Path):
        local_http_session.call_tool_json("open-project", {"path": str(test_binary)})

        push_payload = local_http_session.call_tool_json("sync-project", {"mode": "push"})
        assert push_payload["operation"] == "sync-project"
        assert push_payload["direction"] == "local-save"
        assert push_payload["repository"] == "local-project"

        bidirectional_payload = local_http_session.call_tool_json("sync-project", {"mode": "bidirectional"})
        assert bidirectional_payload["operation"] == "sync-project"
        assert bidirectional_payload["direction"] == "local-save-only"
        assert "No shared server session" in bidirectional_payload["note"]
