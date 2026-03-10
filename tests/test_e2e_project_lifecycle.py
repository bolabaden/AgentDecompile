from __future__ import annotations

import json
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
def local_server_base_url(isolated_workspace: Path) -> Generator[str, None, None]:
    with _running_local_server_context(isolated_workspace) as base_url:
        yield base_url


@pytest.fixture
def local_http_session(local_server_base_url: str) -> Generator[JsonRpcMcpSession, None, None]:
    with JsonRpcMcpSession(local_server_base_url) as session:
        yield session


def _run_local_cli(base_url: str, *args: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "agentdecompile_cli.cli", "--server-url", base_url, *args],
        cwd=str(Path(__file__).resolve().parents[1]),
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _cli_json(result: subprocess.CompletedProcess[str]) -> object:
    payload = (result.stdout or "").strip() or (result.stderr or "").strip()
    return json.loads(payload)


def _assert_cli_ok(result: subprocess.CompletedProcess[str]) -> None:
    assert result.returncode == 0, (
        f"CLI failed with rc={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def _known_endpoint_variants() -> tuple[str, ...]:
    return ("/", "/mcp", "/mcp/", "/mcp/message", "/mcp/message/")


def _known_open_tool_variants() -> tuple[str, ...]:
    return ("open-project", "open_project", "switch-project")


def _known_list_tool_variants() -> tuple[str, ...]:
    return ("list-project-files", "list_project_files")


def _current_program_payload_for(session: JsonRpcMcpSession, *, program_path: str) -> dict[str, object]:
    return session.call_tool_json("get-current-program", {"programPath": program_path})


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


class TestLocalProjectWorkflowMatrix:
    @pytest.mark.parametrize("endpoint", _known_endpoint_variants())
    def test_endpoint_variants_support_open_and_current_program(
        self,
        local_server_base_url: str,
        test_binary: Path,
        endpoint: str,
    ):
        with JsonRpcMcpSession(local_server_base_url, endpoint=endpoint) as session:
            open_payload = session.call_tool_json("open-project", {"path": str(test_binary)})
            assert open_payload["operation"] == "import"

            current_payload = _current_program_payload_for(session, program_path=str(test_binary))
            assert current_payload["loaded"] is True
            assert current_payload["programPath"].endswith(test_binary.name)

    @pytest.mark.parametrize("open_tool_name", _known_open_tool_variants())
    @pytest.mark.parametrize("list_tool_name", _known_list_tool_variants())
    def test_open_and_list_tool_name_variants_resolve_same_project_entry(
        self,
        local_server_base_url: str,
        test_binary: Path,
        open_tool_name: str,
        list_tool_name: str,
    ):
        with JsonRpcMcpSession(local_server_base_url) as session:
            open_payload = session.call_tool_json(open_tool_name, {"path": str(test_binary)})
            assert open_payload["filesImported"] == 1

            listing_payload = session.call_tool_json(list_tool_name, {})
            assert find_project_file(listing_payload["files"], name=test_binary.name) is not None

    def test_manage_files_list_and_open_modes_match_project_workflow(self, local_http_session: JsonRpcMcpSession, test_binary: Path):
        local_http_session.call_tool_json("open-project", {"path": str(test_binary)})

        manage_list_payload = local_http_session.call_tool_json("manage-files", {"mode": "list", "path": "/"})
        listed_program = find_project_file(manage_list_payload["files"], name=test_binary.name)
        assert listed_program is not None

        manage_open_payload = local_http_session.call_tool_json(
            "manage-files",
            {"mode": "open", "path": listed_program["path"]},
        )
        assert manage_open_payload["action"] == "open"
        assert manage_open_payload["path"].endswith(test_binary.name)

    def test_resource_payloads_reflect_opened_local_program(self, local_http_session: JsonRpcMcpSession, test_binary: Path):
        local_http_session.call_tool_json("open-project", {"path": str(test_binary)})

        advertised_resources = {str(item["uri"]) for item in local_http_session.list_resources()}
        assert "ghidra://programs" in advertised_resources
        assert "ghidra://static-analysis-results" in advertised_resources
        assert "ghidra://agentdecompile-debug-info" in advertised_resources

        programs_payload = local_http_session.read_resource_json("ghidra://programs")
        assert any(str(program.get("name", "")).endswith(test_binary.name) for program in programs_payload.get("programs", []))

        static_analysis_payload = local_http_session.read_resource_json("ghidra://static-analysis-results")
        assert static_analysis_payload["version"] == "2.1.0"
        assert isinstance(static_analysis_payload.get("runs"), list)

        debug_info_payload = local_http_session.read_resource_json("ghidra://agentdecompile-debug-info")
        assert debug_info_payload["program"]["status"] != "no_program_loaded"
        assert str(debug_info_payload["program"].get("name", "")).endswith(test_binary.name)

    def test_sync_project_without_open_is_actionable_error(self, local_http_session: JsonRpcMcpSession):
        sync_payload = local_http_session.call_tool_json("sync-project", {"mode": "pull"})
        assert sync_payload["success"] is False
        assert sync_payload["operation"] == "sync-project"
        assert sync_payload["context"]["state"] == "no-project-context"


class TestLocalCliDocumentedWorkflows:
    def test_cli_raw_tool_open_project_matches_documented_usage(self, local_server_base_url: str, test_binary: Path):
        result = _run_local_cli(
            local_server_base_url,
            "--format",
            "json",
            "tool",
            "open-project",
            json.dumps({"path": str(test_binary), "format": "json"}),
        )
        _assert_cli_ok(result)
        payload = _cli_json(result)
        assert payload["filesImported"] == 1
        assert payload["importedPrograms"][0]["path"] == str(test_binary)

    def test_cli_tool_seq_keeps_state_for_open_current_and_list(self, local_server_base_url: str, test_binary: Path):
        steps = json.dumps(
            [
                {"name": "open-project", "arguments": {"path": str(test_binary), "format": "json"}},
                {"name": "get-current-program", "arguments": {"programPath": str(test_binary), "format": "json"}},
                {"name": "list-project-files", "arguments": {"format": "json"}},
            ]
        )
        result = _run_local_cli(local_server_base_url, "--format", "json", "tool-seq", steps)
        _assert_cli_ok(result)
        payload = _cli_json(result)
        serialized = json.dumps(payload)
        assert test_binary.name in serialized
        assert "get-current-program" in serialized or "programPath" in serialized

    @pytest.mark.parametrize(
        ("resource_name", "expected_key"),
        (("programs", "programs"), ("static-analysis", "runs"), ("debug-info", "program")),
    )
    def test_cli_resource_commands_cover_documented_resources(
        self,
        local_server_base_url: str,
        resource_name: str,
        expected_key: str,
    ):
        result = _run_local_cli(local_server_base_url, "--format", "json", "resource", resource_name)
        _assert_cli_ok(result)
        payload = _cli_json(result)
        assert expected_key in payload
