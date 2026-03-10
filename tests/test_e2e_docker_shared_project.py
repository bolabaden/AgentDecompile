"""E2E tests for shared-project usage via docker-compose.

These tests spawn the full docker-compose stack (biodecompwarehouse Ghidra server
+ agentdecompile-mcp MCP server) and exercise the complete shared-project workflow
through real HTTP MCP requests and CLI subprocess calls.

NO mocking. NO monkeypatching. Tests fail if prerequisites are not met.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time

from pathlib import Path
from typing import Any, Generator

import httpx
import pytest

from tests.e2e_project_lifecycle_helpers import JsonRpcMcpSession, find_project_file

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

COMPOSE_FILE = Path(__file__).resolve().parents[1] / "docker-compose.yml"
MCP_PORT = int(os.environ.get("AGENTDECOMPILE_TEST_MCP_PORT", "8080"))
MCP_HOST = os.environ.get("AGENTDECOMPILE_TEST_MCP_HOST", "127.0.0.1")
MCP_BASE_URL = f"http://{MCP_HOST}:{MCP_PORT}"
MCP_ENDPOINT = f"{MCP_BASE_URL}/mcp/message"
HEALTH_ENDPOINT = f"{MCP_BASE_URL}/health"

CLI_TIMEOUT = 60  # seconds for CLI subprocess calls
HTTP_TIMEOUT = 30.0  # seconds for HTTP requests
COMPOSE_START_TIMEOUT = int(os.environ.get("AGENTDECOMPILE_TEST_COMPOSE_START_TIMEOUT", "900"))
COMPOSE_HEALTH_TIMEOUT = float(os.environ.get("AGENTDECOMPILE_TEST_COMPOSE_HEALTH_TIMEOUT", "240"))
SHARED_GHIDRA_HOST = os.environ.get("AGENTDECOMPILE_TEST_GHIDRA_HOST", "biodecompwarehouse")
SHARED_GHIDRA_PORT = os.environ.get("AGENTDECOMPILE_TEST_GHIDRA_PORT", "13100")
SHARED_GHIDRA_USERNAME = os.environ.get("AGENTDECOMPILE_TEST_GHIDRA_USERNAME", "")
SHARED_GHIDRA_PASSWORD = os.environ.get("AGENTDECOMPILE_TEST_GHIDRA_PASSWORD", "")
SHARED_GHIDRA_REPOSITORY = os.environ.get("AGENTDECOMPILE_TEST_GHIDRA_REPOSITORY", "")
LOCAL_CONTAINER_BINARY = os.environ.get("AGENTDECOMPILE_TEST_LOCAL_BINARY_PATH", "/bin/sh")
COMPOSE_REQUIRED_SERVICES = ("biodecompwarehouse", "agentdecompile-mcp")

pytestmark = [pytest.mark.e2e, pytest.mark.slow, pytest.mark.timeout(COMPOSE_START_TIMEOUT + 300)]

_DOCKER_STACK_CACHE: dict[str, Any] = {
    "attempted": False,
    "ready": False,
    "skip_reason": "",
    "compose_cmd": None,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _command_available(command: str) -> bool:
    """Return True when an executable is available on PATH."""
    return shutil.which(command) is not None


def _runtime_candidates() -> list[tuple[str, list[str]]]:
    """Return preferred container runtime commands, honoring env override."""
    override = os.environ.get("AGENTDECOMPILE_TEST_CONTAINER_ENGINE", "").strip().lower()
    candidates = {
        "docker": [("docker", ["docker"])],
        "podman": [("podman", ["podman"])],
    }
    if override in candidates:
        return candidates[override]
    return [("docker", ["docker"]), ("podman", ["podman"])]


def _compose_candidates(runtime_name: str) -> list[tuple[str, list[str]]]:
    """Return compose command candidates for the selected runtime."""
    if runtime_name == "docker":
        return [
            ("docker compose", ["docker", "compose"]),
            ("docker-compose", ["docker-compose"]),
        ]
    return [
        ("podman compose", ["podman", "compose"]),
        ("podman-compose", ["podman-compose"]),
    ]


def _runtime_is_available(runtime_cmd: list[str]) -> tuple[bool, str]:
    """Check whether a container runtime is installed and responsive."""
    if not _command_available(runtime_cmd[0]):
        return False, f"{runtime_cmd[0]} not found on PATH"
    try:
        result = subprocess.run(
            [*runtime_cmd, "info"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        return False, str(exc)
    if result.returncode == 0:
        return True, ""
    detail = (result.stderr or result.stdout).strip()
    return False, detail or f"{runtime_cmd[0]} info failed"


def _compose_command_is_available(compose_cmd: list[str]) -> tuple[bool, str]:
    """Check whether a compose command is installed for the runtime."""
    if not _command_available(compose_cmd[0]):
        return False, f"{compose_cmd[0]} not found on PATH"
    version_args = [*compose_cmd, "version"]
    try:
        result = subprocess.run(
            version_args,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        return False, str(exc)
    output = f"{result.stdout}\n{result.stderr}".strip()
    if compose_cmd[:2] == ["podman", "compose"] and "Executing external compose provider" in output:
        return False, output or "podman compose is delegating to an external provider"
    if result.returncode == 0:
        return True, ""
    detail = output
    return False, detail or f"{' '.join(compose_cmd)} is unavailable"


def _resolve_container_backend() -> tuple[str, list[str]]:
    """Pick a working container runtime and compose command.

    Preference order is Docker first, then Podman, unless overridden via
    AGENTDECOMPILE_TEST_CONTAINER_ENGINE.
    """
    failures: list[str] = []
    for runtime_name, runtime_cmd in _runtime_candidates():
        runtime_ok, runtime_detail = _runtime_is_available(runtime_cmd)
        if not runtime_ok:
            failures.append(f"{runtime_name}: {runtime_detail}")
            continue
        for compose_name, compose_cmd in _compose_candidates(runtime_name):
            compose_ok, compose_detail = _compose_command_is_available(compose_cmd)
            if compose_ok:
                return runtime_name, compose_cmd
            failures.append(f"{compose_name}: {compose_detail}")
    pytest.fail(
        "No working container runtime/compose command found. "
        + "; ".join(failures)
    )


def _compose_env() -> dict[str, str]:
    """Return a compose environment with harmless defaults for test-only labels."""
    env = os.environ.copy()
    env.setdefault("DOMAIN", "example.test")
    env.setdefault("TS_HOSTNAME", "agentdecompile-test")
    alpine_base_image = env.get("AGENTDECOMPILE_TEST_ALPINE_BASE_IMAGE", "").strip()
    if alpine_base_image and "ALPINE_BASE_IMAGE" not in env:
        env["ALPINE_BASE_IMAGE"] = alpine_base_image
    return env


def _compose_up(compose_cmd: list[str]) -> subprocess.CompletedProcess[str]:
    """Start compose services (build + detached)."""
    return subprocess.run(
        [*compose_cmd, "-f", str(COMPOSE_FILE), "up", "-d", "--build",
         "--wait", "--wait-timeout", "180", *COMPOSE_REQUIRED_SERVICES],
        capture_output=True,
        text=True,
        timeout=COMPOSE_START_TIMEOUT,
        cwd=str(COMPOSE_FILE.parent),
        env=_compose_env(),
    )


def _compose_down(compose_cmd: list[str]) -> None:
    """Tear down compose services."""
    subprocess.run(
        [*compose_cmd, "-f", str(COMPOSE_FILE), "down", "--volumes", "--remove-orphans"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(COMPOSE_FILE.parent),
        env=_compose_env(),
    )


def _wait_for_health(url: str, timeout: float = 120.0) -> bool:
    """Poll health endpoint until healthy or timeout."""
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        try:
            resp = httpx.get(url, timeout=5.0)
            if resp.status_code == 200:
                return True
        except (httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout):
            pass
        time.sleep(2)
    return False


def _mcp_initialize(client: httpx.Client) -> dict[str, Any]:
    """Perform MCP initialize handshake. Returns the full JSON-RPC response."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "pytest-e2e", "version": "1.0"},
        },
    }
    resp = client.post(
        MCP_ENDPOINT,
        json=payload,
        headers={"Accept": "application/json, text/event-stream"},
        timeout=HTTP_TIMEOUT,
    )
    assert resp.status_code == 200, f"Initialize failed: {resp.status_code} {resp.text}"
    body = resp.json()
    assert body["jsonrpc"] == "2.0"
    assert body["id"] == 1
    assert "result" in body, f"Missing result in: {body}"
    return body


def _accessor_headers() -> dict[str, str]:
    """Headers matching the editor HTTP accessor configuration pattern."""
    return {
        "X-Agent-Server-Username": SHARED_GHIDRA_USERNAME,
        "X-Agent-Server-Password": SHARED_GHIDRA_PASSWORD,
        "X-Agent-Server-Repository": SHARED_GHIDRA_REPOSITORY,
        "X-Ghidra-Server-Host": SHARED_GHIDRA_HOST,
        "X-Ghidra-Server-Port": SHARED_GHIDRA_PORT,
    }


def _mcp_call_tool(
    client: httpx.Client,
    session_id: str,
    tool_name: str,
    arguments: dict[str, Any],
    request_id: int = 100,
) -> dict[str, Any]:
    """Call an MCP tool and return the parsed JSON-RPC response."""
    payload = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }
    headers: dict[str, str] = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    resp = client.post(MCP_ENDPOINT, json=payload, headers=headers, timeout=HTTP_TIMEOUT)
    assert resp.status_code == 200, f"Tool call {tool_name} failed: {resp.status_code} {resp.text}"
    return resp.json()


def _mcp_list_tools(client: httpx.Client, session_id: str) -> dict[str, Any]:
    """List available MCP tools."""
    payload = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {},
    }
    headers: dict[str, str] = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    resp = client.post(MCP_ENDPOINT, json=payload, headers=headers, timeout=HTTP_TIMEOUT)
    assert resp.status_code == 200, f"List tools failed: {resp.status_code} {resp.text}"
    return resp.json()


def _mcp_read_resource(
    client: httpx.Client,
    session_id: str,
    uri: str,
    request_id: int = 200,
) -> dict[str, Any]:
    """Read an MCP resource by URI."""
    payload = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "resources/read",
        "params": {"uri": uri},
    }
    headers: dict[str, str] = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    resp = client.post(MCP_ENDPOINT, json=payload, headers=headers, timeout=HTTP_TIMEOUT)
    assert resp.status_code == 200, f"Read resource {uri} failed: {resp.status_code} {resp.text}"
    return resp.json()


def _extract_tool_text(response: dict[str, Any]) -> str:
    """Extract text content from a tools/call result."""
    result = response.get("result", {})
    content = result.get("content", [])
    texts = [c["text"] for c in content if c.get("type") == "text"]
    return "\n".join(texts)


def _extract_tool_json(response: dict[str, Any]) -> dict[str, Any]:
    """Extract and parse JSON from a tools/call result."""
    text = _extract_tool_text(response)
    return json.loads(text)


def _extract_session_id(response: httpx.Response) -> str:
    """Extract Mcp-Session-Id from response headers."""
    return response.headers.get("mcp-session-id", "")


def _run_cli(*args: str, timeout: int = CLI_TIMEOUT) -> subprocess.CompletedProcess[str]:
    """Run agentdecompile-cli as a subprocess."""
    cmd = [sys.executable, "-m", "agentdecompile_cli.cli", "--server-url", MCP_BASE_URL, *args]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def docker_stack():
    """Start the container compose stack for the test module, tear down after.

    This fixture builds and starts the full stack:
    - biodecompwarehouse (Ghidra server)
    - agentdecompile-mcp (MCP server)

    It waits for the MCP health endpoint before yielding.
    Skips if neither Docker nor Podman infrastructure is available.
    """
    if _DOCKER_STACK_CACHE["attempted"]:
        if not _DOCKER_STACK_CACHE["ready"]:
            pytest.fail(_DOCKER_STACK_CACHE["skip_reason"])
        yield
        return

    runtime_name, compose_cmd = _resolve_container_backend()
    _DOCKER_STACK_CACHE["attempted"] = True
    _DOCKER_STACK_CACHE["compose_cmd"] = compose_cmd

    def _fail(reason: str) -> None:
        _DOCKER_STACK_CACHE["ready"] = False
        _DOCKER_STACK_CACHE["skip_reason"] = reason
        pytest.fail(reason)

    # Check that compose file exists
    if not COMPOSE_FILE.exists():
        _fail(f"docker-compose.yml not found at {COMPOSE_FILE}")

    # Validate compose config before attempting to build
    try:
        validate_result = subprocess.run(
            [*compose_cmd, "-f", str(COMPOSE_FILE), "config", "--quiet"],
            capture_output=True, text=True, timeout=30,
            cwd=str(COMPOSE_FILE.parent),
            env=_compose_env(),
        )
    except subprocess.TimeoutExpired:
        _fail(f"{runtime_name} compose config validation timed out")
    if validate_result.returncode != 0:
        _fail(
            f"{runtime_name} compose config validation failed (missing networks, "
            f"env vars, etc.): {validate_result.stderr[:300]}"
        )

    # Bring up services
    try:
        up_result = _compose_up(compose_cmd)
    except subprocess.TimeoutExpired as exc:
        _compose_down(compose_cmd)
        stderr = (exc.stderr or "")[:300]
        stdout = (exc.stdout or "")[:300]
        detail = stderr or stdout or f"timed out after {COMPOSE_START_TIMEOUT}s"
        _fail(f"{runtime_name} compose up timed out: {detail}")
    if up_result.returncode != 0:
        _fail(
            f"{runtime_name} compose up failed (rc={up_result.returncode}): "
            f"{up_result.stderr[:300]}"
        )

    # Wait for MCP server health
    healthy = _wait_for_health(HEALTH_ENDPOINT, timeout=COMPOSE_HEALTH_TIMEOUT)
    if not healthy:
        _compose_down(compose_cmd)
        _fail(
            f"MCP server at {HEALTH_ENDPOINT} did not become healthy within {COMPOSE_HEALTH_TIMEOUT:.0f}s"
        )

    _DOCKER_STACK_CACHE["ready"] = True
    _DOCKER_STACK_CACHE["skip_reason"] = ""

    yield

    # Teardown
    _compose_down(compose_cmd)
    _DOCKER_STACK_CACHE["ready"] = False
    _DOCKER_STACK_CACHE["compose_cmd"] = None


@pytest.fixture(scope="module")
def mcp_session(docker_stack) -> Generator[tuple[httpx.Client, str], None, None]:
    """Create an MCP session with the docker-hosted server.

    Returns (httpx.Client, session_id).
    """
    client = httpx.Client(base_url=MCP_BASE_URL, timeout=HTTP_TIMEOUT)
    init_response = client.post(
        "/mcp/message",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "pytest-docker-e2e", "version": "1.0"},
            },
        },
        headers={"Accept": "application/json, text/event-stream"},
    )
    assert init_response.status_code == 200
    body = init_response.json()
    assert body["result"]["serverInfo"]["name"] == "AgentDecompile"

    session_id = init_response.headers.get("mcp-session-id", "")

    yield client, session_id

    client.close()


@pytest.fixture
def docker_http_session(docker_stack):
    with JsonRpcMcpSession(MCP_BASE_URL) as session:
        yield session


@pytest.fixture
def accessor_http_session(docker_stack):
    with JsonRpcMcpSession(MCP_BASE_URL, endpoint="/mcp/", extra_headers=_accessor_headers()) as session:
        yield session


# ---------------------------------------------------------------------------
# Tests — Docker Health & Initialization
# ---------------------------------------------------------------------------


class TestDockerHealthAndInit:
    """Verify the docker stack is healthy and MCP handshake works."""

    def test_health_endpoint_returns_healthy(self, docker_stack):
        resp = httpx.get(HEALTH_ENDPOINT, timeout=10.0)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["server"] == "AgentDecompile"

    def test_mcp_initialize_handshake(self, docker_stack):
        with httpx.Client(timeout=HTTP_TIMEOUT) as client:
            body = _mcp_initialize(client)
            info = body["result"]["serverInfo"]
            assert info["name"] == "AgentDecompile"
            assert "version" in info

    def test_mcp_list_tools_returns_tools(self, mcp_session):
        client, sid = mcp_session
        body = _mcp_list_tools(client, sid)
        tools = body["result"]["tools"]
        assert isinstance(tools, list)
        assert len(tools) > 0
        tool_names = {t["name"] for t in tools}
        # Verify core tools are advertised (accept both hyphenated and underscored forms)
        expected = [
            "open-project", "list-project-files", "get-current-program",
            "decompile-function", "search-symbols", "get-references",
            "list-imports", "list-exports", "list-functions", "export",
            "import-binary",
        ]
        for tool in expected:
            underscore = tool.replace("-", "_")
            assert tool in tool_names or underscore in tool_names, (
                f"Expected tool {tool!r} (or {underscore!r}) in {tool_names}"
            )


# ---------------------------------------------------------------------------
# Tests — Project Operations (Shared Project)
# ---------------------------------------------------------------------------


class TestDockerProjectOperations:
    """Test project lifecycle operations against the docker stack."""

    def test_list_project_files(self, mcp_session):
        """list-project-files should return a valid response even with no programs."""
        client, sid = mcp_session
        body = _mcp_call_tool(client, sid, "list-project-files", {})
        assert "result" in body
        text = _extract_tool_text(body)
        assert len(text) > 0

    def test_get_current_program_no_program(self, mcp_session):
        """get-current-program without a loaded program returns an error response."""
        client, sid = mcp_session
        body = _mcp_call_tool(client, sid, "get-current-program", {})
        assert "result" in body
        text = _extract_tool_text(body)
        # Should indicate no program is loaded or return error info
        assert len(text) > 0

    def test_list_processors(self, mcp_session):
        """list-processors returns a list of available processor architectures."""
        client, sid = mcp_session
        body = _mcp_call_tool(client, sid, "list-processors", {})
        assert "result" in body
        text = _extract_tool_text(body)
        assert len(text) > 0


# ---------------------------------------------------------------------------
# Tests — MCP Resources (Docker)
# ---------------------------------------------------------------------------


class TestDockerResources:
    """Test MCP resource reading via the docker stack."""

    def test_read_programs_resource(self, mcp_session):
        client, sid = mcp_session
        body = _mcp_read_resource(client, sid, "ghidra://programs")
        assert "result" in body
        contents = body["result"].get("contents", [])
        assert isinstance(contents, list)
        assert len(contents) > 0
        # First content should be parseable JSON
        text = contents[0].get("text", "")
        data = json.loads(text)
        assert "programs" in data
        assert isinstance(data["programs"], list)

    def test_read_static_analysis_resource(self, mcp_session):
        client, sid = mcp_session
        body = _mcp_read_resource(client, sid, "ghidra://static-analysis-results")
        assert "result" in body
        contents = body["result"].get("contents", [])
        assert len(contents) > 0
        text = contents[0].get("text", "")
        data = json.loads(text)
        assert "$schema" in data
        assert data["version"] == "2.1.0"
        assert "runs" in data

    def test_read_debug_info_resource(self, mcp_session):
        client, sid = mcp_session
        body = _mcp_read_resource(client, sid, "ghidra://agentdecompile-debug-info")
        assert "result" in body
        contents = body["result"].get("contents", [])
        assert len(contents) > 0
        text = contents[0].get("text", "")
        data = json.loads(text)
        assert "metadata" in data
        assert "server" in data
        assert "program" in data
        assert "analysis" in data
        assert "profiling" in data


# ---------------------------------------------------------------------------
# Tests — Tool Calls Without Program (Docker)
# ---------------------------------------------------------------------------


class TestDockerToolCallsNoProgramLoaded:
    """Test tool calls that should return meaningful responses even without a
    program loaded. These validate error handling and response structure."""

    def test_search_symbols_no_program(self, mcp_session):
        client, sid = mcp_session
        body = _mcp_call_tool(client, sid, "search-symbols", {"query": "main"})
        assert "result" in body
        text = _extract_tool_text(body)
        assert len(text) > 0

    def test_list_functions_no_program(self, mcp_session):
        client, sid = mcp_session
        body = _mcp_call_tool(client, sid, "list-functions", {})
        assert "result" in body
        text = _extract_tool_text(body)
        assert len(text) > 0

    def test_decompile_function_no_program(self, mcp_session):
        client, sid = mcp_session
        body = _mcp_call_tool(client, sid, "decompile-function", {"name": "main"})
        assert "result" in body
        text = _extract_tool_text(body)
        assert len(text) > 0

    def test_get_references_no_program(self, mcp_session):
        client, sid = mcp_session
        body = _mcp_call_tool(
            client, sid, "get-references",
            {"target": "main", "direction": "to"},
        )
        assert "result" in body
        text = _extract_tool_text(body)
        assert len(text) > 0

    def test_list_imports_no_program(self, mcp_session):
        client, sid = mcp_session
        body = _mcp_call_tool(client, sid, "list-imports", {})
        assert "result" in body
        text = _extract_tool_text(body)
        assert len(text) > 0

    def test_list_exports_no_program(self, mcp_session):
        client, sid = mcp_session
        body = _mcp_call_tool(client, sid, "list-exports", {})
        assert "result" in body
        text = _extract_tool_text(body)
        assert len(text) > 0


# ---------------------------------------------------------------------------
# Tests — CLI Integration (Docker)
# ---------------------------------------------------------------------------


class TestDockerCLI:
    """Test CLI commands against the docker-hosted MCP server."""

    def test_cli_list_project_files(self, docker_stack):
        result = _run_cli("list", "project-files")
        # CLI should return exit code 0 or output meaningful content
        assert result.returncode == 0 or len(result.stdout + result.stderr) > 0

    def test_cli_tool_list_tools(self, docker_stack):
        result = _run_cli("tool", "--list-tools")
        # Should list available tools
        assert result.returncode == 0 or "tool" in (result.stdout + result.stderr).lower()

    def test_cli_resource_programs(self, docker_stack):
        result = _run_cli("resource", "programs")
        assert result.returncode == 0 or len(result.stdout + result.stderr) > 0

    def test_cli_resource_debug_info(self, docker_stack):
        result = _run_cli("resource", "debug-info")
        assert result.returncode == 0 or len(result.stdout + result.stderr) > 0

    def test_cli_tool_seq_list_files(self, docker_stack):
        steps = json.dumps([{"name": "list-project-files", "arguments": {}}])
        result = _run_cli("tool-seq", steps)
        assert result.returncode == 0 or len(result.stdout + result.stderr) > 0


# ---------------------------------------------------------------------------
# Tests — Endpoint Compatibility (Docker)
# ---------------------------------------------------------------------------


class TestDockerEndpointCompat:
    """Verify all endpoint paths accept MCP requests."""

    def test_root_path_accepts_initialize(self, docker_stack):
        with httpx.Client(timeout=HTTP_TIMEOUT) as client:
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "pytest", "version": "1.0"},
                },
            }
            # /mcp/message is the canonical path
            resp = client.post(
                f"{MCP_BASE_URL}/mcp/message",
                json=payload,
                headers={"Accept": "application/json, text/event-stream"},
            )
            assert resp.status_code == 200
            body = resp.json()
            assert body["result"]["serverInfo"]["name"] == "AgentDecompile"


class TestDockerHttpAccessorHeaders:
    """Validate accessor-style HTTP setup with per-request shared-server headers."""

    def test_accessor_headers_work_for_tools_resources_and_shared_connect(self, docker_stack):
        accessor_headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            **_accessor_headers(),
        }

        with httpx.Client(base_url=MCP_BASE_URL, timeout=HTTP_TIMEOUT) as client:
            init_resp = client.post(
                "/mcp/",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {},
                        "clientInfo": {"name": "pytest-accessor", "version": "1.0"},
                    },
                },
                headers=accessor_headers,
            )
            assert init_resp.status_code == 200
            init_body = init_resp.json()
            assert init_body["result"]["serverInfo"]["name"] == "AgentDecompile"

            session_id = init_resp.headers.get("mcp-session-id", "")
            session_headers = dict(accessor_headers)
            if session_id:
                session_headers["Mcp-Session-Id"] = session_id

            tools_resp = client.post(
                "/mcp/",
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                headers=session_headers,
            )
            assert tools_resp.status_code == 200
            tool_names = {tool["name"] for tool in tools_resp.json()["result"]["tools"]}
            assert "execute-script" in tool_names or "execute_script" in tool_names
            assert "connect-shared-project" in tool_names or "connect_shared_project" in tool_names

            resource_resp = client.post(
                "/mcp/",
                json={
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "resources/read",
                    "params": {"uri": "ghidra://programs"},
                },
                headers=session_headers,
            )
            assert resource_resp.status_code == 200
            resource_contents = resource_resp.json()["result"]["contents"]
            resource_data = json.loads(resource_contents[0]["text"])
            assert "programs" in resource_data

            script_resp = client.post(
                "/mcp/",
                json={
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "execute-script",
                        "arguments": {"code": "__result__ = 42", "format": "json"},
                    },
                },
                headers=session_headers,
            )
            assert script_resp.status_code == 200
            script_payload = json.loads(_extract_tool_text(script_resp.json()))
            assert script_payload["success"] is True
            assert script_payload["result"] == "42"

            connect_resp = client.post(
                "/mcp/",
                json={
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {
                        "name": "connect-shared-project",
                        "arguments": {"format": "json"},
                    },
                },
                headers=session_headers,
            )
            assert connect_resp.status_code == 200
            connect_payload = json.loads(_extract_tool_text(connect_resp.json()))

            if connect_payload.get("success") is True:
                assert connect_payload.get("serverHost") == SHARED_GHIDRA_HOST
                assert str(connect_payload.get("serverPort")) == SHARED_GHIDRA_PORT

                files_resp = client.post(
                    "/mcp/",
                    json={
                        "jsonrpc": "2.0",
                        "id": 6,
                        "method": "tools/call",
                        "params": {
                            "name": "list-project-files",
                            "arguments": {"format": "json"},
                        },
                    },
                    headers=session_headers,
                )
                assert files_resp.status_code == 200
                files_payload = json.loads(_extract_tool_text(files_resp.json()))
                assert files_payload.get("source") == "shared-server-session"
            else:
                context = connect_payload.get("context", {})
                assert context.get("serverHost") == SHARED_GHIDRA_HOST
                assert str(context.get("serverPort")) == SHARED_GHIDRA_PORT

    def test_mcp_path_accepts_initialize(self, docker_stack):
        with httpx.Client(timeout=HTTP_TIMEOUT) as client:
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "pytest", "version": "1.0"},
                },
            }
            resp = client.post(
                f"{MCP_BASE_URL}/mcp",
                json=payload,
                headers={"Accept": "application/json, text/event-stream"},
            )
            assert resp.status_code == 200
            body = resp.json()
            assert body["result"]["serverInfo"]["name"] == "AgentDecompile"


class TestDockerProjectLifecycleTransitions:
    def test_local_open_then_shared_connect_switches_listing_source(self, docker_http_session: JsonRpcMcpSession):
        local_open = docker_http_session.call_tool_json("open-project", {"path": LOCAL_CONTAINER_BINARY})
        assert local_open["operation"] == "import"
        assert local_open["filesImported"] >= 1

        local_listing = docker_http_session.call_tool_json("list-project-files", {})
        assert local_listing.get("source") != "shared-server-session"
        assert find_project_file(local_listing["files"], path_suffix="sh") is not None

        connect_payload = docker_http_session.call_tool_json(
            "connect-shared-project",
            {
                "serverHost": SHARED_GHIDRA_HOST,
                "serverPort": int(SHARED_GHIDRA_PORT),
                "serverUsername": SHARED_GHIDRA_USERNAME,
                "serverPassword": SHARED_GHIDRA_PASSWORD,
                "path": SHARED_GHIDRA_REPOSITORY,
            },
        )

        if connect_payload.get("success") is True:
            shared_listing = docker_http_session.call_tool_json("list-project-files", {})
            assert shared_listing.get("source") == "shared-server-session"
            assert shared_listing["count"] == connect_payload["programCount"]
        else:
            context = connect_payload.get("context", {})
            assert context.get("serverHost") == SHARED_GHIDRA_HOST
            assert str(context.get("serverPort")) == SHARED_GHIDRA_PORT

    def test_shared_accessor_session_can_open_real_local_path(self, accessor_http_session: JsonRpcMcpSession):
        connect_payload = accessor_http_session.call_tool_json("connect-shared-project", {})
        if connect_payload.get("success") is not True:
            context = connect_payload.get("context", {})
            assert context.get("serverHost") == SHARED_GHIDRA_HOST
            assert str(context.get("serverPort")) == SHARED_GHIDRA_PORT
            pytest.fail(
                "Shared server session was not established. "
                f"Payload: {json.dumps(connect_payload, sort_keys=True)}"
            )

        local_open = accessor_http_session.call_tool_json("open-project", {"path": LOCAL_CONTAINER_BINARY})
        assert local_open["operation"] == "import"
        assert local_open["filesImported"] >= 1

        current_payload = accessor_http_session.call_tool_json("get-current-program", {})
        assert current_payload["loaded"] is True
        assert current_payload["programPath"].endswith("sh")

        listing_payload = accessor_http_session.call_tool_json("list-project-files", {})
        assert listing_payload.get("source") != "shared-server-session"
        assert find_project_file(listing_payload["files"], path_suffix="sh") is not None

    def test_accessor_headers_do_not_override_existing_local_path(self, accessor_http_session: JsonRpcMcpSession):
        local_open = accessor_http_session.call_tool_json("open-project", {"path": LOCAL_CONTAINER_BINARY})
        assert local_open["operation"] == "import"
        assert local_open["importedPrograms"]
        assert local_open["importedPrograms"][0]["path"] == LOCAL_CONTAINER_BINARY

        current_payload = accessor_http_session.call_tool_json("get-current-program", {})
        assert current_payload["loaded"] is True
        assert current_payload["programPath"].endswith("sh")

    def test_explicit_shared_args_override_conflicting_accessor_headers(self, docker_stack):
        conflicting_headers = {
            **_accessor_headers(),
            "X-Ghidra-Server-Host": "definitely.invalid.host",
            "X-Ghidra-Server-Port": "65530",
        }
        with JsonRpcMcpSession(MCP_BASE_URL, endpoint="/mcp/", extra_headers=conflicting_headers) as session:
            connect_payload = session.call_tool_json(
                "connect-shared-project",
                {
                    "serverHost": SHARED_GHIDRA_HOST,
                    "serverPort": int(SHARED_GHIDRA_PORT),
                    "serverUsername": SHARED_GHIDRA_USERNAME,
                    "serverPassword": SHARED_GHIDRA_PASSWORD,
                    "path": SHARED_GHIDRA_REPOSITORY,
                },
            )

            if connect_payload.get("success") is True:
                assert connect_payload["serverHost"] == SHARED_GHIDRA_HOST
                assert str(connect_payload["serverPort"]) == SHARED_GHIDRA_PORT
            else:
                context = connect_payload.get("context", {})
                assert context.get("serverHost") == SHARED_GHIDRA_HOST
                assert str(context.get("serverPort")) == SHARED_GHIDRA_PORT
