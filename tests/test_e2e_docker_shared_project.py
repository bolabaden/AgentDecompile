"""E2E tests for shared-project usage via docker-compose.

These tests spawn the full docker-compose stack (ghidra Ghidra server
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
SHARED_GHIDRA_HOST = os.environ.get("AGENTDECOMPILE_TEST_GHIDRA_HOST", "ghidra")
SHARED_GHIDRA_PORT = os.environ.get("AGENTDECOMPILE_TEST_GHIDRA_PORT", "13100")
SHARED_GHIDRA_USERNAME = os.environ.get("AGENTDECOMPILE_TEST_GHIDRA_USERNAME", "")
SHARED_GHIDRA_PASSWORD = os.environ.get("AGENTDECOMPILE_TEST_GHIDRA_PASSWORD", "")
SHARED_GHIDRA_REPOSITORY = os.environ.get("AGENTDECOMPILE_TEST_GHIDRA_REPOSITORY", "")
LOCAL_CONTAINER_BINARY = os.environ.get("AGENTDECOMPILE_TEST_LOCAL_BINARY_PATH", "/bin/busybox")
LOCAL_CONTAINER_PROGRAM_NAME = Path(LOCAL_CONTAINER_BINARY).name
COMPOSE_REQUIRED_SERVICES = ("ghidra", "agentdecompile-mcp")
COMPOSE_REQUIRED_IMAGES = (
    "docker.io/bolabaden/ghidra:latest",
    "docker.io/bolabaden/agentdecompile-mcp:latest",
)

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
    env.setdefault("PUID", "1001")
    env.setdefault("PGID", "1001")
    env.setdefault("DOCKER_BUILDKIT", "1")
    env.setdefault("COMPOSE_DOCKER_CLI_BUILD", "1")
    # Ensure compose always receives a valid base image arg even when a malformed
    # ALPINE_BASE_IMAGE is inherited from the outer environment.
    override_base_image = env.get("AGENTDECOMPILE_TEST_ALPINE_BASE_IMAGE", "").strip()
    if override_base_image:
        env["ALPINE_BASE_IMAGE"] = override_base_image
    else:
        inherited_base_image = env.get("ALPINE_BASE_IMAGE", "").strip()
        if not inherited_base_image or ":" not in inherited_base_image:
            env["ALPINE_BASE_IMAGE"] = "docker.io/library/alpine:latest"
    return env


def _ensure_compose_bind_paths(env: dict[str, str]) -> None:
    """Create required host bind-mount directories for the compose stack."""
    config_root = Path(env.get("CONFIG_PATH", "./volumes")).expanduser()
    if not config_root.is_absolute():
        config_root = (COMPOSE_FILE.parent / config_root).resolve()

    biodecomp_root = config_root / "ghidra"
    for relative_path in ("bsim_datadir", "repos", "projects", "work"):
        (biodecomp_root / relative_path).mkdir(parents=True, exist_ok=True)


def _compose_up(compose_cmd: list[str]) -> subprocess.CompletedProcess[str]:
    """Start compose services (build + detached)."""
    env = _compose_env()
    _ensure_compose_bind_paths(env)
    compose_args = [*compose_cmd, "-f", str(COMPOSE_FILE), "up", "-d"]
    force_build = env.get("AGENTDECOMPILE_TEST_FORCE_BUILD", "").strip().lower() in {"1", "true", "yes", "on"}
    # Default to pulling tagged images; local source builds are opt-in because
    # some developer environments do not support the full Dockerfile feature set.
    if force_build:
        compose_args.append("--build")
    compose_args.extend(["--wait", "--wait-timeout", "180", *COMPOSE_REQUIRED_SERVICES])
    return subprocess.run(
        compose_args,
        capture_output=True,
        text=True,
        timeout=COMPOSE_START_TIMEOUT,
        cwd=str(COMPOSE_FILE.parent),
        env=env,
    )


def _compose_images_ready(runtime_executable: str, env: dict[str, str]) -> bool:
    """Return True when the required stack images already exist locally."""
    if runtime_executable == "podman":
        for image in COMPOSE_REQUIRED_IMAGES:
            result = subprocess.run(
                [runtime_executable, "image", "exists", image],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(COMPOSE_FILE.parent),
                env=env,
            )
            if result.returncode != 0:
                return False
        return True

    if runtime_executable == "docker":
        for image in COMPOSE_REQUIRED_IMAGES:
            result = subprocess.run(
                [runtime_executable, "image", "inspect", image],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(COMPOSE_FILE.parent),
                env=env,
            )
            if result.returncode != 0:
                return False
        return True

    return False


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


def _endpoint_variants() -> tuple[str, ...]:
    return ("/", "/mcp", "/mcp/", "/mcp/message", "/mcp/message/")


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


def _cli_json_output(result: subprocess.CompletedProcess[str]) -> Any:
    """Parse JSON output from a successful CLI subprocess call.

    Automatically unwraps MCP tool/resource envelopes when present.
    """
    payload = (result.stdout or "").strip() or (result.stderr or "").strip()
    assert payload, "CLI produced no output"
    data = json.loads(payload)
    # Unwrap MCP tool envelope: {"content": [{"type": "text", "text": "..."}], ...}
    if isinstance(data, dict) and "content" in data and isinstance(data["content"], list):
        for item in data["content"]:
            if isinstance(item, dict) and item.get("type") == "text":
                try:
                    return json.loads(item["text"])
                except (json.JSONDecodeError, KeyError):
                    pass
    # Unwrap MCP resource envelope: {"contents": [{"uri": "...", "text": "..."}]}
    if isinstance(data, dict) and "contents" in data and isinstance(data["contents"], list):
        for item in data["contents"]:
            if isinstance(item, dict) and "text" in item:
                try:
                    return json.loads(item["text"])
                except (json.JSONDecodeError, KeyError):
                    pass
    return data


def _normalize_cli_step_result(data: Any) -> dict[str, Any]:
    """Normalize CLI tool-seq step payloads to the underlying JSON tool result."""
    if isinstance(data, dict):
        content = data.get("content")
        if isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    text = item.get("text")
                    if isinstance(text, str):
                        try:
                            nested = json.loads(text)
                        except json.JSONDecodeError:
                            continue
                        if isinstance(nested, dict):
                            return nested
        return data
    raise AssertionError(f"Expected dict step result, got {type(data)!r}")


def _assert_cli_backend_banner(result: subprocess.CompletedProcess[str]) -> None:
    stderr_lines = [line.strip() for line in (result.stderr or "").splitlines() if line.strip()]
    assert len(stderr_lines) == 1
    assert stderr_lines[0].startswith("Backend: AgentDecompile v")
    assert "(protocol " in stderr_lines[0]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def docker_stack():
    """Start the container compose stack for the test module, tear down after.

    This fixture builds and starts the full stack:
    - ghidra (Ghidra server)
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


@pytest.fixture
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
            result = body["result"]
            info = result["serverInfo"]
            assert body["jsonrpc"] == "2.0"
            assert body["id"] == 1
            assert info["name"] == "AgentDecompile"
            assert isinstance(info["version"], str)
            assert info["version"]
            assert "capabilities" in result

    def test_mcp_list_tools_returns_tools(self, mcp_session):
        client, sid = mcp_session
        body = _mcp_list_tools(client, sid)
        tools = body["result"]["tools"]
        assert body["jsonrpc"] == "2.0"
        assert body["id"] == 2
        assert isinstance(tools, list)
        assert len(tools) >= 10
        assert len({tool["name"] for tool in tools}) == len(tools)
        for tool in tools:
            assert isinstance(tool["name"], str)
            assert tool["name"]
            assert isinstance(tool["description"], str)
            assert isinstance(tool["inputSchema"], dict)
            assert tool["inputSchema"].get("type") == "object"
        tool_names = {t["name"] for t in tools}
        # Verify core tools are advertised (accept both hyphenated and underscored forms)
        expected = [
            "open", "list-project-files", "get-current-program",
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
        body = _mcp_call_tool(client, sid, "list-project-files", {"format": "json"})
        payload = _extract_tool_json(body)

        assert payload["folder"] == "/"
        assert payload["files"] == []
        assert payload["count"] == 0
        assert payload["note"] == "No project loaded"

    def test_get_current_program_no_program(self, mcp_session):
        """get-current-program without a loaded program returns placeholder values."""
        client, sid = mcp_session
        body = _mcp_call_tool(client, sid, "get-current-program", {"format": "json"})
        payload = _extract_tool_json(body)

        # Server reports loaded=true with placeholder "unknown" values when
        # no specific program has been opened in this session.
        assert payload["loaded"] is True
        assert payload["name"] == "unknown"
        assert payload["programPath"] == "unknown"
        assert payload["functionCount"] == 0

    def test_list_processors(self, mcp_session):
        """list-processors returns processor listing information."""
        client, sid = mcp_session
        body = _mcp_call_tool(client, sid, "list-processors", {"filter": "x86", "format": "json"})
        payload = _extract_tool_json(body)

        assert payload["action"] == "list_processors"
        assert payload["filter"] == "x86"
        assert isinstance(payload["note"], str)
        assert len(payload["note"]) > 0


# ---------------------------------------------------------------------------
# Tests — MCP Resources (Docker)
# ---------------------------------------------------------------------------


class TestDockerResources:
    """Test MCP resource reading via the docker stack."""

    def test_read_programs_resource(self, mcp_session):
        client, sid = mcp_session
        body = _mcp_read_resource(client, sid, "ghidra://programs")
        contents = body["result"].get("contents", [])
        assert isinstance(contents, list)
        assert len(contents) == 1
        assert contents[0]["mimeType"] == "text/plain"
        text = contents[0].get("text", "")
        data = json.loads(text)
        assert data == {"programs": []}

    def test_read_static_analysis_resource(self, mcp_session):
        client, sid = mcp_session
        body = _mcp_read_resource(client, sid, "ghidra://static-analysis-results")
        contents = body["result"].get("contents", [])
        assert len(contents) == 1
        assert contents[0]["mimeType"] == "text/plain"
        text = contents[0].get("text", "")
        data = json.loads(text)
        assert data["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
        assert data["version"] == "2.1.0"
        assert data["runs"][0]["tool"]["driver"]["name"] == "AgentDecompile"
        assert data["runs"][0]["tool"]["driver"]["version"] == "1.0.0"
        assert data["runs"][0]["artifacts"] == []
        assert data["runs"][0]["results"] == []
        assert data["runs"][0]["properties"]["analysisComplete"] is False
        assert data["runs"][0]["properties"]["programPath"] is None
        assert data["runs"][0]["properties"]["status"] == "no_program_loaded"
        assert data["runs"][0]["properties"]["message"] == "No program loaded. Results will be available after loading a program."

    def test_read_debug_info_resource(self, mcp_session):
        client, sid = mcp_session
        body = _mcp_read_resource(client, sid, "ghidra://agentdecompile-debug-info")
        contents = body["result"].get("contents", [])
        assert len(contents) == 1
        assert contents[0]["mimeType"] == "text/plain"
        text = contents[0].get("text", "")
        data = json.loads(text)
        assert data["metadata"]["version"] == "2.0.0"
        assert data["metadata"]["agent_decompile_version"] == "1.1.0"
        assert data["server"]["status"] == "running"
        assert data["program"] == {
            "status": "no_program_loaded",
            "current_program": None,
            "programs_available": 0,
        }
        assert data["analysis"] == {
            "status": "no_program",
            "functions_count": 0,
            "strings_count": 0,
            "symbols_count": 0,
            "data_types_count": 0,
        }
        assert data["profiling"]["status"] == "available"
        assert isinstance(data["profiling"]["recent_runs"], list)
        assert data["profiling"]["run_count"] == len(data["profiling"]["recent_runs"])
        assert data["resources"]["resources_served"] == [
            "agentdecompile://debug-info",
        ]
        assert data["resources"]["cache_status"] == "enabled"


# ---------------------------------------------------------------------------
# Tests — Tool Calls Without Program (Docker)
# ---------------------------------------------------------------------------


class TestDockerToolCallsNoProgramLoaded:
    """Test tool calls that should return meaningful responses even without a
    program loaded. These validate error handling and response structure."""

    def test_search_symbols_no_program(self, mcp_session):
        client, sid = mcp_session
        body = _mcp_call_tool(client, sid, "search-symbols", {"query": "main", "format": "json"})
        payload = _extract_tool_json(body)

        assert payload["success"] is False
        assert payload["error"] == "No program loaded"
        assert payload["state"] == "no-active-program"
        assert payload["context"]["state"] == "no-active-program"
        assert isinstance(payload["nextSteps"], list)
        assert len(payload["nextSteps"]) >= 1

    def test_list_functions_no_program(self, mcp_session):
        client, sid = mcp_session
        body = _mcp_call_tool(client, sid, "list-functions", {"format": "json"})
        payload = _extract_tool_json(body)

        assert payload["success"] is False
        assert payload["error"] == "No program loaded"
        assert payload["state"] == "no-active-program"
        assert payload["context"]["state"] == "no-active-program"

    def test_decompile_function_no_program(self, mcp_session):
        client, sid = mcp_session
        body = _mcp_call_tool(client, sid, "decompile-function", {"name": "main", "format": "json"})
        payload = _extract_tool_json(body)

        assert payload["success"] is False
        assert payload["error"] == "No program loaded"
        assert payload["state"] == "no-active-program"
        assert payload["context"]["state"] == "no-active-program"

    def test_get_references_no_program(self, mcp_session):
        client, sid = mcp_session
        body = _mcp_call_tool(
            client, sid, "get-references",
            {"target": "main", "direction": "to", "format": "json"},
        )
        payload = _extract_tool_json(body)

        assert payload["success"] is False
        assert payload["error"] == "No program loaded"
        assert payload["state"] == "no-active-program"
        assert payload["context"]["state"] == "no-active-program"

    def test_list_imports_no_program(self, mcp_session):
        client, sid = mcp_session
        body = _mcp_call_tool(client, sid, "list-imports", {"format": "json"})
        payload = _extract_tool_json(body)

        assert payload["success"] is False
        assert payload["error"] == "No program loaded"
        assert payload["state"] == "no-active-program"
        assert payload["context"]["state"] == "no-active-program"

    def test_list_exports_no_program(self, mcp_session):
        client, sid = mcp_session
        body = _mcp_call_tool(client, sid, "list-exports", {"format": "json"})
        payload = _extract_tool_json(body)

        assert payload["success"] is False
        assert payload["error"] == "No program loaded"
        assert payload["state"] == "no-active-program"
        assert payload["context"]["state"] == "no-active-program"


# ---------------------------------------------------------------------------
# Tests — CLI Integration (Docker)
# ---------------------------------------------------------------------------


class TestDockerCLI:
    """Test CLI commands against the docker-hosted MCP server."""

    def test_cli_list_project_files(self, docker_stack):
        result = _run_cli("--format", "json", "list", "project-files")
        data = _cli_json_output(result)

        assert result.returncode == 0
        _assert_cli_backend_banner(result)
        assert data == {
            "folder": "/",
            "files": [],
            "count": 0,
            "note": "No project loaded",
        }

    def test_cli_tool_list_tools(self, docker_stack):
        result = _run_cli("tool", "placeholder", "--list-tools")
        lines = [line.rstrip() for line in result.stdout.splitlines() if line.strip()]

        assert result.returncode == 0
        assert (result.stderr or "").strip() == ""
        assert lines[0] == "Valid tool names:"
        assert "  open" in lines
        assert "  list-project-files" in lines
        assert "  get-current-program" in lines
        assert "  decompile-function" in lines
        assert "  sync-project" in lines

    def test_cli_resource_programs(self, docker_stack):
        result = _run_cli("--format", "json", "resource", "programs")
        data = _cli_json_output(result)

        assert result.returncode == 0
        _assert_cli_backend_banner(result)
        assert data == {"programs": []}

    def test_cli_resource_debug_info(self, docker_stack):
        result = _run_cli("--format", "json", "resource", "debug-info")
        data = _cli_json_output(result)

        assert result.returncode == 0
        _assert_cli_backend_banner(result)
        assert data["metadata"]["version"] == "2.0.0"
        assert data["metadata"]["agent_decompile_version"] == "1.1.0"
        assert data["server"]["status"] == "running"
        assert data["program"] == {
            "status": "no_program_loaded",
            "current_program": None,
            "programs_available": 0,
        }
        assert data["analysis"] == {
            "status": "no_program",
            "functions_count": 0,
            "strings_count": 0,
            "symbols_count": 0,
            "data_types_count": 0,
        }
        assert data["profiling"]["status"] == "available"
        assert isinstance(data["profiling"]["recent_runs"], list)
        assert data["profiling"]["run_count"] == len(data["profiling"]["recent_runs"])
        assert data["resources"]["resources_served"] == [
            "agentdecompile://debug-info",
        ]
        assert data["resources"]["cache_status"] == "enabled"

    def test_cli_tool_seq_list_files(self, docker_stack):
        steps = json.dumps([{"name": "list-project-files", "arguments": {}}])
        result = _run_cli("--format", "json", "tool-seq", steps)
        data = _cli_json_output(result)

        assert result.returncode == 0
        _assert_cli_backend_banner(result)
        assert data["success"] is True
        assert len(data["steps"]) == 1
        step = data["steps"][0]
        assert step["index"] == 1
        assert step["name"] == "list-project-files"
        assert step["success"] is True
        step_result = _normalize_cli_step_result(step["result"])
        assert step_result["folder"] == "/"
        assert step_result["files"] == []
        assert step_result["count"] == 0
        assert step_result["note"] == "No project loaded"


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
            assert body["jsonrpc"] == "2.0"
            assert body["id"] == 1
            assert body["result"]["serverInfo"]["name"] == "AgentDecompile"
            assert isinstance(body["result"]["serverInfo"]["version"], str)
            assert body["result"]["protocolVersion"] == "2025-11-25"
            assert isinstance(body["result"]["capabilities"], dict)


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
            assert init_body["jsonrpc"] == "2.0"
            assert init_body["id"] == 1
            assert init_body["result"]["serverInfo"]["name"] == "AgentDecompile"
            assert isinstance(init_body["result"]["serverInfo"]["version"], str)
            assert init_body["result"]["protocolVersion"] == "2025-11-25"
            assert isinstance(init_body["result"]["capabilities"], dict)

            session_id = init_resp.headers.get("mcp-session-id", "")
            assert isinstance(session_id, str)
            session_headers = dict(accessor_headers)
            if session_id:
                session_headers["Mcp-Session-Id"] = session_id

            tools_resp = client.post(
                "/mcp/",
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                headers=session_headers,
            )
            assert tools_resp.status_code == 200
            tools_body = tools_resp.json()
            assert tools_body["jsonrpc"] == "2.0"
            assert tools_body["id"] == 2
            advertised_tools = tools_body["result"]["tools"]
            assert len(advertised_tools) >= 10
            tool_names = {tool["name"] for tool in advertised_tools}
            assert "execute-script" in tool_names or "execute_script" in tool_names

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
            resource_body = resource_resp.json()
            assert resource_body["jsonrpc"] == "2.0"
            assert resource_body["id"] == 3
            resource_contents = resource_body["result"]["contents"]
            assert len(resource_contents) == 1
            assert resource_contents[0]["mimeType"] in ("application/json", "text/plain")
            resource_data = json.loads(resource_contents[0]["text"])
            assert resource_data == {"programs": []}

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
            script_body = script_resp.json()
            assert script_body["jsonrpc"] == "2.0"
            assert script_body["id"] == 4
            script_payload = json.loads(_extract_tool_text(script_body))
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
            connect_body = connect_resp.json()
            assert connect_body["jsonrpc"] == "2.0"
            assert connect_body["id"] == 5
            connect_payload = json.loads(_extract_tool_text(connect_body))

            if connect_payload.get("success") is True:
                assert connect_payload["action"] == "connect-shared-project"
                assert connect_payload["mode"] == "shared-server"
                assert connect_payload.get("serverHost") == SHARED_GHIDRA_HOST
                assert str(connect_payload.get("serverPort")) == SHARED_GHIDRA_PORT
                assert connect_payload["serverReachable"] is True
                assert connect_payload["serverConnected"] is True
                assert connect_payload["authProvided"] is bool(SHARED_GHIDRA_USERNAME and SHARED_GHIDRA_PASSWORD)
                assert connect_payload["serverUsername"] == (SHARED_GHIDRA_USERNAME or None)
                assert connect_payload["repository"] in connect_payload["availableRepositories"]
                assert connect_payload["programCount"] == len(connect_payload["programs"])
                assert connect_payload["checkedOutProgram"] is None
                assert connect_payload["checkoutError"] is None
                assert connect_payload["message"] == (
                    f"Connected to shared repository '{connect_payload['repository']}' "
                    f"and discovered {connect_payload['programCount']} items."
                )

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
                assert connect_payload["success"] is False
                assert isinstance(connect_payload["error"], str)
                context = connect_payload.get("context", {})
                assert context.get("mode") == "shared-server"
                assert context.get("serverHost") == SHARED_GHIDRA_HOST
                assert str(context.get("serverPort")) == SHARED_GHIDRA_PORT
                assert isinstance(connect_payload.get("nextSteps"), list)
                assert len(connect_payload["nextSteps"]) >= 1

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
            assert body["jsonrpc"] == "2.0"
            assert body["id"] == 1
            assert body["result"]["serverInfo"]["name"] == "AgentDecompile"
            assert isinstance(body["result"]["serverInfo"]["version"], str)
            assert body["result"]["protocolVersion"] == "2025-11-25"
            assert isinstance(body["result"]["capabilities"], dict)


class TestDockerProjectLifecycleTransitions:
    @pytest.mark.parametrize("endpoint", _endpoint_variants())
    def test_endpoint_variants_support_local_open_workflow(self, docker_stack, endpoint: str):
        with JsonRpcMcpSession(MCP_BASE_URL, endpoint=endpoint) as session:
            open_payload = session.call_tool_json("open", {"path": LOCAL_CONTAINER_BINARY})
            assert open_payload["operation"] == "import"
            assert open_payload["importedFrom"] == LOCAL_CONTAINER_BINARY
            assert open_payload["filesDiscovered"] == 1
            assert open_payload["filesImported"] == 1
            assert open_payload["groupsCreated"] == 0
            assert open_payload["maxDepthUsed"] == 16
            assert open_payload["wasRecursive"] is False
            assert open_payload["analysisRequested"] is False
            assert open_payload["errors"] == []
            assert len(open_payload["importedPrograms"]) == 1
            assert open_payload["importedPrograms"][0]["path"] == LOCAL_CONTAINER_BINARY
            assert open_payload["importedPrograms"][0]["programName"] == LOCAL_CONTAINER_PROGRAM_NAME

            current_payload = session.call_tool_json("get-current-program", {})
            assert current_payload["loaded"] is True
            assert current_payload["name"] == LOCAL_CONTAINER_PROGRAM_NAME
            assert current_payload["programPath"].endswith(LOCAL_CONTAINER_PROGRAM_NAME)
            assert current_payload["language"] != ""
            assert current_payload["compiler"] != ""
            assert isinstance(current_payload["functionCount"], int)
            assert current_payload["functionCount"] >= 0

    def test_local_open_then_shared_connect_switches_listing_source(self, docker_http_session: JsonRpcMcpSession):
        local_open = docker_http_session.call_tool_json("open", {"path": LOCAL_CONTAINER_BINARY})
        assert local_open["operation"] == "import"
        assert local_open["importedFrom"] == LOCAL_CONTAINER_BINARY
        assert local_open["filesDiscovered"] == 1
        assert local_open["filesImported"] == 1
        assert local_open["groupsCreated"] == 0
        assert local_open["maxDepthUsed"] == 16
        assert local_open["wasRecursive"] is False
        assert local_open["analysisRequested"] is False
        assert local_open["errors"] == []
        assert len(local_open["importedPrograms"]) == 1
        assert local_open["importedPrograms"][0]["path"] == LOCAL_CONTAINER_BINARY
        assert local_open["importedPrograms"][0]["programName"] == LOCAL_CONTAINER_PROGRAM_NAME

        local_listing = docker_http_session.call_tool_json("list-project-files", {})
        assert local_listing.get("source") != "shared-server-session"
        assert local_listing["folder"] == "/"
        assert local_listing["count"] >= 1
        local_program = find_project_file(local_listing["files"], path_suffix=LOCAL_CONTAINER_PROGRAM_NAME)
        assert local_program is not None
        assert local_program["name"] == LOCAL_CONTAINER_PROGRAM_NAME
        assert local_program["isDirectory"] is False
        assert local_program["type"] == "Program"

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
            assert connect_payload["action"] == "connect-shared-project"
            assert connect_payload["mode"] == "shared-server"
            assert connect_payload["serverHost"] == SHARED_GHIDRA_HOST
            assert str(connect_payload["serverPort"]) == SHARED_GHIDRA_PORT
            assert connect_payload["serverReachable"] is True
            assert connect_payload["serverConnected"] is True
            assert connect_payload["authProvided"] is bool(SHARED_GHIDRA_USERNAME and SHARED_GHIDRA_PASSWORD)
            expected_username = SHARED_GHIDRA_USERNAME or None
            assert connect_payload["serverUsername"] == expected_username
            assert connect_payload["repository"] in connect_payload["availableRepositories"]
            assert connect_payload["programCount"] == len(connect_payload["programs"])
            assert connect_payload["checkedOutProgram"] is None
            assert connect_payload["checkoutError"] is None
            assert connect_payload["message"] == (
                f"Connected to shared repository '{connect_payload['repository']}' "
                f"and discovered {connect_payload['programCount']} items."
            )
            shared_listing = docker_http_session.call_tool_json("list-project-files", {})
            assert shared_listing.get("source") == "shared-server-session"
            assert shared_listing["count"] == connect_payload["programCount"]
            assert shared_listing["folder"] == "/"
        else:
            assert connect_payload["success"] is False
            assert isinstance(connect_payload["error"], str)
            context = connect_payload.get("context", {})
            assert context.get("mode") == "shared-server"
            assert context.get("serverHost") == SHARED_GHIDRA_HOST
            assert str(context.get("serverPort")) == SHARED_GHIDRA_PORT
            assert isinstance(connect_payload.get("nextSteps"), list)

    def test_shared_accessor_session_can_open_real_local_path(self, accessor_http_session: JsonRpcMcpSession):
        connect_payload = accessor_http_session.call_tool_json("connect-shared-project", {})
        if connect_payload.get("success") is not True:
            context = connect_payload.get("context", {})
            assert connect_payload["success"] is False
            assert connect_payload["error"].startswith(
                f"Repository connection failed for {SHARED_GHIDRA_HOST}:{SHARED_GHIDRA_PORT}:"
            )
            assert connect_payload["state"] == "shared-session-unavailable"
            assert connect_payload["mode"] == "shared-server"
            assert connect_payload["tool"] == "connect_shared_project"
            assert connect_payload["provider"] == "ProjectToolProvider"
            assert context.get("mode") == "shared-server"
            assert context.get("serverHost") == SHARED_GHIDRA_HOST
            assert str(context.get("serverPort")) == SHARED_GHIDRA_PORT
            prerequisite_calls = context.get("prerequisiteCalls", [])
            assert len(prerequisite_calls) == 1
            assert prerequisite_calls[0]["tool"] == "list-project-files"
        else:
            assert connect_payload["action"] == "connect-shared-project"
            assert connect_payload["mode"] == "shared-server"
            assert connect_payload["serverHost"] == SHARED_GHIDRA_HOST
            assert str(connect_payload["serverPort"]) == SHARED_GHIDRA_PORT
            assert connect_payload["serverReachable"] is True
            assert connect_payload["serverConnected"] is True
            assert connect_payload["authProvided"] is bool(SHARED_GHIDRA_USERNAME and SHARED_GHIDRA_PASSWORD)
            expected_username = SHARED_GHIDRA_USERNAME or None
            assert connect_payload["serverUsername"] == expected_username
            assert connect_payload["repository"] in connect_payload["availableRepositories"]
            assert connect_payload["programCount"] == len(connect_payload["programs"])
            assert connect_payload["checkedOutProgram"] is None
            assert connect_payload["checkoutError"] is None
            assert connect_payload["message"] == (
                f"Connected to shared repository '{connect_payload['repository']}' "
                f"and discovered {connect_payload['programCount']} items."
            )

        local_open = accessor_http_session.call_tool_json("open", {"path": LOCAL_CONTAINER_BINARY})
        assert local_open["operation"] == "import"
        assert local_open["importedFrom"] == LOCAL_CONTAINER_BINARY
        assert local_open["filesDiscovered"] == 1
        assert local_open["filesImported"] == 1
        assert local_open["groupsCreated"] == 0
        assert local_open["maxDepthUsed"] == 16
        assert local_open["wasRecursive"] is False
        assert local_open["analysisRequested"] is False
        assert local_open["errors"] == []
        assert len(local_open["importedPrograms"]) == 1
        assert local_open["importedPrograms"][0]["path"] == LOCAL_CONTAINER_BINARY
        assert local_open["importedPrograms"][0]["programName"] == LOCAL_CONTAINER_PROGRAM_NAME

        current_payload = accessor_http_session.call_tool_json("get-current-program", {})
        assert current_payload["loaded"] is True
        assert current_payload["name"] == LOCAL_CONTAINER_PROGRAM_NAME
        assert current_payload["programPath"].endswith(LOCAL_CONTAINER_PROGRAM_NAME)
        assert current_payload["language"] != ""
        assert current_payload["compiler"] != ""
        assert isinstance(current_payload["functionCount"], int)

        listing_payload = accessor_http_session.call_tool_json("list-project-files", {})
        assert listing_payload.get("source") != "shared-server-session"
        assert listing_payload["folder"] == "/"
        listed_program = find_project_file(listing_payload["files"], path_suffix=LOCAL_CONTAINER_PROGRAM_NAME)
        assert listed_program is not None
        assert listed_program["name"] == LOCAL_CONTAINER_PROGRAM_NAME
        assert listed_program["isDirectory"] is False
        assert listed_program["type"] == "Program"

    def test_accessor_headers_do_not_override_existing_local_path(self, accessor_http_session: JsonRpcMcpSession):
        local_open = accessor_http_session.call_tool_json("open", {"path": LOCAL_CONTAINER_BINARY})
        assert local_open["operation"] == "import"
        assert local_open["importedFrom"] == LOCAL_CONTAINER_BINARY
        assert local_open["filesDiscovered"] == 1
        assert local_open["filesImported"] == 1
        assert local_open["importedPrograms"]
        assert local_open["importedPrograms"][0]["path"] == LOCAL_CONTAINER_BINARY
        assert local_open["importedPrograms"][0]["programName"] == LOCAL_CONTAINER_PROGRAM_NAME

        current_payload = accessor_http_session.call_tool_json("get-current-program", {})
        assert current_payload["loaded"] is True
        assert current_payload["name"] == LOCAL_CONTAINER_PROGRAM_NAME
        assert current_payload["programPath"].endswith(LOCAL_CONTAINER_PROGRAM_NAME)

    def test_checkout_status_reports_local_only_state_after_local_open(self, docker_http_session: JsonRpcMcpSession):
        docker_http_session.call_tool_json("open", {"path": LOCAL_CONTAINER_BINARY})

        checkout_payload = docker_http_session.call_tool_json("checkout-status", {})
        assert checkout_payload["action"] == "checkout_status"
        assert checkout_payload["program"] == LOCAL_CONTAINER_PROGRAM_NAME
        assert checkout_payload["is_versioned"] is False
        assert checkout_payload["is_checked_out"] is False
        assert checkout_payload["is_exclusive"] is False
        assert checkout_payload["modified_since_checkout"] is False
        assert checkout_payload["can_checkout"] is False
        assert checkout_payload["can_checkin"] is False
        assert checkout_payload["latest_version"] is None
        assert checkout_payload["current_version"] is None
        assert checkout_payload["checkout_status"] is None
        assert checkout_payload["versionControlEnabled"] is False
        assert checkout_payload["note"] == "Program is local-only. Shared checkout/checkin is unavailable until the program exists in a shared Ghidra repository."

    def test_local_sync_project_uses_documented_local_save_modes_after_open(self, docker_http_session: JsonRpcMcpSession):
        docker_http_session.call_tool_json("open", {"path": LOCAL_CONTAINER_BINARY})

        push_payload = docker_http_session.call_tool_json("sync-project", {"mode": "push"})
        assert push_payload["operation"] == "sync-project"
        assert push_payload["mode"] == "push"
        assert push_payload["direction"] == "local-save"
        assert push_payload["repository"] == "local-project"
        assert isinstance(push_payload["requested"], int)
        assert isinstance(push_payload["transferred"], int)
        assert isinstance(push_payload["skipped"], int)
        assert isinstance(push_payload["errors"], list)
        assert push_payload["note"] == "No shared server session. Performed local project save."
        assert push_payload["success"] is (len(push_payload["errors"]) == 0)

        bidirectional_payload = docker_http_session.call_tool_json("sync-project", {"mode": "bidirectional"})
        assert bidirectional_payload["operation"] == "sync-project"
        assert bidirectional_payload["mode"] == "bidirectional"
        assert bidirectional_payload["direction"] == "local-save-only"
        assert bidirectional_payload["repository"] == "local-project"
        assert isinstance(bidirectional_payload["requested"], int)
        assert isinstance(bidirectional_payload["transferred"], int)
        assert isinstance(bidirectional_payload["skipped"], int)
        assert isinstance(bidirectional_payload["errors"], list)
        assert bidirectional_payload["note"] == "No shared server session. Only local save was performed (pull requires a shared server connection)."
        assert bidirectional_payload["success"] is (len(bidirectional_payload["errors"]) == 0)

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
                assert connect_payload["action"] == "connect-shared-project"
                assert connect_payload["mode"] == "shared-server"
                assert connect_payload["serverHost"] == SHARED_GHIDRA_HOST
                assert str(connect_payload["serverPort"]) == SHARED_GHIDRA_PORT
                assert connect_payload["authProvided"] is bool(SHARED_GHIDRA_USERNAME and SHARED_GHIDRA_PASSWORD)
                assert connect_payload["serverUsername"] == (SHARED_GHIDRA_USERNAME or None)
                assert connect_payload["checkedOutProgram"] is None
                assert connect_payload["checkoutError"] is None
                assert connect_payload["message"] == (
                    f"Connected to shared repository '{connect_payload['repository']}' "
                    f"and discovered {connect_payload['programCount']} items."
                )
            else:
                assert connect_payload["success"] is False
                assert isinstance(connect_payload["error"], str)
                context = connect_payload.get("context", {})
                assert context.get("mode") == "shared-server"
                assert context.get("serverHost") == SHARED_GHIDRA_HOST
                assert str(context.get("serverPort")) == SHARED_GHIDRA_PORT

    def test_cli_tool_seq_keeps_state_for_documented_local_container_workflow(self, docker_stack):
        steps = json.dumps(
            [
                {"name": "open", "arguments": {"path": LOCAL_CONTAINER_BINARY, "format": "json"}},
                {"name": "get-current-program", "arguments": {"format": "json"}},
                {"name": "list-project-files", "arguments": {"format": "json"}},
                {"name": "checkout-status", "arguments": {"format": "json"}},
            ]
        )
        result = _run_cli("--format", "json", "tool-seq", steps)
        assert result.returncode == 0, result.stderr or result.stdout
        payload = _cli_json_output(result)

        assert payload["success"] is True
        assert len(payload["steps"]) == 4
        assert payload["steps"][0]["index"] == 1
        assert payload["steps"][1]["index"] == 2
        assert payload["steps"][2]["index"] == 3
        assert payload["steps"][3]["index"] == 4
        assert payload["steps"][0]["name"] == "open"
        assert payload["steps"][1]["name"] == "get-current-program"
        assert payload["steps"][2]["name"] == "list-project-files"
        assert payload["steps"][3]["name"] == "checkout-status"
        assert payload["steps"][0]["success"] is True
        assert payload["steps"][1]["success"] is True
        assert payload["steps"][2]["success"] is True
        assert payload["steps"][3]["success"] is True

        open_payload = _normalize_cli_step_result(payload["steps"][0]["result"])
        current_payload = _normalize_cli_step_result(payload["steps"][1]["result"])
        listing_payload = _normalize_cli_step_result(payload["steps"][2]["result"])
        checkout_payload = _normalize_cli_step_result(payload["steps"][3]["result"])

        assert open_payload["operation"] == "import"
        assert open_payload["importedFrom"] == LOCAL_CONTAINER_BINARY
        assert open_payload["filesDiscovered"] == 1
        assert open_payload["filesImported"] == 1
        assert open_payload["groupsCreated"] == 0
        assert open_payload["maxDepthUsed"] == 16
        assert open_payload["wasRecursive"] is False
        assert open_payload["analysisRequested"] is False
        assert open_payload["errors"] == []
        assert len(open_payload["importedPrograms"]) == 1
        assert open_payload["importedPrograms"][0]["path"] == LOCAL_CONTAINER_BINARY
        assert open_payload["importedPrograms"][0]["programName"] == LOCAL_CONTAINER_PROGRAM_NAME

        assert current_payload["loaded"] is True
        assert current_payload["name"] == LOCAL_CONTAINER_PROGRAM_NAME
        assert current_payload["programPath"].endswith(LOCAL_CONTAINER_PROGRAM_NAME)
        assert current_payload["language"] != ""
        assert current_payload["compiler"] != ""
        assert isinstance(current_payload["functionCount"], int)
        assert current_payload["functionCount"] >= 0

        assert listing_payload["folder"] == "/"
        assert listing_payload["count"] >= 1
        listed_program = find_project_file(listing_payload["files"], path_suffix=LOCAL_CONTAINER_PROGRAM_NAME)
        assert listed_program is not None
        assert listed_program["name"] == LOCAL_CONTAINER_PROGRAM_NAME
        assert listed_program["isDirectory"] is False
        assert listed_program["type"] == "Program"

        assert checkout_payload["action"] == "checkout_status"
        assert checkout_payload["program"] == LOCAL_CONTAINER_PROGRAM_NAME
        assert checkout_payload["is_versioned"] is False
        assert checkout_payload["is_checked_out"] is False
        assert checkout_payload["is_exclusive"] is False
        assert checkout_payload["modified_since_checkout"] is False
        assert checkout_payload["can_checkout"] is False
        assert checkout_payload["can_checkin"] is False
        assert checkout_payload["latest_version"] is None
        assert checkout_payload["current_version"] is None
        assert checkout_payload["checkout_status"] is None
        assert checkout_payload["versionControlEnabled"] is False
        assert checkout_payload["note"] == "Program is local-only. Shared checkout/checkin is unavailable until the program exists in a shared Ghidra repository."

    def test_cli_raw_tool_open_project_matches_documented_usage(self, docker_stack):
        result = _run_cli(
            "--format",
            "json",
            "tool",
            "open",
            json.dumps({"path": LOCAL_CONTAINER_BINARY, "format": "json"}),
        )
        assert result.returncode == 0, result.stderr or result.stdout
        payload = _cli_json_output(result)
        assert payload["operation"] == "import"
        assert payload["importedFrom"] == LOCAL_CONTAINER_BINARY
        assert payload["filesDiscovered"] == 1
        assert payload["filesImported"] == 1
        assert payload["groupsCreated"] == 0
        assert payload["maxDepthUsed"] == 16
        assert payload["wasRecursive"] is False
        assert payload["analysisRequested"] is False
        assert payload["errors"] == []
        assert len(payload["importedPrograms"]) == 1
        assert payload["importedPrograms"][0]["path"] == LOCAL_CONTAINER_BINARY
        assert payload["importedPrograms"][0]["programName"] == LOCAL_CONTAINER_PROGRAM_NAME
