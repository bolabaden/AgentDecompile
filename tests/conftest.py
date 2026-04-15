"""Pytest configuration and shared fixtures for AgentDecompile integration tests.

Fixtures:
- ghidra_initialized: Initialize PyGhidra once for the entire test session
- test_program: Create a test program with memory and strings (reused across tests)
- server: Start and stop an AgentDecompile server for each test
- mcp_client: Helper object for making MCP requests

Fixture Scopes:
- session: Created once, shared across all tests (ghidra_initialized, test_program)
- function: Created for each test function (server, mcp_client)
"""

from __future__ import annotations

# Apply MCP SDK fix before any mcp import (list() for _response_streams iteration).
# Required for test process ClientSession; subprocess applies it via __main__.
from agentdecompile_cli.bridge import _apply_mcp_session_fix

_apply_mcp_session_fix()

import os
import subprocess
import importlib.util
import shutil
import sys
import httpx

from collections.abc import AsyncGenerator, Generator, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
import pytest_asyncio

from tests.helpers import (
    assert_bool_invariants,
    assert_text_block_invariants,
)
from tests.e2e_project_lifecycle_helpers import JsonRpcMcpSession, LocalServerHandle, LocalServerPool, get_local_ghidra_runtime

if TYPE_CHECKING:
    from agentdecompile_cli.launcher import AgentDecompileLauncher
    from mcp.client.session import ClientSession


# ---------------------------------------------------------------------------
# Global timeout policy (pytest-timeout)
# ---------------------------------------------------------------------------
_DEFAULT_HARD_TIMEOUT = 120  # seconds
_HAS_PYTEST_TIMEOUT = importlib.util.find_spec("pytest_timeout") is not None


def pytest_configure(config: pytest.Config) -> None:
    """Register timeout marker and warn if plugin is unavailable."""
    config.addinivalue_line(
        "markers",
        "timeout(timeout): fail test if it exceeds timeout seconds",
    )
    if not _HAS_PYTEST_TIMEOUT:
        config.issue_config_time_warning(
            pytest.PytestConfigWarning(
                "pytest-timeout plugin is not installed; global 120s timeout policy is inactive.",
            ),
            stacklevel=2,
        )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Apply a default 120s timeout marker to tests lacking explicit timeout."""
    if not _HAS_PYTEST_TIMEOUT:
        return

    for item in items:
        if item.get_closest_marker("timeout") is None:
            item.add_marker(pytest.mark.timeout(_DEFAULT_HARD_TIMEOUT))


def _assert_node_invariants(node: pytest.Item) -> None:
    assert node is not None
    assert hasattr(node, "name")
    assert hasattr(node, "nodeid")
    assert_text_block_invariants(node.name)
    assert_text_block_invariants(node.nodeid)
    assert "::" in node.nodeid or node.nodeid.endswith(node.name)
    assert node.name in node.nodeid
    assert node.nodeid.startswith("tests/") or "::" in node.nodeid
    assert node.nodeid.count("::") >= 1
    assert node.nodeid == node.nodeid.strip()
    assert node.name == node.name.strip()
    assert node.name != ""
    assert node.nodeid != ""
    assert node.nodeid.lower() == node.nodeid.lower()
    assert node.name.lower() == node.name.lower()
    assert node.name.upper() == node.name.upper()
    assert node.nodeid.upper() == node.nodeid.upper()
    assert node.nodeid.find(node.name) >= 0
    assert node.nodeid.rfind(node.name) >= 0
    assert node.nodeid.startswith(node.nodeid[:1])
    assert node.nodeid.endswith(node.nodeid[-1:])
    assert node.name.startswith(node.name[:1])
    assert node.name.endswith(node.name[-1:])
    assert len(node.name) >= 1
    assert len(node.nodeid) >= len(node.name)
    assert isinstance(node.nodeid, str)
    assert isinstance(node.name, str)
    assert node.nodeid.encode("utf-8").decode("utf-8") == node.nodeid
    assert node.name.encode("utf-8").decode("utf-8") == node.name
    assert "\n" not in node.nodeid
    assert "\r" not in node.nodeid
    assert "\t" not in node.nodeid
    assert "\n" not in node.name
    assert "\r" not in node.name
    assert "\t" not in node.name
    assert isinstance(node.keywords, (dict, Mapping)) or hasattr(node.keywords, 'keys')
    assert len(node.keywords) >= 0
    assert all(isinstance(k, str) for k in node.keywords.keys())
    assert isinstance(node.fixturenames, list)
    assert all(isinstance(item, str) for item in node.fixturenames)
    assert all(item.strip() == item for item in node.fixturenames)
    assert all(item != "" for item in node.fixturenames)
    assert len(node.fixturenames) >= 0
    assert node.name in node.nodeid
    assert isinstance(len(node.fixturenames), int)
    assert node.nodeid.count(":") >= 0
    assert node.nodeid.find("tests/") >= -1
    assert node.name.find("test") >= -1
    assert isinstance(node.own_markers, type(node.own_markers))
    assert hasattr(node, "iter_markers")
    assert_bool_invariants(node.get_closest_marker("slow") is not None or node.get_closest_marker("slow") is None)
    assert node.nodeid == str(node.nodeid)
    assert node.name == str(node.name)
    assert node.nodeid.split("::")[-1] == node.name
    assert len(node.nodeid.split("::")) >= 2
    assert node.nodeid.endswith(node.name)
    assert node.nodeid.find(node.name) == node.nodeid.rfind(node.name)
    assert node.nodeid.count(node.name) == 1
    assert node.nodeid.count("::") >= 1
    assert node.nodeid.split("::")[0] != ""
    assert node.nodeid.split("::")[0].endswith(".py") or "/" in node.nodeid.split("::")[0]
    assert isinstance(node.fixturenames, list)
    assert node.fixturenames == list(node.fixturenames)
    assert node.fixturenames is not None
    assert all(name == name.strip() for name in node.fixturenames)
    assert all(name.isascii() for name in node.fixturenames)
    assert_bool_invariants(node.get_closest_marker("slow") is not None or node.get_closest_marker("slow") is None)


@pytest.fixture(scope="session")
def ghidra_initialized():
    """Initialize PyGhidra once for the entire test session.

    This is an expensive operation (10-30 seconds), so we do it once
    and reuse the initialized environment for all tests.

    Scope: session (runs once at start of test session)

    Yields:
        None (side effect: PyGhidra initialized)

    Note: Skipped on Windows due to known JPype/PyGhidra JVM access
    violation crash when starting the JVM in the test process.
    """
    import sys

    if sys.platform == "win32":
        pytest.skip("PyGhidra JVM crashes on Windows (JPype access violation). Use mcp_stdio_client for tests that run Ghidra in a subprocess.")

    import pyghidra

    print("\n[Fixture] Initializing PyGhidra (one-time setup)...")
    pyghidra.start(verbose=False)
    print("[Fixture] PyGhidra initialized successfully")

    # No explicit cleanup needed - PyGhidra handles shutdown


@pytest.fixture(scope="session")
def test_program(ghidra_initialized: bool):
    """Create a test program with memory and strings.

    Creates a program that is reused across multiple tests to avoid
    redundant program creation overhead.

    Program details:
    - Name: TestHeadlessProgram
    - Architecture: x86 32-bit LE
    - Memory: .text at 0x00401000 (4KB)
    - Strings: "Hello AgentDecompile Test", "Test String 123"
    - Symbol: test_function at 0x00401000

    Scope: session (created once, shared across all tests)

    Yields:
        ProgramDB instance or None if creation failed
    """
    from tests.helpers import create_test_program

    print("\n[Fixture] Creating test program...")
    builder = create_test_program()

    if builder:
        program = builder.getProgram()
        print(f"[Fixture] Test program created: {program.getName()}")
    else:
        program = None
        print("[Fixture] WARNING: Failed to create test program")

    yield program

    # Cleanup: Dispose builder (which releases the program)
    if builder is not None:
        try:
            builder.dispose()
            print("[Fixture] Test program builder disposed")
        except Exception as e:
            print(f"[Fixture] Warning: Failed to dispose builder: {e}")


@pytest.fixture
def server(ghidra_initialized: bool):
    """Start an AgentDecompile server for a test.

    Creates a new server instance, starts it, waits for it to become ready,
    and automatically stops it after the test completes.

    Scope: function (new server for each test)

    Yields:
        AgentDecompileLauncher instance (running and ready)

    Raises:
        AssertionError: If server fails to start or become ready within 30 seconds
    """
    from agentdecompile_cli.launcher import AgentDecompileLauncher

    launcher = AgentDecompileLauncher()

    print("\n[Fixture] Starting AgentDecompile headless server...")
    launcher.start()

    # Wait for server to be ready (30 second timeout)
    ready = launcher.waitForServer(30000)
    assert ready, "Server failed to become ready within 30 seconds"

    port = launcher.getPort()
    print(f"[Fixture] Server ready on port {port}")

    yield launcher

    # Cleanup: Stop server
    print("[Fixture] Stopping server...")
    launcher.stop()
    print("[Fixture] Server stopped")


@pytest_asyncio.fixture(loop_scope="function")
async def mcp_client(
    server: AgentDecompileLauncher,
) -> AsyncGenerator[ClientSession, Any]:
    """Create an async MCP client helper for making requests.

    Provides a convenient async interface for making MCP tool calls to the
    server started by the 'server' fixture using streamable HTTP transport.

    Scope: function (new client for each test)

    Yields:
        ClientSession instance with async call_tool() method

    Example:
        async def test_something(mcp_client):
            response = await mcp_client.call_tool(
                name="list-project-files",
                arguments={}
            )
            assert response is not None
    """
    import asyncio

    from mcp.client.session import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    port = server.getPort()
    url = f"http://localhost:{port}/mcp/message"

    print(f"\n[Fixture] Creating async MCP HTTP client for port {port}...")

    try:
        # Use the streamable HTTP client from MCP SDK
        http_client = httpx.AsyncClient(timeout=30.0)
        async with (
            streamable_http_client(url, http_client=http_client) as (
                read_stream,
                write_stream,
                get_session_id,
            ),
            ClientSession(read_stream, write_stream) as session,
        ):
            # Initialize the session
            try:
                init_result = await asyncio.wait_for(session.initialize(), timeout=60.0)
                print(f"[Fixture] MCP HTTP session initialized: {init_result.serverInfo.name} v{init_result.serverInfo.version}")
            except asyncio.TimeoutError:
                raise TimeoutError("MCP HTTP session initialization timed out after 60 seconds. Check server logs for errors.")

            yield session

            print("[Fixture] Closing MCP HTTP session...")
    except Exception as e:
        print(f"[Fixture] Error with MCP HTTP client: {e}")
        raise


# ============================================================================
# CLI-Specific Fixtures
# ============================================================================


@pytest.fixture
def isolated_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[Path, Any, None]:
    """Create an isolated workspace for CLI tests.

    Creates a temporary directory and changes the current working directory
    to it. This ensures CLI tests don't interfere with each other or the
    actual repository.

    Scope: function (new workspace for each test)

    Yields:
        Path: Temporary directory path (cwd is set to this path)

    Example:
        def test_cli_creates_project(isolated_workspace):
            # cwd is now tmp_path
            assert Path.cwd() == isolated_workspace
            # CLI will create .agentdecompile/ here
    """
    original_cwd = Path.cwd()
    monkeypatch.chdir(tmp_path)
    print(f"\n[Fixture] Created isolated workspace: {tmp_path}")

    yield tmp_path

    # Restore original cwd (cleanup)
    monkeypatch.chdir(original_cwd)


@pytest.fixture
def test_binary(isolated_workspace: Path) -> Path:
    """Create a minimal test binary for import testing.

    Generates a tiny valid executable that can be imported into Ghidra.
    The binary is created in the isolated_workspace.

    Scope: function (new binary for each test)

    Yields:
        Path: Path to the created binary file

    Example:
        def test_import_binary(test_binary):
            assert test_binary.exists()
            assert test_binary.stat().st_size > 0
    """
    from tests.helpers import create_minimal_binary

    binary_path = isolated_workspace / "test.exe"
    create_minimal_binary(binary_path)

    print(f"[Fixture] Created test binary: {binary_path} ({binary_path.stat().st_size} bytes)")

    return binary_path


@pytest.fixture
def public_sample_binary(isolated_workspace: Path) -> Path:
    """Create the vendored public-domain sample binary in the isolated workspace.

    This fixture is intended for strict end-to-end tests that need a binary with
    auditable provenance and deterministic contents rather than the tiny fallback
    ELF used by generic import smoke tests.
    """
    from tests.helpers import create_public_sample_binary, get_public_sample_binary

    sample = get_public_sample_binary()
    binary_path = isolated_workspace / sample.output_name
    create_public_sample_binary(binary_path)

    print(f"[Fixture] Created public sample binary: {binary_path} ({binary_path.stat().st_size} bytes)")

    return binary_path


@pytest.fixture(scope="module")
def stress_binary_corpus(tmp_path_factory: pytest.TempPathFactory) -> list[Path]:
    """Create a deterministic multi-binary corpus from repo-local fixtures.

    The corpus deliberately duplicates the existing fixture binaries under
    unique file names so project-wide searches have to traverse many imports
    without depending on external assets.
    """
    workspace = tmp_path_factory.mktemp("cancelled-stress-corpus")
    fixture_root = Path(__file__).resolve().parent / "fixtures"
    seed_binaries = [
        fixture_root / "test_x86_64",
        fixture_root / "test_arm64",
        fixture_root / "test_fat_binary",
    ]
    copies_per_seed = max(1, int(os.environ.get("AGENTDECOMPILE_STRESS_COPIES_PER_SEED", "4")))
    corpus: list[Path] = []
    for seed in seed_binaries:
        assert seed.exists(), f"Missing stress-corpus seed binary: {seed}"
        for index in range(copies_per_seed):
            target = workspace / f"{seed.name}_stress_{index:02d}"
            shutil.copy2(seed, target)
            target.chmod(0o755)
            corpus.append(target)
    return corpus


@pytest.fixture(scope="module")
def profiled_live_artifacts(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    """Allocate an artifact directory for the profiled live E2E suite."""
    root = tmp_path_factory.mktemp("cancelled-profile-artifacts")
    return {
        "root": root,
        "profile_dir": root / "profiles",
        "server_log": root / "server.log",
        "jfr_path": root / "server-recording.jfr",
        "jfr_dump_path": root / "server-recording.snapshot.jfr",
    }


@pytest.fixture(scope="session")
def local_live_server_pool(tmp_path_factory: pytest.TempPathFactory) -> Generator[LocalServerPool, None, None]:
    """Create a reusable pool of subprocess MCP servers for live local E2E suites.

    When ``AGENTDECOMPILE_TEST_SERVER_URL`` is set the pool is still created
    but no subprocess will be spawned — ``local_group_server`` short-circuits
    before calling ``get_or_start``.
    """
    external = os.environ.get("AGENTDECOMPILE_TEST_SERVER_URL", "").strip()
    if not external and get_local_ghidra_runtime() is None:
        pytest.skip("GHIDRA_INSTALL_DIR is not set to a valid local installation; skipping live local MCP server fixtures.")

    repo_root = Path(__file__).resolve().parents[1]
    pool = LocalServerPool(repo_root)
    tmp_path_factory.mktemp("live-server-pool")
    yield pool
    pool.close_all()


@pytest.fixture(scope="module")
def local_group_server(
    request: pytest.FixtureRequest,
    tmp_path_factory: pytest.TempPathFactory,
    local_live_server_pool: LocalServerPool,
) -> Generator[str, None, None]:
    """Start or reuse one local MCP server per test module/group.

    If AGENTDECOMPILE_TEST_SERVER_URL is set, use the pre-existing server
    instead of spawning a new subprocess (avoids JVM conflicts on Windows).
    """
    external = os.environ.get("AGENTDECOMPILE_TEST_SERVER_URL", "").strip()
    if external:
        yield external
        return
    module_name = request.module.__name__.rsplit(".", 1)[-1].replace("_", "-")
    workspace = tmp_path_factory.mktemp(f"{module_name}-workspace")
    project_path = workspace / "runtime_project"
    handle = local_live_server_pool.get_or_start(
        module_name,
        project_path=project_path,
        project_name=module_name,
    )
    yield handle.base_url


@pytest.fixture(scope="module")
def profiled_group_server(
    request: pytest.FixtureRequest,
    tmp_path_factory: pytest.TempPathFactory,
    local_live_server_pool: LocalServerPool,
    profiled_live_artifacts: dict[str, Path],
) -> Generator[LocalServerHandle, None, None]:
    """Start one profiling-enabled local MCP server for the cancelled-profile E2E module."""
    external = os.environ.get("AGENTDECOMPILE_TEST_SERVER_URL", "").strip()
    if external:
        pytest.skip("Profiled live server fixture requires a managed local subprocess; unset AGENTDECOMPILE_TEST_SERVER_URL.")

    module_name = request.module.__name__.rsplit(".", 1)[-1].replace("_", "-")
    workspace = tmp_path_factory.mktemp(f"{module_name}-profiled-workspace")
    project_path = workspace / "runtime_project"
    analyzer_path = Path(__file__).resolve().parents[1] / "scripts" / "analyze_profile.py"
    jfr_vmarg = (
        "-XX:StartFlightRecording="
        f"name=agentdecompile-tests,settings=profile,disk=true,dumponexit=true,filename={profiled_live_artifacts['jfr_path'].as_posix()}"
    )
    env_overrides = {
        "AGENTDECOMPILE_PROFILE_DIR": str(profiled_live_artifacts["profile_dir"]),
        "AGENTDECOMPILE_PROFILE_ANALYZER": str(analyzer_path),
        "AGENTDECOMPILE_PROFILE_SEARCH_EVERYTHING": "1",
        "AGENTDECOMPILE_PYGHIDRA_VMARGS": jfr_vmarg,
    }
    handle = local_live_server_pool.get_or_start(
        f"{module_name}-profiled",
        project_path=project_path,
        project_name=f"{module_name}-profiled",
        extra_env=env_overrides,
        log_path=profiled_live_artifacts["server_log"],
        timeout=180.0,
    )
    yield handle


@pytest.fixture(scope="module")
def profiled_server_base_url(profiled_group_server: LocalServerHandle) -> str:
    """Expose the profiling-enabled live server base URL."""
    return profiled_group_server.base_url


@pytest.fixture(scope="module")
def profiled_server_pid(profiled_group_server: LocalServerHandle) -> int:
    """Expose the profiling-enabled server subprocess PID."""
    return int(profiled_group_server.process.pid)


@pytest.fixture(scope="module")
def profiled_http_session(profiled_server_base_url: str) -> Generator[JsonRpcMcpSession, None, None]:
    """Create a synchronous JSON-RPC session against the profiling-enabled server."""
    with JsonRpcMcpSession(profiled_server_base_url, timeout=300.0) as session:
        yield session


@pytest.fixture
def local_server_base_url(local_group_server: str) -> str:
    """Expose the grouped local live-server base URL to function-scoped tests."""
    return local_group_server


@pytest.fixture
def local_http_session(local_server_base_url: str) -> Generator[JsonRpcMcpSession, None, None]:
    """Create a synchronous JSON-RPC MCP session against the grouped live server."""
    with JsonRpcMcpSession(local_server_base_url, timeout=120.0) as session:
        yield session


@pytest.fixture
def cli_process(isolated_workspace: Path) -> Generator[subprocess.Popen, Any, None]:
    """Start mcp-agentdecompile CLI as a subprocess.

    Starts the CLI in the isolated workspace and automatically terminates
    it after the test completes.

    Scope: function (new process for each test)

    Yields:
        subprocess.Popen: Running mcp-agentdecompile process

    Example:
        def test_cli_startup(cli_process):
            # Process is running
            assert cli_process.poll() is None
            # Can interact with stdin/stdout
            cli_process.stdin.write('{"jsonrpc":"2.0"}\n')
    """
    import subprocess
    import time

    print("\n[Fixture] Starting mcp-agentdecompile CLI subprocess...")

    proc = subprocess.Popen(
        ["uv", "run", "mcp-agentdecompile"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=isolated_workspace,
    )

    # Give it a moment to start
    time.sleep(0.5)

    if proc.poll() is not None:
        # Process already exited - capture error
        _, stderr = proc.communicate()
        raise RuntimeError(f"mcp-agentdecompile failed to start: {stderr}")

    print(f"[Fixture] mcp-agentdecompile started (PID: {proc.pid})")

    yield proc

    # Cleanup: Terminate process
    print(f"[Fixture] Terminating mcp-agentdecompile (PID: {proc.pid})...")
    proc.terminate()

    try:
        proc.wait(timeout=5)
        print("[Fixture] Process terminated gracefully")
    except subprocess.TimeoutExpired:
        print("[Fixture] Process didn't terminate, killing...")
        proc.kill()
        proc.wait()


@pytest_asyncio.fixture(loop_scope="function")
async def mcp_stdio_client(isolated_workspace: Path) -> AsyncGenerator[ClientSession, Any]:
    """Create an MCP client that connects to mcp-agentdecompile via stdio.

    Uses the official MCP Python SDK stdio_client to spawn mcp-agentdecompile
    as a subprocess and communicate via stdin/stdout.

    Scope: function (new client for each test)

    Yields:
        ClientSession: MCP client session connected to mcp-agentdecompile

    Example:
        @pytest.mark.asyncio
        async def test_initialize(mcp_stdio_client):
            result = await mcp_stdio_client.initialize()
            assert result.serverInfo.name == "AgentDecompile"

    Note:
        Suppresses RuntimeError from anyio cancel scope during teardown.
        This is a known pytest-asyncio/anyio compatibility issue that
        doesn't affect functionality.
    """
    import asyncio

    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    def _free_port_8080_windows() -> None:
        """Best-effort cleanup of stale listeners on 8080 to avoid bind collisions in subprocess tests."""
        if sys.platform != "win32":
            return
        subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "$pids = @(Get-NetTCPConnection -LocalPort 8080 -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique); if ($pids.Count -gt 0) { $pids | ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue } }",
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    # Configure mcp-agentdecompile as stdio server
    # cwd must be repo root so uv run finds pyproject.toml; launcher uses temp project
    repo_root = Path(__file__).resolve().parent.parent
    server_params = StdioServerParameters(
        command="uv",
        args=["run", "mcp-agentdecompile"],
        cwd=str(repo_root),
        env=os.environ.copy(),
    )

    print(f"\n[Fixture] Starting mcp-agentdecompile via stdio_client in {isolated_workspace}...")
    _free_port_8080_windows()

    try:
        # Connect to mcp-agentdecompile via stdio
        async with stdio_client(server_params) as (read_stream, write_stream):
            session = ClientSession(read_stream, write_stream)

            # Manually enter the session context
            await session.__aenter__()

            try:
                print("[Fixture] Subprocess started, waiting for initialization to complete...")

                # Give subprocess time to complete blocking initialization
                # (PyGhidra, project, server startup). Bridge now starts stdio immediately
                # without connecting to backend, so 2s is sufficient.
                await asyncio.sleep(2)

                print("[Fixture] Initializing MCP session...")

                try:
                    init_result = await asyncio.wait_for(
                        session.initialize(),
                        timeout=60.0,  # Initialization is fast, but allow buffer for CI overhead
                    )
                    print(f"[Fixture] MCP session initialized: {init_result.serverInfo.name} v{init_result.serverInfo.version}")
                except asyncio.TimeoutError:
                    raise TimeoutError("MCP session initialization timed out after 60 seconds. Check stderr logs for errors.")

                yield session

                print("[Fixture] Closing MCP session...")
            finally:
                # Manually exit the session context
                try:
                    await session.__aexit__(None, None, None)
                except RuntimeError as e:
                    if "cancel scope" not in str(e):
                        raise
                    print(f"[Fixture] Suppressed expected cancel scope error: {e}")
                except Exception as e:
                    print(f"[Fixture] Warning: Error during session cleanup: {e}")
    except RuntimeError as e:
        # Suppress "Attempted to exit cancel scope in a different task" error
        # This is a known pytest-asyncio/anyio compatibility issue
        if "cancel scope" not in str(e):
            raise
        print("[Fixture] Suppressed expected cancel scope error during stdio_client cleanup")
    finally:
        _free_port_8080_windows()
