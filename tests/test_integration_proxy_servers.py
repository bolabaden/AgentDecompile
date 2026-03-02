"""Integration tests for the proxy server — remote vs local-proxy parity.

Consolidates root-level test_proxy_http.py and test_proxy_simple.py.
Requires the remote AgentDecompile backend at http://170.9.241.140:8080/
and the agentdecompile-proxy entrypoint available via uvx.

Run with:
    python -m pytest tests/test_integration_proxy_servers.py -v
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from collections.abc import Generator
from typing import Any

import pytest

REMOTE_URL = "http://170.9.241.140:8080/"
PROXY_URL = "http://127.0.0.1:8081/"
PROGRAM_PATH = "/K1/k1_win_gog_swkotor.exe"
_BASE = ["uvx", "--from", ".", "--with-editable", ".", "agentdecompile-cli"]
_PROXY_CMD = [
    "uvx", "--from", ".", "--with-editable", ".",
    "agentdecompile-proxy",
    "--backend", REMOTE_URL,
    "--http",
    "--host", "127.0.0.1",
    "--port", "8081",
]


def _env() -> dict[str, str]:
    env = os.environ.copy()
    env["AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME"] = "OpenKotOR"
    env["AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD"] = "MuchaShakaPaka"
    env["AGENT_DECOMPILE_GHIDRA_SERVER_HOST"] = "170.9.241.140"
    env["AGENT_DECOMPILE_GHIDRA_SERVER_PORT"] = "13100"
    env["AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY"] = "Odyssey"
    env["AGENT_DECOMPILE_BACKEND_URL"] = REMOTE_URL
    return env


def _run(
    cmd: list[str],
    env: dict[str, str],
    timeout: int = 60,
) -> tuple[bool, str, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=timeout)
        return proc.returncode == 0, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "timeout"


def _parse_output(output: str) -> dict[str, Any] | None:
    if not output:
        return None
    try:
        if "content:" in output and "'text':" in output:
            start = output.find("'text': '") + len("'text': '")
            end = output.rfind("'")
            if start > 8 and end > start:
                return json.loads(output[start:end].replace("\\'", "'"))
            return json.loads(output)
        return json.loads(output)
    except json.JSONDecodeError:
        return None


def _cli(server_url: str) -> list[str]:
    return _BASE + ["--server-url", server_url]


def _remote_backend_available(env: dict[str, str]) -> bool:
    ok, _, err = _run(_cli(REMOTE_URL) + ["list", "project-files"], env, timeout=20)
    if ok:
        return True
    return "Cannot connect to AgentDecompile server" not in err


def _wait_proxy_ready(env: dict[str, str], timeout_sec: int = 30) -> bool:
    deadline = time.time() + timeout_sec
    health_cmd = _cli(PROXY_URL) + [
        "tool", "list-imports",
        json.dumps({"programPath": PROGRAM_PATH, "limit": 1}),
    ]
    while time.time() < deadline:
        ok, _, _ = _run(health_cmd, env, timeout=10)
        if ok:
            return True
        time.sleep(1)
    return False


@pytest.fixture(scope="module")
def env() -> dict[str, str]:
    return _env()


@pytest.fixture(scope="module", autouse=True)
def require_remote_backend(env: dict[str, str]) -> None:
    if not _remote_backend_available(env):
        pytest.skip(f"Remote AgentDecompile backend unavailable at {REMOTE_URL}")


@pytest.fixture(scope="module")
def proxy_server(env: dict[str, str], require_remote_backend: None) -> Generator[None, None, None]:
    """Start a local proxy server for the duration of the test module."""
    proc = subprocess.Popen(
        _PROXY_CMD, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    ready = _wait_proxy_ready(env, timeout_sec=40)
    if not ready:
        proc.terminate()
        proc.wait(timeout=5)
        pytest.skip("Local proxy server did not become ready in time")
    yield
    proc.terminate()
    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        proc.kill()


# ---------------------------------------------------------------------------
# Parameterised command table
# ---------------------------------------------------------------------------

_COMMANDS: list[tuple[str, list[str], list[str]]] = [
    (
        "open",
        ["open", "--server_host", "170.9.241.140", "--server_port", "13100",
         "--server_username", "OpenKotOR", "--server_password", "MuchaShakaPaka", PROGRAM_PATH],
        ["serverConnected"],
    ),
    ("list project-files", ["list", "project-files"], ["count"]),
    ("get-functions", ["get-functions", "--program_path", PROGRAM_PATH, "--limit", "5"], ["functions"]),
    (
        "search-symbols-by-name",
        ["tool", "search-symbols-by-name",
         json.dumps({"programPath": PROGRAM_PATH, "query": "main", "maxResults": 5})],
        ["results"],
    ),
    (
        "get-references",
        ["tool", "get-references",
         json.dumps({"binary": PROGRAM_PATH, "target": "WinMain", "mode": "to", "limit": 5})],
        ["references"],
    ),
    (
        "get-current-program",
        ["tool", "get-current-program", json.dumps({"programPath": PROGRAM_PATH})],
        ["functionCount"],
    ),
    (
        "list-imports",
        ["tool", "list-imports", json.dumps({"programPath": PROGRAM_PATH, "limit": 5})],
        ["mode"],
    ),
    (
        "list-exports",
        ["tool", "list-exports", json.dumps({"programPath": PROGRAM_PATH, "limit": 5})],
        ["mode"],
    ),
]


@pytest.mark.integration
@pytest.mark.e2e
@pytest.mark.timeout(120)
class TestRemoteCommands:
    """Validate each command works directly against the remote backend."""

    @pytest.mark.parametrize("label,args,expected_keys", _COMMANDS, ids=[c[0] for c in _COMMANDS])
    def test_remote(
        self,
        label: str,
        args: list[str],
        expected_keys: list[str],
        env: dict[str, str],
    ) -> None:
        ok, out, err = _run(_cli(REMOTE_URL) + args, env)
        assert ok, f"{label}: remote command failed\nstdout: {out}\nstderr: {err}"
        data = _parse_output(out)
        assert data is not None, f"{label}: could not parse JSON from: {out[:300]}"
        for key in expected_keys:
            assert key in data, f"{label}: expected '{key}' in response: {out[:300]}"


@pytest.mark.integration
@pytest.mark.e2e
@pytest.mark.timeout(300)
class TestProxyParity:
    """Validate each command returns equivalent data through the local proxy."""

    @pytest.mark.parametrize("label,args,expected_keys", _COMMANDS, ids=[c[0] for c in _COMMANDS])
    def test_proxy(
        self,
        label: str,
        args: list[str],
        expected_keys: list[str],
        env: dict[str, str],
        proxy_server: None,
    ) -> None:
        ok, out, err = _run(_cli(PROXY_URL) + args, env)
        assert ok, f"{label}: proxy command failed\nstdout: {out}\nstderr: {err}"
        data = _parse_output(out)
        assert data is not None, f"{label}: could not parse JSON from: {out[:300]}"
        for key in expected_keys:
            assert key in data, f"{label}: expected '{key}' in proxy response: {out[:300]}"
