"""Integration tests for agentdecompile-server running in proxy mode.

Ported from root-level test_server_proxy_mode.py.
Starts a local agentdecompile-server that proxies to the remote backend,
then verifies selected CLI commands work through it.

Requires:
- Remote AgentDecompile backend at http://170.9.241.140:8080/
- agentdecompile-server entrypoint available (uvx --from . --with-editable .)

Run with:
    python -m pytest tests/test_integration_server_proxy_mode.py -v
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
SERVER_PROXY_URL = "http://127.0.0.1:8082/"
PROGRAM_PATH = "/K1/k1_win_gog_swkotor.exe"
_BASE_CLI = ["uvx", "--from", ".", "--with-editable", ".", "agentdecompile-cli"]
_SERVER_CMD = [
    "uvx", "--from", ".", "--with-editable", ".",
    "agentdecompile-server",
    "--transport", "streamable-http",
    "--backend-url", REMOTE_URL,
    "--host", "127.0.0.1",
    "--port", "8082",
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
    return _BASE_CLI + ["--server-url", server_url]


def _remote_backend_available(env: dict[str, str]) -> bool:
    ok, _, err = _run(_cli(REMOTE_URL) + ["list", "project-files"], env, timeout=20)
    if ok:
        return True
    return "Cannot connect to AgentDecompile server" not in err


def _wait_server_ready(env: dict[str, str], timeout_sec: int = 40) -> bool:
    deadline = time.time() + timeout_sec
    probe_cmd = _cli(SERVER_PROXY_URL) + ["list", "project-files"]
    while time.time() < deadline:
        ok, _, _ = _run(probe_cmd, env, timeout=10)
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
    """Start agentdecompile-server in proxy mode for the module."""
    proc = subprocess.Popen(
        _SERVER_CMD, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    ready = _wait_server_ready(env, timeout_sec=45)
    if not ready:
        proc.terminate()
        proc.wait(timeout=5)
        pytest.skip("agentdecompile-server proxy mode did not become ready in time")
    yield
    proc.terminate()
    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.mark.integration
@pytest.mark.e2e
@pytest.mark.timeout(300)
class TestServerProxyMode:
    """Commands work through agentdecompile-server running in proxy mode."""

    def test_list_project_files_remote(self, env: dict[str, str]) -> None:
        ok, out, err = _run(_cli(REMOTE_URL) + ["list", "project-files"], env)
        assert ok, f"Remote list project-files failed\nstdout: {out}\nstderr: {err}"
        data = _parse_output(out)
        assert data is not None
        assert "count" in data or "files" in data

    def test_list_project_files_via_server_proxy(
        self, env: dict[str, str], proxy_server: None
    ) -> None:
        ok, out, err = _run(_cli(SERVER_PROXY_URL) + ["list", "project-files"], env)
        assert ok, f"Server-proxy list project-files failed\nstdout: {out}\nstderr: {err}"
        data = _parse_output(out)
        assert data is not None
        assert "count" in data or "files" in data

    def test_get_functions_via_server_proxy(
        self, env: dict[str, str], proxy_server: None
    ) -> None:
        ok, out, err = _run(
            _cli(SERVER_PROXY_URL) + [
                "get-functions", "--mode", "list", "--program_path", PROGRAM_PATH, "--limit", "5"
            ],
            env,
        )
        assert ok, f"Server-proxy get-functions failed\nstdout: {out}\nstderr: {err}"
        data = _parse_output(out)
        assert data is not None
        assert "results" in data

    def test_search_symbols_via_server_proxy(
        self, env: dict[str, str], proxy_server: None
    ) -> None:
        args_json = json.dumps({"programPath": PROGRAM_PATH, "query": "main", "maxResults": 5})
        ok, out, err = _run(
            _cli(SERVER_PROXY_URL) + ["tool", "search-symbols-by-name", args_json],
            env,
        )
        assert ok, f"Server-proxy search-symbols failed\nstdout: {out}\nstderr: {err}"
        data = _parse_output(out)
        assert data is not None
        assert "results" in data

    def test_remote_and_proxy_list_same_program_count(
        self, env: dict[str, str], proxy_server: None
    ) -> None:
        """Both endpoints should report the same number of project files."""
        ok_r, out_r, _ = _run(_cli(REMOTE_URL) + ["list", "project-files"], env)
        ok_p, out_p, _ = _run(_cli(SERVER_PROXY_URL) + ["list", "project-files"], env)
        if not (ok_r and ok_p):
            pytest.skip("One of the endpoints is not responding")
        data_r = _parse_output(out_r)
        data_p = _parse_output(out_p)
        if data_r and data_p and "count" in data_r and "count" in data_p:
            assert data_r["count"] == data_p["count"], (
                f"Remote count={data_r['count']} vs proxy count={data_p['count']}"
            )
