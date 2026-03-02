"""Integration tests for the MCP tool analysis workflow.

Ported from root-level test_analysis.py.
Requires the remote AgentDecompile backend at http://170.9.241.140:8080/
and a local `uv run` / installed `agentdecompile-cli` entrypoint.

Run with:
    python -m pytest tests/test_integration_analysis.py -v
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any

import pytest

BACKEND_URL = "http://170.9.241.140:8080"
REMOTE_URL = f"{BACKEND_URL}/"
PROGRAM_PATH = "/K1/k1_win_gog_swkotor.exe"


def _env() -> dict[str, str]:
    env = os.environ.copy()
    env["AGENT_DECOMPILE_SERVER_HOST"] = "170.9.241.140"
    env["AGENT_DECOMPILE_SERVER_PORT"] = "13100"
    env["AGENT_DECOMPILE_SERVER_USERNAME"] = "OpenKotOR"
    env["AGENT_DECOMPILE_SERVER_PASSWORD"] = "MuchaShakaPaka"
    env["AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY"] = "Odyssey"
    env["AGENT_DECOMPILE_BACKEND_URL"] = BACKEND_URL
    return env


def _base_cmd() -> list[str]:
    return ["uv", "run", "agentdecompile-cli", "--server-url", BACKEND_URL]


def _run(cmd: list[str], env: dict[str, str], timeout: int = 120) -> tuple[bool, str, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=timeout)
        return proc.returncode == 0, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "timeout"


def _parse_json(output: str) -> dict[str, Any] | None:
    if not output:
        return None
    try:
        if output.startswith("{"):
            return json.loads(output)
        # Wrapped content: format
        if "content:" in output and "'text':" in output:
            start = output.find("'text': '") + len("'text': '")
            end = output.rfind("'")
            if start > 8 and end > start:
                return json.loads(output[start:end].replace("\\'", "'"))
        return json.loads(output)
    except json.JSONDecodeError:
        return None


def _remote_backend_available(env: dict[str, str]) -> bool:
    ok, _, err = _run(_base_cmd() + ["list", "project-files"], env, timeout=30)
    if ok:
        return True
    return "Cannot connect to AgentDecompile server" not in err


@pytest.fixture(scope="module")
def env() -> dict[str, str]:
    return _env()


@pytest.fixture(scope="module", autouse=True)
def require_remote_backend(env: dict[str, str]) -> None:
    if not _remote_backend_available(env):
        pytest.skip(f"Remote AgentDecompile backend unavailable at {REMOTE_URL}")


@pytest.fixture(scope="module")
def opened_program(env: dict[str, str], require_remote_backend: None) -> None:
    """Open the test program once before the analysis tests run."""
    ok, out, err = _run(
        _base_cmd() + [
            "open",
            "--server_host", "170.9.241.140",
            "--server_port", "13100",
            "--server_username", "OpenKotOR",
            "--server_password", "MuchaShakaPaka",
            PROGRAM_PATH,
        ],
        env,
        timeout=60,
    )
    if not ok:
        pytest.skip(f"Could not open program: {err}")


@pytest.mark.integration
@pytest.mark.e2e
@pytest.mark.timeout(180)
class TestAnalysisWorkflow:
    """Step-by-step analysis workflow mirroring test_analysis.py."""

    def test_step1_open_program(self, env: dict[str, str]) -> None:
        ok, out, err = _run(
            _base_cmd() + [
                "open",
                "--server_host", "170.9.241.140",
                "--server_port", "13100",
                "--server_username", "OpenKotOR",
                "--server_password", "MuchaShakaPaka",
                PROGRAM_PATH,
            ],
            env,
            timeout=60,
        )
        assert ok, f"open failed\nstdout: {out}\nstderr: {err}"
        data = _parse_json(out)
        assert data is not None
        assert "serverConnected" in data or "programCount" in data, (
            f"Unexpected response shape: {out[:300]}"
        )

    def test_step2_list_functions(self, opened_program: None, env: dict[str, str]) -> None:
        ok, out, err = _run(
            _base_cmd() + ["get-functions", "--program_path", PROGRAM_PATH, "--limit", "10"],
            env,
        )
        assert ok, f"get-functions failed\nstdout: {out}\nstderr: {err}"
        data = _parse_json(out)
        assert data is not None
        assert "functions" in data, f"Expected 'functions' key: {out[:300]}"
        assert isinstance(data["functions"], list)
        assert len(data["functions"]) > 0

    def test_step3_list_structures(self, opened_program: None, env: dict[str, str]) -> None:
        args = json.dumps({"action": "list", "programPath": PROGRAM_PATH, "limit": 10})
        ok, out, err = _run(_base_cmd() + ["tool", "manage-structures", args], env)
        assert ok, f"manage-structures list failed\nstdout: {out}\nstderr: {err}"
        data = _parse_json(out)
        assert data is not None

    def test_step4_search_comments(self, opened_program: None, env: dict[str, str]) -> None:
        args = json.dumps({
            "action": "search",
            "programPath": PROGRAM_PATH,
            "searchText": ".",
            "limit": 10,
        })
        ok, out, err = _run(_base_cmd() + ["tool", "manage-comments", args], env)
        assert ok, f"manage-comments search failed\nstdout: {out}\nstderr: {err}"
        data = _parse_json(out)
        assert data is not None

    def test_step5_list_symbols(self, opened_program: None, env: dict[str, str]) -> None:
        args = json.dumps({"mode": "symbols", "programPath": PROGRAM_PATH, "limit": 10})
        ok, out, err = _run(_base_cmd() + ["tool", "manage-symbols", args], env)
        assert ok, f"manage-symbols list failed\nstdout: {out}\nstderr: {err}"
        data = _parse_json(out)
        assert data is not None
        assert "results" in data or "symbols" in data, (
            f"Expected 'results' or 'symbols' key: {out[:300]}"
        )

    def test_step6_get_single_function(self, opened_program: None, env: dict[str, str]) -> None:
        ok, out, err = _run(
            _base_cmd() + ["get-functions", "--program_path", PROGRAM_PATH, "--limit", "1"],
            env,
        )
        assert ok, f"get-functions (limit=1) failed\nstdout: {out}\nstderr: {err}"
        data = _parse_json(out)
        assert data is not None
        funcs = data.get("functions", [])
        assert len(funcs) >= 1
        func = funcs[0]
        assert "name" in func or "address" in func, (
            f"Function entry missing name/address: {func}"
        )

    def test_list_project_files(self, env: dict[str, str]) -> None:
        ok, out, err = _run(_base_cmd() + ["list", "project-files"], env, timeout=30)
        assert ok, f"list project-files failed\nstdout: {out}\nstderr: {err}"
        data = _parse_json(out)
        assert data is not None
        assert "count" in data or "files" in data, f"Unexpected response: {out[:300]}"
