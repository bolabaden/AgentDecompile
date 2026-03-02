"""Integration tests for 7 core CLI commands against the published package.

Ported from root-level test_7_commands.py.
Requires the remote AgentDecompile backend at http://170.9.241.140:8080/
and the package to be published to git+https://github.com/bolabaden/agentdecompile.

Run with:
    python -m pytest tests/test_integration_7_commands.py -v
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any

import pytest

REMOTE_URL = "http://170.9.241.140:8080/"
PROGRAM_PATH = "/K1/k1_win_gog_swkotor.exe"
_PUBLISHED_FROM = "git+https://github.com/bolabaden/agentdecompile"


def _env() -> dict[str, str]:
    env = os.environ.copy()
    env["AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME"] = "OpenKotOR"
    env["AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD"] = "MuchaShakaPaka"
    env["AGENT_DECOMPILE_GHIDRA_SERVER_HOST"] = "170.9.241.140"
    env["AGENT_DECOMPILE_GHIDRA_SERVER_PORT"] = "13100"
    env["AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY"] = "Odyssey"
    env["AGENT_DECOMPILE_BACKEND_URL"] = REMOTE_URL
    return env


def _base_cmd() -> list[str]:
    return [
        "uvx",
        "--from",
        _PUBLISHED_FROM,
        "agentdecompile-cli",
        "--server-url",
        REMOTE_URL,
    ]


def _run(cmd: list[str], env: dict[str, str], timeout: int = 90) -> tuple[bool, str, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=timeout)
        return proc.returncode == 0, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "timeout"


def _parse_output(output: str) -> dict[str, Any] | None:
    """Extract JSON from CLI output, handling wrapped content: payload format."""
    if not output:
        return None
    try:
        if "content:" in output and "'text':" in output:
            start = output.find("'text': '") + len("'text': '")
            end = output.rfind("'")
            if start > 8 and end > start:
                json_str = output[start:end].replace("\\'", "'")
                return json.loads(json_str)
            return json.loads(output)
        return json.loads(output)
    except json.JSONDecodeError:
        return None


def _remote_backend_available(env: dict[str, str]) -> bool:
    ok, _, err = _run(
        _base_cmd() + ["list", "project-files"],
        env,
        timeout=30,
    )
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


@pytest.mark.integration
@pytest.mark.e2e
@pytest.mark.timeout(120)
class TestPublishedPackage7Commands:
    """Smoke-test the 7 canonical commands against the published package."""

    def test_cmd1_open_program(self, env: dict[str, str]) -> None:
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
        )
        assert ok, f"open failed\nstdout: {out}\nstderr: {err}"
        data = _parse_output(out)
        assert data is not None
        assert "serverConnected" in data or "programCount" in data, (
            f"Expected 'serverConnected' or 'programCount' in response: {out[:300]}"
        )

    def test_cmd2_list_project_files(self, env: dict[str, str]) -> None:
        ok, out, err = _run(_base_cmd() + ["list", "project-files"], env)
        assert ok, f"list project-files failed\nstdout: {out}\nstderr: {err}"
        data = _parse_output(out)
        assert data is not None
        assert "count" in data or "files" in data, (
            f"Expected 'count' or 'files' in response: {out[:300]}"
        )

    def test_cmd3_get_functions(self, env: dict[str, str]) -> None:
        ok, out, err = _run(
            _base_cmd() + ["get-functions", "--program_path", PROGRAM_PATH, "--limit", "5"],
            env,
        )
        assert ok, f"get-functions failed\nstdout: {out}\nstderr: {err}"
        data = _parse_output(out)
        assert data is not None
        assert "functions" in data, f"Expected 'functions' key: {out[:300]}"
        assert isinstance(data["functions"], list)

    def test_cmd4_search_symbols_by_name(self, env: dict[str, str]) -> None:
        args_json = json.dumps({"programPath": PROGRAM_PATH, "query": "main", "maxResults": 5})
        ok, out, err = _run(
            _base_cmd() + ["tool", "search-symbols-by-name", args_json],
            env,
        )
        assert ok, f"search-symbols-by-name failed\nstdout: {out}\nstderr: {err}"
        data = _parse_output(out)
        assert data is not None
        assert "results" in data, f"Expected 'results' key: {out[:300]}"

    def test_cmd5_get_references(self, env: dict[str, str]) -> None:
        args_json = json.dumps({
            "binary": PROGRAM_PATH,
            "target": "WinMain",
            "mode": "to",
            "limit": 5,
        })
        ok, out, err = _run(_base_cmd() + ["tool", "get-references", args_json], env)
        assert ok, f"get-references failed\nstdout: {out}\nstderr: {err}"
        data = _parse_output(out)
        assert data is not None
        assert "references" in data, f"Expected 'references' key: {out[:300]}"

    def test_cmd6_get_current_program(self, env: dict[str, str]) -> None:
        args_json = json.dumps({"programPath": PROGRAM_PATH})
        ok, out, err = _run(
            _base_cmd() + ["tool", "get-current-program", args_json],
            env,
        )
        assert ok, f"get-current-program failed\nstdout: {out}\nstderr: {err}"
        data = _parse_output(out)
        assert data is not None
        assert "functionCount" in data or "loaded" in data, (
            f"Expected 'functionCount' or 'loaded' key: {out[:300]}"
        )

    def test_cmd7a_list_imports(self, env: dict[str, str]) -> None:
        args_json = json.dumps({"programPath": PROGRAM_PATH, "limit": 5})
        ok, out, err = _run(_base_cmd() + ["tool", "list-imports", args_json], env)
        assert ok, f"list-imports failed\nstdout: {out}\nstderr: {err}"
        data = _parse_output(out)
        assert data is not None
        assert "mode" in data or "results" in data, (
            f"Expected 'mode' or 'results' key: {out[:300]}"
        )

    def test_cmd7b_list_exports(self, env: dict[str, str]) -> None:
        args_json = json.dumps({"programPath": PROGRAM_PATH, "limit": 5})
        ok, out, err = _run(_base_cmd() + ["tool", "list-exports", args_json], env)
        assert ok, f"list-exports failed\nstdout: {out}\nstderr: {err}"
        data = _parse_output(out)
        assert data is not None
        assert "mode" in data or "results" in data, (
            f"Expected 'mode' or 'results' key: {out[:300]}"
        )
