from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time

from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Generator

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tests.e2e_project_lifecycle_helpers import JsonRpcMcpSession
from tests.helpers import create_public_sample_binary, get_public_sample_binary


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
            raise RuntimeError(f"Server exited before healthy. stdout={stdout[-800:]} stderr={stderr[-800:]}")
        try:
            response = httpx.get(f"{base_url}/health", timeout=1.0)
            if response.status_code == 200:
                return
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout):
            time.sleep(1)
            continue
        time.sleep(1)
    raise TimeoutError(f"Server at {base_url} did not become healthy within {timeout} seconds")


@contextmanager
def running_local_server(workspace: Path) -> Generator[str, None, None]:
    port = _find_free_port()
    project_path = workspace / "probe_project"
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
            "probe-project",
        ],
        cwd=str(REPO_ROOT),
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


def collect_contract_snapshot(base_url: str, binary_path: Path) -> dict[str, object]:
    sample = get_public_sample_binary()
    snapshot: dict[str, object] = {
        "sample": {
            "key": sample.key,
            "display_name": sample.display_name,
            "binary_path": str(binary_path),
            "binary_name": binary_path.name,
            "language_id": sample.language_id,
            "binary_sha256": sample.output_sha256,
        }
    }
    with JsonRpcMcpSession(base_url, timeout=180.0) as session:
        snapshot["tools_list"] = session.list_tools()
        snapshot["resources_list"] = session.list_resources()
        snapshot["open"] = session.call_tool_json("open", {"path": str(binary_path)})
        snapshot["list_project_files"] = session.call_tool_json("list-project-files", {})
        snapshot["get_current_program"] = session.call_tool_json("get-current-program", {})
        snapshot["analyze_program"] = session.call_tool_json("analyze-program", {})
        snapshot["list_functions"] = session.call_tool_json("list-functions", {"limit": 50})
        functions = snapshot["list_functions"].get("results", []) if isinstance(snapshot["list_functions"], dict) else []
        if functions:
            first_function = functions[0]
            snapshot["get_functions_info"] = session.call_tool_json(
                "get-functions",
                {"function": first_function["address"], "mode": "info"},
            )
            snapshot["decompile_function"] = session.call_tool_json(
                "decompile-function",
                {"functionIdentifier": first_function["address"]},
            )
            snapshot["get_references"] = session.call_tool_json(
                "get-references",
                {"target": first_function["address"], "mode": "all", "limit": 25},
            )
        snapshot["search_strings"] = session.call_tool_json("search-strings", {"pattern": "Hello|World"})
        snapshot["search_symbols"] = session.call_tool_json("search-symbols", {"query": "entry|main|printf"})
        snapshot["resource_programs"] = session.read_resource_json("ghidra://programs")
        snapshot["resource_static_analysis"] = session.read_resource_json("ghidra://static-analysis-results")
        snapshot["resource_debug_info"] = session.read_resource_json("ghidra://agentdecompile-debug-info")
    return snapshot


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe exact MCP outputs for the vendored public sample binary")
    parser.add_argument("--output", type=Path, required=True, help="Path to write JSON snapshot")
    parser.add_argument("--server-url", type=str, default="", help="Existing server base URL; if omitted, a local server is started")
    args = parser.parse_args()

    with TemporaryDirectory(prefix="agentdecompile-public-sample-") as temp_dir_str:
        temp_dir = Path(temp_dir_str)
        sample = get_public_sample_binary()
        binary_path = create_public_sample_binary(temp_dir / sample.output_name)
        if args.server_url:
            snapshot = collect_contract_snapshot(args.server_url.rstrip("/"), binary_path)
        else:
            with running_local_server(temp_dir) as base_url:
                snapshot = collect_contract_snapshot(base_url, binary_path)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(snapshot, indent=2, sort_keys=True), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
