#!/usr/bin/env python3
"""Start a local agentdecompile-server, run agdec-http validation with bootstrap import, then stop the server."""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "test_x86_64"
ENV_FILE = REPO_ROOT / ".env"


def _load_env() -> None:
    """Load .env from repo root so GHIDRA_INSTALL_DIR is set from file (no extra deps)."""
    if not ENV_FILE.exists():
        return
    with open(ENV_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                key, value = key.strip(), value.strip()
                if key:
                    # Remove surrounding quotes if present
                    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                        value = value[1:-1]
                    os.environ[key] = value


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_server(base_url: str, process: subprocess.Popen, timeout: float = 180.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        try:
            r = httpx.get(f"{base_url}/health", timeout=2.0)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def main() -> int:
    _load_env()

    if not FIXTURE_PATH.exists():
        print(f"Fixture not found: {FIXTURE_PATH}")
        return 2

    ghidra_dir_str = os.environ.get("GHIDRA_INSTALL_DIR", "").strip()
    if not ghidra_dir_str:
        print("GHIDRA_INSTALL_DIR is not set. Set it in .env at the repo root (see .env.example).")
        return 2
    ghidra_dir = Path(ghidra_dir_str).resolve()
    if not (ghidra_dir / "support" / "LaunchSupport.jar").exists():
        print(f"GHIDRA_INSTALL_DIR does not contain support/LaunchSupport.jar: {ghidra_dir}")
        return 2
    print(f"Using Ghidra at {ghidra_dir}")

    port = find_free_port()
    base_url = f"http://127.0.0.1:{port}"
    server_url = f"{base_url}/mcp"
    project_path = REPO_ROOT / "tmp" / f"live_agdec_test_{port}"
    project_path.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["GHIDRA_INSTALL_DIR"] = str(ghidra_dir)
    for key in (
        "AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME",
        "AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD",
        "AGENT_DECOMPILE_GHIDRA_SERVER_HOST",
        "AGENT_DECOMPILE_GHIDRA_SERVER_PORT",
        "AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY",
        "AGENT_DECOMPILE_MCP_SERVER_URL",
    ):
        env.pop(key, None)
    env["AGENT_DECOMPILE_PROJECT_PATH"] = str(project_path)
    env["PYTHONUNBUFFERED"] = "1"

    cmd = [
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
        "live_agdec_test",
    ]
    print(f"Starting server on {base_url} ...")
    # Do not use PIPE for stdout/stderr or the buffer can fill and block the server.
    process = subprocess.Popen(
        cmd,
        cwd=str(REPO_ROOT),
        env=env,
        stdout=None,
        stderr=None,
    )
    try:
        if not wait_for_server(base_url, process, timeout=300.0):
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            print("Server failed to become ready within 300s. Run the server manually and use --server-url.")
            return 1
        print("Server ready. Running agdec-http validation ...")
        run_cmd = [
            sys.executable,
            str(REPO_ROOT / "helper_scripts" / "mcp_cli_testing.py"),
            "agdec-http",
            "--server-url",
            server_url,
            "--bootstrap-import",
            str(FIXTURE_PATH),
            "--timeout",
            "90",
            "--no-continue-on-error",
        ]
        rc = subprocess.run(run_cmd, cwd=str(REPO_ROOT), timeout=300)
        return rc.returncode
    finally:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        print("Server stopped.")


if __name__ == "__main__":
    raise SystemExit(main())
