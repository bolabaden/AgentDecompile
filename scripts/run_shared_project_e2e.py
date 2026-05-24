#!/usr/bin/env python3
"""Run shared-project e2e: open(shared), list-project-files; verify source is shared-server-session.

Requires:
  - MCP backend running (e.g. agentdecompile-server or docker-compose agentdecompile-mcp).
  - Ghidra server reachable from the backend (e.g. ghidra service when using docker-compose).

Usage:
  # Backend and Ghidra on same host (e.g. both local):
  set AGENT_DECOMPILE_GHIDRA_SERVER_HOST=127.0.0.1
  set AGENT_DECOMPILE_GHIDRA_SERVER_PORT=13100
  set AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME=admin
  set AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD=admin
  uv run python scripts/run_shared_project_e2e.py

  # Docker Compose (backend uses env AGENT_DECOMPILE_GHIDRA_SERVER_HOST=ghidra; do not set from host):
  uv run python scripts/run_shared_project_e2e.py --server-url http://127.0.0.1:8080

  # Explicit open args (override env):
  uv run python scripts/run_shared_project_e2e.py --server-host ghidra --server-port 13100 --repo agentrepo
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description="E2E: open shared project and list files; verify shared-server-session.")
    parser.add_argument("--server-url", default=os.getenv("AGENT_DECOMPILE_MCP_SERVER_URL", "http://127.0.0.1:8080"), help="MCP server URL")
    parser.add_argument("--server-host", default=os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_HOST"), help="Ghidra server host (omit to use backend env)")
    parser.add_argument("--server-port", type=int, default=int(os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_PORT", "13100") or "13100"), help="Ghidra server port")
    parser.add_argument("--username", default=os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME", "admin"), help="Ghidra server username")
    parser.add_argument("--password", default=os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD", "admin"), help="Ghidra server password")
    parser.add_argument("--repo", default=os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY", "agentrepo"), help="Repository name")
    args = parser.parse_args()

    open_args: dict = {"shared": True, "path": args.repo}
    if args.server_host:
        open_args["serverHost"] = args.server_host
        open_args["serverPort"] = args.server_port
        open_args["serverUsername"] = args.username
        open_args["serverPassword"] = args.password

    steps = [
        {"name": "open", "arguments": open_args},
        {"name": "list-project-files", "arguments": {}},
    ]
    steps_json = json.dumps(steps)

    cmd = [
        sys.executable,
        "-m",
        "uv",
        "run",
        "agentdecompile-cli",
        "--server-url",
        args.server_url,
        "tool-seq",
        steps_json,
    ]
    # Prefer uv run agentdecompile-cli if available
    try:
        result = subprocess.run(
            ["uv", "run", "agentdecompile-cli", "--server-url", args.server_url, "tool-seq", steps_json],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        )
    except FileNotFoundError:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        )

    out = result.stdout or ""
    err = result.stderr or ""

    if result.returncode != 0:
        print("STDOUT:", out, file=sys.stderr)
        print("STDERR:", err, file=sys.stderr)
        print("E2E failed: CLI exited with code", result.returncode, file=sys.stderr)
        return result.returncode

    # Require evidence of shared project: list-project-files must return source=shared-server-session
    if "shared-server-session" not in out:
        print("E2E failed: output does not contain shared-server-session. Listing may be from local project.", file=sys.stderr)
        print(out[:3000], file=sys.stderr)
        return 1

    print("E2E OK: shared project open and list-project-files returned source=shared-server-session.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
