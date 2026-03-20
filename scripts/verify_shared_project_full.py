#!/usr/bin/env python3
"""Full shared-project verification: open(shared) → list → [import → list → checkout → analyze → list-functions].

Run this after the MCP backend and Ghidra server are up. It proves the session is using the
*shared* project (not local) by requiring "source": "shared-server-session" and running the
full tool chain.

Usage:
  # Docker Compose (backend at 8080, backend has AGENT_DECOMPILE_GHIDRA_SERVER_HOST=ghidra):
  uv run python scripts/verify_shared_project_full.py --server-url http://127.0.0.1:8080 --server-host ghidra --username ghidra --password admin

  # Local Ghidra + backend on same host:
  uv run python scripts/verify_shared_project_full.py --server-host 127.0.0.1 --username admin --password admin

  # With a binary to import (optional; use path to a real binary):
  uv run python scripts/verify_shared_project_full.py --server-host ghidra --binary tests/fixtures/test_x86_64

Exit code 0 = shared project is functional (create, open, list, and optionally import/checkout/analyze/list-functions).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify shared project: open(shared), list (must show source=shared-server-session), optional import/checkout/analyze/list-functions.",
    )
    parser.add_argument("--server-url", default=os.getenv("AGENT_DECOMPILE_MCP_SERVER_URL", "http://127.0.0.1:8080"), help="MCP server URL")
    parser.add_argument("--server-host", default=os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_HOST"), help="Ghidra server host (e.g. ghidra for Docker, 127.0.0.1 for local)")
    parser.add_argument("--server-port", type=int, default=int(os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_PORT", "13100") or "13100"), help="Ghidra server port")
    parser.add_argument("--username", default=os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME", "ghidra"), help="Ghidra server username")
    parser.add_argument("--password", default=os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD", "admin"), help="Ghidra server password")
    parser.add_argument("--repo", default=os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY", "agentrepo"), help="Repository name")
    parser.add_argument("--binary", default=None, help="Optional: path to binary to import (enables import→checkout→analyze→list-functions)")
    parser.add_argument("--program-name", default=None, help="Program name in repo (default: binary filename)")
    args = parser.parse_args()

    if not args.server_host:
        print("Error: --server-host or AGENT_DECOMPILE_GHIDRA_SERVER_HOST required.", file=sys.stderr)
        return 1

    open_args: dict = {
        "shared": True,
        "path": args.repo,
        "serverHost": args.server_host,
        "serverPort": args.server_port,
        "serverUsername": args.username,
        "serverPassword": args.password,
    }

    steps: list[dict] = [
        {"name": "open", "arguments": open_args},
        {"name": "list-project-files", "arguments": {}},
    ]

    if args.binary:
        bin_path = Path(args.binary)
        if not bin_path.exists():
            print(f"Error: binary path does not exist: {bin_path}", file=sys.stderr)
            return 1
        program_name = args.program_name or bin_path.name
        steps.extend([
            {"name": "import-binary", "arguments": {"filePath": str(bin_path.resolve()), "programPath": program_name, "enableVersionControl": True}},
            {"name": "list-project-files", "arguments": {}},
            {"name": "checkout-program", "arguments": {"programPath": program_name}},
            {"name": "analyze-program", "arguments": {"programPath": program_name}},
            {"name": "list-functions", "arguments": {"programPath": program_name, "limit": 5}},
        ])

    steps_json = json.dumps(steps)
    repo_root = Path(__file__).resolve().parent.parent

    try:
        result = subprocess.run(
            ["uv", "run", "agentdecompile-cli", "--server-url", args.server_url, "tool-seq", steps_json],
            capture_output=True,
            text=True,
            timeout=300,
            cwd=str(repo_root),
        )
    except FileNotFoundError:
        result = subprocess.run(
            [sys.executable, "-m", "uv", "run", "agentdecompile-cli", "--server-url", args.server_url, "tool-seq", steps_json],
            capture_output=True,
            text=True,
            timeout=300,
            cwd=str(repo_root),
        )

    out = result.stdout or ""
    err = result.stderr or ""

    if result.returncode != 0:
        print("STDOUT:", out, file=sys.stderr)
        print("STDERR:", err, file=sys.stderr)
        print("Verification failed: CLI exited with code", result.returncode, file=sys.stderr)
        return result.returncode

    if "shared-server-session" not in out:
        print("Verification failed: output does not contain 'shared-server-session'. Session may be using a local project.", file=sys.stderr)
        print(out[:4000], file=sys.stderr)
        return 1

    if args.binary and "functions" not in out.lower() and "entry" not in out.lower():
        print("Warning: full workflow ran but list-functions output was not clearly present. Check output.", file=sys.stderr)

    print("OK: Shared project is functional. list-project-files returned source=shared-server-session.")
    if args.binary:
        print("OK: Full workflow (import → checkout → analyze → list-functions) completed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
