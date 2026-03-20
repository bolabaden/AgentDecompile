#!/usr/bin/env python3
"""Run shared-project workflow: open (shared) + list-project-files. Verifies source is shared-server-session."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
JSON_PATH = SCRIPT_DIR / "shared_open_list_oneline.json"
if not JSON_PATH.exists():
    JSON_PATH = SCRIPT_DIR / "shared_open_list.json"


def main() -> int:
    server_url = "http://127.0.0.1:8080"
    if len(sys.argv) > 1:
        server_url = sys.argv[1].strip()

    print("=== Testing Shared Ghidra Project Workflow ===")
    print(f"Server URL: {server_url}")
    print(f"Steps: {JSON_PATH}")
    print()

    steps_json = JSON_PATH.read_text(encoding="utf-8")
    try:
        json.loads(steps_json)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON in {JSON_PATH}: {e}")
        return 1

    print("Open shared project + list-project-files...")
    result = subprocess.run(
        ["uv", "run", "agentdecompile-cli", "--server-url", server_url, "tool-seq", steps_json],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=SCRIPT_DIR.parent,
    )
    out = (result.stdout or "") + (result.stderr or "")

    if result.returncode != 0:
        print("ERROR: tool-seq failed")
        print(out)
        return 1

    if "shared-server-session" in out:
        print("PASS: Response shows shared-server-session source")
    else:
        print("WARNING: Response does not show shared-server-session source")
        print(out)

    if "local-ghidra-project" in out:
        print("FAIL: Response shows local-ghidra-project (using local project instead of shared)")
        return 1

    print()
    print("=== Test complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
