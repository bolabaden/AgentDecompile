#!/usr/bin/env python3
"""Bulk migrate function metadata: runs agentdecompile-cli migrate-metadata.

This script is a backward-compatible launcher for the CLI command. All logic
lives in the match-function tool (when no function identifier is given, it
iterates all functions and discovers targets from the session). Prefer:

  uv run agentdecompile-cli migrate-metadata --binary /path/to/source

For shared projects, open the project first (e.g. via MCP or tool-seq with
open-project and server options), then run migrate-metadata.

Examples:
  uv run python helper_scripts/migrate_k1_metadata.py --server-url http://127.0.0.1:8080
  uv run python helper_scripts/migrate_k1_metadata.py --server-url http://127.0.0.1:8080 --source-path /K1/swkotor.exe --limit 10
"""

from __future__ import annotations

import os
import subprocess
import sys


def main() -> int:
    # Map script argv to CLI migrate-metadata; set env for server URL
    argv = sys.argv[1:]
    out: list[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--server-url" and i + 1 < len(argv):
            os.environ["AGENT_DECOMPILE_MCP_SERVER_URL"] = argv[i + 1].strip()
            i += 2
            continue
        if a in ("--source-path", "--limit", "--min-similarity") and i + 1 < len(argv):
            if a == "--source-path":
                out.append("--binary")
            else:
                out.append(a.replace("_", "-"))
            out.append(argv[i + 1])
            i += 2
            continue
        if a == "--target-paths" and i + 1 < len(argv):
            for p in argv[i + 1].split(","):
                if p.strip():
                    out.append("--target-paths")
                    out.append(p.strip())
            i += 2
            continue
        if a == "--include-externals":
            out.append("--include-externals")
            i += 1
            continue
        if a in ("--no-include-externals", "--dry-run", "--verbose"):
            if a == "--dry-run":
                out.extend(("--limit", "0"))
            elif a == "--verbose":
                out.append("--verbose")
            else:
                out.append(a)
            i += 1
            continue
        if a.startswith("--") and "=" in a:
            out.append(a)
            i += 1
            continue
        out.append(a)
        i += 1

    cli_argv = [sys.executable, "-m", "agentdecompile_cli.cli", "migrate-metadata", *out]
    return subprocess.run(cli_argv, env=os.environ).returncode


if __name__ == "__main__":
    sys.exit(main())
