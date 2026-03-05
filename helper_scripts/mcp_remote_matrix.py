#!/usr/bin/env python3
"""Thin wrapper around ``mcp_cli_testing.py matrix`` for backwards compatibility.

All flags are forwarded verbatim to the ``matrix`` subcommand.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_CLI_TESTING = Path(__file__).with_name("mcp_cli_testing.py")


def main() -> int:
    return subprocess.run(
        [sys.executable, str(_CLI_TESTING), "matrix", *sys.argv[1:]],
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
