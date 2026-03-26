#!/usr/bin/env python3
"""Set password for Ghidra user non-interactively."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys

from typing import Any


def main():
    parser = argparse.ArgumentParser(description="Set password for Ghidra user non-interactively.")
    parser.add_argument("ghidra_public_path", nargs="?", default=r"C:\ghidra12\ghidra_12.0_PUBLIC", help="Path to the Ghidra public directory (default: %(default)s)")
    args = parser.parse_args()

    svradmin_path: str = os.path.join(args.ghidra_public_path, "server", "svrAdmin.bat")
    cmd: list[str] = [svradmin_path, "-reset", "ghidra", "--p"]
    password: str = "admin\nadmin\n"

    result: subprocess.CompletedProcess[Any] = subprocess.run(
        cmd,
        input=password,
        text=True,
        capture_output=True,
        timeout=30,
    )

    print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
