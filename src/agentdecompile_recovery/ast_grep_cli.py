"""Locate a real `ast-grep` CLI binary.

Linux ships `/usr/bin/sg` as the setgid(1) helper from shadow-utils. Our
callers historically fell back from `ast-grep` to `sg` (ast-grep's short
name), which makes CI falsely believe the scanner is installed and then fail
when `sg run --pattern ...` is not an ast-grep invocation. Probe `--help`
before accepting a candidate.
"""

from __future__ import annotations

import shutil
import subprocess


def _looks_like_ast_grep(path: str) -> bool:
    try:
        completed = subprocess.run(
            [path, "--help"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    blob = f"{completed.stdout}\n{completed.stderr}".lower()
    return "ast-grep" in blob


def resolve_ast_grep_binary() -> str | None:
    for name in ("ast-grep", "sg"):
        path = shutil.which(name)
        if path and _looks_like_ast_grep(path):
            return path
    return None
