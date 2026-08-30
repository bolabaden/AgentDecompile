"""Compile recovered units and link a complete executable.

Priority 1 of the corpus pipeline: one donor project becomes a real linked
image. Object files alone are not a complete executable. Byte-accuracy is a
later, separate stage.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any


def find_c_compiler() -> str | None:
    for name in ("cc", "gcc", "clang"):
        found = shutil.which(name)
        if found:
            return found
    return None


def compile_unit(compiler: str, source: Path, obj: Path, *, timeout: int = 60) -> dict[str, Any]:
    obj.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        [compiler, "-c", str(source), "-o", str(obj)],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return {
        "ok": proc.returncode == 0 and obj.is_file(),
        "source": str(source),
        "object": str(obj),
        "returncode": proc.returncode,
        "stderr": (proc.stderr or "")[-2000:],
    }


def link_executable(
    compiler: str,
    objects: list[Path],
    output: Path,
    *,
    timeout: int = 60,
) -> dict[str, Any]:
    if not objects:
        return {"ok": False, "reason": "no object files", "output": str(output)}
    output.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        [compiler, *[str(path) for path in objects], "-o", str(output)],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return {
        "ok": proc.returncode == 0 and output.is_file() and output.stat().st_size > 0,
        "output": str(output),
        "returncode": proc.returncode,
        "stderr": (proc.stderr or "")[-2000:],
        "objectCount": len(objects),
        "claimBoundary": (
            "A linked image proves the generated project builds. It does not "
            "prove byte-accuracy against a shipped binary."
        ),
    }
