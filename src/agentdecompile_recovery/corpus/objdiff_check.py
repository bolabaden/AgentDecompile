"""Run the Mizuchi objdiff-check helper (Node) against two COFF objects."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


def default_script() -> Path | None:
    env = os.environ.get("AGENT_DECOMPILE_OBJDIFF_CHECK", "").strip()
    if env:
        p = Path(env)
        return p if p.is_file() else None
    here = Path(__file__).resolve().parent
    for candidate in (
        here.parent.parent.parent / "scripts" / "recovery-toolchains" / "objdiff-check.mjs",
        Path("scripts/recovery-toolchains/objdiff-check.mjs"),
    ):
        if candidate.is_file():
            return candidate.resolve()
    return None


def run_check(
    base_object: Path | str,
    target_object: Path | str,
    symbol: str | None = None,
    *,
    script_path: Path | str | None = None,
) -> dict:
    script = Path(script_path) if script_path else default_script()
    if script is None or not script.is_file():
        return {"ok": False, "skipped": "no-objdiff-script", "script": str(script_path or "")}
    node = shutil.which("node")
    if not node:
        return {"ok": False, "skipped": "no-node"}
    argv = [node, str(script), str(base_object), str(target_object)]
    if symbol:
        argv.append(symbol)
    proc = subprocess.run(argv, capture_output=True, text=True)
    return {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "script": str(script),
    }
