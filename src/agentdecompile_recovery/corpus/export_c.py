"""Export whole-program decompiled C + header via Ghidra's CppExporter.

Destination directory is required. An existing C file larger than 1 KiB is skipped.
"""

from __future__ import annotations

import time
from pathlib import Path

from . import ghidra_env as ge


def export_dest(out_dir: Path | str, repo_path: str) -> Path:
    slug = repo_path.strip("/").replace("/", "__")
    return Path(out_dir) / slug / f"{slug}.c"


def run(
    repo_path: str,
    out_dir: Path | str,
    *,
    source_path: str | None = None,
    open_program=None,
    start=None,
) -> dict:
    """Export one program's C. *out_dir* is required; there is no workspace default."""
    dest_c = export_dest(out_dir, repo_path)
    dest_c.parent.mkdir(parents=True, exist_ok=True)
    if dest_c.exists() and dest_c.stat().st_size > 1024:
        return {
            "repo_path": repo_path,
            "skipped": "already exported",
            "size": dest_c.stat().st_size,
            "c": str(dest_c),
        }

    opener = open_program or ge.open_program
    starter = start or ge.start
    if starter() is False:
        return {"repo_path": repo_path, "ok": False, "skipped": "no-program", "c": str(dest_c), "size": 0}

    from ghidra.app.util.exporter import CppExporter
    from java.io import File as JFile  # type: ignore

    t0 = time.time()
    with opener(source_path or repo_path) as program:
        if program is None:
            return {"repo_path": repo_path, "ok": False, "skipped": "no-program", "c": str(dest_c), "size": 0}
        cpp = CppExporter(None, True, True, True, True, False, None)
        ok = cpp.export(JFile(str(dest_c)), program, None, ge.monitor())
    elapsed = time.time() - t0
    hdr = dest_c.with_suffix(".h")
    return {
        "repo_path": repo_path,
        "ok": bool(ok),
        "seconds": round(elapsed, 1),
        "c": str(dest_c),
        "size": dest_c.stat().st_size if dest_c.exists() else 0,
        "header_size": hdr.stat().st_size if hdr.exists() else 0,
    }
