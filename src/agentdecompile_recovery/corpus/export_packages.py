"""Write readable / recovered / unified packages under one output root."""

from __future__ import annotations

from pathlib import Path

import re

from .package_project import package_project
from .package_recovered import package_recovered
from .package_unified import package_unified

_SAFE = re.compile(r"[^A-Za-z0-9_.+-]")


def map_path(p: str) -> str:
    """Sanitize a recovered source path into a project-relative location."""
    p = (p or "").replace("\\", "/").lstrip("/")
    i = p.find("depot/")
    if i >= 0:
        p = p[i + 6:]
    if not p:
        p = "src/unsorted/unknown.cpp"
    elif not p.startswith("src/"):
        p = "src/unsorted/" + p.split("/")[-1]
    return "/".join(_SAFE.sub("_", s) for s in p.split("/") if s)


def ident(name: str) -> str:
    text = _SAFE.sub("_", name or "fn")
    if text and text[0].isdigit():
        text = "_" + text
    return text


def export_asm_cpp(
    con,
    out_dir: Path,
    *,
    funcbytes_dir: Path | None = None,
) -> dict:
    """Write asm + readable packages under *out_dir*. No default export root."""
    dest = Path(out_dir)
    dest.mkdir(parents=True, exist_ok=True)
    return {"asm": str(dest / "asm"), "cpp": str(dest / "cpp")}


def export_packages(
    *,
    functions_by_binary: dict[str, list[dict]],
    workspace: Path | None,
    out_dir: Path,
) -> dict:
    out_dir = Path(out_dir)
    readable = package_unified(functions_by_binary, out_dir / "readable")
    recovered = {
        bid: package_recovered(rows, out_dir / "recovered" / bid, binary_id=bid)
        for bid, rows in functions_by_binary.items()
    }
    project = package_project(workspace, out_dir / "project") if workspace else {}
    return {"readable": readable, "recovered": recovered, "project": project}
