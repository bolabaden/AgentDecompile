"""Build a source-tree skeleton from STABS/DWARF paths, then fill compiling C.

The donor binary is the one that still knows original file paths. Other
binaries inherit layout through identity. Fill writes a body only when that
body is recovered source that compiled.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

SAFE_SEG = re.compile(r"^[A-Za-z0-9._+\- ]+$")
SOURCE_SUFFIXES = (".c", ".cpp", ".cp", ".cc", ".cxx", ".h", ".hpp", ".m", ".mm")

STRIP_PREFIXES = (
    "/AspyrBuild/depot/",
    "/AspyrBuild/",
    "/Users/",
    "/home/",
)


def rel_source(path: str) -> str | None:
    if not path:
        return None
    text = path.replace("\\", "/").strip()
    for prefix in STRIP_PREFIXES:
        if text.startswith(prefix):
            text = text[len(prefix) :]
            break
    text = text.lstrip("/")
    if not text or ".." in text.split("/"):
        return None
    parts = text.split("/")
    if not all(SAFE_SEG.match(seg) for seg in parts):
        return None
    if not parts[-1].endswith(SOURCE_SUFFIXES):
        return None
    return text


def write_skeleton(root: Path, functions: list[dict[str, Any]]) -> dict[str, Any]:
    """Create one file per unique `source_file`. Returns the path map."""
    files: dict[str, list[str]] = {}
    for fn in functions:
        rel = rel_source(str(fn.get("source_file") or fn.get("sourceFile") or ""))
        if not rel:
            continue
        files.setdefault(rel, []).append(str(fn.get("id") or fn.get("name") or ""))
    created: list[str] = []
    for rel, owners in sorted(files.items()):
        dest = root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not dest.exists():
            dest.write_text(
                f"/* AgentDecompile workspace file for {rel} */\n"
                f"/* owners: {', '.join(o for o in owners if o)} */\n",
                encoding="utf-8",
            )
        created.append(rel)
    return {"files": created, "count": len(created)}


def fill_function(root: Path, source_file: str, address: str, body: str) -> Path | None:
    rel = rel_source(source_file)
    if not rel:
        return None
    dest = root / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    marker = f"/* ---- {address} from program ---- */"
    existing = dest.read_text(encoding="utf-8") if dest.exists() else ""
    if marker in existing:
        return dest
    block = f"\n{marker}\n{body.rstrip()}\n"
    dest.write_text(existing + block, encoding="utf-8")
    return dest
