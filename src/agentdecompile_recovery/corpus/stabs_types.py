"""Persist STABS types from Mach-O images.

Never calls ``stabs_link.link()`` and never json.loads giant STABS dumps.
Re-parses a caller-supplied Mach-O (or accepts already-parsed type rows).
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from .machostabs import analyze as analyze_macho
from .stabs_link import replace_stabs_types, select_slices


def persist_types(
    con,
    binary_id: int,
    *,
    macho_path: Path | str | None = None,
    types: list[dict] | None = None,
    arch: str | None = None,
) -> dict:
    """Persist STABS types for one binary. *macho_path* or *types* is required."""
    parsed = list(types or [])
    if not parsed:
        if macho_path is None:
            raise ValueError("macho_path or types is required")
        result = analyze_macho(Path(macho_path))
        for sl in select_slices(result, arch):
            st = sl.get("stabs") or {}
            parsed.extend(st.get("types") or [])
    stored = replace_stabs_types(con, binary_id, parsed)
    kinds = Counter(t.get("kind") for t in parsed)
    return {"parsed": stored, "stored": stored, "kinds": dict(kinds)}


def persist_types_from_macho(con, raw_dir: Path | str, *, repo_paths: set[str] | None = None) -> dict:
    """Parse Mach-O images under *raw_dir* (required) and persist types.

    Binaries are selected from the store; there is no product-slug filter.
    """
    stats = {}
    raw_root = Path(raw_dir)
    rows = con.execute("SELECT id, slug, repo_path, arch FROM binary").fetchall()
    for row in rows:
        if repo_paths is not None and row["repo_path"] not in repo_paths:
            continue
        raw = raw_root / row["slug"]
        if not raw.is_file():
            continue
        stats[row["repo_path"]] = persist_types(con, row["id"], macho_path=raw, arch=row["arch"])
    return stats
