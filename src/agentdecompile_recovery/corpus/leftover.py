"""Leftover recovery predicate.

A leftover is a bound logical function that still has assembly on disk,
already tried C (or failed compile), and has no assembly-free real C.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from . import asm_seed


def is_leftover(
    *,
    logical_id: Any,
    has_asm: bool,
    tried_or_failed: bool,
    has_real_c: bool,
) -> bool:
    """True when targeted leftover AI / genproject may run."""
    if has_real_c:
        return False
    if not logical_id and logical_id != 0:
        return False
    if str(logical_id).strip() in {"", "None"}:
        return False
    return bool(has_asm) and bool(tried_or_failed)


def leftover_from_file(
    path: Path,
    *,
    logical_id: Any = None,
    has_real_c: bool = False,
) -> bool:
    """File-level leftover: asm still present, C already tried, no real_c."""
    if has_real_c:
        return False
    if not path.is_file():
        return False
    has_asm = asm_seed.is_compile_only_asm(path)
    tried = asm_seed.is_c_replace_tried(path)
    return is_leftover(
        logical_id=logical_id if logical_id not in (None, "") else path.stem,
        has_asm=has_asm,
        tried_or_failed=tried,
        has_real_c=False,
    )


def count_leftovers(root: Path | None, *, limit: int = 500) -> int:
    """How many leftover C files sit under a recovered-source tree."""
    if root is None or not root.is_dir():
        return 0
    n = 0
    try:
        for path in root.rglob("*.c"):
            if leftover_from_file(path, logical_id=path.stem):
                n += 1
            if n >= limit:
                break
    except OSError:
        return n
    return n


def leftover_store_sets(con) -> tuple[set[int], set[int]]:
    """real_c logical_ids, then logical_ids that already tried C."""
    real_c: set[int] = set()
    tried: set[int] = set()
    try:
        for row in con.execute(
            "SELECT DISTINCT logical_id FROM recovered_function "
            "WHERE real_c=1 AND logical_id IS NOT NULL"
        ):
            real_c.add(int(row["logical_id"]))
        for row in con.execute(
            "SELECT DISTINCT logical_id FROM recovered_function "
            "WHERE logical_id IS NOT NULL AND (real_c=0 OR real_c IS NULL)"
        ):
            tried.add(int(row["logical_id"]))
    except sqlite3.Error:
        return set(), set()
    return real_c, tried


def keep_leftover_queue_row(
    fn: dict[str, Any],
    real_c_lids: set[int],
    tried_lids: set[int],
) -> bool:
    lid = fn.get("logical_id")
    if lid in (None, ""):
        return False
    try:
        nlid = int(lid)
    except (TypeError, ValueError):
        return False
    if nlid in real_c_lids or nlid not in tried_lids:
        return False
    return True


def explain_empty() -> str:
    return (
        "No leftover functions. Leftover means a bound logical_id, assembly "
        "still on disk, C-replace already tried or compile failed, and no real_c."
    )
