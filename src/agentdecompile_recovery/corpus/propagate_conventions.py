"""Recover calling-convention decoration for functions Ghidra left as ``unknown``.

Two sources: the terminating ``ret``/``ret imm16``, and same-game identity
donors collapsed to the ecx-vs-stack decoration class. Ambiguous cases are skipped.
"""

from __future__ import annotations

import collections
import sqlite3
from pathlib import Path

DECORATION_CLASS = {
    "__thiscall": "ecx",
    "__fastcall": "ecx",
    "__stdcall": "stack",
    "__cdecl": "stack",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS func_convention_derived (
    binary_id     INTEGER NOT NULL,
    addr          INTEGER NOT NULL,
    deco_class    TEXT NOT NULL,
    stack_bytes   INTEGER,
    fastcall_n    INTEGER,
    class_source  TEXT NOT NULL,
    n_source      TEXT NOT NULL,
    PRIMARY KEY (binary_id, addr)
);
"""


def popped_bytes(body: bytes) -> tuple[int, str] | tuple[None, None]:
    """Stack bytes the callee pops, read off the terminating instruction."""
    buf = body.rstrip(b"\xcc")
    if len(buf) >= 3 and buf[-3] == 0xC2:
        return int.from_bytes(buf[-2:], "little"), "ret_imm"
    if buf and buf[-1] == 0xC3:
        return 0, "ret_zero"
    return None, None


def donor_classes(con: sqlite3.Connection) -> tuple[dict[int, list[tuple[str, str]]], dict[int, dict[int, int]]]:
    bins = {r["id"]: r["game"] for r in con.execute("SELECT id, game FROM binary")}
    ident: dict[int, dict[int, int]] = collections.defaultdict(dict)
    for row in con.execute("SELECT logical_id, binary_id, addr FROM identity"):
        ident[row["binary_id"]][row["addr"]] = row["logical_id"]
    out: dict[int, list[tuple[str, str]]] = collections.defaultdict(list)
    for row in con.execute(
        "SELECT binary_id, addr, calling_convention FROM func"
        " WHERE calling_convention IS NOT NULL AND calling_convention<>'unknown'"
    ):
        lid = ident.get(row["binary_id"], {}).get(row["addr"])
        cls = DECORATION_CLASS.get(row["calling_convention"])
        if lid is not None and cls:
            out[lid].append((cls, bins.get(row["binary_id"]) or ""))
    return out, ident


def derive_conventions(
    con: sqlite3.Connection,
    binary_id: int,
    raw: bytes,
    mapper,
    *,
    game: str | None = None,
    cross_game: bool = False,
    apply_rows: bool = False,
) -> dict:
    """Derive decoration class + stack bytes. *raw* and *mapper* are caller-supplied."""
    donors, ident = donor_classes(con)
    mine = ident.get(binary_id, {})
    stats = collections.Counter()
    rows = []
    for row in con.execute(
        "SELECT addr, size, calling_convention FROM func"
        " WHERE binary_id=? AND is_thunk=0 AND n_instr>=1 AND size>0",
        (binary_id,),
    ):
        cc = row["calling_convention"]
        if cc and cc != "unknown":
            stats["already_known"] += 1
            continue
        addr, size = int(row["addr"]), int(row["size"])
        off = mapper(addr)
        n, nsrc = popped_bytes(raw[off : off + size]) if off is not None and off + size <= len(raw) else (None, None)

        lid = mine.get(addr)
        cls = None
        csrc = ""
        if lid is not None:
            ds = donors.get(lid, [])
            same = [d for d in ds if d[1] == game]
            pool = same if same else (ds if cross_game else [])
            classes = {d[0] for d in pool}
            if len(classes) == 1:
                cls = classes.pop()
                csrc = "same_game" if same else "cross_game"
            elif len(classes) > 1:
                stats["class_conflict"] += 1

        if cls is None and n is None:
            stats["undetermined"] += 1
            continue
        if cls is None:
            stats["N_only_class_unknown"] += 1
            continue
        if n is None:
            if cls == "stack":
                stats["stack_no_N_needed"] += 1
            else:
                stats["ecx_but_N_unknown"] += 1
            continue

        stats[f"determined_{cls}"] += 1
        rows.append((binary_id, addr, cls, n, 8 + n if cls == "ecx" else None, csrc, nsrc))

    if apply_rows:
        con.executescript(SCHEMA)
        con.executemany(
            "INSERT OR REPLACE INTO func_convention_derived"
            " (binary_id, addr, deco_class, stack_bytes, fastcall_n, class_source, n_source)"
            " VALUES (?,?,?,?,?,?,?)",
            rows,
        )
        con.commit()
    return {"stats": dict(stats), "rows": rows, "applied": apply_rows}


def load_raw(raw_path: Path | str) -> bytes:
    return Path(raw_path).read_bytes()
