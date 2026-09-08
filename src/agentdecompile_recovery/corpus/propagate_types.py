"""Share struct layouts between binaries only where they provably agree.

A type is adopted when the recipient has no layout of its own, every donor
agrees on size, and a same-game donor is preferred. Ambiguous cases are skipped.
"""

from __future__ import annotations

import collections

from . import corpus_config
from .export_types import SCHEMA

ORIGIN_DDL = """
CREATE TABLE IF NOT EXISTS ghidra_type_origin (
    binary_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    donor_slug TEXT NOT NULL,
    donor_game TEXT,
    size INTEGER,
    PRIMARY KEY (binary_id, name)
)
"""


def _has_origin(con) -> bool:
    return any(r[1] == "origin" for r in con.execute("PRAGMA table_info(ghidra_type)"))


def _targets(con, config_dir_path=None) -> list[str]:
    listed = corpus_config.load_maps(config_dir_path).get("type_propagate_targets")
    if isinstance(listed, list) and listed:
        return [str(x) for x in listed]
    rows = con.execute("SELECT repo_path FROM binary ORDER BY repo_path").fetchall()
    return [str(r["repo_path"] if not isinstance(r, tuple) else r[0]) for r in rows]


def plan_adoptions(con, *, cross_game: bool = False, targets: list[str] | None = None, config_dir_path=None) -> dict:
    """Report (and optionally apply) type adoptions. No product-path defaults."""
    con.executescript(SCHEMA)
    con.executescript(ORIGIN_DDL)
    if _has_origin(con) is False:
        try:
            con.execute("ALTER TABLE ghidra_type ADD COLUMN origin TEXT")
        except Exception:
            pass

    bins = {}
    for rp in targets if targets is not None else _targets(con, config_dir_path):
        row = con.execute("SELECT id, slug, game FROM binary WHERE repo_path=?", (rp,)).fetchone()
        if row:
            bins[rp] = (int(row["id"]), row["slug"], row["game"])

    donors: dict[str, list] = collections.defaultdict(list)
    native: dict[int, set] = collections.defaultdict(set)
    origin_filter = " AND (origin IS NULL OR origin='native')" if _has_origin(con) else ""
    for bid, slug, game in bins.values():
        for row in con.execute(
            f"SELECT name, size, definition FROM ghidra_type WHERE binary_id=?{origin_filter}",
            (bid,),
        ):
            donors[row["name"]].append((int(row["size"] or 0), row["definition"], slug, game, bid))
            native[bid].add(row["name"])

    stats = collections.Counter()
    adopted: list[tuple] = []
    for _rp, (bid, slug, game) in bins.items():
        for name, cands in donors.items():
            if name in native[bid]:
                stats["already_native"] += 1
                continue
            others = [c for c in cands if c[4] != bid]
            if not others:
                continue
            sizes = {c[0] for c in others}
            if len(sizes) != 1:
                stats["skipped_size_conflict"] += 1
                continue
            same_game = [c for c in others if c[3] == game]
            if not same_game and not cross_game:
                stats["skipped_cross_game"] += 1
                continue
            pick = (same_game or others)[0]
            adopted.append((bid, name, pick[1], pick[0], pick[2], pick[3], "same_game" if same_game else "cross_game"))
            stats["adopted_same_game" if same_game else "adopted_cross_game"] += 1

    per = collections.Counter(a[0] for a in adopted)
    binaries = []
    for rp, (bid, slug, game) in bins.items():
        binaries.append(
            {
                "repo_path": rp,
                "slug": slug,
                "native": len(native[bid]),
                "adopt": per[bid],
                "after": len(native[bid]) + per[bid],
            }
        )
    return {"stats": dict(stats), "adopted": adopted, "binaries": binaries}


def apply_adoptions(con, adopted: list[tuple]) -> int:
    for bid, name, definition, size, dslug, dgame, kind in adopted:
        note = (
            f"/* layout adopted from {dslug} ({kind}); this binary had no\n"
            f"   definition of its own, and every donor agreed on size 0x{size:x}. */\n"
        )
        con.execute(
            "INSERT OR REPLACE INTO ghidra_type"
            " (binary_id, name, kind, size, definition, n_fields, origin)"
            " VALUES (?,?,?,?,?,?,?)",
            (bid, name, "struct", size, note + definition, 0, f"adopted:{dslug}"),
        )
        con.execute(
            "INSERT OR REPLACE INTO ghidra_type_origin"
            " (binary_id, name, donor_slug, donor_game, size) VALUES (?,?,?,?,?)",
            (bid, name, dslug, dgame, size),
        )
    con.commit()
    return len(adopted)
