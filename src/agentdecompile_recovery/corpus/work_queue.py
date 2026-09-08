"""Logical-function-first work queue. Highest member-count first."""

from __future__ import annotations

import json
from pathlib import Path

COST_BANDS = [
    (8, 75),
    (16, 182),
    (32, 300),
    (64, 450),
    (128, 700),
    (256, 1100),
    (512, 1800),
    (1024, 3000),
]


def cost_seconds(size: int) -> int:
    for lim, cost in COST_BANDS:
        if size <= lim:
            return cost
    return 4500


def export_queue(con, outdir: Path, *, arches: tuple[str, ...] | None = None) -> Path:
    """Write one JSONL row per logical function. *arches* filters member binaries."""
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    dest = outdir / "logical_queue.jsonl"
    rows = []
    for logical in con.execute(
        """SELECT id, canon_key, canon_class, canon_method, n_members, source_file
             FROM logical_function ORDER BY n_members DESC, id"""
    ):
        members = [
            dict(row)
            for row in con.execute(
                """SELECT i.binary_id, i.addr, i.confidence, i.method,
                          f.size, f.n_instr, b.arch, b.slug
                     FROM identity i
                     JOIN func f ON f.binary_id=i.binary_id AND f.addr=i.addr
                     JOIN binary b ON b.id=i.binary_id
                    WHERE i.logical_id=?""",
                (logical["id"],),
            )
        ]
        if arches:
            members = [m for m in members if (m.get("arch") or "") in arches]
            if not members:
                continue
        size = max((m.get("size") or 0) for m in members) if members else 0
        rows.append(
            {
                "logical_id": logical["id"],
                "canon_key": logical["canon_key"],
                "n_members": len(members),
                "source_file": logical["source_file"],
                "cost_s": cost_seconds(int(size or 0)),
                "members": [
                    {"slug": m["slug"], "addr": m["addr"], "size": m["size"]} for m in members
                ],
            }
        )
    dest.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return dest
