"""Merge per-program part databases into one identity store. Destination is required."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from .store import connect


def merge_parts(part_paths: list[Path | str], dest: Path | str) -> dict:
    """Merge part sqlite files into *dest*. *dest* is required; no default store."""
    dest_path = Path(dest)
    con = connect(dest_path)
    con.execute("DELETE FROM calledge")
    con.execute("DELETE FROM func")
    con.execute("DELETE FROM binary")
    con.commit()

    merged: list[dict] = []
    for part in part_paths:
        src_path = Path(part)
        src = sqlite3.connect(src_path)
        src.row_factory = sqlite3.Row
        brows = src.execute("SELECT * FROM binary").fetchall()
        if not brows:
            merged.append({"part": str(src_path), "warning": "no binary row"})
            src.close()
            continue
        for binary in brows:
            cols = [k for k in binary.keys() if k != "id"]
            cur = con.execute(
                f"INSERT INTO binary({','.join(cols)}) VALUES({','.join('?' * len(cols))})",
                [binary[k] for k in cols],
            )
            new_id = cur.lastrowid
            fcols = [r[1] for r in src.execute("PRAGMA table_info(func)") if r[1] != "id"]
            dest_func_cols = {r[1] for r in con.execute("PRAGMA table_info(func)")}
            use_cols = [c for c in fcols if c in dest_func_cols]
            frows = src.execute(
                f"SELECT {','.join(use_cols)} FROM func WHERE binary_id=?",
                (binary["id"],),
            ).fetchall()
            bi = use_cols.index("binary_id")
            payload = []
            for row in frows:
                vals = list(row)
                vals[bi] = new_id
                payload.append(vals)
            if payload:
                con.executemany(
                    f"INSERT INTO func({','.join(use_cols)}) VALUES({','.join('?' * len(use_cols))})",
                    payload,
                )
            edges = src.execute(
                "SELECT caller_addr, callee_addr FROM calledge WHERE binary_id=?",
                (binary["id"],),
            ).fetchall()
            con.executemany(
                "INSERT INTO calledge(binary_id,caller_addr,callee_addr) VALUES(?,?,?)",
                [(new_id, e[0], e[1]) for e in edges],
            )
            merged.append(
                {
                    "part": str(src_path),
                    "repo_path": binary["repo_path"],
                    "funcs": len(payload),
                    "edges": len(edges),
                }
            )
        src.close()
    con.commit()
    summary = [
        dict(r)
        for r in con.execute(
            """SELECT b.repo_path, b.game, b.platform, b.arch, b.bits, b.func_count,
                      SUM(f.canon_key IS NOT NULL) AS canon
                 FROM binary b LEFT JOIN func f ON f.binary_id=b.id
                GROUP BY b.id ORDER BY b.repo_path"""
        )
    ]
    con.close()
    return {"dest": str(dest_path), "parts": merged, "binaries": summary}
