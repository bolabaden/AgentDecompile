"""Independent BinDiff and Diaphora evidence. Never creates canonical identities."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from . import store


def _address(value, *, text_is_hex: bool = False) -> int:
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if text.lower().startswith("0x"):
        return int(text, 16)
    return int(text, 16 if text_is_hex else 10)


def _binary(con: sqlite3.Connection, repo_path: str) -> sqlite3.Row:
    row = con.execute(
        "SELECT id, repo_path, slug FROM binary WHERE repo_path=?", (repo_path,)
    ).fetchone()
    if row is None:
        raise ValueError(f"binary.repo_path not found: {repo_path}")
    return row


def store_matches(
    rows: list[dict],
    tool: str,
    result_path: Path,
    primary_repo: str,
    secondary_repo: str,
    db_path: Path | str,
) -> dict:
    con = store.connect(db_path)
    primary = _binary(con, primary_repo)
    secondary = _binary(con, secondary_repo)
    run = f"{tool}:{primary['slug']}:{secondary['slug']}"
    known_primary = {r[0] for r in con.execute("SELECT addr FROM func WHERE binary_id=?", (primary["id"],))}
    known_secondary = {r[0] for r in con.execute("SELECT addr FROM func WHERE binary_id=?", (secondary["id"],))}
    accepted = []
    unknown = 0
    for row in rows:
        if row["src_addr"] not in known_primary or row["dst_addr"] not in known_secondary:
            unknown += 1
            continue
        evidence = {"tool": tool, "result": str(result_path), **row.get("evidence", {})}
        accepted.append(
            (
                run,
                primary["id"],
                row["src_addr"],
                secondary["id"],
                row["dst_addr"],
                row["score"],
                row.get("margin"),
                store.j(evidence),
                "verify",
            )
        )
    with con:
        con.execute("DELETE FROM match WHERE run=?", (run,))
        con.executemany(
            """INSERT INTO match(run, src_binary, src_addr, dst_binary, dst_addr,
                                  score, margin, evidence, status)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            accepted,
        )
    con.close()
    return {
        "tool": tool,
        "run": run,
        "read": len(rows),
        "inserted": len(accepted),
        "unknown_addresses": unknown,
        "status": "verify",
    }


def import_diaphora(
    result_path: Path | str,
    primary_repo: str,
    secondary_repo: str,
    db_path: Path | str,
) -> dict:
    result_path = Path(result_path).resolve()
    con = sqlite3.connect(result_path)
    con.row_factory = sqlite3.Row
    try:
        source = con.execute(
            "SELECT type, address, name, address2, name2, ratio, nodes1, nodes2, description FROM results"
        ).fetchall()
    finally:
        con.close()
    rows = [
        {
            "src_addr": _address(r["address"], text_is_hex=True),
            "dst_addr": _address(r["address2"], text_is_hex=True),
            "score": float(r["ratio"]),
            "margin": None,
            "evidence": {
                "category": r["type"],
                "primary_name": r["name"],
                "secondary_name": r["name2"],
                "primary_nodes": r["nodes1"],
                "secondary_nodes": r["nodes2"],
                "description": r["description"],
            },
        }
        for r in source
    ]
    return store_matches(rows, "diaphora", result_path, primary_repo, secondary_repo, db_path)


def import_bindiff(
    result_path: Path | str,
    primary_repo: str,
    secondary_repo: str,
    db_path: Path | str,
) -> dict:
    result_path = Path(result_path).resolve()
    con = sqlite3.connect(result_path)
    con.row_factory = sqlite3.Row
    try:
        table = None
        columns = set()
        for candidate in con.execute("SELECT name FROM sqlite_master WHERE type='table'"):
            name = candidate[0]
            cols = {r[1] for r in con.execute(f'PRAGMA table_info("{name}")')}
            if {"address1", "address2", "similarity"} <= cols:
                table, columns = name, cols
                break
        if table is None:
            raise ValueError("no BinDiff function-match table with address1/address2/similarity")
        optional = [c for c in ("confidence", "basicblocks", "edges", "instructions") if c in columns]
        selected = ["address1", "address2", "similarity", *optional]
        source = con.execute(f'SELECT {", ".join(selected)} FROM "{table}"').fetchall()
    finally:
        con.close()
    rows = []
    for r in source:
        confidence = float(r["confidence"]) if "confidence" in r.keys() else None
        rows.append(
            {
                "src_addr": _address(r["address1"]),
                "dst_addr": _address(r["address2"]),
                "score": float(r["similarity"]),
                "margin": confidence,
                "evidence": {"confidence": confidence, **{c: r[c] for c in optional if c != "confidence"}},
            }
        )
    return store_matches(rows, "bindiff", result_path, primary_repo, secondary_repo, db_path)
