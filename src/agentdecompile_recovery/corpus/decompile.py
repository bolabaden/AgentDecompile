"""Persist decompiled-C shape features into a store or part file."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .decompile_shape import features
from .store import connect

PART_SCHEMA = """
CREATE TABLE IF NOT EXISTS decomp_part (
    repo_path     TEXT NOT NULL,
    addr          INTEGER NOT NULL,
    ok            INTEGER,
    n_tokens      INTEGER,
    n_lines       INTEGER,
    max_nest      INTEGER,
    n_calls       INTEGER,
    n_locals      INTEGER,
    n_deref       INTEGER,
    n_index       INTEGER,
    n_field       INTEGER,
    ctrl          TEXT,
    ops           TEXT,
    skeleton_hash TEXT,
    PRIMARY KEY (repo_path, addr)
);
"""

MAIN_SCHEMA = """
CREATE TABLE IF NOT EXISTS decomp (
    binary_id     INTEGER NOT NULL,
    addr          INTEGER NOT NULL,
    ok            INTEGER,
    n_tokens      INTEGER,
    n_lines       INTEGER,
    max_nest      INTEGER,
    n_calls       INTEGER,
    n_locals      INTEGER,
    n_deref       INTEGER,
    n_index       INTEGER,
    n_field       INTEGER,
    ctrl          TEXT,
    ops           TEXT,
    skeleton_hash TEXT,
    PRIMARY KEY (binary_id, addr)
);
CREATE INDEX IF NOT EXISTS ix_decomp_bin ON decomp(binary_id);
"""


def persist_code(con, binary_id: int, addr: int, code: str | None) -> dict:
    con.executescript(MAIN_SCHEMA)
    if not code:
        con.execute(
            """INSERT OR REPLACE INTO decomp
               (binary_id, addr, ok, n_tokens, n_lines, max_nest, n_calls, n_locals,
                n_deref, n_index, n_field, ctrl, ops, skeleton_hash)
               VALUES (?,?,0,?,?,?,?,?,?,?,?,?,?,?)""",
            (binary_id, addr, *[None] * 11),
        )
        con.commit()
        return {"ok": 0, "addr": addr}
    ft = features(code)
    con.execute(
        """INSERT OR REPLACE INTO decomp
           (binary_id, addr, ok, n_tokens, n_lines, max_nest, n_calls, n_locals,
            n_deref, n_index, n_field, ctrl, ops, skeleton_hash)
           VALUES (?,?,1,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            binary_id,
            addr,
            ft["n_tokens"],
            ft["n_lines"],
            ft["max_nest"],
            ft["n_calls"],
            ft["n_locals"],
            ft["n_deref"],
            ft["n_index"],
            ft["n_field"],
            json.dumps(ft["ctrl"]),
            json.dumps(ft["ops"]),
            ft["skeleton_hash"],
        ),
    )
    con.commit()
    return {"ok": 1, "addr": addr, **ft}


def persist_part(part_path: Path, repo_path: str, addr: int, code: str | None) -> dict:
    con = sqlite3.connect(part_path)
    con.executescript(PART_SCHEMA)
    if not code:
        con.execute(
            """INSERT OR REPLACE INTO decomp_part
               (repo_path, addr, ok, n_tokens, n_lines, max_nest, n_calls, n_locals,
                n_deref, n_index, n_field, ctrl, ops, skeleton_hash)
               VALUES (?,?,0,?,?,?,?,?,?,?,?,?,?,?)""",
            (repo_path, addr, *[None] * 11),
        )
        con.commit()
        con.close()
        return {"ok": 0, "addr": addr}
    ft = features(code)
    con.execute(
        """INSERT OR REPLACE INTO decomp_part
           (repo_path, addr, ok, n_tokens, n_lines, max_nest, n_calls, n_locals,
            n_deref, n_index, n_field, ctrl, ops, skeleton_hash)
           VALUES (?,?,1,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            repo_path,
            addr,
            ft["n_tokens"],
            ft["n_lines"],
            ft["max_nest"],
            ft["n_calls"],
            ft["n_locals"],
            ft["n_deref"],
            ft["n_index"],
            ft["n_field"],
            json.dumps(ft["ctrl"]),
            json.dumps(ft["ops"]),
            ft["skeleton_hash"],
        ),
    )
    con.commit()
    con.close()
    return {"ok": 1, "addr": addr, **ft}


def attach_store(store_path: Path) -> sqlite3.Connection:
    con = connect(store_path)
    con.executescript(MAIN_SCHEMA)
    return con
