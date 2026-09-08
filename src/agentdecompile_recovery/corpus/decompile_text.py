"""Store Ghidra decompiled C text. The C is the input to source recovery."""

from __future__ import annotations

import sqlite3
from pathlib import Path

CTEXT_SCHEMA = """
CREATE TABLE IF NOT EXISTS ctext (
    repo_path TEXT NOT NULL,
    addr      INTEGER NOT NULL,
    ok        INTEGER,
    signature TEXT,
    code      TEXT,
    PRIMARY KEY (repo_path, addr)
);
"""


def connect_ctext(path: Path | str) -> sqlite3.Connection:
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(dest)
    con.executescript(CTEXT_SCHEMA)
    return con


def persist_text(con, repo_path: str, addr: int, *, ok: bool, signature: str | None, code: str | None) -> None:
    con.execute(
        """INSERT OR REPLACE INTO ctext(repo_path, addr, ok, signature, code)
           VALUES (?,?,?,?,?)""",
        (repo_path, addr, int(bool(ok)), signature, code),
    )
    con.commit()


def pending_addrs(store_con, ctext_con, repo_path: str, binary_id: int, *, min_instr: int = 1) -> list[int]:
    want = [
        r[0]
        for r in store_con.execute(
            "SELECT addr FROM func WHERE binary_id=? AND n_instr>=? AND size>0",
            (binary_id, min_instr),
        )
    ]
    done = {r[0] for r in ctext_con.execute("SELECT addr FROM ctext WHERE repo_path=?", (repo_path,))}
    return [addr for addr in want if addr not in done]
