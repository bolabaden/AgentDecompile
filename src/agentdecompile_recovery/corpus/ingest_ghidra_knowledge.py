"""Ingest per-function Ghidra knowledge JSON into a local cache store.

Knowledge directory and destination store path are required. There is no
product checkout default.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS func_knowledge (
    program   TEXT NOT NULL,
    entry_hex TEXT NOT NULL,
    name      TEXT,
    size      INTEGER,
    file_offset INTEGER,
    calling_convention TEXT,
    signature TEXT,
    decompiled TEXT,
    asm        TEXT,
    n_instructions INTEGER,
    n_refs         INTEGER,
    PRIMARY KEY (program, entry_hex)
);
CREATE INDEX IF NOT EXISTS ix_fk_name ON func_knowledge(program, name);

CREATE TABLE IF NOT EXISTS ingest_status (
    program TEXT PRIMARY KEY,
    functions_done INTEGER,
    functions_total INTEGER,
    seconds REAL,
    complete INTEGER
);
"""


def programs(knowledge_root: Path | str) -> list[str]:
    root = Path(knowledge_root)
    out = []
    if not root.is_dir():
        return out
    for directory in sorted(root.iterdir()):
        if not directory.is_dir():
            continue
        idx = directory / "ghidra_knowledge" / "functions" / "index.json"
        if idx.exists():
            out.append(directory.name)
    return out


def ingest_one(con: sqlite3.Connection, program: str, knowledge_dir: Path | str) -> dict:
    """Ingest one program's ``ghidra_knowledge/functions`` tree."""
    row = con.execute("SELECT complete FROM ingest_status WHERE program=?", (program,)).fetchone()
    if row and row[0]:
        return {"program": program, "skipped": "already ingested"}

    knowledge = Path(knowledge_dir)
    idx_path = knowledge / "functions" / "index.json"
    if not idx_path.is_file():
        return {"program": program, "error": f"missing {idx_path}"}
    idx = json.loads(idx_path.read_text(encoding="utf-8"))
    entries = idx.get("functions", {})
    total = len(entries)
    t0 = time.time()
    base = knowledge / "functions"
    batch = []
    done = 0
    for entry_hex, meta in entries.items():
        path = base / meta.get("path", "")
        if not path.exists():
            path = knowledge / meta.get("path", "")
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(errors="replace"))
        except (OSError, ValueError):
            continue
        instr = data.get("instructions", [])
        nrefs = sum(len(i.get("refs", [])) for i in instr)
        batch.append(
            (
                program,
                entry_hex,
                data.get("name"),
                data.get("size"),
                data.get("fileOffset"),
                data.get("callingConvention"),
                data.get("signature"),
                data.get("decompiled"),
                data.get("asm"),
                len(instr),
                nrefs,
            )
        )
        done += 1
        if len(batch) >= 2000:
            con.executemany("INSERT OR REPLACE INTO func_knowledge VALUES (?,?,?,?,?,?,?,?,?,?,?)", batch)
            con.commit()
            batch.clear()
    if batch:
        con.executemany("INSERT OR REPLACE INTO func_knowledge VALUES (?,?,?,?,?,?,?,?,?,?,?)", batch)
        con.commit()
    elapsed = time.time() - t0
    con.execute("INSERT OR REPLACE INTO ingest_status VALUES (?,?,?,?,1)", (program, done, total, elapsed))
    con.commit()
    return {"program": program, "done": done, "total": total, "seconds": elapsed}


def ingest(knowledge_root: Path | str, dest: Path | str, program_names: list[str] | None = None) -> dict:
    """Walk *knowledge_root* into *dest* (both required)."""
    dest_path = Path(dest)
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(dest_path)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    root = Path(knowledge_root)
    targets = program_names or programs(root)
    results = []
    for name in targets:
        knowledge = root / name / "ghidra_knowledge"
        if not knowledge.is_dir():
            knowledge = root / name
        results.append(ingest_one(con, name, knowledge))
    con.close()
    return {"dest": str(dest_path), "programs": results}
