from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from agentdecompile_recovery.corpus import second_opinion, store


def _seed(db_path: Path) -> None:
    con = store.connect(db_path)
    con.executemany(
        "INSERT INTO binary(id, repo_path, slug) VALUES (?, ?, ?)",
        [(1, "/primary", "primary"), (2, "/secondary", "secondary")],
    )
    con.executemany(
        "INSERT INTO func(binary_id, addr, name) VALUES (?, ?, ?)",
        [(1, 0x401000, "one"), (2, 0x501000, "one"), (1, 0x402000, "two"), (2, 0x502000, "two")],
    )
    con.commit()
    con.close()


def test_import_diaphora_results_as_verify_evidence(tmp_path: Path) -> None:
    db_path = tmp_path / "corpus.sqlite"
    _seed(db_path)
    result = tmp_path / "pair.diaphora"
    con = sqlite3.connect(result)
    con.execute(
        "CREATE TABLE results(type, line, address, name, address2, name2, "
        "ratio, nodes1, nodes2, description)"
    )
    con.execute(
        "INSERT INTO results VALUES (?,?,?,?,?,?,?,?,?,?)",
        ("best", 1, "00401000", "one", "00501000", "one", 0.97, 4, 4, "Best match"),
    )
    con.commit()
    con.close()

    summary = second_opinion.import_diaphora(result, "/primary", "/secondary", db_path)
    assert summary["inserted"] == 1
    con = store.connect(db_path)
    row = con.execute("SELECT * FROM match").fetchone()
    assert row["status"] == "verify"
    assert row["score"] == 0.97
    assert json.loads(row["evidence"])["tool"] == "diaphora"


def test_import_bindiff_discovers_function_table_and_is_idempotent(tmp_path: Path) -> None:
    db_path = tmp_path / "corpus.sqlite"
    _seed(db_path)
    result = tmp_path / "pair.BinDiff"
    con = sqlite3.connect(result)
    con.execute(
        "CREATE TABLE function(address1 INTEGER, address2 INTEGER, "
        "similarity REAL, confidence REAL, basicblocks INTEGER)"
    )
    con.execute("INSERT INTO function VALUES (?,?,?,?,?)", (0x401000, 0x501000, 0.91, 0.8, 4))
    con.commit()
    con.close()

    first = second_opinion.import_bindiff(result, "/primary", "/secondary", db_path)
    second = second_opinion.import_bindiff(result, "/primary", "/secondary", db_path)
    assert first["inserted"] == 1
    assert second["inserted"] == 1
    con = store.connect(db_path)
    assert con.execute("SELECT COUNT(*) FROM match").fetchone()[0] == 1
