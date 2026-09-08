from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from agentdecompile_recovery.corpus.sibling_conflicts import export_sibling_conflicts


def test_exports_same_class_different_method_matches_by_status(tmp_path: Path) -> None:
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.executescript(
        """
        CREATE TABLE binary (id INTEGER PRIMARY KEY, slug TEXT);
        CREATE TABLE func (
            binary_id INTEGER, addr INTEGER, canon_key TEXT, canon_class TEXT, canon_method TEXT
        );
        CREATE TABLE match (
            id INTEGER PRIMARY KEY, src_binary INTEGER, src_addr INTEGER,
            dst_binary INTEGER, dst_addr INTEGER, score REAL, margin REAL, status TEXT
        );
        INSERT INTO binary VALUES (1, 'source.exe'), (2, 'target.app');
        INSERT INTO func VALUES
            (1, 10, 'C::First', 'C', 'First'),
            (2, 20, 'C::Second', 'C', 'Second'),
            (1, 11, 'C::Same', 'C', 'Same'),
            (2, 21, 'C::Same', 'C', 'Same'),
            (1, 12, 'D::One', 'D', 'One'),
            (2, 22, 'E::Two', 'E', 'Two');
        INSERT INTO match VALUES
            (1, 1, 10, 2, 20, 0.99, 0.20, 'verify'),
            (2, 1, 11, 2, 21, 0.99, 0.20, 'auto'),
            (3, 1, 12, 2, 22, 0.99, 0.20, 'auto');
        """
    )
    summary = export_sibling_conflicts(con, tmp_path)
    verify_rows = [json.loads(line) for line in (tmp_path / "sibling_verify.jsonl").read_text().splitlines()]
    auto_rows = (tmp_path / "sibling_auto.jsonl").read_text().splitlines()
    assert summary == {"auto": 0, "verify": 1, "auto_name_conflicts": 1}
    assert verify_rows[0]["src_m"] == "First"
    assert verify_rows[0]["dst_m"] == "Second"
    assert auto_rows == []
