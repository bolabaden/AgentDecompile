from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

from agentdecompile_recovery.corpus import external_bridge

pytestmark = pytest.mark.unit


def test_reuse_candidates_come_from_coverage_gated_recovered_rows(tmp_path: Path) -> None:
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.executescript(
        """
        CREATE TABLE binary (id INTEGER PRIMARY KEY, repo_path TEXT);
        CREATE TABLE func (
            binary_id INTEGER, addr INTEGER, name TEXT, n_instr INTEGER,
            size INTEGER
        );
        CREATE TABLE logical_function (
            id INTEGER PRIMARY KEY, canon_key TEXT, best_signature TEXT,
            source_file TEXT
        );
        CREATE TABLE identity (
            logical_id INTEGER, binary_id INTEGER, addr INTEGER,
            confidence REAL, method TEXT
        );
        CREATE TABLE recovered_function (
            program TEXT, binary_id INTEGER, addr INTEGER, name TEXT,
            size INTEGER, real_c INTEGER, logical_id INTEGER, path TEXT
        );
        INSERT INTO binary VALUES (1, '/arbitrary/a.bin');
        INSERT INTO binary VALUES (2, '/arbitrary/b.bin');
        INSERT INTO func VALUES (1, 4096, 'C::Work', 5, 16);
        INSERT INTO func VALUES (2, 8192, 'C::Work', 5, 16);
        INSERT INTO logical_function VALUES (7, 'C::Work', 'void C::Work()', 'c.cpp');
        INSERT INTO identity VALUES (7, 1, 4096, 0.99, 'named');
        INSERT INTO identity VALUES (7, 2, 8192, 0.98, 'named');
        INSERT INTO recovered_function VALUES (
            'a.bin', 1, 4096, 'C_Work', 16, 1, 7,
            '/verified/C_Work.c'
        );
        """
    )

    with patch.object(external_bridge, "OUTDIR", tmp_path):
        summary = external_bridge.emit_reuse_candidates(con)
        rows = [
            json.loads(line)
            for line in (tmp_path / "reuse_candidates.jsonl").read_text().splitlines()
        ]

    assert summary["recovered_functions_scanned"] == 1
    assert summary["recovered_with_identity"] == 1
    assert summary["reuse_rows"] == 1
    assert rows[0]["recovered_from"]["source_path"] == "/verified/C_Work.c"
    assert rows[0]["reuse_target"]["address"] == "00002000"


def test_priority_refresh_qualifies_identity_groups_and_excludes_recovered(
    tmp_path: Path,
) -> None:
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.executescript(
        """
        CREATE TABLE binary(id INTEGER PRIMARY KEY, repo_path TEXT);
        CREATE TABLE logical_function(
            id INTEGER PRIMARY KEY, canon_key TEXT, best_signature TEXT,
            source_file TEXT
        );
        CREATE TABLE identity(
            logical_id INTEGER, binary_id INTEGER, addr INTEGER,
            confidence REAL, method TEXT
        );
        CREATE INDEX ix_identity_logical ON identity(logical_id);
        CREATE TABLE func(
            binary_id INTEGER, addr INTEGER, size INTEGER, name TEXT,
            n_instr INTEGER, UNIQUE(binary_id, addr)
        );
        CREATE TABLE recovered_function(
            program TEXT, name TEXT, path TEXT, binary_id INTEGER,
            addr INTEGER, size INTEGER, real_c INTEGER, logical_id INTEGER
        );
        INSERT INTO binary VALUES (1, '/arbitrary/a.bin');
        INSERT INTO binary VALUES (2, '/arbitrary/b.bin');
        INSERT INTO logical_function VALUES (10, 'CThing::Work', 'void Work()', 'thing.cpp');
        INSERT INTO logical_function VALUES (20, 'CThing::Done', 'void Done()', 'thing.cpp');
        INSERT INTO identity VALUES (10, 1, 4096, 0.98, 'name');
        INSERT INTO identity VALUES (10, 2, 8192, 0.97, 'name');
        INSERT INTO identity VALUES (20, 1, 12288, 0.99, 'name');
        INSERT INTO identity VALUES (20, 2, 16384, 0.99, 'name');
        INSERT INTO func VALUES (1, 4096, 80, 'CThing::Work', 20);
        INSERT INTO func VALUES (2, 8192, 84, 'CThing::Work', 21);
        INSERT INTO func VALUES (1, 12288, 60, 'CThing::Done', 15);
        INSERT INTO func VALUES (2, 16384, 60, 'CThing::Done', 15);
        INSERT INTO recovered_function VALUES ('p', 'CThing::Done', 'x.c', 1, 12288, 60, 1, 20);
        """
    )

    with patch.object(external_bridge, "OUTDIR", tmp_path):
        summary = external_bridge.emit_priority_targets(con)
        rows = [json.loads(line) for line in (tmp_path / "priority_targets.jsonl").read_text().splitlines()]

    assert summary["candidates"] == 1
    assert rows[0]["logical_id"] == 10
    assert rows[0]["builds"] == 2
    assert len(rows[0]["targets"]) == 2

    index_columns = [
        row[2] for row in con.execute("PRAGMA index_info(ix_func_priority_cover)")
    ]
    assert index_columns == ["binary_id", "addr", "size", "n_instr", "name"]
