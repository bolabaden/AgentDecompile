from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.corpus.dashboard.entity_activity import (
    add_facet,
    attach_dimensions,
    origin_evidence,
)
from agentdecompile_recovery.corpus.store import connect

pytestmark = pytest.mark.unit


def test_origin_evidence_keeps_human_stabs_and_match() -> None:
    kinds = {row["kind"] for row in origin_evidence("human", logical_id=12)}
    assert kinds == {"human", "match"}
    kinds = {row["kind"] for row in origin_evidence("stabs", logical_id=12)}
    assert kinds == {"debug", "match"}


def test_add_facet_does_not_replace_stabs_with_human() -> None:
    entity = {"facets": [{"kind": "debug", "label": "STABS types"}]}
    add_facet(entity, {"kind": "human", "label": "Human name"})
    add_facet(entity, {"kind": "match", "label": "Cross-match recorded"})
    add_facet(entity, {"kind": "human", "label": "Human name"})
    assert [row["kind"] for row in entity["facets"]] == ["debug", "human", "match"]


def test_attach_dimensions_split_proof_from_evidence() -> None:
    entity = {
        "status": "running",
        "stage": "Compare related builds",
        "action": "corpus.match-pair",
        "jobId": "job-1",
        "facets": [
            {"kind": "debug", "label": "STABS types"},
            {"kind": "human", "label": "Human names preserved"},
            {"kind": "match", "label": "Cross-match recorded"},
            {"kind": "recorded-proof", "label": "Recorded receipt", "source": "/tmp/receipt.json"},
        ],
        "proofReceipts": [{"label": "Recorded objdiff receipt", "path": "/tmp/objdiff.json"}],
    }
    attach_dimensions(entity)
    assert {row["kind"] for row in entity["evidence"]} == {"debug", "human", "match"}
    assert all(row["kind"] != "recorded-proof" for row in entity["evidence"])
    assert {row["kind"] for row in entity["proof"]} == {"recorded-proof"}
    assert entity["activity"]["status"] == "running"
    assert entity["activity"]["action"] == "corpus.match-pair"


def test_snapshot_reports_stabs_human_and_match_together(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    db = tmp_path / "corpus.sqlite"
    source = tmp_path / "game.exe"
    source.write_bytes(b"MZ" + b"\0" * 64)
    con = connect(db)
    con.execute("INSERT INTO binary (repo_path, slug) VALUES (?, ?)", (str(source), "game.exe"))
    binary_id = con.execute("SELECT id FROM binary").fetchone()[0]
    con.execute(
        "INSERT INTO func (binary_id, addr, name, name_origin, source) VALUES (?,?,?,?,?)",
        (binary_id, 0x401000, "Init", "human", "USER_DEFINED"),
    )
    con.execute(
        "INSERT INTO stabs_type (binary_id, name, kind, stab) VALUES (?,?,?,?)",
        (binary_id, "int", "typedef", "int:t(0,1)"),
    )
    con.execute("INSERT INTO logical_function (best_name) VALUES ('Init')")
    logical_id = con.execute("SELECT id FROM logical_function").fetchone()[0]
    con.execute(
        "INSERT INTO identity (logical_id, binary_id, addr, confidence, method) VALUES (?,?,?,?,?)",
        (logical_id, binary_id, 0x401000, 0.9, "match:engine"),
    )
    con.commit()
    con.close()
    monkeypatch.setenv("AGENT_DECOMPILE_CORPUS_DB", str(db))
    monkeypatch.setenv("AGENT_DECOMPILE_CORPUS_WORK_DIR", str(tmp_path / "work"))
    from agentdecompile_recovery.corpus.dashboard import entity_activity as activity
    from agentdecompile_recovery.corpus.dashboard.common import query_db

    rows, error = query_db("SELECT slug FROM binary")
    assert error is None
    assert rows == [("game.exe",)]
    activity._LIBRARY = ("", 0, {})
    payload = activity.snapshot("", "game.exe")
    binary = next(row for row in payload["entities"] if row["kind"] == "binary" and row["slug"] == "game.exe")
    kinds = {row["kind"] for row in binary["evidence"]}
    assert "debug" in kinds
    assert "human" in kinds
    assert "match" in kinds
    assert all(row["kind"] != "recorded-proof" for row in binary["evidence"])
    assert binary["activity"]["status"] in {"idle", "running", "queued", "waiting", "cancelling"}
