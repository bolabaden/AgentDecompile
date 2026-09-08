from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentdecompile_recovery.corpus.ingest_recovered import (
    ADDR_SUFFIX,
    existing_logical_for_recovery,
    load_coverage_index,
    load_seed_promotions,
    load_verified_coverage,
    logical_from_indexes,
)
from agentdecompile_recovery.corpus.store import connect

pytestmark = pytest.mark.unit


@pytest.fixture
def con(tmp_path: Path):
    db = connect(tmp_path / "corpus.sqlite")
    db.execute("INSERT INTO binary(id, repo_path, slug) VALUES (1, '/arbitrary/game', 'game__bin')")
    db.execute(
        "INSERT INTO logical_function(id, canon_key, best_name) "
        "VALUES (10, 'C::Method', 'C::Method')"
    )
    db.execute(
        "INSERT INTO func(binary_id, addr, name, canon_key) "
        "VALUES (1, 4096, 'FUN_00001000', NULL)"
    )
    db.execute(
        "INSERT INTO func(binary_id, addr, name, canon_key) "
        "VALUES (1, 8192, 'Method', 'C::Method')"
    )
    db.commit()
    yield db
    db.close()


def test_exact_address_without_independent_identity_stays_unbound(con) -> None:
    row = {"binary_id": 1, "addr": 4096, "name": "FUN_00001000"}
    assert existing_logical_for_recovery(con, row) is None


def test_exact_address_inherits_existing_identity(con) -> None:
    con.execute(
        "INSERT INTO identity(logical_id, binary_id, addr, method) "
        "VALUES (10, 1, 4096, 'name-unique')"
    )
    row = {"binary_id": 1, "addr": 4096, "name": "FUN_00001000"}
    assert existing_logical_for_recovery(con, row) == 10


def test_named_recovery_can_use_unique_canonical_identity(con) -> None:
    con.execute(
        "INSERT INTO identity(logical_id, binary_id, addr, method) "
        "VALUES (10, 1, 8192, 'name-unique')"
    )
    row = {"binary_id": 1, "addr": None, "name": "C_Method"}
    assert existing_logical_for_recovery(con, row) == 10


def test_bulk_indexes_do_not_invent_an_identity() -> None:
    row = {"binary_id": 1, "addr": None, "name": "Unknown"}
    assert logical_from_indexes(row, {}, {}) is None


def test_coverage_ledger_not_header_text_controls_verified_set(tmp_path: Path) -> None:
    ledger = tmp_path / "game.jsonl"
    ledger.write_text(
        json.dumps({"function": "Good", "byteExact": True}) + "\n"
        + json.dumps({"function": "OnlyObjdiff", "byteExact": False}) + "\n"
    )
    verified = load_verified_coverage(tmp_path)
    assert {("game", "Good")} == verified


def test_coverage_index_retains_original_bytes(tmp_path: Path) -> None:
    ledger = tmp_path / "game.jsonl"
    ledger.write_text(json.dumps({
        "function": "Named_00401000",
        "byteExact": True,
        "originalBytes": "33c0c3",
    }) + "\n")
    index = load_coverage_index(tmp_path)
    assert index[("game", "Named_00401000")]["originalBytes"] == "33c0c3"


def test_canonical_recovered_filename_can_supply_address() -> None:
    match = ADDR_SUFFIX.search("Material_HasNormalMap_00401000")
    assert match is not None
    assert match.group(1) == "00401000"


def test_seed_promotion_requires_byte_exact_compile_and_destination_identity(
    con, tmp_path: Path
) -> None:
    con.execute(
        "INSERT INTO identity(logical_id, binary_id, addr, method, confidence) "
        "VALUES (10, 1, 4096, 'name-unique', 0.99)"
    )
    seed = tmp_path / "seed.c"
    seed.write_text("int C_Method(void) { return 0; }\n")
    results = tmp_path / "seed_validation.jsonl"
    results.write_text(json.dumps({
        "compile_status": "byte_exact",
        "static_status": "identity_linked",
        "dst_slug": "game__bin",
        "dst_repo": "/arbitrary/game",
        "dst_addr": "1000",
        "dst_name": "Method",
        "source_name": "C_Method",
        "source_path": "/verified/C_Method.c",
        "seed": str(seed),
        "size": 3,
        "destination_bytes": "33c0c3",
        "real_c": True,
    }) + "\n")
    reuse = tmp_path / "reuse_candidates.jsonl"
    reuse.write_text(json.dumps({
        "logical_id": 10,
        "recovered_from": {"source_path": "/verified/C_Method.c"},
        "reuse_target": {"repo_path": "/arbitrary/game", "address": "00001000"},
    }) + "\n")

    promotions = load_seed_promotions(con, results, reuse)
    assert len(promotions) == 1
    assert promotions[0]["logical_id"] == 10
    assert promotions[0]["binary_id"] == 1
    assert promotions[0]["program"] == "bin"
