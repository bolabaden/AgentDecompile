from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.corpus.leftover import (
    count_leftovers,
    explain_empty,
    is_leftover,
    keep_leftover_queue_row,
    leftover_from_file,
    leftover_store_sets,
)

pytestmark = pytest.mark.unit


def test_leftover_predicate() -> None:
    assert is_leftover(logical_id=3, has_asm=True, tried_or_failed=True, has_real_c=False)
    assert not is_leftover(logical_id=3, has_asm=True, tried_or_failed=True, has_real_c=True)
    assert not is_leftover(logical_id=None, has_asm=True, tried_or_failed=True, has_real_c=False)
    assert not is_leftover(logical_id=3, has_asm=True, tried_or_failed=False, has_real_c=False)
    assert "bound logical_id" in explain_empty()


def test_leftover_from_file_needs_tried_asm(tmp_path: Path) -> None:
    from agentdecompile_recovery.corpus import asm_seed

    dest = tmp_path / "Tried_00000001.c"
    dest.write_text(
        asm_seed.asm_banner("Tried_00000001", "00000001")
        + asm_seed.emit_naked_asm("Tried", b"\x90")
    )
    asm_seed.mark_c_replace_tried(dest)
    assert leftover_from_file(dest, logical_id=1, has_real_c=False)
    assert leftover_from_file(dest, logical_id=1, has_real_c=True) is False
    assert count_leftovers(tmp_path) == 1


def test_leftover_only_queue_skips_real_c_and_untried() -> None:
    real_c = {9}
    tried = {3}
    assert keep_leftover_queue_row({"logical_id": 3}, real_c, tried)
    assert not keep_leftover_queue_row({"logical_id": 9}, real_c, tried)
    assert not keep_leftover_queue_row({"logical_id": 4}, real_c, tried)
    assert not keep_leftover_queue_row({"logical_id": None}, real_c, tried)


def test_leftover_store_sets_and_empty_reason(tmp_path: Path) -> None:
    from agentdecompile_recovery.corpus.ingest_recovered import ensure_recovered_schema
    from agentdecompile_recovery.corpus.store import connect

    con = connect(tmp_path / "c.sqlite")
    ensure_recovered_schema(con)
    con.execute("INSERT INTO binary(id, repo_path, slug) VALUES (1, '/a', 'win')")
    con.execute(
        "INSERT INTO recovered_function(program, name, real_c, logical_id, path) "
        "VALUES ('/a', 'Done', 1, 9, '/tmp/done.c')"
    )
    con.commit()
    real_c, tried = leftover_store_sets(con)
    assert 9 in real_c
    assert 9 not in tried
    assert "bound logical_id" in explain_empty()
