from __future__ import annotations

from agentdecompile_recovery.corpus.calibrate import sweep
from agentdecompile_recovery.corpus.decompile_shape import features, normalize
from agentdecompile_recovery.corpus.evaluate import ground_truth
from agentdecompile_recovery.corpus.extract import write_snapshot
from agentdecompile_recovery.corpus.features import mnemonic_class, mnemonic_profile
from agentdecompile_recovery.corpus.store import SCHEMA, connect


def test_mnemonic_class_collapses_architectures() -> None:
    assert mnemonic_class("mov") == "MOV"
    assert mnemonic_class("ldr") == "MOV"
    assert mnemonic_class("je") == "CBRANCH"
    assert mnemonic_class("b.eq") == "CBRANCH"
    assert mnemonic_profile({"MOV": 3, "CALL": 1})["MOV"] == 0.75


def test_decompile_shape_is_name_free() -> None:
    code = "if (iVar1) { return DAT_006f1234 + 3; } return 0;"
    assert "FUN_" not in normalize(code)
    shape = features(code)
    assert shape["ctrl"]["if"] == 1
    assert shape["n_calls"] == 0
    assert shape["skeleton_hash"]


def test_write_snapshot_and_ground_truth(tmp_path) -> None:
    dest = write_snapshot(tmp_path, "donor", [{"id": "0x10", "name": "Foo", "strings": ["x"]}])
    assert dest.is_file()
    con = connect(tmp_path / "store.sqlite")
    con.executescript(SCHEMA)
    con.execute("INSERT INTO binary(id, repo_path, slug) VALUES (1,'/a','a')")
    con.execute("INSERT INTO binary(id, repo_path, slug) VALUES (2,'/b','b')")
    con.executemany(
        "INSERT INTO func(binary_id, addr, name, canon_key, canon_class, canon_method, is_thunk, n_instr, plate) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        [
            (1, 0x10, "Foo::one", "Foo::one", "Foo", "one", 0, 20, None),
            (2, 0x20, "Foo::one", "Foo::one", "Foo", "one", 0, 22, None),
            (1, 0x11, "Foo::dup", "Foo::dup", "Foo", "dup", 0, 20, None),
            (1, 0x12, "Foo::dup", "Foo::dup", "Foo", "dup", 0, 21, None),
        ],
    )
    con.commit()
    gt = ground_truth(con, 1, 2)
    assert gt == {0x10: 0x20}


def test_calibrate_sweep_precision() -> None:
    rows = [(0.9, 0.2, 2, 1.0, 1), (0.8, 0.1, 1, 1.0, 0), (0.6, 0.0, 0, 1.0, 1)]
    points = sweep(rows, 0.06, 1)
    at_90 = next(p for p in points if p["score_min"] == 0.90)
    assert at_90["accepted"] == 1
    assert at_90["precision"] == 1.0
