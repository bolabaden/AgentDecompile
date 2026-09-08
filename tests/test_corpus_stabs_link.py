from __future__ import annotations

import sqlite3

from agentdecompile_recovery.corpus import store
from agentdecompile_recovery.corpus.stabs_link import (
    apply_manifest_records,
    ensure_columns,
    propagate_source_files,
    replace_stabs_types,
    select_slices,
)


def _connect() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.executescript(store.SCHEMA)
    ensure_columns(con)
    con.executemany(
        "INSERT INTO binary(id, repo_path, slug, platform) VALUES (?,?,?,?)",
        [(1, "one", "one", "mac"), (2, "two", "two", "win")],
    )
    return con


def test_preserves_existing_logical_attribution_and_uses_one_donor_pair() -> None:
    con = _connect()
    con.executemany(
        "INSERT INTO logical_function(id, source_file, object_file) VALUES (?,?,?)",
        [(1, "reviewed.cpp", "reviewed.o"), (2, None, None)],
    )
    con.executemany(
        "INSERT INTO func(binary_id, addr, source_file, object_file) VALUES (?,?,?,?)",
        [
            (1, 0x10, "old.cpp", "old.o"),
            (1, 0x20, "first.cpp", "first.o"),
            (2, 0x20, "second.cpp", "second.o"),
            (2, 0x21, None, None),
        ],
    )
    con.executemany(
        "INSERT INTO identity(logical_id, binary_id, addr, confidence) VALUES (?,?,?,?)",
        [(1, 1, 0x10, 1.0), (2, 1, 0x20, 1.0), (2, 2, 0x20, 1.0), (2, 2, 0x21, 1.0)],
    )
    con.commit()

    propagate_source_files(con)

    rows = {
        r["id"]: (r["source_file"], r["object_file"])
        for r in con.execute("SELECT id, source_file, object_file FROM logical_function")
    }
    assert rows[1] == ("reviewed.cpp", "reviewed.o")
    assert rows[2] in {("first.cpp", "first.o"), ("second.cpp", "second.o")}
    propagated = con.execute(
        "SELECT source_file, object_file FROM func WHERE binary_id=2 AND addr=?",
        (0x21,),
    ).fetchone()
    assert tuple(propagated) == rows[2]


def test_type_refresh_is_idempotent_with_nullable_fields() -> None:
    con = _connect()
    duplicated = [
        {
            "source_file": None,
            "object_file": None,
            "name": "CThing",
            "kind": None,
            "stab": "CThing:t(0,1)",
            "func_addr": None,
        },
        {
            "source_file": None,
            "object_file": None,
            "name": "CThing",
            "kind": None,
            "stab": "CThing:t(0,1)",
            "func_addr": None,
        },
    ]
    replace_stabs_types(con, 1, duplicated)
    replace_stabs_types(con, 1, duplicated)
    count = con.execute("SELECT COUNT(*) FROM stabs_type WHERE binary_id=1").fetchone()[0]
    assert count == 1
    replace_stabs_types(con, 1, [{**duplicated[0], "stab": "CThing:t(0,2)"}])
    stabs = con.execute("SELECT stab FROM stabs_type WHERE binary_id=1").fetchall()
    assert [row[0] for row in stabs] == ["CThing:t(0,2)"]


def test_selects_only_the_binary_architecture_from_a_fat_image() -> None:
    parsed = {
        "slices": [
            {"arch": "i386", "stabs": {"types": [{"name": "X86"}]}},
            {"arch": "ppc", "stabs": {"types": [{"name": "PPC"}]}},
        ]
    }
    selected = select_slices(parsed, "i386")
    assert [item["arch"] for item in selected] == ["i386"]


def test_manifest_application_preserves_existing_function_attribution() -> None:
    con = _connect()
    con.executemany(
        "INSERT INTO func(binary_id, addr, source_file, object_file) VALUES (?,?,?,?)",
        [(1, 0x10, "reviewed.cpp", "reviewed.o"), (1, 0x20, None, "stale.o")],
    )
    records = [
        {
            "addr": 0x10,
            "action": "keep_human_attach_metadata",
            "source_file": "compiler.cpp",
            "object_file": "compiler.o",
            "stabs_name": "CompilerName",
            "stabs_type": "F(0,1)",
        },
        {
            "addr": 0x20,
            "action": "attach_stabs",
            "source_file": "fresh.cpp",
            "object_file": "fresh.o",
            "stabs_name": "FreshName",
            "stabs_type": "F(0,2)",
        },
    ]
    assert apply_manifest_records(con, 1, records) == 2
    rows = {
        row["addr"]: tuple(row)[1:]
        for row in con.execute(
            "SELECT addr, source_file, object_file, stabs_name, stabs_type "
            "FROM func WHERE binary_id=1 ORDER BY addr"
        )
    }
    assert rows[0x10] == ("reviewed.cpp", "reviewed.o", "CompilerName", "F(0,1)")
    assert rows[0x20] == ("fresh.cpp", "fresh.o", "FreshName", "F(0,2)")


def test_manifest_donors_scope_propagation_to_reachable_identities() -> None:
    con = _connect()
    con.executemany(
        "INSERT INTO logical_function(id, source_file, object_file) VALUES (?,?,?)",
        [(1, None, None), (2, "unrelated.cpp", "unrelated.o")],
    )
    con.executemany(
        "INSERT INTO func(binary_id, addr, source_file, object_file) VALUES (?,?,?,?)",
        [(1, 0x10, "donor.cpp", "donor.o"), (2, 0x20, None, None), (2, 0x30, None, None)],
    )
    con.executemany(
        "INSERT INTO identity(logical_id, binary_id, addr, confidence) VALUES (?,?,?,?)",
        [(1, 1, 0x10, 1.0), (1, 2, 0x20, 1.0), (2, 2, 0x30, 1.0)],
    )
    con.commit()
    pushed = propagate_source_files(
        con,
        donor_rows=[{"binary_id": 1, "addr": 0x10, "source_file": "donor.cpp", "object_file": "donor.o"}],
    )
    assert pushed == 1
    propagated = con.execute(
        "SELECT source_file, object_file FROM func WHERE binary_id=2 AND addr=?",
        (0x20,),
    ).fetchone()
    unrelated = con.execute("SELECT source_file FROM func WHERE binary_id=2 AND addr=?", (0x30,)).fetchone()[0]
    assert tuple(propagated) == ("donor.cpp", "donor.o")
    assert unrelated is None
