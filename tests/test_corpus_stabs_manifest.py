from __future__ import annotations

from agentdecompile_recovery.corpus.stabs_manifest import build_records


def test_manifest_is_keyed_by_n_fun_address_intersection() -> None:
    stabs_functions = [
        {"addr": 0x10, "name": "Foo::one", "source_file": "foo.cpp", "object_file": "foo.o"},
        {"addr": 0x20, "name": "Foo::two", "source_file": "foo.cpp", "object_file": "foo.o"},
        {"addr": 0x30, "name": "not_in_ghidra", "source_file": "lost.cpp", "object_file": "lost.o"},
    ]
    database_functions = {
        0x10: {"addr": 0x10, "name": "FUN_00000010", "name_origin": "none"},
        0x20: {"addr": 0x20, "name": "HandName", "name_origin": "plate"},
        0x99: {"addr": 0x99, "name": "GhidraOnly", "name_origin": "bare"},
    }

    records, summary = build_records(stabs_functions, database_functions)

    assert summary["n_fun_unique_addresses"] == 3
    assert summary["func_address_hits"] == 2
    assert summary["address_misses"] == 1
    assert {row["addr"] for row in records if row["address_hit"]} == {0x10, 0x20}
    actions = {row["addr"]: row["action"] for row in records}
    assert actions[0x10] == "attach_stabs"
    assert actions[0x20] == "keep_human_attach_metadata"
    assert actions[0x30] == "address_miss"


def test_conflicting_duplicate_n_fun_addresses_are_not_applicable() -> None:
    stabs_functions = [
        {"addr": 0x10, "name": "Foo::one", "source_file": "a.cpp"},
        {"addr": 0x10, "name": "Foo::other", "source_file": "b.cpp"},
    ]
    database_functions = {0x10: {"addr": 0x10, "name": "FUN_00000010"}}

    records, summary = build_records(stabs_functions, database_functions)

    assert records[0]["action"] == "ambiguous_n_fun"
    assert summary["func_address_hits"] == 1
    assert summary["ambiguous_addresses"] == 1
    assert summary["applicable_addresses"] == 0
