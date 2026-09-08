from __future__ import annotations

from agentdecompile_recovery.corpus.naming import HUMAN, STABS, resolve, tier_of


def test_stabs_replaces_a_placeholder() -> None:
    row = {
        "binary_id": 1,
        "name": "FUN_00401000",
        "name_origin": "none",
        "stabs_name": "Named::Update",
    }
    assert tier_of(row) == STABS
    assert resolve([row])["name"] == "Named::Update"


def test_human_name_remains_above_stabs() -> None:
    row = {
        "binary_id": 1,
        "name": "HandCorrectedName",
        "name_origin": "plate",
        "stabs_name": "CompilerDebugName",
    }
    assert tier_of(row) == HUMAN
    assert resolve([row])["name"] == "HandCorrectedName"


def test_stabs_value_wins_over_a_derived_name() -> None:
    row = {
        "binary_id": 1,
        "name": "StringDerivedName",
        "name_origin": "bare",
        "stabs_name": "CompilerDebugName",
    }
    assert tier_of(row) == STABS
    assert resolve([row])["name"] == "CompilerDebugName"
