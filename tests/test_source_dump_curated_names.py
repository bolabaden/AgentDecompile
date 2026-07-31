"""Tests for emit-time curated function renaming in `dump_source_tree`.

The enrich-stage naming tier (`pyghidra_enrich.build_names_by_entry`) only runs
during a full pyghidra re-analysis, so a dump over an already-built facts file
kept the generated `sub_1060`/`FUN_00401060` spellings even when the curated
project knew the real name. These cover the emit-time path that fixes that,
including call-site rewriting.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentdecompile_recovery.source_dump import (
    apply_curated_renames,
    build_curated_rename_map,
    dump_source_tree,
)

pytestmark = pytest.mark.unit


# -- build_curated_rename_map -------------------------------------------------


def test_rename_map_maps_generated_name_to_curated_name() -> None:
    rows = [{"entry": "00401060", "name": "sub_1060"}]
    renames = build_curated_rename_map(rows, {"00401060": "GetObjectTableManager"})
    assert renames == {"sub_1060": "GetObjectTableManager"}


def test_rename_map_covers_fun_prefixed_names() -> None:
    rows = [{"entry": "00401060", "name": "FUN_00401060"}]
    renames = build_curated_rename_map(rows, {"00401060": "GetObjectTableManager"})
    assert renames == {"FUN_00401060": "GetObjectTableManager"}


def test_rename_map_never_overwrites_an_already_real_name() -> None:
    """A row that already carries real naming evidence is left alone."""

    rows = [{"entry": "00401060", "name": "CServer::Boot"}]
    renames = build_curated_rename_map(rows, {"00401060": "GetObjectTableManager"})
    assert renames == {}


def test_rename_map_skips_entries_with_no_curated_name() -> None:
    rows = [{"entry": "00402000", "name": "sub_2000"}]
    renames = build_curated_rename_map(rows, {"00401060": "GetObjectTableManager"})
    assert renames == {}


# -- apply_curated_renames -----------------------------------------------------


def test_apply_renames_rewrites_call_sites_on_word_boundaries() -> None:
    text = "void sub_1060(void) { sub_2000(); }\n"
    out = apply_curated_renames(text, {"sub_1060": "GetObjectTableManager", "sub_2000": "DestroyServer"})
    assert "GetObjectTableManager" in out
    assert "DestroyServer" in out
    assert "sub_1060" not in out


def test_apply_renames_does_not_touch_substring_matches() -> None:
    """`sub_10` must not rewrite inside `sub_1060`."""

    text = "void sub_1060(void) {}\n"
    out = apply_curated_renames(text, {"sub_10": "Short"})
    assert out == text


def test_apply_renames_is_a_noop_without_renames() -> None:
    text = "void sub_1060(void) {}\n"
    assert apply_curated_renames(text, {}) == text


# -- end-to-end through dump_source_tree ---------------------------------------


def _facts(tmp_path: Path, rows: list[dict]) -> Path:
    path = tmp_path / "facts.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return path


def test_dump_source_tree_renames_function_and_its_call_sites(tmp_path: Path) -> None:
    facts = _facts(
        tmp_path,
        [
            {
                "entry": "00401060",
                "entryOffset": 0x401060,
                "name": "sub_1060",
                "decompiled": "void sub_1060(void)\n{\n  sub_1280();\n}\n",
                "decompilationStatus": "complete",
                "prototype": "void sub_1060(void)",
            },
            {
                "entry": "00401280",
                "entryOffset": 0x401280,
                "name": "sub_1280",
                "decompiled": "void sub_1280(void)\n{\n  return;\n}\n",
                "decompilationStatus": "complete",
                "prototype": "void sub_1280(void)",
            },
        ],
    )

    dump_source_tree(
        out_dir=tmp_path / "dump",
        summaries=[],
        ghidra_facts=facts,
        target_name="swkotor.exe",
        layers="advisory",
        curated_names={"00401060": "GetObjectTableManager", "00401280": "DestroyServer"},
    )

    files = sorted((tmp_path / "dump" / "advisory" / "ghidra").glob("*.c"))
    assert len(files) == 2
    names = " ".join(p.name for p in files)
    assert "GetObjectTableManager" in names
    assert "DestroyServer" in names

    caller = next(p for p in files if "GetObjectTableManager" in p.name)
    text = caller.read_text(encoding="utf-8")
    # Its own name, its prototype, and the call site all use curated spellings.
    assert "GetObjectTableManager" in text
    assert "DestroyServer()" in text
    assert "sub_1060" not in text
    assert "sub_1280" not in text


def test_dump_source_tree_without_curated_names_is_unchanged(tmp_path: Path) -> None:
    """Omitting curated_names must leave output exactly as before the feature."""

    rows = [
        {
            "entry": "00401060",
            "entryOffset": 0x401060,
            "name": "sub_1060",
            "decompiled": "void sub_1060(void)\n{\n  return;\n}\n",
            "decompilationStatus": "complete",
            "prototype": "void sub_1060(void)",
        }
    ]

    dump_source_tree(
        out_dir=tmp_path / "a",
        summaries=[],
        ghidra_facts=_facts(tmp_path / "x", rows) if (tmp_path / "x").mkdir() or True else None,
        target_name="swkotor.exe",
        layers="advisory",
    )
    dump_source_tree(
        out_dir=tmp_path / "b",
        summaries=[],
        ghidra_facts=_facts(tmp_path / "y", rows) if (tmp_path / "y").mkdir() or True else None,
        target_name="swkotor.exe",
        layers="advisory",
        curated_names=None,
    )

    a = sorted((tmp_path / "a" / "advisory" / "ghidra").glob("*.c"))
    b = sorted((tmp_path / "b" / "advisory" / "ghidra").glob("*.c"))
    assert [p.name for p in a] == [p.name for p in b]
    assert a[0].read_text(encoding="utf-8") == b[0].read_text(encoding="utf-8")
    assert "sub_1060" in a[0].read_text(encoding="utf-8")
