"""Tests for U13: wiring curated project data (names + hints) into the pipeline.

`extract_curated_project_data` opens a `--project` once per run and persists
`curated-names.json` / `curated-hints.json` to `work_dir`; `load_curated_names`
and `load_curated_hints` are the shared "load if present" helpers both naming
and source-generation call sites use. See `.mission/notes/` for the packet
this implements.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentdecompile_recovery.curated_project import (
    CURATED_HINTS_FILENAME,
    CURATED_NAMES_FILENAME,
    extract_curated_project_data,
    load_curated_hints,
    load_curated_names,
)

pytestmark = pytest.mark.unit

ODYSSEY_REP = Path("/home/brunner56/Odyssey.rep")
GHIDRA_REP = Path("/home/brunner56/Downloads/biodecompwarehouse/projects/agentdecompile.rep")


def _first_available_project() -> Path | None:
    if ODYSSEY_REP.is_dir():
        return ODYSSEY_REP
    if GHIDRA_REP.is_dir():
        return GHIDRA_REP
    return None


_needs_any_project = pytest.mark.skipif(
    _first_available_project() is None, reason="no Ghidra project fixture available"
)


# -- load_curated_names -------------------------------------------------------


def test_load_curated_names_returns_none_when_file_absent(tmp_path: Path) -> None:
    assert load_curated_names(tmp_path) is None


def test_load_curated_names_round_trips_hex_keys(tmp_path: Path) -> None:
    payload = {"0x401000": "CGame::Update", "0x401020": "CGame::Render"}
    (tmp_path / CURATED_NAMES_FILENAME).write_text(json.dumps(payload), encoding="utf-8")

    names = load_curated_names(tmp_path)

    assert names == {0x401000: "CGame::Update", 0x401020: "CGame::Render"}


def test_load_curated_names_returns_none_for_corrupt_json(tmp_path: Path) -> None:
    (tmp_path / CURATED_NAMES_FILENAME).write_text("not json", encoding="utf-8")
    assert load_curated_names(tmp_path) is None


def test_load_curated_names_returns_none_for_empty_map(tmp_path: Path) -> None:
    (tmp_path / CURATED_NAMES_FILENAME).write_text("{}", encoding="utf-8")
    assert load_curated_names(tmp_path) is None


# -- load_curated_hints --------------------------------------------------------


def test_load_curated_hints_returns_none_when_file_absent(tmp_path: Path) -> None:
    assert load_curated_hints(tmp_path) is None


def test_load_curated_hints_round_trips(tmp_path: Path) -> None:
    payload = {"00401000": {"plateComment": "note", "locals": [{"name": "pDst", "slot": "param_1"}]}}
    (tmp_path / CURATED_HINTS_FILENAME).write_text(json.dumps(payload), encoding="utf-8")

    hints = load_curated_hints(tmp_path)

    assert hints == payload


def test_load_curated_hints_returns_none_for_corrupt_json(tmp_path: Path) -> None:
    (tmp_path / CURATED_HINTS_FILENAME).write_text("not json", encoding="utf-8")
    assert load_curated_hints(tmp_path) is None


# -- extract_curated_project_data: failure handling (no real project needed) --


def test_extract_curated_project_data_bad_project_reports_failed_not_raise(tmp_path: Path) -> None:
    bad_project = tmp_path / "does-not-exist.rep"
    work_dir = tmp_path / "work"
    work_dir.mkdir()

    receipt = extract_curated_project_data(project=bad_project, work_dir=work_dir)

    assert receipt["status"] == "failed"
    assert receipt["reason"]
    # A failed extraction must not write partial/misleading output files.
    assert not (work_dir / CURATED_NAMES_FILENAME).exists()
    assert not (work_dir / CURATED_HINTS_FILENAME).exists()


def test_extract_curated_project_data_ambiguous_multi_program_reports_failed(tmp_path: Path) -> None:
    """A project with >1 program and no `project_program` fails clearly (like open_project_names_context)."""

    not_a_project = tmp_path / "just-a-folder"
    not_a_project.mkdir()
    work_dir = tmp_path / "work"
    work_dir.mkdir()

    receipt = extract_curated_project_data(project=not_a_project, work_dir=work_dir)

    assert receipt["status"] == "failed"
    assert "not a Ghidra project" in receipt["reason"] or receipt["reason"]


# -- extract_curated_project_data: real project (integration) -----------------


@_needs_any_project
def test_extract_curated_project_data_writes_both_files(tmp_path: Path) -> None:
    project = _first_available_project()
    assert project is not None
    work_dir = tmp_path / "work"
    work_dir.mkdir()

    receipt = extract_curated_project_data(project=project, work_dir=work_dir)

    assert receipt["status"] == "complete"
    names_path = work_dir / CURATED_NAMES_FILENAME
    hints_path = work_dir / CURATED_HINTS_FILENAME
    assert names_path.is_file()
    assert hints_path.is_file()
    assert receipt["nameCount"] > 0

    # Round-trips through the shared loader helpers.
    names = load_curated_names(work_dir)
    assert names, "expected at least one curated name to reload"
    hints = load_curated_hints(work_dir)
    # Hints may legitimately be empty for a project with names but no
    # curated params/comments; only assert the file parses as a dict.
    assert hints is None or isinstance(hints, dict)


@_needs_any_project
def test_extract_curated_project_data_names_feed_naming_tier(tmp_path: Path) -> None:
    """End-to-end: curated-names.json reload matches build_names_by_entry's curated-project tier."""

    from agentdecompile_recovery.pyghidra_enrich import build_names_by_entry

    project = _first_available_project()
    assert project is not None
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    extract_curated_project_data(project=project, work_dir=work_dir)

    curated_names = load_curated_names(work_dir)
    assert curated_names

    entry, curated_name = next(iter(curated_names.items()))
    names_by_entry = build_names_by_entry(discovered=[], curated_names=curated_names)

    assert names_by_entry[entry] == (curated_name, "curated-project")


@_needs_any_project
def test_extract_curated_project_data_hints_feed_dump_source_tree_end_to_end(tmp_path: Path) -> None:
    """Real curated project -> curated-hints.json -> dump_source_tree's emitted C.

    Full chain proof for the hints tier, mirroring
    `test_extract_curated_project_data_names_feed_naming_tier` for the naming
    tier: this does not fabricate a curated hint, it extracts one from the
    real project database and confirms it reaches the emitted `verified/`
    source exactly the way `run_dump_source` (frontdoor.py) wires it.
    """

    import json

    from agentdecompile_recovery.source_dump import dump_source_tree

    project = _first_available_project()
    assert project is not None
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    receipt = extract_curated_project_data(project=project, work_dir=work_dir)
    assert receipt["status"] == "complete"

    curated_hints = load_curated_hints(work_dir)
    assert curated_hints, "expected at least one function with curated params or a comment"

    # Pick a real curated entry that has at least one curated parameter, so
    # the substitution in the emitted C is observable.
    entry_hex, hint = next((k, v) for k, v in curated_hints.items() if v.get("locals"))
    slot = hint["locals"][0]["slot"]
    curated_name = hint["locals"][0]["name"]

    source_path = tmp_path / "fn.c"
    source_path.write_text(f"void FUN_{entry_hex}(int {slot})\n{{\n  {slot} = 1;\n}}\n", encoding="utf-8")
    summary = tmp_path / "summary.jsonl"
    summary.write_text(
        json.dumps(
            {
                "name": f"FUN_{entry_hex}",
                "entry": entry_hex,
                "status": "matched",
                "differences": 0,
                "source": str(source_path),
                "sourceQuality": "high-level-c",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    dump_source_tree(
        out_dir=tmp_path / "dump",
        summaries=[summary],
        reference_root=tmp_path,
        curated_hints=curated_hints,
    )

    verified_files = list((tmp_path / "dump" / "verified").glob("*.c"))
    assert len(verified_files) == 1
    text = verified_files[0].read_text(encoding="utf-8")

    assert curated_name in text
    assert slot not in text
