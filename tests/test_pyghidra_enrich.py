"""Unit tests for pyghidra enrich fact writing."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.pyghidra_enrich import FakeEnrichProgram, run_enrich_pipeline

pytestmark = pytest.mark.unit

ODYSSEY_GBF = Path("/home/brunner56/Odyssey.rep/idata/00/~00000000.db/db.1.gbf")
_needs_odyssey = pytest.mark.skipif(not ODYSSEY_GBF.is_file(), reason="Odyssey project fixture unavailable")


def test_run_enrich_pipeline_writes_facts(tmp_path: Path) -> None:
    out = tmp_path / "facts.jsonl"
    summary = run_enrich_pipeline(
        boundaries=[{"entry": 0x1000, "length": 8}],
        corpus=None,
        rtti_classes=[],
        out_facts=out,
        program_factory=FakeEnrichProgram,
    )
    assert out.exists()
    assert summary["functionCount"] == 1
    assert (tmp_path / "enrich-receipt.json").exists() or (out.parent / "enrich-receipt.json").exists()


def test_build_names_by_entry_prefers_ghidra_symbols() -> None:
    from agentdecompile_recovery.pyghidra_enrich import build_names_by_entry

    names = build_names_by_entry(
        discovered=[
            {"entry": 0x1000, "name": "FUN_001000"},
            {"entry": 0x2000, "name": "LoadArea"},
        ]
    )
    assert 0x1000 not in names
    assert names[0x2000] == ("LoadArea", "ghidra-symbol")


# -- U8: curated-project tier -------------------------------------------------


def test_build_names_by_entry_curated_wins_over_ghidra_symbol() -> None:
    from agentdecompile_recovery.pyghidra_enrich import build_names_by_entry

    names = build_names_by_entry(
        discovered=[{"entry": 0x2000, "name": "LoadArea"}],
        curated_names={0x2000: "CreateServer"},
    )
    assert names[0x2000] == ("CreateServer", "curated-project")


def test_build_names_by_entry_curated_wins_with_corpus_and_rtti_present() -> None:
    """Curated must win even when corpus/RTTI evidence is also supplied.

    Note: with this exact fixture the "rtti-corpus" tier itself never claims
    the entry -- its guard (`entry in names`) only lets it fill entries the
    ghidra-symbol tier skipped for being default-shaped, but it re-checks
    `is_default_ghidra_name` on that same already-non-default name before
    matching against the corpus, so a real corpus win needs the ghidra-symbol
    name and the corpus-matched name to differ (not exercised here). That is
    a pre-existing property of the two lower tiers, out of scope for this
    curated-project addition; what this test proves is narrower and still
    correct: passing `corpus`/`rtti_classes` alongside `curated_names` does
    not stop the curated tier from applying with top priority.
    """

    from agentdecompile_recovery.pyghidra_enrich import build_names_by_entry
    from agentdecompile_recovery.reference_corpus import CorpusClass, ReferenceCorpus
    from agentdecompile_recovery.rtti_recover import RttiClass

    corpus = ReferenceCorpus(
        reference_root="ref",
        classes={"CServer": CorpusClass(name="CServer", path="CServer.h", methods=["CServer::Start"])},
    )
    rtti_classes = [RttiClass(mangled=".?AVCServer@@", name="CServer")]

    names = build_names_by_entry(
        discovered=[{"entry": 0x2000, "name": "Start"}],
        corpus=corpus,
        rtti_classes=rtti_classes,
        curated_names={0x2000: "CreateServer"},
    )
    assert names[0x2000] == ("CreateServer", "curated-project")


def test_build_names_by_entry_curated_skips_default_shaped_names() -> None:
    from agentdecompile_recovery.pyghidra_enrich import build_names_by_entry

    names = build_names_by_entry(
        discovered=[],
        curated_names={0x1000: "FUN_00401000", 0x2000: "", 0x3000: "   "},
    )
    assert names == {}


def test_build_names_by_entry_curated_leaves_unrelated_entries_unaffected() -> None:
    from agentdecompile_recovery.pyghidra_enrich import build_names_by_entry

    names = build_names_by_entry(
        discovered=[
            {"entry": 0x1000, "name": "FUN_001000"},
            {"entry": 0x2000, "name": "LoadArea"},
        ],
        curated_names={0x3000: "CreateServer"},
    )
    assert 0x1000 not in names
    assert names[0x2000] == ("LoadArea", "ghidra-symbol")
    assert names[0x3000] == ("CreateServer", "curated-project")


def test_build_names_by_entry_default_behavior_unchanged_without_curated_names() -> None:
    """Literal before/after proof: omitting `curated_names` must be identical to before U8."""

    from agentdecompile_recovery.pyghidra_enrich import build_names_by_entry
    from agentdecompile_recovery.reference_corpus import CorpusClass, ReferenceCorpus
    from agentdecompile_recovery.rtti_recover import RttiClass

    # Entry 0x3000's Ghidra symbol name ("Start") looks like a plain
    # identifier, not a class-qualified corpus method, and the corpus tier
    # only applies when the entry is still unclaimed after the ghidra-symbol
    # tier -- so a default-shaped Ghidra name is what lets the corpus tier win.
    discovered = [
        {"entry": 0x1000, "name": "FUN_001000"},
        {"entry": 0x2000, "name": "LoadArea"},
        {"entry": 0x3000, "name": "FUN_003000"},
    ]
    corpus = ReferenceCorpus(
        reference_root="ref",
        classes={"CServer": CorpusClass(name="CServer", path="CServer.h", methods=["CServer::Start"])},
    )
    rtti_classes = [RttiClass(mangled=".?AVCServer@@", name="CServer")]

    without_curated_param = build_names_by_entry(discovered=discovered, corpus=corpus, rtti_classes=rtti_classes)
    with_explicit_none = build_names_by_entry(
        discovered=discovered, corpus=corpus, rtti_classes=rtti_classes, curated_names=None
    )
    assert without_curated_param == with_explicit_none
    assert without_curated_param == {
        0x2000: ("LoadArea", "ghidra-symbol"),
    }


@_needs_odyssey
def test_build_names_by_entry_curated_tier_against_real_odyssey_database() -> None:
    from agentdecompile_recovery.ghidra_db.program import open_program
    from agentdecompile_recovery.pyghidra_enrich import build_names_by_entry

    with open_program(ODYSSEY_GBF) as program:
        curated_names = program.names_by_entry()

    assert curated_names, "expected at least one curated function name in the real Odyssey database"
    entry, name = next(iter(curated_names.items()))
    names = build_names_by_entry(discovered=[], curated_names=curated_names)
    assert names.get(entry) == (name, "curated-project") or entry not in names
