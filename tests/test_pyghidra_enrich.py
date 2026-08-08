"""Unit tests for pyghidra enrich fact writing."""

from __future__ import annotations

import json
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


def test_run_enrich_pipeline_fact_name_prefers_names_by_entry(tmp_path: Path) -> None:
    """Curated tier must reach the fact even if decompile still echoes sub_*."""
    out = tmp_path / "facts.jsonl"
    summary = run_enrich_pipeline(
        boundaries=[{"entry": 0x401060, "length": 8, "name": "sub_1060"}],
        corpus=None,
        rtti_classes=[],
        out_facts=out,
        program_factory=FakeEnrichProgram,
        names_by_entry={0x401060: ("GetObjectTableManager", "curated-project")},
    )
    assert summary["namedCount"] == 1
    row = json.loads(out.read_text(encoding="utf-8").splitlines()[0])
    assert row["name"] == "GetObjectTableManager"
    assert row["provenance"] == "curated-project"


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


# -- curated prototypes reach the decompiler ----------------------------------


def _thiscall_signature() -> dict[str, object]:
    return {
        "name": "GetObjectTableManager",
        "qualifiedName": "CAppManager::GetObjectTableManager",
        "callingConvention": "__thiscall",
        "returnType": "undefined4",
        "parameters": [{"ordinal": 0, "name": "nIndex", "type": "int", "slot": "param_1"}],
        "arityCheck": "match",
        "signature": "undefined4 __thiscall CAppManager::GetObjectTableManager(int)",
    }


def test_curated_prototype_is_applied_before_decompile(tmp_path: Path) -> None:
    """Order is the whole point: the calling convention decides argument storage.

    Applied after the decompile it would change nothing, and the emitted C
    would keep reading an uninitialised `in_ECX` for every `__thiscall` method.
    """

    program = FakeEnrichProgram()
    run_enrich_pipeline(
        boundaries=[{"entry": 0x401060, "length": 32}],
        corpus=None,
        rtti_classes=[],
        out_facts=tmp_path / "facts.jsonl",
        program_factory=lambda: program,
        signatures_by_entry={0x401060: _thiscall_signature()},
    )

    assert program.calls.index("signature:4198496:__thiscall") < program.calls.index("decompile:4198496")


def test_applied_prototype_lands_in_the_fact_row(tmp_path: Path) -> None:
    out = tmp_path / "facts.jsonl"
    summary = run_enrich_pipeline(
        boundaries=[{"entry": 0x401060, "length": 32}],
        corpus=None,
        rtti_classes=[],
        out_facts=out,
        program_factory=FakeEnrichProgram,
        signatures_by_entry={0x401060: _thiscall_signature()},
    )

    fact = json.loads(out.read_text(encoding="utf-8").splitlines()[0])

    assert fact["callingConvention"] == "__thiscall"
    assert fact["qualifiedName"] == "CAppManager::GetObjectTableManager"
    assert fact["curatedSignature"] == "undefined4 __thiscall CAppManager::GetObjectTableManager(int)"
    assert fact["locals"] == [{"name": "nIndex", "slot": "param_1"}]
    assert summary["curatedPrototypeCount"] == 1


def test_facts_are_unchanged_when_no_curated_prototype_is_supplied(tmp_path: Path) -> None:
    out = tmp_path / "facts.jsonl"
    summary = run_enrich_pipeline(
        boundaries=[{"entry": 0x401060, "length": 32}],
        corpus=None,
        rtti_classes=[],
        out_facts=out,
        program_factory=FakeEnrichProgram,
    )

    fact = json.loads(out.read_text(encoding="utf-8").splitlines()[0])

    assert "callingConvention" not in fact
    assert "curatedSignature" not in fact
    assert summary["curatedPrototypeCount"] == 0


def test_a_prototype_the_program_rejects_does_not_reach_the_fact(tmp_path: Path) -> None:
    class RejectingProgram(FakeEnrichProgram):
        def apply_signature(self, entry: int, signature: dict[str, object]) -> bool:
            self.calls.append(f"signature-rejected:{entry}")
            return False

    out = tmp_path / "facts.jsonl"
    run_enrich_pipeline(
        boundaries=[{"entry": 0x401060, "length": 32}],
        corpus=None,
        rtti_classes=[],
        out_facts=out,
        program_factory=RejectingProgram,
        signatures_by_entry={0x401060: _thiscall_signature()},
    )

    fact = json.loads(out.read_text(encoding="utf-8").splitlines()[0])

    assert "curatedSignature" not in fact
    assert "callingConvention" not in fact
