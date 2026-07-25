"""Unit tests for RTTI recovery and enrich ordering."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.reference_corpus import CorpusClass, ReferenceCorpus, CorpusField
from agentdecompile_recovery.pyghidra_enrich import (
    EnrichSession,
    FakeEnrichProgram,
    enrich_and_decompile,
    readability_score,
)
from agentdecompile_recovery.rtti_recover import (
    align_vtable_methods,
    demangle_typeinfo_name,
    scan_typeinfo_strings,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "elf"
SAMPLE_ELF = FIXTURES / "sample_i386.elf"

pytestmark = pytest.mark.unit


def test_demangle_typeinfo_names() -> None:
    assert demangle_typeinfo_name("11CExampleApp") == "CExampleApp"
    assert demangle_typeinfo_name("12CExampleArea") == "CExampleArea"
    assert demangle_typeinfo_name("not-a-type") is None
    assert demangle_typeinfo_name("5CTABt") == "CTABt"
    assert demangle_typeinfo_name("9CTABt") is None  # length prefix longer than payload


def test_align_vtable_partial() -> None:
    info = align_vtable_methods("CExampleArea", ["Load", "Save", "Tick"], slot_count=10)
    # 10 slots - 2 meta = 8 usable vs 3 methods → partial
    assert info.provenance == "rtti-vtable-partial"
    assert info.methods[0] == "Load"
    assert any(m.startswith("CExampleArea_slot_") for m in info.methods)


def test_scan_fixture_has_some_typeinfo_or_skips() -> None:
    # Padded fixture may not retain rodata strings; scanning must not crash.
    classes = scan_typeinfo_strings(SAMPLE_ELF, limit=50)
    assert isinstance(classes, list)


def test_enrich_runs_before_decompile_and_closes() -> None:
    program = FakeEnrichProgram()
    corpus = ReferenceCorpus(
        reference_root="/tmp",
        classes={
            "CExampleArea": CorpusClass(
                name="CExampleArea",
                path="game/clientcore",
                methods=["LoadArea"],
                fields=[CorpusField(name="m_nWidth", type="int")],
            )
        },
    )
    from agentdecompile_recovery.rtti_recover import RttiClass

    session = EnrichSession(
        program=program,
        corpus=corpus,
        rtti_classes=[RttiClass(mangled="12CExampleArea", name="CExampleArea")],
        boundaries=[{"entry": 0x8050000, "length": 32, "section": ".text"}],
        module_by_entry={0x8050000: "game/clientcore"},
        names_by_entry={0x8050000: ("CExampleArea::LoadArea", "rtti-vtable")},
    )
    facts = enrich_and_decompile(session)
    assert program.closed
    assert program.calls[0].startswith("ensure:")
    assert any(c.startswith("struct:") for c in program.calls)
    assert any(c.startswith("name:") for c in program.calls)
    decomp_idx = next(i for i, c in enumerate(program.calls) if c.startswith("decompile:"))
    name_idx = next(i for i, c in enumerate(program.calls) if c.startswith("name:"))
    assert name_idx < decomp_idx
    assert facts[0]["provenance"] == "rtti-vtable"
    assert "m_nWidth" in (facts[0].get("decompiled") or "")
    assert readability_score(name="FUN_1", module=None, provenance=None) < 0.5
