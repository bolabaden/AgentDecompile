"""Unit tests for PE MSVC RTTI recovery."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from agentdecompile_recovery.pyghidra_enrich import EnrichSession, FakeEnrichProgram, enrich_and_decompile
from agentdecompile_recovery.rtti_recover import (
    RttiClass,
    align_vtable_methods,
    demangle_msvc_type_descriptor,
    extract_ghidra_rtti_classes,
    merge_rtti_classes,
    rtti_scan_receipt,
    scan_msvc_rtti_strings,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "pe"
SAMPLE_PE = FIXTURES / "sample_msvc_rtti.bin"

pytestmark = pytest.mark.unit


def test_demangle_msvc_type_descriptors() -> None:
    assert demangle_msvc_type_descriptor(".?AVCExampleArea@@") == "CExampleArea"
    assert demangle_msvc_type_descriptor(".?AVFoo@Game@@") == "Game::Foo"
    assert demangle_msvc_type_descriptor(".?AUCPortGate@@") == "CPortGate"
    assert demangle_msvc_type_descriptor("not-msvc") is None
    assert demangle_msvc_type_descriptor(".?AV@@") is None


def test_scan_msvc_fixture_finds_classes() -> None:
    classes = scan_msvc_rtti_strings(SAMPLE_PE)
    names = {c.name for c in classes}
    assert "CExampleArea" in names
    assert "Game::Foo" in names
    assert "CPortGate" in names
    assert all(c.provenance == "msvc-rtti-string" for c in classes)


def test_rtti_scan_receipt_pe_abi() -> None:
    receipt = rtti_scan_receipt(SAMPLE_PE)
    assert receipt["abi"] == "msvc"
    assert receipt["classCount"] >= 3


def test_extract_ghidra_rtti_from_fake_program() -> None:
    class _Sym:
        def __init__(self, name: str) -> None:
            self._name = name

        def getName(self) -> str:
            return self._name

    class _Data:
        def __init__(self, value: str) -> None:
            self._value = value

        def getValue(self) -> str:
            return self._value

        def getLabel(self) -> None:
            return None

    program = SimpleNamespace(
        getSymbolTable=lambda: SimpleNamespace(
            getAllSymbols=lambda _dynamic: [_Sym(".?AVLoadArea@@"), _Sym("FUN_00401000")]
        ),
        getListing=lambda: SimpleNamespace(getDefinedData=lambda _forward: [_Data(".?AVSaveGame@@")]),
        getDataTypeManager=lambda: SimpleNamespace(getCategory=lambda _path: None),
    )
    classes = extract_ghidra_rtti_classes(program)
    names = {c.name for c in classes}
    assert "LoadArea" in names
    assert "SaveGame" in names
    assert "FUN_00401000" not in names


def test_merge_prefers_first_provenance() -> None:
    a = [RttiClass(mangled=".?AVFoo@@", name="Foo", provenance="msvc-rtti-string")]
    b = [RttiClass(mangled="Foo", name="Foo", provenance="ghidra-rtti-symbol")]
    merged = merge_rtti_classes(a, b)
    assert len(merged) == 1
    assert merged[0].provenance == "msvc-rtti-string"


def test_align_vtable_unmapped_slots() -> None:
    info = align_vtable_methods("CPort", [], slot_count=4)
    # 4 slots - 2 meta = 2 usable placeholders
    assert info.methods == ["CPort_slot_0", "CPort_slot_1"]
    assert info.provenance == "rtti-vtable-partial"


def test_enrich_applies_pe_class_struct_without_corpus() -> None:
    program = FakeEnrichProgram()
    session = EnrichSession(
        program=program,
        corpus=None,
        rtti_classes=[RttiClass(mangled=".?AVCExampleArea@@", name="CExampleArea", provenance="msvc-rtti-string")],
        boundaries=[{"entry": 0x401000, "length": 16}],
        names_by_entry={0x401000: ("CExampleArea::Load", "msvc-rtti")},
    )
    facts = enrich_and_decompile(session)
    assert any(c.startswith("struct:CExampleArea") for c in program.calls)
    assert facts[0]["name"] == "CExampleArea::Load"
    assert "vftable" in program.structs["CExampleArea"][0]["name"]


def test_missing_rtti_soft_degrades(tmp_path: Path) -> None:
    empty = tmp_path / "empty_mz.bin"
    empty.write_bytes(b"MZ" + b"\x00" * 64)
    receipt = rtti_scan_receipt(empty)
    assert receipt["abi"] == "msvc"
    assert receipt["classCount"] == 0
