"""Unit tests for evidence-based module resolution and readability gate."""

from __future__ import annotations

import pytest

from agentdecompile_recovery.module_resolver import (
    ModuleResolver,
    passes_readability_gate,
)

pytestmark = pytest.mark.unit


def test_assert_string_beats_rtti() -> None:
    resolver = ModuleResolver(
        assert_paths_by_entry={0x100: "../CODE/game/clientcore/nwccreature.cpp"},
        rtti_module_by_entry={0x100: "libsource/AURORA"},
    )
    ev = resolver.resolve(0x100)
    assert ev.provenance == "assert-string"
    assert ev.module == "game/clientcore"


def test_rtti_only_resolves_corpus_path() -> None:
    resolver = ModuleResolver(rtti_module_by_entry={0x200: "game/servercore"})
    ev = resolver.resolve(0x200)
    assert ev.module == "game/servercore"
    assert ev.provenance == "rtti-class"


def test_fallback_and_callgraph_vote_and_tie() -> None:
    resolver = ModuleResolver(
        rtti_module_by_entry={0x10: "game/swmain", 0x20: "game/clientcore"},
        call_graph={0x30: [0x10, 0x10, 0x20]},
    )
    assert resolver.resolve(0x99).module == "recovered/unmapped"
    voted = resolver.resolve(0x30)
    assert voted.provenance == "callgraph-vote"
    assert voted.module == "game/swmain"
    tie = ModuleResolver(
        rtti_module_by_entry={0x10: "game/swmain", 0x20: "game/clientcore"},
        call_graph={0x40: [0x10, 0x20]},
    )
    assert tie.resolve(0x40).module == "recovered/unmapped"


def test_optional_va_bands() -> None:
    resolver = ModuleResolver(va_bands=[(0x480000, "game/core"), (0x500000, "game/ui")])
    assert resolver.resolve(0x401000).module == "game/core"
    assert resolver.resolve(0x490000).module == "game/ui"


def test_readability_gate() -> None:
    assert not passes_readability_gate(name="FUN_1", module="game/swmain", module_provenance="rtti-class")
    assert not passes_readability_gate(name="LoadArea", module="recovered/unmapped", module_provenance="fallback")
    assert passes_readability_gate(name="LoadArea", module="game/clientcore", module_provenance="rtti-class")


def test_bare_source_filename_normalizes_to_recovered_module() -> None:
    from agentdecompile_recovery.module_resolver import normalize_code_path

    assert normalize_code_path("exoinputinternal.cpp") == "recovered/exoinputinternal"
    resolver = ModuleResolver(assert_paths_by_entry={0x50: "exoinputinternal.cpp"})
    assert resolver.resolve(0x50).module == "recovered/exoinputinternal"
