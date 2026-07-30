"""Unit tests for the byte-field-guard-return-self idiom permutation.

Grounded in a real observed mismatch: swkotor.exe's sub_78650 has a
"if (byte field == const) return self; return 0;" shape whose packaged-source
(raw decompiler output) candidate compiled to setne/dec/and codegen, while the
original compiler used branchless sub/neg/sbb/not/and codegen for the same
semantics. semantic_equivalent_variants() previously had no rule-agnostic
fallback, so packaged-source candidates (no matching named template) always
got zero shape-search variants regardless of source_shape_search.
"""

from __future__ import annotations

import pytest

from agentdecompile_recovery.source_parity_synthesize import (
    GeneratedCandidate,
    byte_field_guard_return_self_variants,
    semantic_equivalent_variants,
)

pytestmark = pytest.mark.unit

SUB_78650_SOURCE = (
    "void *__fastcall sub_78650(void *self) {\n"
    "    if (*(unsigned char *)((char *)self + 0x55) == 0x01) {\n"
    "        return self;\n"
    "    }\n"
    "    return 0;\n"
    "}\n"
)


def _candidate(source: str, *, rule: str = "packaged-source", suffix: str = ".c", semantic: bool = True) -> GeneratedCandidate:
    return GeneratedCandidate(
        rule=rule,
        variant="packaged-source",
        c_name="sub_78650",
        symbol="sub_78650",
        source=source,
        callconv="fastcall",
        return_type="unknown",
        source_suffix=suffix,
        semantic_source=semantic,
    )


def test_matches_real_swkotor_packaged_source_shape() -> None:
    variants = byte_field_guard_return_self_variants({}, _candidate(SUB_78650_SOURCE))

    assert [v["name"] for v in variants] == [
        "byte-field-guard-mask-arithmetic-ternary",
        "byte-field-guard-mask-arithmetic-local",
        "byte-field-guard-not-equal-flip",
    ]
    flip = next(v for v in variants if v["name"] == "byte-field-guard-not-equal-flip")
    assert "field == 0x01" not in flip["source"]
    assert "!= 0x01" in flip["source"]
    assert "return 0;" in flip["source"]
    assert "return self;" in flip["source"]


def test_reachable_via_semantic_equivalent_variants_for_packaged_source() -> None:
    """This is the actual entry point run_msvc_source_shape_search() calls --
    packaged-source candidates never matched any of the named rule branches
    above it, so without the generic fallback this always returned []."""
    variants = semantic_equivalent_variants({}, _candidate(SUB_78650_SOURCE))
    assert len(variants) == 3


def test_non_matching_source_yields_no_variants() -> None:
    other = "void __cdecl helper(int x) {\n    return x + 1;\n}\n"
    assert byte_field_guard_return_self_variants({}, _candidate(other)) == []


def test_skips_non_c_and_non_semantic_candidates() -> None:
    assert byte_field_guard_return_self_variants({}, _candidate(SUB_78650_SOURCE, suffix=".asm")) == []
    assert byte_field_guard_return_self_variants({}, _candidate(SUB_78650_SOURCE, semantic=False)) == []


def test_handles_null_return_spelling_and_different_callconv() -> None:
    source = (
        "void *__stdcall sub_9000(void *ctx) {\n"
        "    if (*(unsigned char *)((char *)ctx + 0x10) == 0x02) {\n"
        "        return ctx;\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
    )
    variants = byte_field_guard_return_self_variants({}, _candidate(source))
    assert len(variants) == 3
    for v in variants:
        assert "__stdcall sub_9000(void *ctx)" in v["source"]
        assert "0x10" in v["source"]
        assert "0x02" in v["source"]
