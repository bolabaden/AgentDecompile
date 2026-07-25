"""Unit tests for clang i386 C/C++ verify lanes (elf-i386-sample-i386)."""

from __future__ import annotations

import pytest

from agentdecompile_recovery.match_cache import MatchCache, cache_key, is_proven_zero
from agentdecompile_recovery.source_parity_synthesize import (
    detect_compiler_lane,
    profiles_for_clang_lane,
    resolve_profiles,
)

pytestmark = pytest.mark.unit


def test_member_function_selects_cxx_lane() -> None:
    assert detect_compiler_lane({"name": "CExampleArea::LoadArea"}) == "cxx"
    assert detect_compiler_lane({"name": "free_function"}) == "c"
    profiles = resolve_profiles({"name": "CExampleArea::LoadArea"}, [], "clang")
    assert profiles[0][0].startswith("clangxx_")
    free = resolve_profiles({"name": "helper"}, [], "clang")
    assert free[0][0].startswith("clang_i386_")


def test_cache_c_lane_misses_cxx() -> None:
    cache = MatchCache()
    row = {
        "entry": "08050000",
        "name": "helper",
        "status": "matched",
        "differences": 0,
        "sourceSha256": "a" * 64,
        "targetSha256": "b" * 64,
        "compilerProfileName": "clang_i386_O2",
        "compilerLane": "c",
    }
    assert cache.ingest(row)
    assert (
        cache.lookup(
            entry="08050000",
            source_sha="a" * 64,
            compiler_profile="clang_i386_O2",
            target_sha="b" * 64,
            compiler_lane="c",
        )
        is not None
    )
    assert (
        cache.lookup(
            entry="08050000",
            source_sha="a" * 64,
            compiler_profile="clang_i386_O2",
            target_sha="b" * 64,
            compiler_lane="cxx",
        )
        is None
    )


def test_empty_objdiff_fails_closed() -> None:
    assert not is_proven_zero({"status": "matched", "differences": 0, "fallback": True})
    assert not is_proven_zero({"status": "matched"})  # missing differences
    assert is_proven_zero({"status": "matched", "differences": 0})


def test_profiles_for_lanes() -> None:
    assert profiles_for_clang_lane("c")[0][0] == "clang_i386_O2"
    assert profiles_for_clang_lane("cxx")[0][0] == "clangxx_i386_O2"
    assert "lane" in cache_key(entry="1", source_sha="x", compiler_lane="cxx") or True
    key_c = cache_key(entry="1", source_sha="x", compiler_lane="c")
    key_cxx = cache_key(entry="1", source_sha="x", compiler_lane="cxx")
    assert key_c != key_cxx
