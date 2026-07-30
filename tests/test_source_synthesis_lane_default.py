"""The synthesis compiler lane must follow the target format.

swkotor.exe is an MSVC-built PE. Compiling candidates with clang and diffing the
result against MSVC-generated target objects essentially never byte-matches, so
a clang default silently caps the whole pipeline's accept rate regardless of how
good candidate generation gets.

STRATEGY.md already states profiles are format/stem-derived (PE vs ELF); this
extends that rule to the compiler lane.
"""

from __future__ import annotations

import pytest

from agentdecompile_recovery.pipeline import resolve_source_synthesis_mode

pytestmark = pytest.mark.unit


def test_explicit_mode_always_wins() -> None:
    for target_format in ("pe", "elf", None):
        assert resolve_source_synthesis_mode("clang", target_format=target_format, vc_root_available=True) == "clang"
        assert resolve_source_synthesis_mode("none", target_format=target_format, vc_root_available=True) == "none"


def test_pe_with_toolchain_selects_msvc() -> None:
    assert resolve_source_synthesis_mode("auto", target_format="pe", vc_root_available=True) == "msvc"


def test_pe_without_toolchain_falls_back_to_clang_cl() -> None:
    """clang-cl at least uses MSVC calling conventions and name decoration."""

    assert resolve_source_synthesis_mode("auto", target_format="pe", vc_root_available=False) == "clang-cl"


def test_non_pe_uses_clang() -> None:
    for target_format in ("elf", "macho"):
        assert resolve_source_synthesis_mode("auto", target_format=target_format, vc_root_available=True) == "clang"


def test_unknown_format_uses_clang() -> None:
    assert resolve_source_synthesis_mode("auto", target_format=None, vc_root_available=False) == "clang"


def test_format_matching_is_case_insensitive() -> None:
    assert resolve_source_synthesis_mode("auto", target_format="PE", vc_root_available=True) == "msvc"


def test_resolved_mode_is_always_a_valid_lane() -> None:
    from agentdecompile_recovery.pipeline import compiler_for_source_synthesis_mode

    for target_format in ("pe", "elf", None):
        for available in (True, False):
            mode = resolve_source_synthesis_mode("auto", target_format=target_format, vc_root_available=available)
            assert compiler_for_source_synthesis_mode(mode)
