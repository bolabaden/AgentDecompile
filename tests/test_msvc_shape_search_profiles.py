"""Unit tests for the extended MSVC compiler-profile search used by shape search.

packaged-source candidates (raw decompiler output) have no alternate C idiom
to try, so the only lever available to match the original compiler's exact
codegen shape is exploring more optimization-flag combinations. resolve_profiles
falls back to a broader profile set when source_shape_search is requested.
"""

from __future__ import annotations

import pytest

from agentdecompile_recovery.source_parity_synthesize import (
    DEFAULT_PROFILES,
    EXTENDED_PROFILES,
    resolve_profiles,
)

pytestmark = pytest.mark.unit


def test_extended_profiles_is_a_strict_superset_of_default() -> None:
    assert len(EXTENDED_PROFILES) > len(DEFAULT_PROFILES)
    default_names = {name for name, _ in DEFAULT_PROFILES}
    extended_names = {name for name, _ in EXTENDED_PROFILES}
    assert default_names.issubset(extended_names)


def test_msvc_without_shape_search_uses_default_profiles() -> None:
    profiles = resolve_profiles({"name": "sub_1000"}, [], "msvc")
    assert profiles == DEFAULT_PROFILES


def test_msvc_with_shape_search_uses_extended_profiles() -> None:
    profiles = resolve_profiles({"name": "sub_1000"}, [], "msvc", source_shape_search=True)
    assert profiles == EXTENDED_PROFILES


def test_explicit_cli_profiles_override_shape_search() -> None:
    explicit = [("pinned", ["/O2"])]
    profiles = resolve_profiles({"name": "sub_1000"}, explicit, "msvc", source_shape_search=True)
    assert profiles == explicit


def test_row_hint_still_takes_priority_but_widens_fallback_list_under_shape_search() -> None:
    row = {
        "name": "sub_1000",
        "compilerProfileHints": {"compiler": "msvc", "args": ["/O2", "/Gz", "/Oy", "/GS-"]},
    }
    without_search = resolve_profiles(row, [], "msvc")
    with_search = resolve_profiles(row, [], "msvc", source_shape_search=True)
    assert without_search[0][0] == "row-hint"
    assert with_search[0][0] == "row-hint"
    # The fallback list appended after the row-hint widens under shape search.
    assert len(with_search) > len(without_search)


def test_clang_lane_unaffected_by_shape_search_flag() -> None:
    with_search = resolve_profiles({"name": "helper"}, [], "clang", source_shape_search=True)
    without_search = resolve_profiles({"name": "helper"}, [], "clang", source_shape_search=False)
    assert with_search == without_search
