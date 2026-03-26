"""Unit tests for mcp_utils.decompiler_util helpers."""

from __future__ import annotations

import pytest

from unittest.mock import MagicMock

from agentdecompile_cli.mcp_utils.decompiler_util import (
    merge_decompile_dict_keys,
    programs_same_decompiler_context,
)


@pytest.mark.unit
def test_merge_decompile_dict_keys_from_code_only() -> None:
    d = merge_decompile_dict_keys({"name": "f", "code": "void f() {}"})
    assert d["code"] == "void f() {}"
    assert d["decompilation"] == "void f() {}"
    assert d["name"] == "f"


@pytest.mark.unit
def test_merge_decompile_dict_keys_from_decompilation_only() -> None:
    d = merge_decompile_dict_keys({"decompilation": "int main();"})
    assert d["code"] == "int main();"
    assert d["decompilation"] == "int main();"


@pytest.mark.unit
def test_merge_decompile_dict_keys_preserves_distinct_strings() -> None:
    d = merge_decompile_dict_keys({"code": "a", "decompilation": "b"})
    assert d["code"] == "a"
    assert d["decompilation"] == "b"


@pytest.mark.unit
def test_merge_decompile_dict_keys_empty_unchanged() -> None:
    d = merge_decompile_dict_keys({"x": 1})
    assert d == {"x": 1}


@pytest.mark.unit
def test_programs_same_decompiler_context_identity() -> None:
    p = object()
    assert programs_same_decompiler_context(p, p) is True


@pytest.mark.unit
def test_programs_same_decompiler_context_domain_path() -> None:
    a = MagicMock()
    b = MagicMock()
    a.getDomainFile.return_value.getPathname.return_value = "/K1/foo.exe"
    b.getDomainFile.return_value.getPathname.return_value = "/K1/foo.exe"
    assert programs_same_decompiler_context(a, b) is True


@pytest.mark.unit
def test_programs_same_decompiler_context_different_paths() -> None:
    a = MagicMock()
    b = MagicMock()
    a.getDomainFile.return_value.getPathname.return_value = "/a.exe"
    b.getDomainFile.return_value.getPathname.return_value = "/b.exe"
    assert programs_same_decompiler_context(a, b) is False
