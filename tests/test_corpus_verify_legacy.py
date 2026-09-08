from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentdecompile_recovery.corpus.verify_legacy_recovered import (
    address_named_function,
    coverage_row,
    merge_coverage,
)

pytestmark = pytest.mark.unit


def test_address_named_function_handles_msvc_qualifiers() -> None:
    source = "void __declspec(naked) F_004ae170(void) { }"
    assert address_named_function(source, "004ae170") == "F_004ae170"


def test_address_named_function_handles_leading_underscore() -> None:
    source = "void __fastcall _F_0040d960(void *self, int value) { }"
    assert address_named_function(source, "0040d960") == "_F_0040d960"


def test_coverage_row_rejects_unverified_result() -> None:
    with pytest.raises(ValueError):
        coverage_row({"status": "not_byte_exact"})


def test_merge_coverage_replaces_only_matching_function(tmp_path: Path) -> None:
    path = tmp_path / "coverage.jsonl"
    old = [
        {"function": "keep", "byteExact": False},
        {"function": "replace", "byteExact": False},
    ]
    path.write_text("".join(json.dumps(row) + "\n" for row in old))
    merge_coverage(path, [{"function": "replace", "byteExact": True}])
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert rows == [
        {"function": "keep", "byteExact": False},
        {"byteExact": True, "function": "replace"},
    ]
