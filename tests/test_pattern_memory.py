"""Unit tests for mismatch-signature pattern memory."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentdecompile_recovery.pattern_memory import (
    ingest_verified_directory,
    load_pattern_memory,
    retrieve_patterns,
    store_verified_pattern,
)

pytestmark = pytest.mark.unit


def test_store_and_retrieve_pattern(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    store_verified_pattern(
        work,
        mismatch_class="operand",
        fix_shape="permuter-operand",
        function_name="LoadArea",
    )
    matches = retrieve_patterns(work, mismatch_class="operand")
    assert len(matches) == 1
    assert matches[0]["functionName"] == "LoadArea"


def test_ingest_verified_directory_only_zero_diff(tmp_path: Path) -> None:
    work = tmp_path / "work"
    verified = work / "verified"
    verified.mkdir(parents=True)
    (verified / "LoadArea_401000.json").write_text(
        json.dumps({"name": "LoadArea", "differences": 0, "routedPlaybook": "permuter-operand"}),
        encoding="utf-8",
    )
    (verified / "Bad_402000.json").write_text(
        json.dumps({"name": "Bad", "differences": 3}),
        encoding="utf-8",
    )
    summary = ingest_verified_directory(work)
    assert summary["stored"] == 1
    assert len(load_pattern_memory(work)["patterns"]) == 1
