"""Tests for pattern memory that accumulates transferable exemplars.

The original store keyed on (compiler, arch, mismatchClass, fixShape) and
deleted every row sharing a signature before appending. Across thousands of
functions that signature space has on the order of a dozen values, so the store
held roughly one row per class and each accept erased the previous exemplar for
its class. Rows also carried only labels -- no before/after source -- so even a
complete retrieval had nothing a rewrite prompt could use.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.pattern_memory import (
    MAX_PATTERNS_PER_SIGNATURE,
    load_pattern_memory,
    retrieve_patterns,
    store_verified_pattern,
)

pytestmark = pytest.mark.unit


def _work(tmp_path: Path) -> Path:
    work = tmp_path / "work"
    work.mkdir()
    return work


def test_same_class_accepts_accumulate(tmp_path: Path) -> None:
    work = _work(tmp_path)
    for index in range(3):
        store_verified_pattern(
            work,
            mismatch_class="operand",
            fix_shape="permuter-operand",
            function_name=f"Fn{index}",
            source_before=f"x = y * {index + 2};",
            source_after=f"x = y + y + {index};",
        )

    assert len(load_pattern_memory(work)["patterns"]) == 3


def test_stored_pattern_carries_the_transformation(tmp_path: Path) -> None:
    """Labels alone are not transferable; the prompt needs before/after source."""

    work = _work(tmp_path)
    store_verified_pattern(
        work,
        mismatch_class="operand",
        function_name="LoadArea",
        source_before="x = y * 2;",
        source_after="x = y + y;",
    )

    row = retrieve_patterns(work, mismatch_class="operand")[0]

    assert row["sourceBefore"] == "x = y * 2;"
    assert row["sourceAfter"] == "x = y + y;"


def test_identical_transformation_is_not_duplicated(tmp_path: Path) -> None:
    work = _work(tmp_path)
    for _ in range(4):
        store_verified_pattern(
            work,
            mismatch_class="operand",
            function_name="LoadArea",
            source_before="x = y * 2;",
            source_after="x = y + y;",
        )

    assert len(load_pattern_memory(work)["patterns"]) == 1


def test_per_signature_cap_bounds_growth(tmp_path: Path) -> None:
    work = _work(tmp_path)
    for index in range(MAX_PATTERNS_PER_SIGNATURE + 5):
        store_verified_pattern(
            work,
            mismatch_class="operand",
            function_name=f"Fn{index}",
            source_before=f"a{index} = 1;",
            source_after=f"b{index} = 1;",
        )

    assert len(load_pattern_memory(work)["patterns"]) == MAX_PATTERNS_PER_SIGNATURE


def test_cap_is_per_signature_not_global(tmp_path: Path) -> None:
    work = _work(tmp_path)
    for mismatch_class in ("operand", "opcode"):
        for index in range(MAX_PATTERNS_PER_SIGNATURE):
            store_verified_pattern(
                work,
                mismatch_class=mismatch_class,
                function_name=f"{mismatch_class}{index}",
                source_before=f"a{index} = 1;",
                source_after=f"b{index} = 1;",
            )

    assert len(load_pattern_memory(work)["patterns"]) == MAX_PATTERNS_PER_SIGNATURE * 2


def test_retrieve_limits_results(tmp_path: Path) -> None:
    work = _work(tmp_path)
    for index in range(6):
        store_verified_pattern(
            work,
            mismatch_class="operand",
            function_name=f"Fn{index}",
            source_before=f"a{index} = 1;",
            source_after=f"b{index} = 1;",
        )

    assert len(retrieve_patterns(work, mismatch_class="operand", limit=2)) == 2


def test_retrieve_prefers_patterns_with_a_transformation(tmp_path: Path) -> None:
    """A label-only row teaches a prompt nothing; content-bearing rows rank first."""

    work = _work(tmp_path)
    store_verified_pattern(work, mismatch_class="operand", function_name="LabelOnly")
    store_verified_pattern(
        work,
        mismatch_class="operand",
        function_name="WithSource",
        source_before="x = y * 2;",
        source_after="x = y + y;",
    )

    rows = retrieve_patterns(work, mismatch_class="operand", limit=1)

    assert rows[0]["functionName"] == "WithSource"


def test_retrieve_filters_by_mismatch_class(tmp_path: Path) -> None:
    work = _work(tmp_path)
    store_verified_pattern(work, mismatch_class="operand", function_name="A", source_before="a;", source_after="b;")
    store_verified_pattern(work, mismatch_class="opcode", function_name="B", source_before="c;", source_after="d;")

    rows = retrieve_patterns(work, mismatch_class="opcode")

    assert [row["functionName"] for row in rows] == ["B"]
