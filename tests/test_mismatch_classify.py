"""Unit tests for mismatch classification."""

from __future__ import annotations

import pytest

from agentdecompile_recovery.mismatch_classify import (
    CLASS_BOUNDARY_SUSPECT,
    CLASS_INSERT_DELETE,
    CLASS_OPERAND,
    CLASS_OPCODE,
    CLASS_UNCLASSIFIED,
    PLAYBOOK_OPERAND,
    classify_mismatch,
    routed_playbook_for_class,
)

pytestmark = pytest.mark.unit


def test_operand_dominance() -> None:
    result = classify_mismatch(
        histogram={"ARGUMENT_MISMATCH": 3, "OPCODE_MISMATCH": 1},
        detail_level="instruction",
    )

    assert result["mismatchClass"] == CLASS_OPERAND
    assert result["primaryMismatchKind"] == "ARGUMENT_MISMATCH"


def test_usable_histogram_outranks_boundary_suspect() -> None:
    """A coherent instruction-level histogram is direct evidence the slice
    compiled to something comparable, so it outranks the boundary-suspect
    heuristic -- otherwise real near-misses on non-PE-export functions (the
    common case for internal sub_* functions) never reach shape-search."""
    result = classify_mismatch(
        histogram={"ARGUMENT_MISMATCH": 3},
        boundary_quality={"status": "suspect"},
        detail_level="instruction",
    )

    assert result["mismatchClass"] == CLASS_OPERAND


def test_boundary_suspect_is_fallback_without_usable_histogram() -> None:
    """boundary-suspect still fires when there's no histogram evidence to
    classify from (e.g. compile failure, or an objdiff report that never
    reached instruction-level detail)."""
    result = classify_mismatch(
        histogram=None,
        boundary_quality={"status": "suspect"},
        detail_level="scalar-only",
    )

    assert result["mismatchClass"] == CLASS_BOUNDARY_SUSPECT

    result = classify_mismatch(
        histogram={},
        boundary_quality={"status": "suspect"},
        detail_level="instruction",
    )

    assert result["mismatchClass"] == CLASS_BOUNDARY_SUSPECT


def test_boundary_not_suspect_and_no_histogram_is_unclassified() -> None:
    result = classify_mismatch(histogram=None, boundary_quality={"status": "plausible"})

    assert result["mismatchClass"] == CLASS_UNCLASSIFIED


def test_insert_delete_equal_counts() -> None:
    result = classify_mismatch(
        histogram={"INSERTION": 2, "DELETION": 2},
        detail_level="instruction",
    )

    assert result["mismatchClass"] == CLASS_INSERT_DELETE


def test_sole_argument_mismatch_is_operand() -> None:
    result = classify_mismatch(
        histogram={"ARGUMENT_MISMATCH": 1},
        detail_level="instruction",
    )

    assert result["mismatchClass"] == CLASS_OPERAND


def test_opcode_replacement_dominance() -> None:
    result = classify_mismatch(
        histogram={"REPLACEMENT": 2, "ARGUMENT_MISMATCH": 1},
        detail_level="instruction",
    )

    assert result["mismatchClass"] == CLASS_OPCODE


def test_empty_histogram_is_unclassified() -> None:
    result = classify_mismatch(histogram={}, detail_level="scalar-only")

    assert result["mismatchClass"] == CLASS_UNCLASSIFIED


def test_routed_playbook_for_operand() -> None:
    assert routed_playbook_for_class(CLASS_OPERAND) == PLAYBOOK_OPERAND


def test_plurality_without_majority_still_routes_to_a_class() -> None:
    """A genuinely mixed diff (no category crosses 50%) is common for real
    near-misses -- requiring an outright majority meant these always fell
    through to unclassified/scalar-default regardless of how much real
    instruction-level evidence existed. Plurality (highest count) is enough
    signal to route to shape search; every real class enables it."""
    result = classify_mismatch(
        # ARGUMENT_MISMATCH and REPLACEMENT tie at 22 each, out of 70 total --
        # observed live on swkotor.exe's sub_127b0.
        histogram={"ARGUMENT_MISMATCH": 22, "DELETION": 16, "INSERTION": 10, "REPLACEMENT": 22},
        detail_level="instruction",
    )

    assert result["mismatchClass"] != CLASS_UNCLASSIFIED
    # Deterministic tie-break: highest count, then alphabetical kind.
    assert result["primaryMismatchKind"] == "ARGUMENT_MISMATCH"
    assert result["mismatchClass"] == CLASS_OPERAND


def test_plurality_insertion_dominant_without_majority() -> None:
    """Observed live on swkotor.exe's sub_11d70: INSERTION (64) is the
    plurality winner out of 180 total but not a majority (64*2=128 < 180)."""
    result = classify_mismatch(
        histogram={"ARGUMENT_MISMATCH": 60, "DELETION": 26, "INSERTION": 64, "REPLACEMENT": 30},
        detail_level="instruction",
    )

    assert result["mismatchClass"] == CLASS_INSERT_DELETE
    assert result["primaryMismatchKind"] == "INSERTION"
