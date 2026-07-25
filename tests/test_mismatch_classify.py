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


def test_boundary_suspect_preempts_histogram() -> None:
    result = classify_mismatch(
        histogram={"ARGUMENT_MISMATCH": 3},
        boundary_quality={"status": "suspect"},
        detail_level="instruction",
    )

    assert result["mismatchClass"] == CLASS_BOUNDARY_SUSPECT


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
