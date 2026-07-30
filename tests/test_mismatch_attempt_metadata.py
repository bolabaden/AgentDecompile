"""Tests for mismatch metadata on attempt records."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentdecompile_recovery.mismatch_classify import (
    CLASS_OPCODE,
    CLASS_OPERAND,
    PLAYBOOK_OPCODE,
    classify_verify_report,
    enrich_attempt_record,
    routed_playbook_for_class,
)
from agentdecompile_recovery.objdiff_verification import parse_objdiff_report

pytestmark = pytest.mark.unit

REAL_CAPTURE_FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "objdiff" / "sub_78650-real-capture.json"
)


def test_enrich_attempt_record_from_verify_report(tmp_path: Path) -> None:
    raw = json.dumps(
        {
            "kind": "SYMBOL_FUNCTION",
            "match_percent": 80.0,
            "instructions": [
                {"diff_kind": "DIFF_ARG_MISMATCH"},
                {"diff_kind": "DIFF_ARG_MISMATCH"},
            ],
        }
    )
    report = parse_objdiff_report(0, raw)
    verify_path = tmp_path / "verify.json"
    verify_path.write_text(json.dumps(report), encoding="utf-8")
    record = {"status": "mismatched", "differences": 1, "verifyReport": str(verify_path)}

    enrich_attempt_record(record)

    assert record["mismatchClass"] == CLASS_OPERAND
    assert record["mismatchHistogram"]["ARGUMENT_MISMATCH"] == 2


def test_enrich_without_verify_is_unclassified() -> None:
    record = {"status": "mismatched", "differences": 1}
    enrich_attempt_record(record)
    assert record["mismatchClass"] == "unclassified"


def test_real_objdiff_capture_routes_to_shape_search_playbook() -> None:
    """Regression for a real swkotor-parity capture (sub_78650) that was
    silently misclassified as unclassified/boundary-suspect because
    extract_mismatch_histogram() read the wrong JSON field. objdiff reports
    both the "left" and "right" symbol's instructions, so each mismatch is
    counted twice (2 ARGUMENT_MISMATCH, 8 REPLACEMENT)."""
    raw = REAL_CAPTURE_FIXTURE.read_text(encoding="utf-8")
    report = parse_objdiff_report(0, raw)

    assert report["detailLevel"] == "instruction"
    assert report["mismatchHistogram"]["ARGUMENT_MISMATCH"] == 2
    assert report["mismatchHistogram"]["REPLACEMENT"] == 8

    classification = classify_verify_report(report)
    assert classification["mismatchClass"] == CLASS_OPCODE
    playbook = routed_playbook_for_class(classification["mismatchClass"])
    assert playbook == PLAYBOOK_OPCODE
    assert playbook != "boundary-repair"
