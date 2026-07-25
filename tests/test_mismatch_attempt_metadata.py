"""Tests for mismatch metadata on attempt records."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentdecompile_recovery.mismatch_classify import CLASS_OPERAND, enrich_attempt_record
from agentdecompile_recovery.objdiff_verification import parse_objdiff_report

pytestmark = pytest.mark.unit


def test_enrich_attempt_record_from_verify_report(tmp_path: Path) -> None:
    raw = json.dumps(
        {
            "kind": "SYMBOL_FUNCTION",
            "match_percent": 80.0,
            "instructions": [
                {"kind": "ARGUMENT_MISMATCH"},
                {"kind": "ARGUMENT_MISMATCH"},
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
