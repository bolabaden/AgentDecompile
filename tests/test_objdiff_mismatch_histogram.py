"""Unit tests for objdiff mismatch histogram parsing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentdecompile_recovery.objdiff_verification import parse_objdiff_report

pytestmark = pytest.mark.unit

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "objdiff" / "instruction-mismatch-sample.json"


def test_histogram_counts_instruction_mismatches() -> None:
    raw = json.dumps(
        {
            "kind": "SYMBOL_FUNCTION",
            "match_percent": 80.0,
            "instructions": [
                {"kind": "ARGUMENT_MISMATCH"},
                {"kind": "ARGUMENT_MISMATCH"},
                {"kind": "ARGUMENT_MISMATCH"},
                {"kind": "OPCODE_MISMATCH"},
            ],
        }
    )
    report = parse_objdiff_report(0, raw)

    assert report["status"] == "mismatched"
    assert report["differences"] == 1
    assert report["detailLevel"] == "instruction"
    assert report["mismatchHistogram"] == {
        "ARGUMENT_MISMATCH": 3,
        "OPCODE_MISMATCH": 1,
    }
    assert report["instructionMismatchCount"] == 4


def test_fixture_histogram_matches_expectations() -> None:
    raw = FIXTURE.read_text(encoding="utf-8")
    report = parse_objdiff_report(0, raw)

    assert report["mismatchHistogram"]["ARGUMENT_MISMATCH"] == 3
    assert report["mismatchHistogram"]["OPCODE_MISMATCH"] == 1


def test_match_has_scalar_detail_level_only() -> None:
    raw = json.dumps({"kind": "SECTION_CODE", "match_percent": 100.0})
    report = parse_objdiff_report(0, raw)

    assert report["differences"] == 0
    assert report["detailLevel"] == "scalar-only"
    assert "mismatchHistogram" not in report


def test_empty_stdout_remains_error() -> None:
    report = parse_objdiff_report(0, "")

    assert report["status"] == "error"
    assert report["differences"] == -1
    assert "mismatchHistogram" not in report
