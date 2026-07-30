"""Unit tests for instruction-aligned objdiff extraction.

The aligned diff is what a rewrite prompt needs: which instruction differs and
what the target holds there. The mismatch histogram is a lossy projection of
this same data and cannot substitute for it.
"""

from __future__ import annotations

import json

import pytest

from agentdecompile_recovery.objdiff_verification import (
    extract_aligned_diff,
    parse_objdiff_report,
    render_aligned_diff,
)

pytestmark = pytest.mark.unit


def _report(left_rows: list[dict], right_rows: list[dict]) -> str:
    """objdiff invokes as `-1 target -2 candidate`, so left is the target."""

    def side(rows: list[dict]) -> dict:
        return {
            "symbols": [
                {
                    "name": "f",
                    "kind": "SYMBOL_FUNCTION",
                    "match_percent": 50.0,
                    "instructions": rows,
                }
            ]
        }

    return json.dumps({"left": side(left_rows), "right": side(right_rows)})


def _insn(text: str, diff_kind: str | None = None) -> dict:
    row: dict = {"instruction": {"formatted": text}}
    if diff_kind is not None:
        row["diff_kind"] = diff_kind
    return row


def test_aligns_target_and_candidate_by_index() -> None:
    raw = _report(
        [_insn("mov eax, [esp+0x4]"), _insn("add eax, eax", "DIFF_REPLACE"), _insn("ret ")],
        [_insn("mov eax, [esp+0x4]"), _insn("lea eax, [eax+eax*0x2]", "DIFF_REPLACE"), _insn("ret ")],
    )

    rows = extract_aligned_diff(json.loads(raw))

    assert [row["target"] for row in rows] == [
        "mov eax, [esp+0x4]",
        "add eax, eax",
        "ret",
    ]
    assert [row["candidate"] for row in rows] == [
        "mov eax, [esp+0x4]",
        "lea eax, [eax+eax*0x2]",
        "ret",
    ]
    assert [row["differs"] for row in rows] == [False, True, False]
    assert rows[1]["diffKind"] == "DIFF_REPLACE"


def test_ragged_sides_do_not_lose_instructions() -> None:
    """An insertion makes the sides different lengths; neither may be truncated."""

    raw = _report(
        [_insn("push ebp"), _insn("mov ebp, esp")],
        [_insn("push ebp"), _insn("mov ebp, esp"), _insn("nop", "DIFF_INSERT")],
    )

    rows = extract_aligned_diff(json.loads(raw))

    assert len(rows) == 3
    assert rows[2]["target"] is None
    assert rows[2]["candidate"] == "nop"
    assert rows[2]["differs"] is True


def test_parse_report_attaches_aligned_diff() -> None:
    raw = _report(
        [_insn("add eax, eax", "DIFF_REPLACE")],
        [_insn("shl eax, 1", "DIFF_REPLACE")],
    )

    report = parse_objdiff_report(0, raw)

    assert report["alignedDiff"][0]["target"] == "add eax, eax"
    assert report["alignedDiff"][0]["candidate"] == "shl eax, 1"


def test_matched_report_has_no_aligned_diff_rows_flagged() -> None:
    raw = _report([_insn("ret ")], [_insn("ret ")])

    rows = extract_aligned_diff(json.loads(raw))

    assert [row["differs"] for row in rows] == [False]


def test_limit_keeps_differing_rows_in_preference_to_context() -> None:
    """Truncation must never drop the differing instructions -- they are the signal."""

    left = [_insn(f"nop{i}") for i in range(50)] + [_insn("add eax, eax", "DIFF_REPLACE")]
    right = [_insn(f"nop{i}") for i in range(50)] + [_insn("shl eax, 1", "DIFF_REPLACE")]

    rows = extract_aligned_diff(json.loads(_report(left, right)), limit=5)

    assert len(rows) <= 5
    assert any(row["differs"] for row in rows)
    assert any(row["target"] == "add eax, eax" for row in rows)


def test_render_marks_differing_lines() -> None:
    rows = [
        {"index": 0, "target": "push ebp", "candidate": "push ebp", "differs": False, "diffKind": None},
        {"index": 1, "target": "add eax, eax", "candidate": "shl eax, 1", "differs": True, "diffKind": "DIFF_REPLACE"},
    ]

    text = render_aligned_diff(rows)

    assert "add eax, eax" in text
    assert "shl eax, 1" in text
    lines = text.splitlines()
    assert any(line.startswith("!") for line in lines)
    assert any(line.startswith(" ") for line in lines)


def test_render_handles_missing_side() -> None:
    rows = [{"index": 0, "target": None, "candidate": "nop", "differs": True, "diffKind": "DIFF_INSERT"}]

    text = render_aligned_diff(rows)

    assert "nop" in text
    assert "<none>" in text


def test_extract_tolerates_absent_sides() -> None:
    assert extract_aligned_diff({}) == []
    assert extract_aligned_diff({"left": {}, "right": {}}) == []
    assert extract_aligned_diff("not json") == []
