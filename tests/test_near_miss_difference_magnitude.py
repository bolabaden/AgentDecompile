"""Near-miss ranking must use the instruction count, not the objdiff status flag.

parse_objdiff_report sets `differences` to 0 (matched), 1 (mismatched), or -1
(error) -- a status flag, never a magnitude. Ranking near-misses by it made
every mismatched function score `1`, which is <= NEAR_MISS_MAX_DIFF (8), so
every mismatch qualified as a near miss and every one drew the maximum
tight-band score bonus. A function 200 instructions away ranked identically to
one a single instruction away.

`instructionMismatchCount` is the real magnitude and was already being computed.
"""

from __future__ import annotations

import pytest

from agentdecompile_recovery.proof_target import near_miss_difference

pytestmark = pytest.mark.unit


def test_prefers_instruction_count_over_status_flag() -> None:
    assert near_miss_difference({"differences": 1, "instructionMismatchCount": 37}) == 37


def test_falls_back_to_status_flag_when_count_absent() -> None:
    """Older receipts predate instructionMismatchCount; they must still rank."""

    assert near_miss_difference({"differences": 1}) == 1


def test_matched_row_has_no_near_miss_magnitude() -> None:
    assert near_miss_difference({"differences": 0, "instructionMismatchCount": 0}) is None


def test_error_row_has_no_near_miss_magnitude() -> None:
    assert near_miss_difference({"differences": -1}) is None


def test_zero_instruction_count_falls_back_rather_than_claiming_match() -> None:
    """A mismatched row reporting 0 instruction diffs is inconsistent; it must not
    be read as a match."""

    assert near_miss_difference({"differences": 1, "instructionMismatchCount": 0}) == 1


def test_non_numeric_count_is_ignored() -> None:
    assert near_miss_difference({"differences": 1, "instructionMismatchCount": "many"}) == 1


def test_large_counts_are_preserved_not_clamped() -> None:
    """Ranking needs the real magnitude; the band filter is applied downstream."""

    assert near_miss_difference({"differences": 1, "instructionMismatchCount": 400}) == 400


def test_magnitude_distinguishes_close_from_far() -> None:
    close = near_miss_difference({"differences": 1, "instructionMismatchCount": 2})
    far = near_miss_difference({"differences": 1, "instructionMismatchCount": 200})

    assert close is not None and far is not None
    assert close < far
