"""Tests for capped_output.py, ported from the upstream CappedOutput spec."""

from __future__ import annotations

import pytest

from agentdecompile_recovery.capped_output import CappedOutput

pytestmark = pytest.mark.unit


def test_returns_all_content_when_under_the_limit():
    cap = CappedOutput(100)
    cap.push("hello ")
    cap.push("world")
    assert str(cap) == "hello world"
    assert cap.truncated is False
    assert cap.total_size == 11


def test_returns_a_single_push_unchanged_when_under_the_limit():
    cap = CappedOutput(1024)
    cap.push("short string")
    assert str(cap) == "short string"
    assert cap.truncated is False


def test_truncates_middle_content_when_over_the_limit():
    cap = CappedOutput(10)
    cap.push("A" * 10)
    cap.push("B" * 10)
    cap.push("C" * 10)

    result = str(cap)
    assert "A" * 10 in result
    assert "C" * 10 in result
    assert "B" * 10 not in result
    assert "truncated" in result
    assert cap.truncated is True
    assert cap.total_size == 30


def test_keeps_head_and_tail_within_limits():
    limit = 20
    cap = CappedOutput(limit)

    for i in range(100):
        cap.push(f"chunk{i:03d}_")

    result = str(cap)
    assert result.startswith("chunk000_")
    assert result.endswith("chunk099_")
    assert "truncated" in result
    assert cap.truncated is True
    assert cap.total_size == 900


def test_shows_dropped_size_in_mb_in_the_truncation_marker():
    cap = CappedOutput(5)
    cap.push("HEAD_")
    big_chunk = "x" * (1024 * 1024)
    cap.push(big_chunk)
    cap.push("_TAIL")

    result = str(cap)
    assert "1.0 MB" in result
    assert result.startswith("HEAD_")
    assert result.endswith("_TAIL")


def test_handles_empty_input():
    cap = CappedOutput(100)
    assert str(cap) == ""
    assert cap.truncated is False
    assert cap.total_size == 0


def test_handles_a_single_push_that_exactly_fills_the_limit():
    cap = CappedOutput(10)
    cap.push("0123456789")
    assert str(cap) == "0123456789"
    assert cap.truncated is False


def test_handles_a_single_push_that_exceeds_the_limit_goes_to_head_only():
    cap = CappedOutput(5)
    cap.push("0123456789")
    assert str(cap) == "0123456789"
    assert cap.truncated is False


def test_uses_32kb_default_limit():
    cap = CappedOutput()
    cap.push("A" * (32 * 1024))
    cap.push("B" * (100 * 1024))
    cap.push("C" * (32 * 1024))

    assert cap.truncated is True
    result = str(cap)
    assert result.startswith("A")
    assert result.endswith("C")
    assert "truncated" in result


def test_preserves_content_when_total_equals_exactly_2x_limit():
    cap = CappedOutput(10)
    cap.push("A" * 10)
    cap.push("B" * 10)
    assert str(cap) == "A" * 10 + "B" * 10
    assert cap.truncated is False


def test_tracks_total_size_across_many_pushes():
    cap = CappedOutput(10)
    for _ in range(1000):
        cap.push("x")
    assert cap.total_size == 1000
