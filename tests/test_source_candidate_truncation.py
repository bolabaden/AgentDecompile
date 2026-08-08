"""Silent inventory truncation must be visible in the source-generation summary.

--source-task-limit defaults to 500. On a 12,845-function binary that queues 4%
of the inventory and reports success, so a run asked to recover a whole binary
reports "complete" having skipped 96% of it. The counts were already recorded
(candidateTotal, candidateLimit); nothing derived the conclusion from them.
"""

from __future__ import annotations

import pytest

from agentdecompile_recovery.sourcegen import candidate_truncation

pytestmark = pytest.mark.unit


def test_reports_truncation_when_limit_bites() -> None:
    result = candidate_truncation(total=12845, offset=0, limit=500)

    assert result["truncated"] is True
    assert result["skipped"] == 12345
    assert "12845" in result["warning"]
    assert "500" in result["warning"]


def test_no_truncation_when_limit_covers_inventory() -> None:
    result = candidate_truncation(total=400, offset=0, limit=500)

    assert result["truncated"] is False
    assert result["skipped"] == 0
    assert result["warning"] is None


def test_exact_fit_is_not_truncation() -> None:
    result = candidate_truncation(total=500, offset=0, limit=500)

    assert result["truncated"] is False
    assert result["skipped"] == 0


def test_offset_counts_toward_skipped() -> None:
    """Candidates before the offset are skipped too, not just those past the limit."""

    result = candidate_truncation(total=1000, offset=100, limit=500)

    assert result["truncated"] is True
    assert result["skipped"] == 500


def test_offset_past_end_skips_everything() -> None:
    result = candidate_truncation(total=100, offset=200, limit=500)

    assert result["truncated"] is True
    assert result["skipped"] == 100


def test_zero_limit_skips_everything() -> None:
    result = candidate_truncation(total=100, offset=0, limit=0)

    assert result["truncated"] is True
    assert result["skipped"] == 100


def test_empty_inventory_is_not_truncation() -> None:
    result = candidate_truncation(total=0, offset=0, limit=500)

    assert result["truncated"] is False
    assert result["warning"] is None


def test_warning_names_the_flag_to_change() -> None:
    result = candidate_truncation(total=12845, offset=0, limit=500)

    assert "--source-task-limit" in result["warning"]
