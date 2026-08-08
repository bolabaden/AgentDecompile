"""The campaign receipt must show whether the reconstruction lane actually ran.

Before this, a campaign that never reached mechanism 3 and one whose rewrites all
failed produced identical receipts: `accepts: 0, nearMisses: 0`. That is how the
lane stayed dormant for weeks without anyone noticing -- there was no field that
would have differed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery import rewrite_queue
from agentdecompile_recovery.proof_campaign import summarize_rewrite_lane

pytestmark = pytest.mark.unit


def test_absent_queue_reports_zero_not_missing(tmp_path: Path) -> None:
    summary = summarize_rewrite_lane(tmp_path)

    assert summary["requested"] == 0
    assert summary["completed"] == 0
    assert summary["failed"] == 0
    assert summary["pending"] == 0


def test_counts_each_status(tmp_path: Path) -> None:
    for index, status in enumerate(("completed", "failed", "pending")):
        request_id = rewrite_queue.write_rewrite_request(
            tmp_path,
            function_name=f"Fn{index}",
            entry=f"0x{index}",
            candidate_source=f"void f{index}(void){{}}",
            mismatch_class="operand",
            mismatch_histogram={"REPLACEMENT": 1},
        )
        if status == "pending":
            continue
        rewrite_queue.claim_pending_entry(tmp_path, request_id, claimant="t")
        rewrite_queue.write_claimed_result(
            tmp_path,
            request_id,
            claimant="t",
            status=status,
            source="void g(void){}" if status == "completed" else None,
            reason=None if status == "completed" else "no fenced code block",
        )

    summary = summarize_rewrite_lane(tmp_path)

    assert summary["completed"] == 1
    assert summary["failed"] == 1
    assert summary["pending"] == 1


def test_requested_counts_cumulative_not_live_entries(tmp_path: Path) -> None:
    """Entries get pruned once consumed; the durable counter must survive that."""

    request_id = rewrite_queue.write_rewrite_request(
        tmp_path,
        function_name="Fn",
        entry="0x1",
        candidate_source="void f(void){}",
        mismatch_class="operand",
        mismatch_histogram=None,
    )
    rewrite_queue.claim_pending_entry(tmp_path, request_id, claimant="t")
    rewrite_queue.write_claimed_result(tmp_path, request_id, claimant="t", status="completed", source="void g(void){}")
    rewrite_queue.prune_consumed_entries(tmp_path, [request_id])

    summary = summarize_rewrite_lane(tmp_path)

    assert summary["requested"] == 1
    assert summary["completed"] == 0


def test_summary_distinguishes_dormant_from_failing(tmp_path: Path) -> None:
    dormant = summarize_rewrite_lane(tmp_path)

    request_id = rewrite_queue.write_rewrite_request(
        tmp_path,
        function_name="Fn",
        entry="0x1",
        candidate_source="void f(void){}",
        mismatch_class="operand",
        mismatch_histogram=None,
    )
    rewrite_queue.claim_pending_entry(tmp_path, request_id, claimant="t")
    rewrite_queue.write_claimed_result(tmp_path, request_id, claimant="t", status="failed", reason="banned construct")
    failing = summarize_rewrite_lane(tmp_path)

    assert dormant != failing
    assert dormant["requested"] == 0
    assert failing["requested"] == 1
