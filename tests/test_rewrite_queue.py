"""Unit tests for the rewrite-request file queue (challenger-lane mechanism 3).

Covers the write/claim/result-write/prune lifecycle and the compare-and-swap
discipline that prevents duplicate dispatch and lost-write races between
concurrent /loop-driven worker sessions.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentdecompile_recovery import rewrite_queue

pytestmark = pytest.mark.unit


def test_write_rewrite_request_creates_pending_entry(tmp_path: Path) -> None:
    request_id = rewrite_queue.write_rewrite_request(
        tmp_path,
        function_name="sub_1000",
        entry="0x1000",
        candidate_source="int sub_1000(void) { return 0; }",
        mismatch_class="operand",
        mismatch_histogram={"ARGUMENT_MISMATCH": 2},
    )
    entry = rewrite_queue.find_entry(tmp_path, request_id)
    assert entry is not None
    assert entry["status"] == rewrite_queue.STATUS_PENDING
    assert entry["functionName"] == "sub_1000"
    assert entry["mismatchClass"] == "operand"

    path = rewrite_queue.queue_path(tmp_path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["schema"] == rewrite_queue.SCHEMA
    assert "claimBoundary" in payload


def test_write_rewrite_request_is_deduped_for_identical_candidate(tmp_path: Path) -> None:
    kwargs = dict(
        function_name="sub_1000",
        entry="0x1000",
        candidate_source="int sub_1000(void) { return 0; }",
        mismatch_class="operand",
        mismatch_histogram=None,
    )
    first_id = rewrite_queue.write_rewrite_request(tmp_path, **kwargs)
    rewrite_queue.claim_pending_entry(tmp_path, first_id, claimant="worker-a")
    second_id = rewrite_queue.write_rewrite_request(tmp_path, **kwargs)
    assert first_id == second_id
    entry = rewrite_queue.find_entry(tmp_path, first_id)
    assert entry["status"] == rewrite_queue.STATUS_CLAIMED, "existing entry must not be clobbered by a duplicate write"


def test_claim_pending_entry_succeeds_once(tmp_path: Path) -> None:
    request_id = rewrite_queue.write_rewrite_request(
        tmp_path,
        function_name="sub_2000",
        entry="0x2000",
        candidate_source="int sub_2000(void) { return 1; }",
        mismatch_class="opcode",
        mismatch_histogram=None,
    )
    assert rewrite_queue.claim_pending_entry(tmp_path, request_id, claimant="worker-a") is True
    entry = rewrite_queue.find_entry(tmp_path, request_id)
    assert entry["claimedBy"] == "worker-a"
    assert entry["status"] == rewrite_queue.STATUS_CLAIMED


def test_claim_pending_entry_fails_when_already_claimed_and_fresh(tmp_path: Path) -> None:
    request_id = rewrite_queue.write_rewrite_request(
        tmp_path,
        function_name="sub_2000",
        entry="0x2000",
        candidate_source="int sub_2000(void) { return 1; }",
        mismatch_class="opcode",
        mismatch_histogram=None,
    )
    assert rewrite_queue.claim_pending_entry(tmp_path, request_id, claimant="worker-a") is True
    # Simulates a second /loop poll firing before worker-a's subagent finishes --
    # duplicate dispatch is prevented here, not by the poll interval.
    assert rewrite_queue.claim_pending_entry(tmp_path, request_id, claimant="worker-b") is False
    entry = rewrite_queue.find_entry(tmp_path, request_id)
    assert entry["claimedBy"] == "worker-a"


def test_claim_pending_entry_reoffers_stale_claim(tmp_path: Path) -> None:
    request_id = rewrite_queue.write_rewrite_request(
        tmp_path,
        function_name="sub_2000",
        entry="0x2000",
        candidate_source="int sub_2000(void) { return 1; }",
        mismatch_class="opcode",
        mismatch_histogram=None,
    )
    assert rewrite_queue.claim_pending_entry(tmp_path, request_id, claimant="worker-a") is True
    # A crashed/killed worker-a session never writes a result; staleness_seconds=0
    # makes any claim immediately eligible for re-offer in this test.
    assert (
        rewrite_queue.claim_pending_entry(
            tmp_path, request_id, claimant="worker-b", staleness_seconds=0
        )
        is True
    )
    entry = rewrite_queue.find_entry(tmp_path, request_id)
    assert entry["claimedBy"] == "worker-b"


def test_write_claimed_result_completed(tmp_path: Path) -> None:
    request_id = rewrite_queue.write_rewrite_request(
        tmp_path,
        function_name="sub_3000",
        entry="0x3000",
        candidate_source="int sub_3000(void) { return 2; }",
        mismatch_class="insert-delete",
        mismatch_histogram=None,
    )
    rewrite_queue.claim_pending_entry(tmp_path, request_id, claimant="worker-a")
    ok = rewrite_queue.write_claimed_result(
        tmp_path, request_id, claimant="worker-a", status=rewrite_queue.STATUS_COMPLETED, source="int rewritten(void) { return 2; }"
    )
    assert ok is True
    entry = rewrite_queue.find_entry(tmp_path, request_id)
    assert entry["status"] == rewrite_queue.STATUS_COMPLETED
    assert entry["source"] == "int rewritten(void) { return 2; }"


def test_write_claimed_result_failed_with_reason(tmp_path: Path) -> None:
    request_id = rewrite_queue.write_rewrite_request(
        tmp_path,
        function_name="sub_3000",
        entry="0x3000",
        candidate_source="int sub_3000(void) { return 2; }",
        mismatch_class="insert-delete",
        mismatch_histogram=None,
    )
    rewrite_queue.claim_pending_entry(tmp_path, request_id, claimant="worker-a")
    ok = rewrite_queue.write_claimed_result(
        tmp_path, request_id, claimant="worker-a", status=rewrite_queue.STATUS_FAILED, reason="no usable rewrite"
    )
    assert ok is True
    entry = rewrite_queue.find_entry(tmp_path, request_id)
    assert entry["status"] == rewrite_queue.STATUS_FAILED
    assert entry["reason"] == "no usable rewrite"


def test_write_claimed_result_discarded_when_claim_no_longer_matches(tmp_path: Path) -> None:
    """The lost-write race adversarial review flagged: a slower writer must not
    clobber a result already written by whoever currently holds the claim."""

    request_id = rewrite_queue.write_rewrite_request(
        tmp_path,
        function_name="sub_3000",
        entry="0x3000",
        candidate_source="int sub_3000(void) { return 2; }",
        mismatch_class="insert-delete",
        mismatch_histogram=None,
    )
    rewrite_queue.claim_pending_entry(tmp_path, request_id, claimant="worker-a", staleness_seconds=0)
    # worker-a's claim goes stale and worker-b re-claims and completes it first.
    rewrite_queue.claim_pending_entry(tmp_path, request_id, claimant="worker-b", staleness_seconds=0)
    rewrite_queue.write_claimed_result(
        tmp_path, request_id, claimant="worker-b", status=rewrite_queue.STATUS_COMPLETED, source="worker-b's answer"
    )
    # worker-a, unaware it lost the claim, tries to write its own (now-late) result.
    stale_write_ok = rewrite_queue.write_claimed_result(
        tmp_path, request_id, claimant="worker-a", status=rewrite_queue.STATUS_COMPLETED, source="worker-a's answer"
    )
    assert stale_write_ok is False
    entry = rewrite_queue.find_entry(tmp_path, request_id)
    assert entry["source"] == "worker-b's answer"


def test_prune_consumed_entries_removes_completed_and_failed(tmp_path: Path) -> None:
    completed_id = rewrite_queue.write_rewrite_request(
        tmp_path, function_name="a", entry="0x1", candidate_source="s1", mismatch_class=None, mismatch_histogram=None
    )
    failed_id = rewrite_queue.write_rewrite_request(
        tmp_path, function_name="b", entry="0x2", candidate_source="s2", mismatch_class=None, mismatch_histogram=None
    )
    pending_id = rewrite_queue.write_rewrite_request(
        tmp_path, function_name="c", entry="0x3", candidate_source="s3", mismatch_class=None, mismatch_histogram=None
    )
    for rid, status in ((completed_id, rewrite_queue.STATUS_COMPLETED), (failed_id, rewrite_queue.STATUS_FAILED)):
        rewrite_queue.claim_pending_entry(tmp_path, rid, claimant="worker-a")
        rewrite_queue.write_claimed_result(tmp_path, rid, claimant="worker-a", status=status)

    rewrite_queue.prune_consumed_entries(tmp_path, [completed_id, failed_id, pending_id])

    assert rewrite_queue.find_entry(tmp_path, completed_id) is None
    assert rewrite_queue.find_entry(tmp_path, failed_id) is None
    assert rewrite_queue.find_entry(tmp_path, pending_id) is not None, "pending entries must never be pruned"


def test_count_requests_for_function(tmp_path: Path) -> None:
    rewrite_queue.write_rewrite_request(
        tmp_path, function_name="sub_1000", entry="0x1000", candidate_source="s1", mismatch_class=None, mismatch_histogram=None
    )
    rewrite_queue.write_rewrite_request(
        tmp_path, function_name="sub_1000", entry="0x1000", candidate_source="s2", mismatch_class=None, mismatch_histogram=None
    )
    rewrite_queue.write_rewrite_request(
        tmp_path, function_name="sub_9999", entry="0x9999", candidate_source="s3", mismatch_class=None, mismatch_histogram=None
    )
    assert rewrite_queue.count_requests_for_function(tmp_path, "sub_1000") == 2
    assert rewrite_queue.count_requests_for_function(tmp_path, "sub_9999") == 1
    assert rewrite_queue.count_requests_for_function(tmp_path, "sub_absent") == 0


def test_read_rewrite_queue_missing_file_returns_empty(tmp_path: Path) -> None:
    queue = rewrite_queue.read_rewrite_queue(tmp_path)
    assert queue["entries"] == {}
    assert queue["schema"] == rewrite_queue.SCHEMA


def test_derive_request_id_is_deterministic_and_source_sensitive() -> None:
    id_a = rewrite_queue.derive_request_id("sub_1000", "int x(void) { return 0; }")
    id_b = rewrite_queue.derive_request_id("sub_1000", "int x(void) { return 0; }")
    id_c = rewrite_queue.derive_request_id("sub_1000", "int x(void) { return 1; }")
    assert id_a == id_b
    assert id_a != id_c
    assert id_a.startswith("sub_1000:")
