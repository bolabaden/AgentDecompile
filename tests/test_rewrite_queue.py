"""Unit tests for the rewrite-request file queue (challenger-lane mechanism 3).

Covers the write/claim/result-write/prune lifecycle and the compare-and-swap
discipline that prevents duplicate dispatch and lost-write races between
concurrent /loop-driven worker sessions.
"""

from __future__ import annotations

import json
import multiprocessing
from pathlib import Path

import pytest

from agentdecompile_recovery import rewrite_queue

pytestmark = pytest.mark.unit


def _claim_worker(work_dir: str, request_id: str, claimant: str, result_path: str) -> None:
    ok = rewrite_queue.claim_pending_entry(Path(work_dir), request_id, claimant=claimant)
    Path(result_path).write_text("1" if ok else "0", encoding="utf-8")


def _write_request_worker(work_dir: str, name: str) -> None:
    rewrite_queue.write_rewrite_request(
        Path(work_dir), function_name=name, entry="0x1", candidate_source=f"src-{name}", mismatch_class=None, mismatch_histogram=None
    )


# macOS defaults multiprocessing to the "spawn" start method, which re-imports
# the target function in a fresh interpreter rather than fork()ing the
# already-loaded parent. Under pytest, the test module isn't reliably
# importable by that fresh interpreter (no guaranteed `tests` package on
# sys.path), so spawn-based Process creation fails here with
# ModuleNotFoundError/AttributeError on macOS CI even though the exact same
# code passes on Linux (which defaults to fork). Force fork explicitly --
# available on both Linux and macOS (the only two CI platforms) -- since
# these tests only need process-level isolation, not spawn's clean-slate
# import behavior.
_FORK_CONTEXT = multiprocessing.get_context("fork")


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


# -- real cross-process concurrency (code review: claim was a TOCTOU race
# without file locking; these exercise actual separate processes, not just
# sequential calls in one process) --------------------------------------


def test_concurrent_claims_from_separate_processes_only_one_wins(tmp_path: Path) -> None:
    request_id = rewrite_queue.write_rewrite_request(
        tmp_path, function_name="sub_5000", entry="0x5000", candidate_source="s", mismatch_class=None, mismatch_histogram=None
    )
    result_a = tmp_path / "result_a.txt"
    result_b = tmp_path / "result_b.txt"
    proc_a = _FORK_CONTEXT.Process(target=_claim_worker, args=(str(tmp_path), request_id, "proc-a", str(result_a)))
    proc_b = _FORK_CONTEXT.Process(target=_claim_worker, args=(str(tmp_path), request_id, "proc-b", str(result_b)))
    proc_a.start()
    proc_b.start()
    proc_a.join(timeout=10)
    proc_b.join(timeout=10)
    assert proc_a.exitcode == 0
    assert proc_b.exitcode == 0

    outcome_a = result_a.read_text(encoding="utf-8")
    outcome_b = result_b.read_text(encoding="utf-8")
    # Exactly one of the two processes must have won the claim -- the file
    # lock (not just an in-memory check) must serialize the two attempts.
    assert (outcome_a, outcome_b) in {("1", "0"), ("0", "1")}
    entry = rewrite_queue.find_entry(tmp_path, request_id)
    assert entry["claimedBy"] in {"proc-a", "proc-b"}


def test_write_rewrite_request_survives_concurrent_writes_to_different_entries(tmp_path: Path) -> None:
    """Two writers touching different request ids in the same queue file must
    not lose each other's entries (the lock serializes the whole file, not
    just same-entry races)."""

    procs = [
        _FORK_CONTEXT.Process(target=_write_request_worker, args=(str(tmp_path), f"sub_{i}"))
        for i in range(6)
    ]
    for proc in procs:
        proc.start()
    for proc in procs:
        proc.join(timeout=10)
        assert proc.exitcode == 0

    queue = rewrite_queue.read_rewrite_queue(tmp_path)
    assert len(queue["entries"]) == 6


# -- durable budget accounting (code review: pruning a resolved entry must
# not silently reset max_rewrite_requests_per_function's remaining budget) --


def test_count_requests_for_function_survives_pruning(tmp_path: Path) -> None:
    request_id = rewrite_queue.write_rewrite_request(
        tmp_path, function_name="sub_6000", entry="0x6000", candidate_source="s", mismatch_class=None, mismatch_histogram=None
    )
    assert rewrite_queue.count_requests_for_function(tmp_path, "sub_6000") == 1

    rewrite_queue.claim_pending_entry(tmp_path, request_id, claimant="worker-a")
    rewrite_queue.write_claimed_result(tmp_path, request_id, claimant="worker-a", status=rewrite_queue.STATUS_COMPLETED, source="int x(void){return 0;}")
    rewrite_queue.prune_consumed_entries(tmp_path, [request_id])

    assert rewrite_queue.find_entry(tmp_path, request_id) is None, "entry should be pruned"
    assert rewrite_queue.count_requests_for_function(tmp_path, "sub_6000") == 1, (
        "budget accounting must survive pruning -- otherwise "
        "max_rewrite_requests_per_function silently resets to full every time "
        "a resolved request is consumed"
    )


def test_count_requests_for_function_accumulates_across_multiple_requests(tmp_path: Path) -> None:
    for i in range(3):
        request_id = rewrite_queue.write_rewrite_request(
            tmp_path, function_name="sub_7000", entry="0x7000", candidate_source=f"variant-{i}", mismatch_class=None, mismatch_histogram=None
        )
        rewrite_queue.claim_pending_entry(tmp_path, request_id, claimant="worker-a")
        rewrite_queue.write_claimed_result(tmp_path, request_id, claimant="worker-a", status=rewrite_queue.STATUS_FAILED, reason="no usable rewrite")
        rewrite_queue.prune_consumed_entries(tmp_path, [request_id])
    assert rewrite_queue.count_requests_for_function(tmp_path, "sub_7000") == 3
