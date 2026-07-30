"""File-queue handoff for challenger-lane mechanism 3 (subagent-fulfilled candidate rewriting).

The autonomous recovery loop never calls an LLM API directly. When a near-miss
exhausts mechanisms 1+2 (compiler-flag exploration, idiom permutation) and
rewrite-request budget remains, it writes a typed pending request here and
stops (non-blocking). A separate, live Claude Code session -- running /loop
against the agentdecompile-rewrite-worker skill -- claims pending entries,
dispatches a tool-restricted Agent subagent, and writes the result back. A
later --autonomous invocation picks up completed results.

Lifecycle: pending -> claimed -> completed | failed. Every mutation holds an
exclusive file lock across its read -> verify-expected-state -> write cycle
(see `_locked`), so two processes racing on the same entry cannot both
succeed -- one blocks until the other's mutation (and lock release) completes,
then re-reads current state before deciding whether its own mutation still
applies.
"""

from __future__ import annotations

import fcntl
import hashlib
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .state import atomic_write_json, now, read_json

SCHEMA = "agentdecompile.rewrite-queue.v1"
CLAIM_BOUNDARY = (
    "rewrite-queue entries are advisory only; the objdiff compile-verify gate "
    "is the sole proof mechanism for any resulting candidate"
)

STATUS_PENDING = "pending"
STATUS_CLAIMED = "claimed"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"

DEFAULT_CLAIM_STALENESS_SECONDS = 1800


def queue_path(work_dir: Path) -> Path:
    return work_dir / "state" / "rewrite-queue.json"


def _lock_path(work_dir: Path) -> Path:
    return work_dir / "state" / "rewrite-queue.lock"


@contextmanager
def _locked(work_dir: Path) -> Iterator[None]:
    """Exclusive cross-process lock spanning a full read-check-write cycle.

    Blocking (not try-lock): a losing writer waits for the winner to finish
    and release, then proceeds against fresh on-disk state, rather than
    failing outright. Without this, two processes can both read the same
    "pending" snapshot and both believe their write is the first to land.
    """

    lock_path = _lock_path(work_dir)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+") as fh:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


def derive_request_id(function_name: str, candidate_source: str) -> str:
    digest = hashlib.sha256(candidate_source.encode("utf-8")).hexdigest()[:16]
    return f"{function_name}:{digest}"


def _empty_queue() -> dict[str, Any]:
    return {"schema": SCHEMA, "claimBoundary": CLAIM_BOUNDARY, "entries": {}, "requestCounts": {}}


def read_rewrite_queue(work_dir: Path) -> dict[str, Any]:
    path = queue_path(work_dir)
    if not path.exists():
        return _empty_queue()
    try:
        data = read_json(path)
    except (OSError, ValueError):
        return _empty_queue()
    if not isinstance(data, dict) or not isinstance(data.get("entries"), dict):
        return _empty_queue()
    if not isinstance(data.get("requestCounts"), dict):
        data["requestCounts"] = {}
    return data


def find_entry(work_dir: Path, request_id: str) -> dict[str, Any] | None:
    queue = read_rewrite_queue(work_dir)
    entry = queue["entries"].get(request_id)
    return dict(entry) if isinstance(entry, dict) else None


def count_requests_for_function(work_dir: Path, function_name: str) -> int:
    """Cumulative requests ever written for this function.

    Reads the durable requestCounts counter, not a scan of currently-live
    entries -- entries are pruned once consumed (prune_consumed_entries), and
    a live-entry scan would let max_rewrite_requests_per_function silently
    reset to full every time a resolved entry gets pruned.
    """

    queue = read_rewrite_queue(work_dir)
    return int(queue["requestCounts"].get(function_name, 0) or 0)


def write_rewrite_request(
    work_dir: Path,
    *,
    function_name: str,
    entry: str,
    candidate_source: str,
    mismatch_class: str | None,
    mismatch_histogram: dict[str, int] | None,
) -> str:
    """Write a pending request; a no-op if one already exists for this candidate."""

    request_id = derive_request_id(function_name, candidate_source)
    with _locked(work_dir):
        queue = read_rewrite_queue(work_dir)
        if request_id in queue["entries"]:
            return request_id
        queue["entries"][request_id] = {
            "requestId": request_id,
            "functionName": function_name,
            "entry": entry,
            "candidateSource": candidate_source,
            "mismatchClass": mismatch_class,
            "mismatchHistogram": mismatch_histogram,
            "status": STATUS_PENDING,
            "writtenAt": now(),
        }
        queue["requestCounts"][function_name] = int(queue["requestCounts"].get(function_name, 0) or 0) + 1
        atomic_write_json(queue_path(work_dir), queue)
    return request_id


def claim_pending_entry(
    work_dir: Path,
    request_id: str,
    *,
    claimant: str,
    staleness_seconds: int = DEFAULT_CLAIM_STALENESS_SECONDS,
) -> bool:
    """Claim a pending (or stale-claimed) entry. Returns whether the claim succeeded."""

    with _locked(work_dir):
        queue = read_rewrite_queue(work_dir)
        entry = queue["entries"].get(request_id)
        if not isinstance(entry, dict):
            return False
        status = entry.get("status")
        if status == STATUS_PENDING:
            pass
        elif status == STATUS_CLAIMED and _claim_is_stale(entry, staleness_seconds):
            pass
        else:
            return False
        entry["status"] = STATUS_CLAIMED
        entry["claimedBy"] = claimant
        entry["claimedAt"] = now()
        queue["entries"][request_id] = entry
        atomic_write_json(queue_path(work_dir), queue)
        return True


def _claim_is_stale(entry: dict[str, Any], staleness_seconds: int) -> bool:
    claimed_at = entry.get("claimedAt")
    if not isinstance(claimed_at, str):
        return True
    try:
        claimed_dt = datetime.fromisoformat(claimed_at.replace("Z", "+00:00"))
    except ValueError:
        return True
    age = (datetime.now(timezone.utc) - claimed_dt).total_seconds()
    return age >= staleness_seconds


def write_claimed_result(
    work_dir: Path,
    request_id: str,
    *,
    claimant: str,
    status: str,
    source: str | None = None,
    reason: str | None = None,
) -> bool:
    """Write a completed/failed result. No-op (discarded) if no longer claimed by `claimant`."""

    if status not in (STATUS_COMPLETED, STATUS_FAILED):
        raise ValueError("status must be completed or failed")
    with _locked(work_dir):
        queue = read_rewrite_queue(work_dir)
        entry = queue["entries"].get(request_id)
        if not isinstance(entry, dict):
            return False
        if entry.get("status") != STATUS_CLAIMED or entry.get("claimedBy") != claimant:
            return False
        entry["status"] = status
        entry["resolvedAt"] = now()
        if source is not None:
            entry["source"] = source
        if reason is not None:
            entry["reason"] = reason
        queue["entries"][request_id] = entry
        atomic_write_json(queue_path(work_dir), queue)
        return True


def prune_consumed_entries(work_dir: Path, request_ids: list[str]) -> None:
    """Remove completed/failed entries once a campaign pass has read them.

    Never touches requestCounts -- pruning an entry must not free up budget
    the function has already spent.
    """

    if not request_ids:
        return
    with _locked(work_dir):
        queue = read_rewrite_queue(work_dir)
        changed = False
        for request_id in request_ids:
            entry = queue["entries"].get(request_id)
            if isinstance(entry, dict) and entry.get("status") in (STATUS_COMPLETED, STATUS_FAILED):
                del queue["entries"][request_id]
                changed = True
        if changed:
            atomic_write_json(queue_path(work_dir), queue)
