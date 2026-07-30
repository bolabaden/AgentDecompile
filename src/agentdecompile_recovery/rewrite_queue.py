"""File-queue handoff for challenger-lane mechanism 3 (subagent-fulfilled candidate rewriting).

The autonomous recovery loop never calls an LLM API directly. When a near-miss
exhausts mechanisms 1+2 (compiler-flag exploration, idiom permutation) and
rewrite-request budget remains, it writes a typed pending request here and
stops (non-blocking). A separate, live Claude Code session -- running /loop
against the agentdecompile-rewrite-worker skill -- claims pending entries,
dispatches a tool-restricted Agent subagent, and writes the result back. A
later --autonomous invocation picks up completed results.

Lifecycle: pending -> claimed -> completed | failed. Every mutation is
read-current -> verify-expected-state -> write-full-snapshot; a mutation that
finds an entry no longer in the expected state is discarded rather than
clobbering a concurrent writer's result (see docs/plans/2026-07-29-002-...).
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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


def derive_request_id(function_name: str, candidate_source: str) -> str:
    digest = hashlib.sha256(candidate_source.encode("utf-8")).hexdigest()[:16]
    return f"{function_name}:{digest}"


def _empty_queue() -> dict[str, Any]:
    return {"schema": SCHEMA, "claimBoundary": CLAIM_BOUNDARY, "entries": {}}


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
    return data


def find_entry(work_dir: Path, request_id: str) -> dict[str, Any] | None:
    queue = read_rewrite_queue(work_dir)
    entry = queue["entries"].get(request_id)
    return dict(entry) if isinstance(entry, dict) else None


def count_requests_for_function(work_dir: Path, function_name: str) -> int:
    queue = read_rewrite_queue(work_dir)
    prefix = f"{function_name}:"
    return sum(1 for request_id in queue["entries"] if request_id.startswith(prefix))


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
    """Remove completed/failed entries once a campaign pass has read them."""

    if not request_ids:
        return
    queue = read_rewrite_queue(work_dir)
    changed = False
    for request_id in request_ids:
        entry = queue["entries"].get(request_id)
        if isinstance(entry, dict) and entry.get("status") in (STATUS_COMPLETED, STATUS_FAILED):
            del queue["entries"][request_id]
            changed = True
    if changed:
        atomic_write_json(queue_path(work_dir), queue)
