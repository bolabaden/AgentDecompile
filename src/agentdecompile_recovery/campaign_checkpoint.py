"""Monotonic best-so-far campaign checkpoints per function."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .state import atomic_write_json, now

SCHEMA = "agentdecompile.campaign-checkpoint.v1"
INDEX_SCHEMA = "agentdecompile.campaign-checkpoint-index.v1"
CLAIM_BOUNDARY = (
    "best-so-far checkpoints are advisory progress markers; "
    "only objdiff-zero under verified/ moves the proof ladder numerator"
)


def checkpoint_index_path(work_dir: Path) -> Path:
    return work_dir.resolve() / "facts" / "campaign-checkpoints.json"


def checkpoint_detail_path(work_dir: Path, name: str) -> Path:
    slug = name.replace("/", "_").replace("\\", "_")
    return work_dir.resolve() / "facts" / "campaign-checkpoints" / f"{slug}.json"


def load_checkpoint_index(work_dir: Path) -> dict[str, Any]:
    path = checkpoint_index_path(work_dir)
    if not path.is_file():
        return {"schema": INDEX_SCHEMA, "entries": {}, "claimBoundary": CLAIM_BOUNDARY}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return {"schema": INDEX_SCHEMA, "entries": {}, "claimBoundary": CLAIM_BOUNDARY}
    if not isinstance(payload, dict):
        return {"schema": INDEX_SCHEMA, "entries": {}, "claimBoundary": CLAIM_BOUNDARY}
    entries = payload.get("entries")
    if not isinstance(entries, dict):
        payload["entries"] = {}
    payload.setdefault("schema", INDEX_SCHEMA)
    payload.setdefault("claimBoundary", CLAIM_BOUNDARY)
    return payload


def record_attempt_checkpoint(
    work_dir: Path,
    *,
    name: str,
    entry: str | None,
    differences: int | None,
    mismatch_class: str | None = None,
    routed_playbook: str | None = None,
    attempt_id: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    """Update best-so-far checkpoint when ``differences`` improves monotonically."""

    work_dir = work_dir.resolve()
    if differences is None:
        return {"updated": False, "reason": "missing-differences"}
    try:
        diff = int(differences)
    except (TypeError, ValueError):
        return {"updated": False, "reason": "invalid-differences"}

    index = load_checkpoint_index(work_dir)
    entries: dict[str, Any] = index.setdefault("entries", {})
    prior = entries.get(name) if isinstance(entries.get(name), dict) else {}
    prior_best = prior.get("bestDifference")
    try:
        prior_best_int = int(prior_best) if prior_best is not None else None
    except (TypeError, ValueError):
        prior_best_int = None

    improved = prior_best_int is None or diff < prior_best_int
    if not improved and prior:
        return {"updated": False, "reason": "not-improved", "bestDifference": prior_best_int}

    detail = {
        "schema": SCHEMA,
        "writtenAt": now(),
        "functionName": name,
        "entry": entry,
        "bestDifference": diff,
        "mismatchClass": mismatch_class,
        "routedPlaybook": routed_playbook,
        "lastAttemptId": attempt_id,
        "lastStatus": status,
        "claimBoundary": CLAIM_BOUNDARY,
    }
    detail_path = checkpoint_detail_path(work_dir, name)
    detail_path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(detail_path, detail)
    entries[name] = {
        "bestDifference": diff,
        "mismatchClass": mismatch_class,
        "routedPlaybook": routed_playbook,
        "detailPath": str(detail_path),
        "updatedAt": detail["writtenAt"],
    }
    index["writtenAt"] = now()
    index["claimBoundary"] = CLAIM_BOUNDARY
    atomic_write_json(checkpoint_index_path(work_dir), index)
    return {"updated": True, "bestDifference": diff, "detailPath": str(detail_path)}


def ingest_attempts_jsonl(work_dir: Path, path: Path | None = None) -> dict[str, Any]:
    """Scan synthesis attempts and refresh checkpoint index."""

    work_dir = work_dir.resolve()
    attempts_path = path or (work_dir / "source-synthesis" / "attempts.jsonl")
    updated = 0
    scanned = 0
    if not attempts_path.is_file():
        return {"scanned": 0, "updated": 0, "status": "missing"}
    for line in attempts_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        scanned += 1
        diff = row.get("differences")
        if diff is None:
            diff = row.get("differenceCount")
        result = record_attempt_checkpoint(
            work_dir,
            name=str(row.get("name") or row.get("functionName") or ""),
            entry=str(row.get("entry") or "") or None,
            differences=diff if diff is not None else None,
            mismatch_class=str(row.get("mismatchClass") or "") or None,
            routed_playbook=str(row.get("routedPlaybook") or "") or None,
            attempt_id=str(row.get("attemptId") or row.get("id") or "") or None,
            status=str(row.get("status") or "") or None,
        )
        if result.get("updated"):
            updated += 1
    return {"scanned": scanned, "updated": updated, "status": "complete"}
