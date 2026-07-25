"""Bounded near-miss repair via source-shape search / permuter."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .mismatch_classify import routed_playbook_for_class
from .pattern_memory import retrieve_patterns
from .playbook_config import playbook_receipt
from .proof_target import NEAR_MISS_MAX_DIFF
from .state import atomic_write_json, now
from .vacuum_runner import run_vacuum_prompt

RUN_SCHEMA = "agentdecompile.near-miss-repair-run.v1"
CLAIM_BOUNDARY = (
    "near-miss repair is advisory; only objdiff-zero accepts under verified/ move the proof ladder"
)


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def select_near_miss_targets(work_dir: Path, *, threshold: int = NEAR_MISS_MAX_DIFF, limit: int = 3) -> list[dict[str, Any]]:
    work_dir = work_dir.resolve()
    queue = _load_json(work_dir / "facts" / "proof-target-queue.json") or {}
    entries = [row for row in (queue.get("entries") or []) if isinstance(row, dict)]
    ranked: list[dict[str, Any]] = []
    for row in entries:
        best = row.get("nearMissBestDifference")
        if best is None:
            continue
        try:
            diff = int(best)
        except (TypeError, ValueError):
            continue
        if diff <= threshold:
            ranked.append({**row, "nearMissBestDifference": diff})
    ranked.sort(
        key=lambda row: (
            int(row.get("nearMissBestDifference") or 999),
            -int(row.get("score") or 0),
            0 if row.get("nearMissMismatchClass") in {"operand", "insert-delete"} else 1,
        )
    )
    return ranked[: max(0, limit)]


def run_near_miss_repair(
    work_dir: Path,
    *,
    threshold: int = NEAR_MISS_MAX_DIFF,
    limit: int = 3,
    max_attempts: int = 3,
) -> dict[str, Any]:
    work_dir = work_dir.resolve()
    targets = select_near_miss_targets(work_dir, threshold=threshold, limit=limit)
    if not targets:
        receipt = {
            "schema": RUN_SCHEMA,
            "status": "skipped:no-targets",
            "writtenAt": now(),
            "workDir": str(work_dir),
            "threshold": threshold,
            "attempted": [],
            "claimBoundary": CLAIM_BOUNDARY,
        }
        atomic_write_json(work_dir / "state" / "near-miss-repair-run.json", receipt)
        return receipt

    attempted: list[dict[str, Any]] = []
    for row in targets:
        name = str(row.get("name") or row.get("functionName") or "")
        if not name:
            continue
        mismatch_class = row.get("nearMissMismatchClass")
        routed_playbook = routed_playbook_for_class(str(mismatch_class) if mismatch_class else None)
        pattern_hints = retrieve_patterns(
            work_dir,
            mismatch_class=str(mismatch_class) if mismatch_class else None,
        )
        result = run_vacuum_prompt(
            work_dir=work_dir,
            name=name,
            max_attempts=max_attempts,
            source_shape_search=True,
            routed_playbook=routed_playbook,
        )
        attempted.append(
            {
                "name": name,
                "nearMissBestDifference": row.get("nearMissBestDifference"),
                "mismatchClass": mismatch_class,
                "routedPlaybook": routed_playbook,
                "playbookReceipt": playbook_receipt(routed_playbook),
                "patternHintCount": len(pattern_hints),
                "vacuumStatus": result.get("status"),
                "exitCode": result.get("exitCode"),
                "sourceShapeSearch": True,
            }
        )

    matched = sum(1 for row in attempted if int(row.get("exitCode") or 1) == 0)
    status = "complete" if matched > 0 else "near-miss"
    receipt = {
        "schema": RUN_SCHEMA,
        "status": status,
        "writtenAt": now(),
        "workDir": str(work_dir),
        "threshold": threshold,
        "targetCount": len(targets),
        "matchedCount": matched,
        "attempted": attempted,
        "claimBoundary": CLAIM_BOUNDARY,
    }
    atomic_write_json(work_dir / "state" / "near-miss-repair-run.json", receipt)
    return receipt
