"""Phase 5 proof ladder: inventoried functions vs objdiff-verified accepts.

Coverage rungs are 1% → 5% → 20%. Numerator is receipt-backed objdiff only —
never bare verified/ source files or acceptedCandidates.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import claim_report as claim_report_mod
from .state import atomic_write_json, now

SCHEMA = "agentdecompile.proof-ladder.v1"
RUNGS: tuple[tuple[str, float], ...] = (
    ("1%", 0.01),
    ("5%", 0.05),
    ("20%", 0.20),
)
CLAIM_BOUNDARY = (
    "proof ladder coverage is receipt-backed objdiff-verified-semantic accepts "
    "over inventoried function candidates; bare verified/ trees and advisory "
    "artifacts do not count; this is not a ≥90% whole-binary recovery claim"
)


def build_proof_ladder(work_dir: Path) -> dict[str, Any]:
    """Compute proof-ladder coverage for a reconstruct work directory."""

    work_dir = work_dir.resolve()
    denominator, denominator_source = _count_inventoried_functions(work_dir)
    numerator = int(claim_report_mod._count_objdiff_verified(work_dir))
    if denominator <= 0:
        coverage = 0.0
        status = "no-inventory" if denominator_source is None else "empty"
        rung = "below-1"
        next_rung: str | None = "1%"
    else:
        coverage = numerator / denominator
        status = "complete"
        rung = _rung_for_coverage(coverage)
        next_rung = _next_rung(rung)

    return {
        "schema": SCHEMA,
        "status": status,
        "writtenAt": now(),
        "workDir": str(work_dir),
        "denominator": denominator,
        "denominatorSource": denominator_source,
        "numerator": numerator,
        "coverage": coverage,
        "coveragePercent": round(coverage * 100.0, 4),
        "rung": rung,
        "nextRung": next_rung,
        "rungs": [name for name, _ in RUNGS],
        "thresholds": {name: threshold for name, threshold in RUNGS},
        "claimBoundary": CLAIM_BOUNDARY,
    }


def write_proof_ladder(work_dir: Path) -> dict[str, Any]:
    ladder = build_proof_ladder(work_dir)
    atomic_write_json(work_dir / "proof-ladder.json", ladder)
    return ladder


def _count_inventoried_functions(work_dir: Path) -> tuple[int, str | None]:
    """Count only function-candidates.json — never shrink via binary-inventory."""

    path = work_dir / "function-candidates.json"
    if not path.is_file():
        return 0, None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return 0, "function-candidates.json"
    if not isinstance(data, dict):
        return 0, "function-candidates.json"
    candidates = data.get("candidates")
    if isinstance(candidates, list):
        return len([row for row in candidates if isinstance(row, dict)]), "function-candidates.json"
    summary = data.get("summary")
    if isinstance(summary, dict):
        for key in ("count", "candidates", "functions"):
            value = summary.get(key)
            if isinstance(value, int) and value >= 0:
                return value, "function-candidates.json"
    return 0, "function-candidates.json"


def _rung_for_coverage(coverage: float) -> str:
    current = "below-1"
    for name, threshold in RUNGS:
        if coverage + 1e-12 >= threshold:
            current = name
    return current


def _next_rung(rung: str) -> str | None:
    names = [name for name, _ in RUNGS]
    if rung == "below-1":
        return names[0]
    if rung not in names:
        return names[0]
    idx = names.index(rung)
    if idx + 1 >= len(names):
        return None
    return names[idx + 1]
