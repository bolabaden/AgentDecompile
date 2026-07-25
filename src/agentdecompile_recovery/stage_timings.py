"""Accumulate wall-time stage receipts for one-shot / reconstruct runs."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from .state import atomic_write_json, now

SCHEMA = "agentdecompile.stage-timings.v1"


def empty_timings(work_dir: Path) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "writtenAt": now(),
        "workDir": str(work_dir),
        "stages": {},
        "claimBoundary": "Wall times only; not a recovery-quality claim.",
    }


def load_stage_timings(work_dir: Path) -> dict[str, Any]:
    """Load an existing stage-timings receipt or start a fresh one.

    Both the one-shot pipeline and the reconstruct front door append into the
    same ``<work_dir>/stage-timings.json`` so a run has one timings artifact.
    """
    path = work_dir / "stage-timings.json"
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, ValueError):
            return empty_timings(work_dir)
        if isinstance(data, dict) and data.get("schema") == SCHEMA:
            data.setdefault("stages", {})
            return data
    return empty_timings(work_dir)


def record_stage(
    timings: dict[str, Any],
    name: str,
    *,
    started: float,
    ended: float | None = None,
    **extra: Any,
) -> None:
    end = time.monotonic() if ended is None else ended
    stages = timings.setdefault("stages", {})
    stages[name] = {
        "wallSeconds": round(end - started, 3),
        **extra,
    }
    timings["writtenAt"] = now()


def write_stage_timings(work_dir: Path, timings: dict[str, Any]) -> Path:
    path = work_dir / "stage-timings.json"
    timings = {**timings, "workDir": str(work_dir), "writtenAt": now()}
    atomic_write_json(path, timings)
    return path
