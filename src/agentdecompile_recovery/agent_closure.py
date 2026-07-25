"""Orchestrate agent loop closure stages before proof campaign."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from .autonomy_budget import AutonomyBudget
from .context_apply import run_context_apply
from .state import atomic_write_json, now
from .symbol_provenance import ingest_symbol_provenance

SCHEMA = "agentdecompile.agent-closure-run.v1"
CLAIM_BOUNDARY = (
    "agent closure stages are advisory executors; "
    "objdiff-verified-semantic accepts under verified/ remain the proof ladder numerator"
)


def _load_target_input(work_dir: Path) -> str | None:
    target = work_dir / "target.json"
    if not target.is_file():
        return None
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    for key in ("inputPath", "binaryPath"):
        value = str(payload.get(key) or "").strip()
        if value:
            return value
    return None


def run_enrich_refresh_subprocess(work_dir: Path, *, timeout: int = 600) -> dict[str, Any]:
    work_dir = work_dir.resolve()
    target_input = _load_target_input(work_dir)
    if not target_input:
        return {"status": "skipped:no-target", "returncode": None}
    cmd = [
        "uv",
        "run",
        "agentdecompile-reconstruct",
        target_input,
        "--work-dir",
        str(work_dir),
        "--resume",
        "--stop-after",
        "enrich-decompile",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "error", "error": str(exc), "returncode": None}
    return {
        "status": "complete" if proc.returncode == 0 else "error",
        "returncode": proc.returncode,
        "command": cmd,
    }


def run_agent_closure_stages(
    work_dir: Path,
    budget: AutonomyBudget,
    *,
    skip_context_apply: bool = False,
    skip_symbol_provenance: bool = False,
    run_context_apply_fn=run_context_apply,
    run_symbol_provenance_fn=ingest_symbol_provenance,
) -> dict[str, Any]:
    """Run context apply and symbol provenance before proof campaign loop."""

    work_dir = work_dir.resolve()
    stages: dict[str, Any] = {}

    if not skip_context_apply and budget.max_functions > 0:
        stages["contextApply"] = run_context_apply_fn(work_dir, limit=budget.max_functions)

    if not skip_symbol_provenance:
        stages["symbolProvenance"] = run_symbol_provenance_fn(work_dir)

    receipt = {
        "schema": SCHEMA,
        "status": "complete",
        "writtenAt": now(),
        "workDir": str(work_dir),
        "stages": stages,
        "claimBoundary": CLAIM_BOUNDARY,
    }
    atomic_write_json(work_dir / "state" / "agent-closure-run.json", receipt)
    return receipt
