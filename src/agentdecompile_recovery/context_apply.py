"""Apply ready context propose-labels via MCP tool-seq."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .context_propose import build_propose_labels
from .mcp_tool_seq import conflict_resolution_default, run_tool_seq
from .state import atomic_write_json, now

RUN_SCHEMA = "agentdecompile.context-apply-run.v1"
CLAIM_BOUNDARY = (
    "context apply is advisory; applied labels do not increment proof ladder without objdiff zero"
)


def build_apply_tool_seq(proposals: list[dict[str, Any]], *, limit: int = 0) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    ready = [row for row in proposals if isinstance(row, dict) and row.get("status") == "ready"]
    if limit > 0:
        ready = ready[:limit]
    for row in ready:
        address = str(row.get("addressHex") or "")
        name = str(row.get("proposedName") or "").strip()
        if not address or not name:
            continue
        steps.append(
            {
                "name": "rename-function",
                "arguments": {
                    "addressOrSymbol": address,
                    "name": name,
                },
            }
        )
    return steps


def run_context_apply(
    work_dir: Path,
    *,
    limit: int = 50,
    run_tool_seq_fn=run_tool_seq,
) -> dict[str, Any]:
    work_dir = work_dir.resolve()
    propose_path = work_dir / "acquisition" / "propose-labels.json"
    if propose_path.is_file():
        try:
            propose = json.loads(propose_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            propose = None
    else:
        propose = build_propose_labels(work_dir)
        atomic_write_json(propose_path, propose)

    if not isinstance(propose, dict):
        propose = build_propose_labels(work_dir)

    proposals = [row for row in (propose.get("proposals") or []) if isinstance(row, dict)]
    ready_rows = [row for row in proposals if row.get("status") == "ready"]
    conflict_rows = [row for row in proposals if row.get("status") == "conflict"]

    if not ready_rows:
        receipt = {
            "schema": RUN_SCHEMA,
            "status": "skipped:no-ready",
            "writtenAt": now(),
            "workDir": str(work_dir),
            "applied": 0,
            "skippedConflict": len(conflict_rows),
            "claimBoundary": CLAIM_BOUNDARY,
        }
        atomic_write_json(work_dir / "state" / "context-apply-run.json", receipt)
        return receipt

    steps = build_apply_tool_seq(proposals, limit=limit)
    mcp_result = run_tool_seq_fn(steps, work_dir=work_dir)
    mcp_status = str(mcp_result.get("status") or "unknown")

    applied = sum(1 for row in (mcp_result.get("steps") or []) if row.get("ok"))
    conflicts = [row for row in (mcp_result.get("steps") or []) if row.get("conflictId")]

    receipt = {
        "schema": RUN_SCHEMA,
        "status": "complete" if mcp_status == "complete" else mcp_status,
        "writtenAt": now(),
        "workDir": str(work_dir),
        "proposeLabelsPath": str(propose_path),
        "readyCount": len(ready_rows),
        "applied": applied,
        "skippedConflict": len(conflict_rows) + len(conflicts),
        "conflictResolution": conflict_resolution_default(),
        "mcpStatus": mcp_status,
        "toolsInvoked": mcp_result.get("toolsInvoked") or [],
        "stepResults": mcp_result.get("steps") or [],
        "claimBoundary": CLAIM_BOUNDARY,
    }
    atomic_write_json(work_dir / "state" / "context-apply-run.json", receipt)
    return receipt
