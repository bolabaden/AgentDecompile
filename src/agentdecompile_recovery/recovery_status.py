"""Read-only recovery run status for CLI and curated MCP tools."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _queue_counts(queue: dict[str, Any] | None) -> dict[str, int] | None:
    if queue is None:
        return None
    counts: dict[str, int] = {}
    for key in ("pending", "matched", "integrated", "failed", "difficult"):
        value = queue.get(key)
        counts[key] = len(value) if isinstance(value, list) else 0
    return counts


def build_recovery_status(work_dir: Path) -> dict[str, Any]:
    """Summarize reconstruct/recover work-dir progress without claiming semantic parity."""

    work_dir = work_dir.resolve()
    report = _load_json(work_dir / "report.json")
    state = _load_json(work_dir / "state.json")
    analysis = _load_json(work_dir / "analysis-target.json")
    claim = _load_json(work_dir / "claim-report.json")
    synth = _load_json(work_dir / "source-synthesis" / "summary.json")
    budget = _load_json(work_dir / "autonomy-budget.json")
    queue = _load_json(work_dir / "state" / "queue.json")
    session = _load_json(work_dir / "state" / "vacuum-session.json")
    seed = _load_json(work_dir / "state" / "vacuum-queue-seed.json")
    export_pkg = _load_json(work_dir / "export" / "manifest.json")
    if export_pkg is None and isinstance((report or {}).get("exportPackage"), dict):
        export_pkg = report.get("exportPackage")  # type: ignore[assignment]
    ladder = _load_json(work_dir / "proof-ladder.json")
    if ladder is None and isinstance((claim or {}).get("proofLadder"), dict):
        ladder = claim.get("proofLadder")  # type: ignore[assignment]
    if ladder is None and isinstance((report or {}).get("proofLadder"), dict):
        ladder = report.get("proofLadder")  # type: ignore[assignment]
    critical = _load_json(work_dir / "critical-path.json")
    if critical is None and isinstance((report or {}).get("criticalPath"), dict):
        critical = report.get("criticalPath")  # type: ignore[assignment]
    if critical is None and (work_dir / "target.json").is_file():
        from .critical_path import build_critical_path

        critical = build_critical_path(work_dir)
    placement = _load_json(work_dir / "acquisition" / "placement.json")
    acquire = _load_json(work_dir / "acquisition" / "acquire.json")
    slice_verify = _load_json(work_dir / "slice-verify" / "summary.json")
    if placement is None and isinstance((acquire or {}).get("placement"), dict):
        placement = acquire.get("placement")  # type: ignore[assignment]
    seeds = _load_json(work_dir / "advisory" / "context-seeds" / "manifest.json")
    if seeds is None and isinstance((acquire or {}).get("contextSeeds"), dict):
        seeds = acquire.get("contextSeeds")  # type: ignore[assignment]

    terminal = None
    for source in (claim, analysis, state, report):
        if not source:
            continue
        for key in ("terminalStatus", "status"):
            value = source.get(key)
            if value:
                terminal = str(value)
                break
        if terminal:
            break

    stage = None
    if state:
        stage = state.get("currentStage") or state.get("stage") or state.get("lastStage")
    if report and stage is None:
        stage = report.get("currentStage") or report.get("stage")

    verified = work_dir / "verified"
    advisory = work_dir / "advisory"
    verified_count = sum(1 for path in verified.rglob("*") if path.is_file()) if verified.is_dir() else 0
    advisory_count = sum(1 for path in advisory.rglob("*") if path.is_file()) if advisory.is_dir() else 0
    queue_counts = _queue_counts(queue)

    vacuum: dict[str, Any] | None = None
    if budget is not None or queue is not None or session is not None or seed is not None:
        vacuum = {
            "budgetStatus": (budget or {}).get("status"),
            "requested": bool((budget or {}).get("requested")) if budget is not None else False,
            "queueCounts": queue_counts,
            "sessionStatus": (session or {}).get("status") if session is not None else None,
            "seededCount": int((seed or {}).get("seededCount") or 0) if seed is not None else None,
            "seedStatus": (seed or {}).get("status") if seed is not None else None,
            "claimBoundary": (
                "vacuum/budget fields summarize autonomy loop progress only; "
                "they are not objdiff-verified-semantic proof"
            ),
        }

    return {
        "schema": "agentdecompile.recovery-status.v1",
        "workDir": str(work_dir),
        "terminalStatus": terminal or "unknown",
        "stage": stage,
        "hasReport": report is not None,
        "hasClaimReport": claim is not None,
        "counts": {
            "verified": verified_count,
            "advisory": advisory_count,
            "acceptedCandidates": int((synth or {}).get("acceptedCandidates") or (synth or {}).get("accepted") or 0),
            "objdiffVerified": int((claim or {}).get("counts", {}).get("objdiffVerified") or 0),
        },
        "autonomyBudget": budget,
        "vacuum": vacuum,
        "exportPackage": (
            {
                "status": export_pkg.get("status"),
                "viewCount": export_pkg.get("viewCount"),
                "countsByAuthorityClass": export_pkg.get("countsByAuthorityClass"),
                "exportDir": export_pkg.get("exportDir") or str(work_dir / "export"),
                "claimBoundary": export_pkg.get("claimBoundary")
                or (
                    "export package aggregates recovery views with authority classes; "
                    "only objdiff-verified-semantic is accepted source"
                ),
            }
            if export_pkg is not None
            else None
        ),
        "proofLadder": (
            {
                "status": ladder.get("status"),
                "denominator": ladder.get("denominator"),
                "numerator": ladder.get("numerator"),
                "coverage": ladder.get("coverage"),
                "coveragePercent": ladder.get("coveragePercent"),
                "rung": ladder.get("rung"),
                "nextRung": ladder.get("nextRung"),
                "claimBoundary": ladder.get("claimBoundary")
                or (
                    "proof ladder coverage is receipt-backed objdiff accepts only; "
                    "not a ≥90% whole-binary recovery claim"
                ),
            }
            if ladder is not None
            else None
        ),
        "contextFusion": (
            {
                "placed": (placement or {}).get("counts", {}).get("placed") if placement else None,
                "unplaced": (placement or {}).get("counts", {}).get("unplaced") if placement else None,
                "conflicts": (placement or {}).get("counts", {}).get("conflicts") if placement else None,
                "skipped": (placement or {}).get("counts", {}).get("skipped") if placement else None,
                "seeds": (seeds or {}).get("counts", {}).get("seeded") if seeds else None,
                "claimBoundary": (placement or {}).get("claimBoundary")
                or (
                    "context fusion is address-keyed advisory evidence only; "
                    "unplaced pieces are not inventively assigned VAs"
                ),
            }
            if placement is not None or seeds is not None
            else None
        ),
        "criticalPath": (
            {
                "readiness": critical.get("readiness"),
                "peCriticalPathStopAfter": critical.get("peCriticalPathStopAfter"),
                "nextActions": critical.get("nextActions"),
                "claimBoundary": critical.get("claimBoundary")
                or (
                    "critical path readiness is orchestration metadata only; "
                    "proof ladder objdiff accepts remain the semantic KPI"
                ),
            }
            if critical is not None
            else None
        ),
        "sliceVerify": (
            {
                "status": slice_verify.get("status"),
                "verificationTier": slice_verify.get("verificationTier"),
                "format": slice_verify.get("format"),
                "candidate": slice_verify.get("candidate"),
                "claimBoundary": slice_verify.get("claimBoundary")
                or (
                    "slice verify is weaker byte-roundtrip evidence only; "
                    "does not count toward proof ladder objdiff numerator"
                ),
            }
            if slice_verify is not None
            else None
        ),
        "claimBoundary": (
            "status summarizes orchestration progress only; "
            "objdiff-verified-semantic proof remains required for accepted source"
        ),
        "paths": {
            "report": str(work_dir / "report.json") if report is not None else None,
            "claimReport": str(work_dir / "claim-report.json") if claim is not None else None,
            "autonomyBudget": str(work_dir / "autonomy-budget.json") if budget is not None else None,
            "vacuumQueue": str(work_dir / "state" / "queue.json") if queue is not None else None,
            "proofLadder": str(work_dir / "proof-ladder.json")
            if (work_dir / "proof-ladder.json").is_file()
            else None,
            "criticalPath": str(work_dir / "critical-path.json")
            if (work_dir / "critical-path.json").is_file()
            else None,
            "sliceVerify": str(work_dir / "slice-verify" / "summary.json")
            if (work_dir / "slice-verify" / "summary.json").is_file()
            else None,
            "placement": str(work_dir / "acquisition" / "placement.json")
            if (work_dir / "acquisition" / "placement.json").is_file()
            else None,
            "contextSeeds": str(work_dir / "advisory" / "context-seeds" / "manifest.json")
            if (work_dir / "advisory" / "context-seeds" / "manifest.json").is_file()
            else None,
            "exportManifest": str(work_dir / "export" / "manifest.json")
            if (work_dir / "export" / "manifest.json").is_file()
            else None,
            "verified": str(verified) if verified.is_dir() else None,
            "advisory": str(advisory) if advisory.is_dir() else None,
        },
    }
