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
    proof_target_queue = _load_json(work_dir / "facts" / "proof-target-queue.json")
    proof_campaign = _load_json(work_dir / "state" / "proof-campaign.json")
    proof_campaign_loop = _load_json(work_dir / "state" / "proof-campaign-loop.json")
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
    propose = _load_json(work_dir / "acquisition" / "propose-labels.json")
    context_apply_run = _load_json(work_dir / "state" / "context-apply-run.json")
    near_miss_repair_run = _load_json(work_dir / "state" / "near-miss-repair-run.json")
    agent_closure_run = _load_json(work_dir / "state" / "agent-closure-run.json")
    symbol_provenance = _load_json(work_dir / "facts" / "symbol-provenance.json")
    campaign_checkpoints = _load_json(work_dir / "facts" / "campaign-checkpoints.json")
    pattern_memory = _load_json(work_dir / "facts" / "pattern-memory.json")
    if propose is None and isinstance((acquire or {}).get("proposeLabels"), dict):
        propose = acquire.get("proposeLabels")  # type: ignore[assignment]
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
                "functionsToNextRung": ladder.get("functionsToNextRung"),
                "nextRungTargetNumerator": ladder.get("nextRungTargetNumerator"),
                "claimBoundary": ladder.get("claimBoundary")
                or (
                    "proof ladder coverage is receipt-backed objdiff accepts only; "
                    "not a ≥90% whole-binary recovery claim"
                ),
            }
            if ladder is not None
            else None
        ),
        "proofTargetQueue": (
            {
                "status": proof_target_queue.get("status"),
                "queueCount": proof_target_queue.get("queueCount"),
                "synthesisEligibleCount": proof_target_queue.get("synthesisEligibleCount"),
                "functionsToNextRung": proof_target_queue.get("functionsToNextRung"),
                "nearMissRetryCount": proof_target_queue.get("nearMissRetryCount"),
                "topEntries": (proof_target_queue.get("entries") or [])[:3],
                "claimBoundary": proof_target_queue.get("claimBoundary")
                or "proof-target queue is advisory; does not count toward numerator",
            }
            if proof_target_queue is not None
            else None
        ),
        "proofCampaign": (
            {
                "status": proof_campaign.get("status"),
                "attempted": proof_campaign.get("attempted"),
                "accepts": proof_campaign.get("accepts"),
                "nearMisses": proof_campaign.get("nearMisses"),
                "bestDifference": proof_campaign.get("bestDifference"),
                "rungBefore": proof_campaign.get("rungBefore"),
                "rungAfter": proof_campaign.get("rungAfter"),
                "claimBoundary": proof_campaign.get("claimBoundary"),
            }
            if proof_campaign is not None
            else None
        ),
        "proofCampaignLoop": (
            {
                "status": proof_campaign_loop.get("status"),
                "campaignCount": proof_campaign_loop.get("campaignCount"),
                "maxCampaigns": proof_campaign_loop.get("maxCampaigns"),
                "stopOnAccept": proof_campaign_loop.get("stopOnAccept"),
                "totalAttempted": proof_campaign_loop.get("totalAttempted"),
                "totalAccepts": proof_campaign_loop.get("totalAccepts"),
                "numeratorDelta": proof_campaign_loop.get("numeratorDelta"),
                "bestDifference": proof_campaign_loop.get("bestDifference"),
                "claimBoundary": proof_campaign_loop.get("claimBoundary"),
            }
            if proof_campaign_loop is not None
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
        "proposeLabels": (
            {
                "status": propose.get("status"),
                "proposed": (propose.get("counts") or {}).get("proposed"),
                "ready": (propose.get("counts") or {}).get("ready"),
                "conflicts": (propose.get("counts") or {}).get("conflicts"),
                "claimBoundary": propose.get("claimBoundary")
                or (
                    "proposed labels are context hints only; apply via MCP conflict protocol"
                ),
                "nextStep": propose.get("nextStep"),
            }
            if propose is not None
            else None
        ),
        "contextApplyRun": (
            {
                "status": context_apply_run.get("status"),
                "applied": context_apply_run.get("applied"),
                "mcpStatus": context_apply_run.get("mcpStatus"),
                "claimBoundary": context_apply_run.get("claimBoundary"),
            }
            if context_apply_run is not None
            else None
        ),
        "nearMissRepairRun": (
            {
                "status": near_miss_repair_run.get("status"),
                "matchedCount": near_miss_repair_run.get("matchedCount"),
                "claimBoundary": near_miss_repair_run.get("claimBoundary"),
            }
            if near_miss_repair_run is not None
            else None
        ),
        "agentClosureRun": (
            {
                "status": agent_closure_run.get("status"),
                "claimBoundary": agent_closure_run.get("claimBoundary"),
            }
            if agent_closure_run is not None
            else None
        ),
        "symbolProvenance": (
            {
                "status": symbol_provenance.get("status"),
                "symbolCount": symbol_provenance.get("symbolCount"),
                "source": symbol_provenance.get("source"),
                "claimBoundary": symbol_provenance.get("claimBoundary"),
            }
            if symbol_provenance is not None
            else None
        ),
        "campaignCheckpoints": (
            {
                "entryCount": len(campaign_checkpoints.get("entries") or {}),
                "writtenAt": campaign_checkpoints.get("writtenAt"),
                "claimBoundary": campaign_checkpoints.get("claimBoundary"),
            }
            if campaign_checkpoints is not None
            else None
        ),
        "patternMemory": (
            {
                "patternCount": len(pattern_memory.get("patterns") or []),
                "writtenAt": pattern_memory.get("writtenAt"),
                "claimBoundary": pattern_memory.get("claimBoundary"),
            }
            if pattern_memory is not None
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
            "proofTargetQueue": str(work_dir / "facts" / "proof-target-queue.json")
            if (work_dir / "facts" / "proof-target-queue.json").is_file()
            else None,
            "proofCampaign": str(work_dir / "state" / "proof-campaign.json")
            if (work_dir / "state" / "proof-campaign.json").is_file()
            else None,
            "proofCampaignLoop": str(work_dir / "state" / "proof-campaign-loop.json")
            if (work_dir / "state" / "proof-campaign-loop.json").is_file()
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
            "proposeLabels": str(work_dir / "acquisition" / "propose-labels.json")
            if (work_dir / "acquisition" / "propose-labels.json").is_file()
            else None,
            "contextApplyRun": str(work_dir / "state" / "context-apply-run.json")
            if (work_dir / "state" / "context-apply-run.json").is_file()
            else None,
            "nearMissRepairRun": str(work_dir / "state" / "near-miss-repair-run.json")
            if (work_dir / "state" / "near-miss-repair-run.json").is_file()
            else None,
            "agentClosureRun": str(work_dir / "state" / "agent-closure-run.json")
            if (work_dir / "state" / "agent-closure-run.json").is_file()
            else None,
            "symbolProvenance": str(work_dir / "facts" / "symbol-provenance.json")
            if (work_dir / "facts" / "symbol-provenance.json").is_file()
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
