"""Proof-campaign receipts and bounded multi-campaign autonomy loops."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .autonomy_budget import (
    AutonomyBudget,
    ensure_vacuum_queue,
    reconstruct_vacuum_runner_command,
    write_autonomy_budget_receipt,
)
from .proof_ladder import build_proof_ladder
from .proof_target import write_proof_target_queue
from .state import atomic_write_json, now
from .vacuum_queue import seed_vacuum_queue_from_work_dir

SCHEMA = "agentdecompile.proof-campaign.v1"
LOOP_SCHEMA = "agentdecompile.proof-campaign-loop.v1"
HISTORY_SCHEMA = "agentdecompile.proof-campaign-history.v1"
CLAIM_BOUNDARY = (
    "proof campaign summarizes autonomous proof attempts only; "
    "numerator changes require objdiff-verified-semantic receipts"
)
LOOP_CLAIM_BOUNDARY = (
    "proof campaign loop summarizes bounded autonomous iterations only; "
    "objdiff-verified-semantic accepts under verified/ remain the proof ladder numerator"
)


@dataclass(frozen=True)
class ProofCampaignResult:
    status: str
    reason: str
    seed_receipt: dict[str, Any]
    bridge_returncode: int | None
    attempted: int
    campaign_receipt: dict[str, Any]
    bridge_called: bool


def campaign_path(work_dir: Path) -> Path:
    return work_dir.resolve() / "state" / "proof-campaign.json"


def loop_path(work_dir: Path) -> Path:
    return work_dir.resolve() / "state" / "proof-campaign-loop.json"


def history_path(work_dir: Path) -> Path:
    return work_dir.resolve() / "state" / "proof-campaign-history.jsonl"


def snapshot_ladder(work_dir: Path) -> dict[str, Any]:
    return build_proof_ladder(work_dir)


def infer_near_misses(work_dir: Path) -> tuple[int, int | None]:
    """Return (near_miss_count, best_difference) from synthesis attempts."""

    attempts = work_dir / "source-synthesis" / "attempts.jsonl"
    if not attempts.is_file():
        return 0, None
    near_misses = 0
    best: int | None = None
    for line in attempts.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        status = str(row.get("status") or "")
        try:
            differences = int(row.get("differences", -1))
        except (TypeError, ValueError):
            continue
        if status in {"mismatched", "matched"} and differences > 0:
            near_misses += 1
            best = differences if best is None else min(best, differences)
    return near_misses, best


def write_proof_campaign(
    work_dir: Path,
    *,
    before: dict[str, Any],
    status: str,
    reason: str,
    attempted: int = 0,
    bridge_returncode: int | None = None,
    seed_receipt: dict[str, Any] | None = None,
) -> dict[str, Any]:
    work_dir = work_dir.resolve()
    after = build_proof_ladder(work_dir)
    before_num = int(before.get("numerator") or 0)
    after_num = int(after.get("numerator") or 0)
    numerator_delta = after_num - before_num
    accepts = max(0, numerator_delta)
    near_misses, best_diff = infer_near_misses(work_dir)

    if accepts > 0:
        outcome = "accepted"
    elif near_misses > 0:
        outcome = "near-miss"
    elif status in {"skipped:budget-exhausted", "skipped:empty-queue"}:
        outcome = "budget-stop"
    elif attempted == 0:
        outcome = "empty-queue"
    else:
        outcome = status or "unknown"

    payload = {
        "schema": SCHEMA,
        "status": outcome,
        "writtenAt": now(),
        "workDir": str(work_dir),
        "reason": reason,
        "attempted": attempted,
        "accepts": accepts,
        "nearMisses": near_misses,
        "bestDifference": best_diff,
        "numeratorDelta": numerator_delta,
        "rungBefore": before.get("rung"),
        "rungAfter": after.get("rung"),
        "nextRungBefore": before.get("nextRung"),
        "nextRungAfter": after.get("nextRung"),
        "functionsToNextRungBefore": before.get("functionsToNextRung"),
        "functionsToNextRungAfter": after.get("functionsToNextRung"),
        "bridgeReturncode": bridge_returncode,
        "proofTargetFirst": bool((seed_receipt or {}).get("proofTargetFirst")),
        "seededCount": (seed_receipt or {}).get("seededCount"),
        "claimBoundary": CLAIM_BOUNDARY,
    }
    atomic_write_json(campaign_path(work_dir), payload)
    return payload


def run_single_proof_campaign(
    work_dir: Path,
    budget: AutonomyBudget,
    *,
    run_decomp_cli_bridge: Callable[[list[str]], int],
) -> ProofCampaignResult:
    """Seed proof targets and bridge vacuum for one autonomous campaign iteration."""

    work_dir = work_dir.resolve()
    write_proof_target_queue(work_dir)
    queue = ensure_vacuum_queue(work_dir / "state" / "queue.json")
    prompts_dir = work_dir / "prompts"
    ladder_before = snapshot_ladder(work_dir)
    seed = seed_vacuum_queue_from_work_dir(
        work_dir,
        limit=max(budget.max_functions, 0),
        queue_path=queue,
        prompts_dir=prompts_dir,
        prefer_proof_targets=True,
    )
    bridge_args = budget.vacuum_bridge_args(
        queue=queue,
        prompts_dir=prompts_dir,
        work_dir=work_dir,
        runner_command=reconstruct_vacuum_runner_command(
            work_dir,
            max_attempts=budget.max_attempts_per_function,
        ),
    )
    if bridge_args is None:
        reason = "autonomous-max-functions is 0; vacuum not started"
        write_autonomy_budget_receipt(
            work_dir,
            budget,
            requested=True,
            status="skipped:budget-exhausted",
            reason=reason,
        )
        receipt = write_proof_campaign(
            work_dir,
            before=ladder_before,
            status="skipped:budget-exhausted",
            reason=reason,
            seed_receipt=seed,
        )
        return ProofCampaignResult(
            status="budget-exhausted",
            reason=reason,
            seed_receipt=seed,
            bridge_returncode=None,
            attempted=0,
            campaign_receipt=receipt,
            bridge_called=False,
        )
    if int(seed.get("seededCount") or 0) == 0 and int(seed.get("pendingCount") or 0) == 0:
        reason = "no source-generation tasks available to seed vacuum pending queue"
        write_autonomy_budget_receipt(
            work_dir,
            budget,
            requested=True,
            status="skipped:empty-queue",
            reason=reason,
            bridge_args=None,
        )
        receipt = write_proof_campaign(
            work_dir,
            before=ladder_before,
            status="skipped:empty-queue",
            reason=reason,
            seed_receipt=seed,
        )
        return ProofCampaignResult(
            status="empty-queue",
            reason=reason,
            seed_receipt=seed,
            bridge_returncode=None,
            attempted=0,
            campaign_receipt=receipt,
            bridge_called=False,
        )

    bridge_rc = int(run_decomp_cli_bridge(bridge_args))
    write_autonomy_budget_receipt(
        work_dir,
        budget,
        requested=True,
        status="bridged" if bridge_rc == 0 else "bridge-failed",
        reason=f"vacuum start via decomp-cli bridge; seeded={seed.get('seededCount')}",
        bridge_args=bridge_args,
        bridge_returncode=bridge_rc,
    )
    receipt = write_proof_campaign(
        work_dir,
        before=ladder_before,
        status="bridged" if bridge_rc == 0 else "bridge-failed",
        reason=f"vacuum start via decomp-cli bridge; seeded={seed.get('seededCount')}",
        attempted=int(seed.get("seededCount") or 0),
        bridge_returncode=bridge_rc,
        seed_receipt=seed,
    )
    return ProofCampaignResult(
        status="bridged" if bridge_rc == 0 else "bridge-failed",
        reason=str(receipt.get("reason") or ""),
        seed_receipt=seed,
        bridge_returncode=bridge_rc,
        attempted=int(seed.get("seededCount") or 0),
        campaign_receipt=receipt,
        bridge_called=True,
    )


def append_campaign_history(work_dir: Path, *, iteration: int, result: ProofCampaignResult) -> None:
    path = history_path(work_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    row = {
        "schema": HISTORY_SCHEMA,
        "writtenAt": now(),
        "iteration": iteration,
        "status": result.campaign_receipt.get("status"),
        "attempted": result.attempted,
        "accepts": result.campaign_receipt.get("accepts"),
        "nearMisses": result.campaign_receipt.get("nearMisses"),
        "bestDifference": result.campaign_receipt.get("bestDifference"),
        "bridgeReturncode": result.bridge_returncode,
        "seededCount": result.seed_receipt.get("seededCount"),
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")


def write_proof_campaign_loop(
    work_dir: Path,
    *,
    ladder_before: dict[str, Any],
    budget: AutonomyBudget,
    iterations: list[dict[str, Any]],
    terminal_status: str,
    total_attempted: int,
    total_accepts: int,
    best_difference: int | None,
) -> dict[str, Any]:
    work_dir = work_dir.resolve()
    ladder_after = build_proof_ladder(work_dir)
    before_num = int(ladder_before.get("numerator") or 0)
    after_num = int(ladder_after.get("numerator") or 0)
    payload = {
        "schema": LOOP_SCHEMA,
        "status": terminal_status,
        "writtenAt": now(),
        "workDir": str(work_dir),
        "campaignCount": len(iterations),
        "maxCampaigns": budget.max_campaigns,
        "stopOnAccept": budget.stop_on_accept,
        "totalAttempted": total_attempted,
        "totalAccepts": total_accepts,
        "numeratorDelta": after_num - before_num,
        "bestDifference": best_difference,
        "rungBefore": ladder_before.get("rung"),
        "rungAfter": ladder_after.get("rung"),
        "nextRungBefore": ladder_before.get("nextRung"),
        "nextRungAfter": ladder_after.get("nextRung"),
        "functionsToNextRungBefore": ladder_before.get("functionsToNextRung"),
        "functionsToNextRungAfter": ladder_after.get("functionsToNextRung"),
        "iterations": iterations,
        "claimBoundary": LOOP_CLAIM_BOUNDARY,
    }
    atomic_write_json(loop_path(work_dir), payload)
    return payload


def run_proof_campaign_loop(
    work_dir: Path,
    budget: AutonomyBudget,
    *,
    run_decomp_cli_bridge: Callable[[list[str]], int],
) -> dict[str, Any]:
    """Run one or more proof campaigns until a typed stop or budget exhaustion."""

    from .readability_repair import run_readability_repair

    work_dir = work_dir.resolve()
    ladder_before = snapshot_ladder(work_dir)

    # Port readability repair is advisory and governs Port/CODE export only — it must not
    # block objdiff proof campaigns, which seed from proof-target-queue independently.
    if budget.max_functions > 0:
        run_readability_repair(work_dir, limit=1)

    iterations: list[dict[str, Any]] = []
    total_attempted = 0
    total_accepts = 0
    best_difference: int | None = None
    terminal_status = "budget-stop"
    last_bridge_rc: int | None = None

    for index in range(budget.max_campaigns):
        ladder_now = build_proof_ladder(work_dir)
        if int(ladder_now.get("functionsToNextRung") or 0) <= 0:
            terminal_status = "accepted" if total_accepts > 0 else "complete"
            break

        result = run_single_proof_campaign(work_dir, budget, run_decomp_cli_bridge=run_decomp_cli_bridge)
        append_campaign_history(work_dir, iteration=index + 1, result=result)
        iteration_summary = {
            "iteration": index + 1,
            "status": result.campaign_receipt.get("status"),
            "attempted": result.attempted,
            "accepts": int(result.campaign_receipt.get("accepts") or 0),
            "nearMisses": int(result.campaign_receipt.get("nearMisses") or 0),
            "bridgeReturncode": result.bridge_returncode,
        }
        iterations.append(iteration_summary)
        total_attempted += result.attempted
        accepts = int(result.campaign_receipt.get("accepts") or 0)
        total_accepts += accepts
        if result.campaign_receipt.get("bestDifference") is not None:
            diff = int(result.campaign_receipt["bestDifference"])
            best_difference = diff if best_difference is None else min(best_difference, diff)

        if result.status == "bridge-failed":
            terminal_status = "bridge-failed"
            last_bridge_rc = result.bridge_returncode
            break
        if result.status == "empty-queue":
            terminal_status = "empty-queue"
            break
        if result.status == "budget-exhausted":
            terminal_status = "budget-stop"
            break
        if int(build_proof_ladder(work_dir).get("functionsToNextRung") or 0) <= 0:
            terminal_status = "accepted" if total_accepts > 0 else "complete"
            break
        if budget.stop_on_accept and accepts > 0:
            terminal_status = "accepted"
            break
        campaign_status = str(result.campaign_receipt.get("status") or "")
        campaign_best = result.campaign_receipt.get("bestDifference")
        if (
            campaign_status == "near-miss"
            and campaign_best is not None
            and int(campaign_best) <= 8
            and index + 1 < budget.max_campaigns
        ):
            from .near_miss_repair import run_near_miss_repair

            run_near_miss_repair(work_dir, limit=max(1, budget.max_functions))
        if index + 1 >= budget.max_campaigns:
            if total_accepts > 0:
                terminal_status = "accepted"
            elif best_difference is not None:
                terminal_status = "near-miss"
            else:
                terminal_status = "budget-stop"
            break

    loop_receipt = write_proof_campaign_loop(
        work_dir,
        ladder_before=ladder_before,
        budget=budget,
        iterations=iterations,
        terminal_status=terminal_status,
        total_attempted=total_attempted,
        total_accepts=total_accepts,
        best_difference=best_difference,
    )

    from .campaign_checkpoint import ingest_attempts_jsonl
    from .pattern_memory import ingest_verified_directory

    checkpoint_summary = ingest_attempts_jsonl(work_dir)
    pattern_summary = ingest_verified_directory(work_dir)
    loop_receipt["checkpointIngest"] = checkpoint_summary
    loop_receipt["patternMemoryIngest"] = pattern_summary
    atomic_write_json(work_dir / "state" / "proof-campaign-loop.json", loop_receipt)
    returncode = 0
    if terminal_status == "bridge-failed" and last_bridge_rc not in (None, 0):
        returncode = int(last_bridge_rc)
    return {
        "terminalStatus": terminal_status,
        "returncode": returncode,
        "loopReceipt": loop_receipt,
    }
