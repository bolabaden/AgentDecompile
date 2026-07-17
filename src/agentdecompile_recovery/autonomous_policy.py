"""Evidence-driven retry policy for source recovery plugin loops."""

from __future__ import annotations

from typing import Any

from .artifact_layout import is_objdiff_zero_accept
from .autonomy_budget import AutonomyBudget, remaining_attempts


def choose_next_action(
    context: dict[str, Any],
    previous_attempts: list[dict[str, Any]],
    *,
    budget: AutonomyBudget | dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Classify the next autonomous action from the latest attempt evidence."""

    resolved = _coerce_budget(budget)
    attempts_seen = len(previous_attempts)
    remaining = remaining_attempts(attempts_seen=attempts_seen, budget=resolved) if resolved else None

    # Budget exhaustion is a typed stop before spending another repair cycle.
    if resolved is not None and remaining == 0 and attempts_seen > 0:
        latest = previous_attempts[-1]
        verifier = latest.get("source-candidate-objdiff")
        verifier_data = (verifier.data if verifier else {}) or {}
        best_diff = optional_int(verifier_data.get("differenceCount"))
        if best_diff is None:
            best_diff = optional_int(verifier_data.get("differences"))
        action = "stop-budget-exhausted"
        reason = (
            f"autonomy budget exhausted after {attempts_seen} attempt(s) "
            f"(maxAttemptsPerFunction={resolved.max_attempts_per_function})"
        )
        if best_diff is not None and best_diff > 0:
            action = "reject-near-miss"
            reason = (
                f"near-miss rejected after budget exhaustion "
                f"(bestDifferenceCount={best_diff}; not objdiff-zero)"
            )
        return {
            "schema": "agentdecompile.autonomous-policy-decision.v1",
            "action": action,
            "reason": reason,
            "attemptsSeen": attempts_seen,
            "attemptsRemaining": 0,
            "bestDifferenceCount": best_diff,
            "boundaryQuality": None,
            "claimBoundary": "policy selects the next recovery action; it does not promote source without the verifier gate",
        }

    latest = previous_attempts[-1] if previous_attempts else {}
    generator = latest.get("source-candidate-generator")
    verifier = latest.get("source-candidate-objdiff")
    row = context.get("sourceParityRow") if isinstance(context.get("sourceParityRow"), dict) else {}
    boundary_quality = ((row.get("targetSlice") or {}).get("boundaryQuality") or {}) if isinstance(row, dict) else {}
    verifier_data = (verifier.data if verifier else {}) or {}
    best_diff = optional_int(verifier_data.get("differenceCount"))
    if best_diff is None:
        best_diff = optional_int(verifier_data.get("differences"))
    verifier_error = (verifier.error if verifier else "") or ""
    generator_error = (generator.error if generator else "") or ""

    verifier_ok = getattr(verifier, "status", None) == "success"

    if generator and generator.status == "failure" and "no source candidate" in generator_error:
        action = "reacquire-or-expand-source-facts"
        reason = "candidate generator exhausted compatible source shapes"
    elif boundary_quality.get("status") == "suspect":
        action = "repair-boundary-before-retry"
        reason = "target slice boundary is suspect"
    elif "compile" in verifier_error.lower() or "syntax" in verifier_error.lower():
        action = "regenerate-source-shape"
        reason = "compiler rejected the selected source candidate"
    elif verifier_ok and _is_objdiff_zero_verifier(verifier_data, best_diff):
        action = "promote-or-export"
        reason = "verifier reported objdiff-zero accept"
    elif best_diff == 0 and not verifier_ok:
        # Quality-filtered / non-exportable zero-diff rows must not stop the retry loop.
        action = "try-next-generated-candidate"
        reason = "differenceCount 0 but verifier plugin did not succeed (non-exportable match)"
    elif best_diff is not None and best_diff <= 8:
        action = "try-nearby-source-shape-or-permuter"
        reason = f"candidate is close to match with {best_diff} difference(s); near-miss is not promote"
    elif context.get("compilerProfiles") in (None, [], ()):
        action = "block-on-compiler-profile-evidence"
        reason = "large mismatch without compiler-profile evidence"
    else:
        action = "try-next-generated-candidate"
        reason = "previous candidate did not match"

    decision = {
        "schema": "agentdecompile.autonomous-policy-decision.v1",
        "action": action,
        "reason": reason,
        "attemptsSeen": attempts_seen,
        "bestDifferenceCount": best_diff,
        "boundaryQuality": boundary_quality.get("status"),
        "claimBoundary": "policy selects the next recovery action; it does not promote source without the verifier gate",
    }
    if remaining is not None:
        decision["attemptsRemaining"] = remaining
    return decision


def _is_objdiff_zero_verifier(verifier_data: dict[str, Any], best_diff: int | None) -> bool:
    if best_diff != 0:
        return False
    status = verifier_data.get("status") or verifier_data.get("bestStatus")
    if not status:
        return False
    row = {
        "status": status,
        "differences": 0,
        "proofTier": verifier_data.get("proofTier") or verifier_data.get("verificationTier"),
    }
    if is_objdiff_zero_accept(row):
        return True
    return str(status) in {"matched", "source-parity-accepted", "code-slice-matched"}


def _coerce_budget(budget: AutonomyBudget | dict[str, Any] | None) -> AutonomyBudget | None:
    if budget is None:
        return None
    if isinstance(budget, AutonomyBudget):
        return budget
    return AutonomyBudget(
        max_functions=int(budget.get("max_functions") or budget.get("maxFunctions") or 1),
        max_attempts_per_function=int(
            budget.get("max_attempts_per_function")
            or budget.get("maxAttemptsPerFunction")
            or 3
        ),
        max_wall_seconds=(
            int(budget["max_wall_seconds"])
            if budget.get("max_wall_seconds") is not None
            else (int(budget["maxWallSeconds"]) if budget.get("maxWallSeconds") is not None else None)
        ),
    )


def optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
