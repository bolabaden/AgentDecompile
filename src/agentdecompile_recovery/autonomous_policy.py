"""Evidence-driven retry policy for source recovery plugin loops."""

from __future__ import annotations

from typing import Any

from .artifact_layout import is_objdiff_zero_accept
from .autonomy_budget import AutonomyBudget, remaining_attempts, remaining_llm_calls
from .proof_tier_router import enrich_policy_with_proof_tier
from .mismatch_classify import (
    CLASS_BOUNDARY_SUSPECT,
    CLASS_INSERT_DELETE,
    CLASS_OPCODE,
    CLASS_OPERAND,
    routed_playbook_for_class,
)

NEAR_MISS_MAX_DIFF = 8


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

    # A fatal LLM error (auth/config, not a per-call transient) means the
    # environment is broken -- stop the campaign rather than burning the
    # remaining attempt/LLM budget retrying a call that cannot succeed.
    if previous_attempts:
        latest_verifier = previous_attempts[-1].get("source-candidate-objdiff")
        latest_verifier_data = (latest_verifier.data if latest_verifier else {}) or {}
        if latest_verifier_data.get("llmRewriteStatus") == "llm-fatal":
            decision = {
                "schema": "agentdecompile.autonomous-policy-decision.v1",
                "action": "llm-unavailable",
                "reason": "LLM rewrite call failed with a fatal/config error (auth, bad request, or permission denied); not retrying",
                "attemptsSeen": attempts_seen,
                "boundaryQuality": None,
                "claimBoundary": "policy selects the next recovery action; it does not promote source without the verifier gate",
            }
            return enrich_policy_with_proof_tier(decision, verifier_error="", generator_error="")

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
        decision = {
            "schema": "agentdecompile.autonomous-policy-decision.v1",
            "action": action,
            "reason": reason,
            "attemptsSeen": attempts_seen,
            "attemptsRemaining": 0,
            "bestDifferenceCount": best_diff,
            "boundaryQuality": None,
            "claimBoundary": "policy selects the next recovery action; it does not promote source without the verifier gate",
        }
        verifier_error = (getattr(verifier, "error", None) or "") if verifier else ""
        generator = latest.get("source-candidate-generator")
        generator_error = (getattr(generator, "error", None) or "") if generator else ""
        return enrich_policy_with_proof_tier(
            decision,
            verifier_error=str(verifier_error),
            generator_error=str(generator_error),
        )

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
    mismatch_class, mismatch_histogram = _mismatch_evidence(latest, verifier_data)

    # A classified mismatch (operand/opcode/insert-delete) is direct evidence the
    # candidate compiled to something comparable to the target slice, which
    # outranks the boundary-suspect heuristic -- same precedence as
    # mismatch_classify.classify_mismatch(). Only gate on boundary-suspect when
    # there's no such evidence to route from instead.
    has_mismatch_evidence = mismatch_class in {CLASS_OPERAND, CLASS_OPCODE, CLASS_INSERT_DELETE}

    if generator and generator.status == "failure" and "no source candidate" in generator_error:
        action = "reacquire-or-expand-source-facts"
        reason = "candidate generator exhausted compatible source shapes"
    elif not has_mismatch_evidence and (
        boundary_quality.get("status") == "suspect" or mismatch_class == CLASS_BOUNDARY_SUSPECT
    ):
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
    elif best_diff is not None and best_diff <= NEAR_MISS_MAX_DIFF:
        shape_search_exhausted = bool(context.get("sourceShapeSearch"))
        llm_calls_seen = _llm_calls_seen(previous_attempts)
        llm_remaining = remaining_llm_calls(calls_seen=llm_calls_seen, budget=resolved) if resolved else 0
        if has_mismatch_evidence and shape_search_exhausted and llm_remaining > 0:
            action = "try-llm-rewrite"
            reason = (
                f"mechanisms 1+2 (compiler-flag exploration, idiom permutation) exhausted with "
                f"{best_diff} difference(s) remaining; requesting LLM rewrite "
                f"({llm_remaining} call(s) remaining)"
            )
        else:
            action = "try-nearby-source-shape-or-permuter"
            if mismatch_class == CLASS_OPERAND:
                reason = f"operand near-miss with {best_diff} difference(s); permuter-first playbook"
            elif mismatch_class == CLASS_OPCODE:
                reason = f"opcode near-miss with {best_diff} difference(s); shape-search playbook"
            elif mismatch_class == CLASS_INSERT_DELETE:
                reason = f"insert/delete near-miss with {best_diff} difference(s); branch-shape playbook"
            else:
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
        "mismatchClass": mismatch_class,
        "mismatchHistogram": mismatch_histogram or None,
        "routedPlaybook": routed_playbook_for_class(mismatch_class) if action == "try-nearby-source-shape-or-permuter" else None,
        "claimBoundary": "policy selects the next recovery action; it does not promote source without the verifier gate",
    }
    if remaining is not None:
        decision["attemptsRemaining"] = remaining
    return enrich_policy_with_proof_tier(
        decision,
        verifier_error=verifier_error,
        generator_error=generator_error,
    )


def _llm_calls_seen(previous_attempts: list[dict[str, Any]]) -> int:
    count = 0
    for attempt in previous_attempts:
        verifier = attempt.get("source-candidate-objdiff")
        verifier_data = (verifier.data if verifier else {}) or {}
        if verifier_data.get("llmRewriteStatus") is not None:
            count += 1
    return count


def _mismatch_evidence(latest: dict[str, Any], verifier_data: dict[str, Any]) -> tuple[str | None, dict[str, int] | None]:
    for source in (latest, verifier_data):
        if not isinstance(source, dict):
            continue
        mismatch_class = source.get("mismatchClass")
        histogram = source.get("mismatchHistogram")
        if mismatch_class:
            return str(mismatch_class), histogram if isinstance(histogram, dict) else None
    return None, None


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
        max_campaigns=int(budget.get("max_campaigns") or budget.get("maxCampaigns") or 1),
        stop_on_accept=bool(budget.get("stop_on_accept") or budget.get("stopOnAccept")),
        max_llm_calls_per_function=int(
            budget.get("max_llm_calls_per_function") or budget.get("maxLlmCallsPerFunction") or 0
        ),
    )


def optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
