"""Dual-agent advisory: generator proposes, checker validates policy alignment."""

from __future__ import annotations

from typing import Any

from .autonomous_policy import choose_next_action
from .proof_tier_router import enrich_policy_with_proof_tier

CLAIM_BOUNDARY = (
    "dual-agent advisory separates proposal from checker judgment; "
    "checker never promotes without objdiff-zero verification"
)


def evaluate_checker_gate(
    *,
    generator_proposal: dict[str, Any],
    previous_attempts: list[dict[str, Any]],
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return checker verdict on a generator-side policy proposal."""

    context = context or {}
    latest = previous_attempts[-1] if previous_attempts else {}
    verifier = latest.get("source-candidate-objdiff")
    generator = latest.get("source-candidate-generator")
    verifier_error = getattr(verifier, "error", "") if verifier else ""
    generator_error = getattr(generator, "error", "") if generator else ""

    baseline = choose_next_action(context, previous_attempts)
    enriched = enrich_policy_with_proof_tier(
        baseline,
        verifier_error=str(verifier_error or ""),
        generator_error=str(generator_error or ""),
    )
    proposed_action = str(generator_proposal.get("action") or generator_proposal.get("proposedAction") or "")
    approved = not proposed_action or proposed_action == enriched.get("action")
    parity = "GREEN" if approved else "YELLOW"
    if enriched.get("action") in {"reject-near-miss", "stop-budget-exhausted"}:
        parity = "RED"
    return {
        "schema": "agentdecompile.dual-agent-checker.v1",
        "parity": parity,
        "approved": approved,
        "generatorProposal": proposed_action or None,
        "checkerAction": enriched.get("action"),
        "proofTier": enriched.get("proofTier"),
        "reason": enriched.get("reason"),
        "claimBoundary": CLAIM_BOUNDARY,
    }
