"""Tiered proof routing: syntax/compile gates before objdiff."""

from __future__ import annotations

from typing import Any

PROOF_TIER_SYNTAX = "L1-syntax"
PROOF_TIER_COMPILE = "L2-compile"
PROOF_TIER_OBJDIFF = "L3-objdiff"


def route_proof_tier(*, verifier_error: str = "", generator_error: str = "", best_difference: int | None = None) -> dict[str, Any]:
    """Classify which proof gate should run next for a synthesis attempt."""

    ver = (verifier_error or "").lower()
    gen = (generator_error or "").lower()
    if "syntax" in ver or "syntax" in gen or "parse error" in ver:
        return {
            "proofTier": PROOF_TIER_SYNTAX,
            "nextAction": "regenerate-source-shape",
            "reason": "syntax failure before compile",
        }
    if "compile" in (ver + gen) or "undeclared" in (ver + gen) or "error c" in (ver + gen):
        return {
            "proofTier": PROOF_TIER_COMPILE,
            "nextAction": "regenerate-source-shape",
            "reason": "compile failure before objdiff",
        }
    if best_difference is not None:
        return {
            "proofTier": PROOF_TIER_OBJDIFF,
            "nextAction": "try-nearby-source-shape-or-permuter" if best_difference <= 8 else "try-next-generated-candidate",
            "reason": "objdiff evidence available",
        }
    return {
        "proofTier": PROOF_TIER_OBJDIFF,
        "nextAction": "try-next-generated-candidate",
        "reason": "default objdiff lane",
    }


def enrich_policy_with_proof_tier(decision: dict[str, Any], *, verifier_error: str = "", generator_error: str = "") -> dict[str, Any]:
    updated = dict(decision)
    tier = route_proof_tier(
        verifier_error=verifier_error,
        generator_error=generator_error,
        best_difference=updated.get("bestDifferenceCount"),
    )
    updated["proofTier"] = tier["proofTier"]
    if updated.get("action") in {None, "", "try-next-generated-candidate"} and tier["nextAction"]:
        updated.setdefault("tierSuggestedAction", tier["nextAction"])
    updated["tierReason"] = tier["reason"]
    return updated
