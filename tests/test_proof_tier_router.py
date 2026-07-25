"""Unit tests for tiered proof routing."""

from __future__ import annotations

import pytest

from agentdecompile_recovery.proof_tier_router import (
    PROOF_TIER_COMPILE,
    PROOF_TIER_OBJDIFF,
    PROOF_TIER_SYNTAX,
    enrich_policy_with_proof_tier,
    route_proof_tier,
)

pytestmark = pytest.mark.unit


def test_route_syntax_before_compile() -> None:
    tier = route_proof_tier(verifier_error="syntax error near ';'")
    assert tier["proofTier"] == PROOF_TIER_SYNTAX


def test_route_compile_failure() -> None:
    tier = route_proof_tier(generator_error="error C2065: undeclared identifier")
    assert tier["proofTier"] == PROOF_TIER_COMPILE


def test_route_objdiff_near_miss() -> None:
    tier = route_proof_tier(best_difference=3)
    assert tier["proofTier"] == PROOF_TIER_OBJDIFF
    assert "permuter" in tier["nextAction"]


def test_enrich_policy_adds_tier_fields() -> None:
    decision = enrich_policy_with_proof_tier(
        {"action": "try-next-generated-candidate", "bestDifferenceCount": 2},
        verifier_error="",
        generator_error="",
    )
    assert decision["proofTier"] == PROOF_TIER_OBJDIFF
    assert decision["tierReason"]
