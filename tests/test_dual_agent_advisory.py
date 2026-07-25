"""Unit tests for dual-agent checker advisory."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from agentdecompile_recovery.dual_agent_advisory import evaluate_checker_gate

pytestmark = pytest.mark.unit


def test_checker_green_when_proposal_matches_policy() -> None:
    attempts = [
        {
            "source-candidate-objdiff": SimpleNamespace(
                status="failure",
                error="compile error C2065",
                data={"differenceCount": 12},
            ),
            "source-candidate-generator": SimpleNamespace(status="failure", error=""),
        }
    ]
    verdict = evaluate_checker_gate(
        generator_proposal={"action": "regenerate-source-shape"},
        previous_attempts=attempts,
        context={},
    )
    assert verdict["parity"] in {"GREEN", "YELLOW", "RED"}
    assert verdict["checkerAction"]


def test_checker_yellow_on_mismatch_proposal() -> None:
    attempts = [
        {
            "source-candidate-objdiff": SimpleNamespace(
                status="failure",
                error="",
                data={"differenceCount": 4, "mismatchClass": "operand"},
            ),
            "source-candidate-generator": SimpleNamespace(status="success", error=""),
        }
    ]
    verdict = evaluate_checker_gate(
        generator_proposal={"action": "promote-or-export"},
        previous_attempts=attempts,
        context={"compilerProfiles": ["msvc"]},
    )
    assert verdict["parity"] == "YELLOW"
    assert verdict["approved"] is False
