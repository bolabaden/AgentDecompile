"""Unit tests for Phase 3 autonomy budget controls."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentdecompile_recovery.autonomy_budget import (
    AutonomyBudget,
    budget_from_args,
    write_autonomy_budget_receipt,
)
from agentdecompile_recovery.autonomous_policy import choose_next_action
from agentdecompile_recovery.frontdoor import build_parser, build_reconstruct_namespace

pytestmark = pytest.mark.unit


class _Step:
    def __init__(self, *, status: str = "success", error: str = "", data: dict | None = None) -> None:
        self.status = status
        self.error = error
        self.data = data or {}


def test_budget_defaults_and_vacuum_args(tmp_path: Path) -> None:
    budget = budget_from_args()
    assert budget.max_functions == 1
    assert budget.max_attempts_per_function == 3
    assert budget.max_wall_seconds is None
    args = budget.vacuum_bridge_args(queue=tmp_path / "queue.json")
    assert args is not None
    assert args[args.index("--max-functions") + 1] == "1"
    assert args[args.index("--max-attempts") + 1] == "3"
    assert "--max-wall-seconds" not in args
    timed = AutonomyBudget(max_functions=2, max_wall_seconds=90).vacuum_bridge_args(queue=tmp_path / "q.json")
    assert timed is not None
    assert timed[timed.index("--timeout") + 1] == "90s"
    assert AutonomyBudget(max_functions=0).vacuum_bridge_args(queue=tmp_path / "q.json") is None


def test_ensure_vacuum_queue_creates_empty_schema(tmp_path: Path) -> None:
    from agentdecompile_recovery.autonomy_budget import ensure_vacuum_queue

    queue = ensure_vacuum_queue(tmp_path / "state" / "queue.json")
    payload = json.loads(queue.read_text(encoding="utf-8"))
    assert payload["schema"] == "agentdecompile.vacuum-queue.v1"
    assert payload["pending"] == []
    assert payload["matched"] == []
    # Idempotent: do not clobber an existing queue.
    payload["pending"] = ["fn"]
    queue.write_text(json.dumps(payload), encoding="utf-8")
    ensure_vacuum_queue(queue)
    assert json.loads(queue.read_text(encoding="utf-8"))["pending"] == ["fn"]


def test_write_autonomy_budget_receipt(tmp_path: Path) -> None:
    path = write_autonomy_budget_receipt(
        tmp_path,
        AutonomyBudget(max_functions=2, max_attempts_per_function=4, max_wall_seconds=60),
        requested=True,
        status="skipped:budget-exhausted",
        reason="max-functions is 0",
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["schema"] == "agentdecompile.autonomy-budget.v1"
    assert payload["max_functions"] == 2
    assert payload["status"] == "skipped:budget-exhausted"
    assert "objdiff" in payload["claimBoundary"]


def test_policy_stops_when_attempt_budget_exhausted() -> None:
    attempts = [
        {
            "source-candidate-generator": _Step(),
            "source-candidate-objdiff": _Step(data={"differenceCount": 12}),
        }
        for _ in range(3)
    ]
    decision = choose_next_action(
        {"compilerProfiles": ["clang"]},
        attempts,
        budget=AutonomyBudget(max_attempts_per_function=3),
    )
    # Non-zero best diff + exhausted budget → typed near-miss reject.
    assert decision["action"] == "reject-near-miss"
    assert decision["attemptsRemaining"] == 0


def test_policy_stops_budget_exhausted_without_diff() -> None:
    attempts = [
        {
            "source-candidate-generator": _Step(),
            "source-candidate-objdiff": _Step(data={}),
        }
        for _ in range(2)
    ]
    decision = choose_next_action(
        {},
        attempts,
        budget=AutonomyBudget(max_attempts_per_function=2),
    )
    assert decision["action"] == "stop-budget-exhausted"


def test_policy_continues_within_budget() -> None:
    decision = choose_next_action(
        {"compilerProfiles": ["clang"]},
        [
            {
                "source-candidate-generator": _Step(),
                "source-candidate-objdiff": _Step(data={"differenceCount": 12}),
            }
        ],
        budget=AutonomyBudget(max_attempts_per_function=3),
    )
    assert decision["action"] == "try-next-generated-candidate"
    assert decision["attemptsRemaining"] == 2


def test_policy_promotes_objdiff_zero_not_near_miss() -> None:
    promote = choose_next_action(
        {},
        [
            {
                "source-candidate-generator": _Step(),
                "source-candidate-objdiff": _Step(data={"differenceCount": 0, "status": "matched"}),
            }
        ],
    )
    assert promote["action"] == "promote-or-export"
    near = choose_next_action(
        {},
        [
            {
                "source-candidate-generator": _Step(),
                "source-candidate-objdiff": _Step(data={"differenceCount": 3, "status": "matched"}),
            }
        ],
    )
    assert near["action"] == "try-nearby-source-shape-or-permuter"
    assert near["action"] != "promote-or-export"


def test_policy_does_not_promote_failed_zero_diff_verifier() -> None:
    decision = choose_next_action(
        {"compilerProfiles": ["clang"]},
        [
            {
                "source-candidate-generator": _Step(),
                "source-candidate-objdiff": _Step(
                    status="failure",
                    error="no exportable match",
                    data={"differenceCount": 0, "status": "matched", "exportableMatchCount": 0},
                ),
            }
        ],
    )
    assert decision["action"] == "try-next-generated-candidate"
    assert decision["action"] != "promote-or-export"


def test_policy_rejects_near_miss_when_budget_exhausted() -> None:
    attempts = [
        {
            "source-candidate-generator": _Step(),
            "source-candidate-objdiff": _Step(data={"differenceCount": 2}),
        }
        for _ in range(2)
    ]
    decision = choose_next_action(
        {},
        attempts,
        budget=AutonomyBudget(max_attempts_per_function=2),
    )
    assert decision["action"] == "reject-near-miss"
    assert decision["attemptsRemaining"] == 0


def test_frontdoor_exposes_autonomy_budget_flags() -> None:
    dests = {action.dest for action in build_parser()._actions}
    assert "autonomous_max_functions" in dests
    assert "autonomous_max_attempts" in dests
    assert "autonomous_max_wall_seconds" in dests
    ns = build_reconstruct_namespace(
        Path("/tmp/bin"),
        autonomous=True,
        autonomous_max_functions=0,
        autonomous_max_attempts=5,
        autonomous_max_wall_seconds=120,
    )
    assert ns.autonomous is True
    assert ns.autonomous_max_functions == 0
    assert ns.autonomous_max_attempts == 5
    assert ns.autonomous_max_wall_seconds == 120
