"""Unit tests for bounded multi-campaign proof autonomy loops."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from agentdecompile_recovery.autonomy_budget import AutonomyBudget, budget_from_args
from agentdecompile_recovery.proof_campaign import (
    history_path,
    loop_path,
    run_proof_campaign_loop,
    run_single_proof_campaign,
)
from agentdecompile_recovery.proof_ladder import build_proof_ladder
from agentdecompile_recovery.readability_repair import (
    readability_repair_blocks_vacuum,
    write_readability_repair_queue,
)
from agentdecompile_recovery.recovery_status import build_recovery_status
from agentdecompile_recovery.state import atomic_write_json

pytestmark = pytest.mark.unit


def _write_candidates(work: Path, rows: list[dict]) -> None:
    atomic_write_json(
        work / "function-candidates.json",
        {
            "schema": "agentdecompile.function-candidates.v1",
            "candidates": rows,
            "summary": {"count": len(rows)},
        },
    )


def _write_ladder(work: Path, *, functions_to_next: int = 5, numerator: int = 0, denominator: int = 100) -> None:
    atomic_write_json(
        work / "proof-ladder.json",
        {
            "nextRung": "1%",
            "functionsToNextRung": functions_to_next,
            "numerator": numerator,
            "denominator": denominator,
            "rung": "0%",
        },
    )


def _write_tasks(work: Path, name: str, *, entry: str = "00401000") -> None:
    tasks = work / "source-generation" / "tasks.jsonl"
    tasks.parent.mkdir(parents=True, exist_ok=True)
    source = work / f"{name}.c"
    source.write_text(f"int {name}(void){{return 0;}}\n", encoding="utf-8")
    tasks.write_text(
        json.dumps(
            {
                "name": name,
                "entry": entry,
                "status": "generated-unverified",
                "source": str(source),
            }
        )
        + "\n",
        encoding="utf-8",
    )


def _write_verified(work: Path, name: str, *, entry: str = "00401000") -> None:
    verified = work / "verified"
    verified.mkdir(parents=True, exist_ok=True)
    atomic_write_json(
        verified / f"{name}.json",
        {
            "status": "matched",
            "differences": 0,
            "proofTier": "target-object-objdiff-match",
            "name": name,
            "entry": entry,
        },
    )


def _write_facts_for_readability_block(work: Path) -> None:
    facts_dir = work / "facts"
    facts_dir.mkdir(parents=True, exist_ok=True)
    (facts_dir / "function-facts.jsonl").write_text(
        json.dumps({"name": "FUN_bad", "entry": "00401000", "decompiled": "void x(){}"}) + "\n",
        encoding="utf-8",
    )
    atomic_write_json(
        facts_dir / "module-map.json",
        {"schema": "agentdecompile.module-map.v1", "entries": {"00401000": {"module": "recovered/unmapped"}}},
    )


def test_budget_defaults_max_campaigns() -> None:
    budget = budget_from_args()
    assert budget.max_campaigns == 1
    assert budget.stop_on_accept is False


def test_budget_from_args_campaigns() -> None:
    budget = budget_from_args(max_campaigns=3, stop_on_accept=True)
    assert budget.max_campaigns == 3
    assert budget.stop_on_accept is True


def test_single_campaign_empty_queue_skips_bridge(tmp_path: Path) -> None:
    work = tmp_path / "empty"
    work.mkdir()
    _write_candidates(work, [{"name": "fn", "entry": "00401000"}])
    _write_ladder(work)
    calls: list[list[str]] = []

    def _bridge(args: list[str]) -> int:
        calls.append(args)
        return 0

    result = run_single_proof_campaign(work, AutonomyBudget(), run_decomp_cli_bridge=_bridge)
    assert result.status == "empty-queue"
    assert result.bridge_called is False
    assert calls == []


def test_single_campaign_success_writes_receipt(tmp_path: Path) -> None:
    work = tmp_path / "success"
    work.mkdir()
    _write_candidates(work, [{"name": "fn", "entry": "00401000", "bodyBytes": 32}])
    _write_ladder(work)
    _write_tasks(work, "fn")
    calls: list[list[str]] = []

    def _bridge(args: list[str]) -> int:
        calls.append(args)
        return 0

    result = run_single_proof_campaign(work, AutonomyBudget(), run_decomp_cli_bridge=_bridge)
    assert result.status == "bridged"
    assert result.bridge_called is True
    assert result.attempted == 1
    assert len(calls) == 1
    assert (work / "state" / "proof-campaign.json").is_file()


def test_loop_max_campaigns_one(tmp_path: Path) -> None:
    work = tmp_path / "one"
    work.mkdir()
    _write_candidates(work, [{"name": "fn", "entry": "00401000", "bodyBytes": 32}])
    _write_ladder(work, functions_to_next=5)
    _write_tasks(work, "fn")
    call_count = 0

    def _bridge(_args: list[str]) -> int:
        nonlocal call_count
        call_count += 1
        attempts = work / "source-synthesis" / "attempts.jsonl"
        attempts.parent.mkdir(parents=True, exist_ok=True)
        with attempts.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"status": "mismatched", "differences": 2, "name": "fn"}) + "\n")
        return 0

    with patch(
        "agentdecompile_recovery.proof_campaign.run_single_proof_campaign",
        wraps=run_single_proof_campaign,
    ) as wrapped:
        result = run_proof_campaign_loop(
            work,
            AutonomyBudget(max_campaigns=1),
            run_decomp_cli_bridge=_bridge,
        )
        assert wrapped.call_count == 1
    assert call_count == 1
    assert result["terminalStatus"] == "near-miss"
    assert loop_path(work).is_file()


def test_loop_stop_on_accept(tmp_path: Path) -> None:
    work = tmp_path / "accept"
    work.mkdir()
    _write_candidates(work, [{"name": "fn", "entry": "00401000", "bodyBytes": 32}])
    _write_ladder(work, functions_to_next=5)
    _write_tasks(work, "fn")

    def _bridge(_args: list[str]) -> int:
        _write_verified(work, "fn")
        return 0

    result = run_proof_campaign_loop(
        work,
        AutonomyBudget(max_campaigns=3, stop_on_accept=True),
        run_decomp_cli_bridge=_bridge,
    )
    assert result["terminalStatus"] == "accepted"
    loop_receipt = json.loads(loop_path(work).read_text(encoding="utf-8"))
    assert loop_receipt["campaignCount"] == 1
    assert loop_receipt["totalAccepts"] == 1
    assert history_path(work).is_file()


def test_loop_near_miss_terminal(tmp_path: Path) -> None:
    work = tmp_path / "near"
    work.mkdir()
    _write_candidates(work, [{"name": "fn", "entry": "00401000", "bodyBytes": 32}])
    _write_ladder(work, functions_to_next=5)
    _write_tasks(work, "fn")

    def _bridge(_args: list[str]) -> int:
        attempts = work / "source-synthesis" / "attempts.jsonl"
        attempts.parent.mkdir(parents=True, exist_ok=True)
        with attempts.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"status": "mismatched", "differences": 4, "name": "fn"}) + "\n")
        return 0

    result = run_proof_campaign_loop(
        work,
        AutonomyBudget(max_campaigns=3),
        run_decomp_cli_bridge=_bridge,
    )
    assert result["terminalStatus"] == "near-miss"
    loop_receipt = json.loads(loop_path(work).read_text(encoding="utf-8"))
    assert loop_receipt["campaignCount"] == 3
    assert loop_receipt["totalAccepts"] == 0
    assert loop_receipt["bestDifference"] == 4


def test_loop_proceeds_despite_readability_repair_queue(tmp_path: Path) -> None:
    work = tmp_path / "readability"
    work.mkdir()
    _write_candidates(work, [{"name": "fn", "entry": "00401000", "bodyBytes": 32}])
    _write_ladder(work, functions_to_next=5)
    _write_tasks(work, "fn")
    _write_facts_for_readability_block(work)
    write_readability_repair_queue(work)
    assert readability_repair_blocks_vacuum(work) is True

    bridge_calls: list[list[str]] = []

    def _bridge(args: list[str]) -> int:
        bridge_calls.append(args)
        attempts = work / "source-synthesis" / "attempts.jsonl"
        attempts.parent.mkdir(parents=True, exist_ok=True)
        with attempts.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"status": "mismatched", "differences": 2, "name": "fn"}) + "\n")
        return 0

    result = run_proof_campaign_loop(
        work,
        AutonomyBudget(max_campaigns=1),
        run_decomp_cli_bridge=_bridge,
    )
    assert result["terminalStatus"] == "near-miss"
    assert len(bridge_calls) == 1
    assert (work / "state" / "readability-repair-run.json").is_file()
    loop_receipt = json.loads(loop_path(work).read_text(encoding="utf-8"))
    assert loop_receipt["campaignCount"] == 1


def test_loop_near_miss_does_not_increment_numerator(tmp_path: Path) -> None:
    work = tmp_path / "honesty"
    work.mkdir()
    _write_candidates(work, [{"name": "fn", "entry": "00401000", "bodyBytes": 32}])
    _write_ladder(work, functions_to_next=5)
    _write_tasks(work, "fn")
    before = build_proof_ladder(work)

    def _bridge(_args: list[str]) -> int:
        attempts = work / "source-synthesis" / "attempts.jsonl"
        attempts.parent.mkdir(parents=True, exist_ok=True)
        with attempts.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"status": "mismatched", "differences": 1, "name": "fn"}) + "\n")
        return 0

    run_proof_campaign_loop(work, AutonomyBudget(max_campaigns=2), run_decomp_cli_bridge=_bridge)
    after = build_proof_ladder(work)
    assert after["numerator"] == before["numerator"] == 0


def test_recovery_status_includes_proof_campaign_loop(tmp_path: Path) -> None:
    work = tmp_path / "status"
    work.mkdir()
    atomic_write_json(
        loop_path(work),
        {
            "schema": "agentdecompile.proof-campaign-loop.v1",
            "status": "near-miss",
            "campaignCount": 2,
            "maxCampaigns": 2,
            "stopOnAccept": False,
            "totalAttempted": 2,
            "totalAccepts": 0,
            "numeratorDelta": 0,
            "bestDifference": 3,
            "claimBoundary": "loop-advisory",
        },
    )
    status = build_recovery_status(work)
    loop = status.get("proofCampaignLoop")
    assert loop is not None
    assert loop["status"] == "near-miss"
    assert loop["campaignCount"] == 2
    assert status["paths"]["proofCampaignLoop"] == str(loop_path(work))
