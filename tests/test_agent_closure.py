"""Unit tests for agent closure orchestration."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.agent_closure import run_agent_closure_stages
from agentdecompile_recovery.autonomy_budget import AutonomyBudget

pytestmark = pytest.mark.unit


def test_agent_closure_stages_order(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    budget = AutonomyBudget(max_functions=2)
    calls: list[str] = []

    def fake_context_apply(work_dir, **kwargs):
        calls.append("context")
        return {"status": "skipped:no-ready"}

    def fake_symbol(work_dir, **kwargs):
        calls.append("symbol")
        return {"status": "skipped:no-binary"}

    receipt = run_agent_closure_stages(
        work,
        budget,
        run_context_apply_fn=fake_context_apply,
        run_symbol_provenance_fn=fake_symbol,
    )
    assert calls == ["context", "symbol"]
    assert receipt["status"] == "complete"
    assert (work / "state" / "agent-closure-run.json").is_file()
