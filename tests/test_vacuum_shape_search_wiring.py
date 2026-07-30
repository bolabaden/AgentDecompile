"""The autonomous vacuum loop must be able to reach mechanisms 2 and 3.

`autonomous_policy.choose_next_action` gates `try-rewrite-request` behind
`shape_search_exhausted = bool(context.get("sourceShapeSearch"))`. The vacuum
runner defaulted that to False and exposed no CLI flag for it, and the
reconstruct bridge never emitted one -- so the primary autonomous driver ran
every function with shape search off. Mechanism 2 (idiom permutation) never
engaged and mechanism 3 (rewrite) was permanently unreachable, regardless of
rewrite budget.

Live evidence: every vacuum receipt in the swkotor campaign recorded
`"sourceShapeSearch": false` alongside `"status": "unmatched"`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.autonomy_budget import reconstruct_vacuum_runner_command
from agentdecompile_recovery.vacuum_runner import build_parser

pytestmark = pytest.mark.unit


def test_runner_command_emits_shape_search_flag_when_enabled(tmp_path: Path) -> None:
    cmd = reconstruct_vacuum_runner_command(tmp_path, max_attempts=3, source_shape_search=True)

    assert "--source-shape-search" in cmd


def test_runner_command_omits_shape_search_flag_by_default(tmp_path: Path) -> None:
    """Off by default keeps the flag opt-in for callers that want mechanism 1 only."""

    cmd = reconstruct_vacuum_runner_command(tmp_path, max_attempts=3)

    assert "--source-shape-search" not in cmd


def test_cli_parses_shape_search_flag() -> None:
    args = build_parser().parse_args(
        ["--work-dir", "/tmp/w", "--name", "sub_1000", "--source-shape-search"]
    )

    assert args.source_shape_search is True


def test_cli_defaults_shape_search_off() -> None:
    args = build_parser().parse_args(["--work-dir", "/tmp/w", "--name", "sub_1000"])

    assert args.source_shape_search is False


def test_cli_flag_reaches_run_vacuum_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    """The flag is worthless if main() parses it and then drops it."""

    captured: dict = {}

    def fake_run(**kwargs):
        captured.update(kwargs)
        return {"exitCode": 0}

    monkeypatch.setattr("agentdecompile_recovery.vacuum_runner.run_vacuum_prompt", fake_run)
    from agentdecompile_recovery.vacuum_runner import main

    main(["--work-dir", "/tmp/w", "--name", "sub_1000", "--source-shape-search"])

    assert captured["source_shape_search"] is True


def test_cli_default_reaches_run_vacuum_prompt_as_false(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}

    def fake_run(**kwargs):
        captured.update(kwargs)
        return {"exitCode": 0}

    monkeypatch.setattr("agentdecompile_recovery.vacuum_runner.run_vacuum_prompt", fake_run)
    from agentdecompile_recovery.vacuum_runner import main

    main(["--work-dir", "/tmp/w", "--name", "sub_1000"])

    assert captured["source_shape_search"] is False
