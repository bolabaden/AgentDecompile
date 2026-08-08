"""Tests for permuter_background.py's background decomp-permuter capability."""

from __future__ import annotations

import shutil
import threading
import time
from pathlib import Path

import pytest

from agentdecompile_recovery.background_task_coordinator import BackgroundSpawnContext
from agentdecompile_recovery.permuter_background import (
    PermuterBackgroundCapability,
    _default_permuter_runner,
)

pytestmark = pytest.mark.unit


class _Candidate:
    def __init__(self, source: str) -> None:
        self.source = source


def _plugin_result(difference_count: int):
    class _Result:
        pass

    result = _Result()
    result.data = {"differenceCount": difference_count}
    return result


def _ctx(*, will_retry=True, permuter_dir="/tmp/permuter", code="int f(void) {}", difference_count=5):
    context = {"permuterDir": permuter_dir, "selectedSourceCandidate": _Candidate(code)}
    return BackgroundSpawnContext(
        attempt_number=1,
        will_retry=will_retry,
        context=context,
        attempt_results=[_plugin_result(difference_count)],
    )


def test_should_spawn_none_when_will_not_retry():
    capability = PermuterBackgroundCapability()
    assert capability.should_spawn(_ctx(will_retry=False)) is None


def test_should_spawn_none_without_permuter_dir():
    capability = PermuterBackgroundCapability()
    ctx = _ctx()
    ctx.context.pop("permuterDir")
    assert capability.should_spawn(ctx) is None


def test_should_spawn_config_on_first_improving_attempt():
    capability = PermuterBackgroundCapability(jobs=4)
    config = capability.should_spawn(_ctx(difference_count=5))
    assert config is not None
    assert config["jobs"] == 4
    assert str(config["permuter_dir"]) == "/tmp/permuter"


def test_should_spawn_none_when_same_code_already_spawned():
    capability = PermuterBackgroundCapability()
    first = capability.should_spawn(_ctx(code="same", difference_count=5))
    second = capability.should_spawn(_ctx(code="same", difference_count=5))
    assert first is not None
    assert second is None


def test_should_spawn_none_when_difference_count_regresses():
    capability = PermuterBackgroundCapability()
    assert capability.should_spawn(_ctx(code="a", difference_count=3)) is not None
    assert capability.should_spawn(_ctx(code="b", difference_count=6)) is None


def test_run_delegates_to_injected_runner():
    calls = []

    def runner(config, abort_event: threading.Event):
        calls.append((config, abort_event))
        return {"matched": True, "differences": 0}

    capability = PermuterBackgroundCapability(permuter_runner=runner)
    result = capability.run({"permuter_dir": "/tmp/x"}, threading.Event())

    assert calls
    assert result == {"matched": True, "differences": 0}


def test_default_permuter_runner_returns_aborted_when_event_already_set(monkeypatch: pytest.MonkeyPatch):
    def _must_not_run(**_kwargs):
        raise AssertionError("permuter must not be launched once the abort event is set")

    monkeypatch.setattr(
        "agentdecompile_cli.mcp_utils.decomp_match.build_decomp_match_payload",
        _must_not_run,
    )
    abort_event = threading.Event()
    abort_event.set()

    result = _default_permuter_runner({"permuter_dir": Path("/tmp/permuter")}, abort_event)

    assert result["aborted"] is True
    assert result["matched"] is False


def test_default_permuter_runner_terminates_child_when_aborted_mid_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    if shutil.which("python3") is None:
        pytest.skip("python3 is required to launch the stand-in permuter child process")

    script = tmp_path / "permuter.py"
    script.write_text("import time\n\ntime.sleep(120)\n", encoding="utf-8")
    permuter_dir = tmp_path / "nonmatching"
    permuter_dir.mkdir()
    monkeypatch.setattr(
        "agentdecompile_cli.mcp_utils.decomp_match.shutil.which",
        lambda name: str(script) if name in {"permuter.py", "permuter"} else None,
    )

    abort_event = threading.Event()
    timer = threading.Timer(0.5, abort_event.set)
    timer.start()
    try:
        start = time.monotonic()
        result = _default_permuter_runner(
            {"permuter_dir": permuter_dir, "jobs": None, "timeout_ms": 120_000},
            abort_event,
        )
        elapsed = time.monotonic() - start
    finally:
        timer.cancel()

    assert elapsed < 10.0
    assert result["aborted"] is True
    assert result["matched"] is False
    scan = result["raw"]["scan"]
    assert scan["error"] == "aborted"
    # A non-zero/negative exit code proves the child was signalled and reaped, not orphaned.
    assert scan["exitCode"] not in (0, None)


def test_is_success_requires_matched_and_zero_differences():
    capability = PermuterBackgroundCapability()
    assert capability.is_success({"matched": True, "differences": 0}) is True
    assert capability.is_success({"matched": True, "differences": 1}) is False
    assert capability.is_success({"matched": False, "differences": 0}) is False


def test_reset_clears_spawn_tracking():
    capability = PermuterBackgroundCapability()
    capability.should_spawn(_ctx(code="same", difference_count=5))
    capability.reset()
    assert capability.should_spawn(_ctx(code="same", difference_count=5)) is not None
