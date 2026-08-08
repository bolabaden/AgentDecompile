"""Tests for permuter_background.py's background decomp-permuter capability."""

from __future__ import annotations

import threading

import pytest

from agentdecompile_recovery.background_task_coordinator import BackgroundSpawnContext
from agentdecompile_recovery.permuter_background import PermuterBackgroundCapability

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
