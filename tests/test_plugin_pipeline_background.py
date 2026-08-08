"""Integration tests for PluginPipeline's background-permuter abort path."""

from __future__ import annotations

import threading
import time
from typing import Any

import pytest

from agentdecompile_recovery.plugin_pipeline import PluginPipeline, PluginResult

pytestmark = pytest.mark.unit


class _AlwaysFailPlugin:
    id = "source-candidate-objdiff"
    name = "Stub Objdiff"
    description = "test stub"

    def __init__(self, difference_count: int = 3) -> None:
        self.calls = 0
        self.difference_count = difference_count

    def execute(self, context: dict[str, Any]) -> tuple[PluginResult, dict[str, Any]]:
        self.calls += 1
        return (
            PluginResult(
                self.id,
                self.name,
                "failure",
                1,
                error="no match yet",
                data={"differenceCount": self.difference_count},
            ),
            context,
        )

    def prepare_retry(self, context, _previous_attempts):
        return context


class _ImmediateSuccessBackground:
    """A background capability that reports success on its first spawn."""

    def __init__(self) -> None:
        self.spawn_count = 0
        self.run_count = 0

    def should_spawn(self, ctx):
        if self.spawn_count >= 1:
            return None
        self.spawn_count += 1
        return {}

    def run(self, config, abort_event: threading.Event):
        self.run_count += 1
        return {"matched": True, "differences": 0}

    def is_success(self, result) -> bool:
        return bool(result.get("matched")) and result.get("differences") == 0

    def to_background_task_result(self, result, *, task_id, duration_ms, triggered_by_attempt, start_timestamp):
        from agentdecompile_recovery.background_task_coordinator import BackgroundTaskResult

        return BackgroundTaskResult(
            task_id=task_id,
            plugin_id="stub-permuter",
            success=self.is_success(result),
            duration_ms=duration_ms,
            triggered_by_attempt=triggered_by_attempt,
            start_timestamp=start_timestamp,
            data=result,
        )

    def reset(self) -> None:
        self.spawn_count = 0


class _BackgroundPlugin:
    id = "stub-permuter"

    def __init__(self, background) -> None:
        self.background = background


def _wait_until(predicate, timeout=2.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("condition not met before timeout")


def test_pipeline_stops_early_when_background_permuter_succeeds() -> None:
    events: list[dict[str, Any]] = []
    stub = _AlwaysFailPlugin()
    background = _ImmediateSuccessBackground()
    pipeline = PluginPipeline(
        max_retries=10,
        event_handler=events.append,
        background_plugins=[_BackgroundPlugin(background)],
    )
    pipeline.register(stub)

    result = pipeline.run_pipeline(
        prompt_path="fn",
        prompt_content="",
        function_name="fn",
        target_object_path="",
        asm="",
        config={},
    )

    assert result.success is True
    assert result.match_source == "background-permuter"
    # Stops well short of max_retries once the background task reports success.
    assert stub.calls < 10
    assert any(event.get("type") == "background-match-found" for event in events)


class _DelayedSuccessOnLastAttemptBackground:
    """Succeeds, but only finishes mid-way through cancel_all()'s blocking wait.

    Regresses the race where a background task spawned on the final foreground
    attempt (no further loop iteration to observe it) reports success only
    during the cancel_all() teardown -- after the loop's single mid-attempt
    check already saw the abort event unset.
    """

    def __init__(self, delay: float) -> None:
        self.delay = delay
        self.spawn_count = 0

    def should_spawn(self, ctx):
        if self.spawn_count >= 1:
            return None
        self.spawn_count += 1
        return {}

    def run(self, config, abort_event: threading.Event):
        abort_event.wait(self.delay)
        return {"matched": True, "differences": 0}

    def is_success(self, result) -> bool:
        return bool(result.get("matched")) and result.get("differences") == 0

    def to_background_task_result(self, result, *, task_id, duration_ms, triggered_by_attempt, start_timestamp):
        from agentdecompile_recovery.background_task_coordinator import BackgroundTaskResult

        return BackgroundTaskResult(
            task_id=task_id,
            plugin_id="stub-permuter",
            success=self.is_success(result),
            duration_ms=duration_ms,
            triggered_by_attempt=triggered_by_attempt,
            start_timestamp=start_timestamp,
            data=result,
        )

    def reset(self) -> None:
        self.spawn_count = 0


def test_pipeline_picks_up_background_success_that_lands_during_cancel_all() -> None:
    stub = _AlwaysFailPlugin()
    background = _DelayedSuccessOnLastAttemptBackground(delay=0.1)
    pipeline = PluginPipeline(
        max_retries=1,  # single attempt: will_retry is False, so on_attempt_complete's
        # spawn is the only chance this background task gets, and there's no further
        # loop iteration to re-poll foreground_abort_event before cancel_all() runs.
        background_plugins=[_BackgroundPlugin(background)],
    )
    pipeline.register(stub)

    result = pipeline.run_pipeline(
        prompt_path="fn",
        prompt_content="",
        function_name="fn",
        target_object_path="",
        asm="",
        config={},
    )

    assert result.success is True
    assert result.match_source == "background-permuter"


def test_pipeline_without_background_plugins_runs_unaffected() -> None:
    stub = _AlwaysFailPlugin()
    pipeline = PluginPipeline(max_retries=2)
    pipeline.register(stub)

    result = pipeline.run_pipeline(
        prompt_path="fn",
        prompt_content="",
        function_name="fn",
        target_object_path="",
        asm="",
        config={},
    )

    assert result.success is False
    assert result.match_source is None
    assert stub.calls == 2
