"""Tests for background_task_coordinator.py.

Ports the concurrency contract of the upstream background-task-coordinator:
background plugins (e.g. decomp-permuter) run alongside the AI-powered phase,
and a success there fires a foreground abort signal so the synchronous
plugins (e.g. the Claude runner) can stop early.
"""

from __future__ import annotations

import threading
import time

import pytest

from agentdecompile_recovery.background_task_coordinator import (
    BackgroundSpawnContext,
    BackgroundTaskCoordinator,
    BackgroundTaskResult,
)

pytestmark = pytest.mark.unit


class _StubBackground:
    def __init__(
        self,
        *,
        spawn_config=None,
        run_result="ok",
        is_success=False,
        run_delay=0.0,
        raise_error=None,
        respect_abort=True,
    ):
        self.spawn_config = spawn_config
        self.run_result = run_result
        self.success_flag = is_success
        self.run_delay = run_delay
        self.raise_error = raise_error
        self.respect_abort = respect_abort
        self.reset_calls = 0
        self.run_calls: list[tuple] = []
        self.spawn_calls: list[BackgroundSpawnContext] = []

    def should_spawn(self, ctx: BackgroundSpawnContext):
        self.spawn_calls.append(ctx)
        return self.spawn_config

    def run(self, config, abort_event: threading.Event):
        self.run_calls.append((config, abort_event))
        if self.run_delay:
            if self.respect_abort:
                abort_event.wait(self.run_delay)
            else:
                time.sleep(self.run_delay)  # misbehaving plugin: never polls abort_event
        if self.raise_error is not None:
            raise self.raise_error
        return self.run_result

    def is_success(self, result) -> bool:
        return self.success_flag

    def to_background_task_result(self, result, *, task_id, duration_ms, triggered_by_attempt, start_timestamp) -> BackgroundTaskResult:
        return BackgroundTaskResult(
            task_id=task_id,
            plugin_id="stub-plugin",
            success=self.success_flag,
            duration_ms=duration_ms,
            triggered_by_attempt=triggered_by_attempt,
            start_timestamp=start_timestamp,
            data={"result": result},
        )

    def reset(self) -> None:
        self.reset_calls += 1


class _StubPlugin:
    def __init__(self, plugin_id: str, background: _StubBackground):
        self.id = plugin_id
        self.background = background


def _ctx(attempt_number=1, will_retry=True) -> BackgroundSpawnContext:
    return BackgroundSpawnContext(
        attempt_number=attempt_number,
        will_retry=will_retry,
        context={},
        attempt_results=[],
    )


def _wait_until(predicate, timeout=2.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("condition not met before timeout")


def test_on_attempt_complete_skips_spawn_when_should_spawn_returns_none():
    background = _StubBackground(spawn_config=None)
    coordinator = BackgroundTaskCoordinator([_StubPlugin("permuter", background)])

    coordinator.on_attempt_complete(_ctx())

    assert background.spawn_calls
    assert background.run_calls == []
    assert coordinator.get_active_task_count() == 0
    coordinator.shutdown()


def test_on_attempt_complete_spawns_task_when_config_returned():
    background = _StubBackground(spawn_config={"code": "int f(void) {}"})
    coordinator = BackgroundTaskCoordinator([_StubPlugin("permuter", background)])

    coordinator.on_attempt_complete(_ctx(attempt_number=2))
    _wait_until(lambda: len(coordinator.get_all_results()) == 1)

    assert background.run_calls
    results = coordinator.get_all_results()
    assert results[0].triggered_by_attempt == 2
    assert results[0].plugin_id == "stub-plugin"
    coordinator.shutdown()


def test_success_result_fires_foreground_abort_signal():
    background = _StubBackground(spawn_config={"code": "x"}, is_success=True)
    coordinator = BackgroundTaskCoordinator([_StubPlugin("permuter", background)])

    coordinator.on_attempt_complete(_ctx())
    _wait_until(lambda: coordinator.foreground_abort_event.is_set())

    assert coordinator.get_success_result() is not None
    assert coordinator.get_success_result().success is True
    coordinator.shutdown()


def test_only_first_success_is_recorded():
    background = _StubBackground(spawn_config={"code": "x"}, is_success=True)
    coordinator = BackgroundTaskCoordinator([_StubPlugin("permuter", background)])

    coordinator.on_attempt_complete(_ctx(attempt_number=1))
    _wait_until(lambda: coordinator.get_success_result() is not None)
    first = coordinator.get_success_result()

    coordinator.on_attempt_complete(_ctx(attempt_number=2))
    _wait_until(lambda: len(coordinator.get_all_results()) == 2)

    assert coordinator.get_success_result() is first
    coordinator.shutdown()


def test_run_exception_produces_failure_result_without_crashing():
    background = _StubBackground(spawn_config={"code": "x"}, raise_error=RuntimeError("permuter crashed"))
    coordinator = BackgroundTaskCoordinator([_StubPlugin("permuter", background)])

    coordinator.on_attempt_complete(_ctx())
    _wait_until(lambda: len(coordinator.get_all_results()) == 1)

    result = coordinator.get_all_results()[0]
    assert result.success is False
    assert "permuter crashed" in result.data.get("error", "")
    assert coordinator.foreground_abort_event.is_set() is False
    coordinator.shutdown()


def test_cancel_all_sets_abort_event_and_clears_active_tasks():
    background = _StubBackground(spawn_config={"code": "x"}, run_delay=5.0)
    coordinator = BackgroundTaskCoordinator([_StubPlugin("permuter", background)])

    coordinator.on_attempt_complete(_ctx())
    _wait_until(lambda: coordinator.get_active_task_count() == 1)

    abandoned = coordinator.cancel_all()

    assert abandoned == []
    assert coordinator.get_abandoned_task_ids() == []
    assert coordinator.get_active_task_count() == 0
    _, abort_event = background.run_calls[0]
    assert abort_event.is_set()
    coordinator.shutdown()


def test_cancel_all_is_bounded_when_task_ignores_abort_event():
    # The plugin never polls abort_event, so only the coordinator's bounded join can
    # reclaim the worker; the pre-fix future.result() waited the full run_delay.
    background = _StubBackground(spawn_config={"code": "x"}, run_delay=2.0, respect_abort=False)
    coordinator = BackgroundTaskCoordinator([_StubPlugin("permuter", background)], cancel_timeout=0.2)

    coordinator.on_attempt_complete(_ctx())
    _wait_until(lambda: coordinator.get_active_task_count() == 1)

    start = time.monotonic()
    abandoned = coordinator.cancel_all()
    elapsed = time.monotonic() - start

    assert elapsed < 1.0
    assert abandoned == ["permuter-1"]
    assert coordinator.get_abandoned_task_ids() == ["permuter-1"]
    assert coordinator.get_active_task_count() == 0
    coordinator.shutdown()


def test_shutdown_is_bounded_when_task_ignores_abort_event():
    background = _StubBackground(spawn_config={"code": "x"}, run_delay=2.0, respect_abort=False)
    coordinator = BackgroundTaskCoordinator([_StubPlugin("permuter", background)], cancel_timeout=0.2)

    coordinator.on_attempt_complete(_ctx())
    _wait_until(lambda: coordinator.get_active_task_count() == 1)

    start = time.monotonic()
    abandoned = coordinator.shutdown()
    elapsed = time.monotonic() - start

    assert elapsed < 1.0
    assert abandoned == ["permuter-1"]


def test_shutdown_after_cancel_all_does_not_rejoin_abandoned_task():
    # cancel_all() clears _tasks, so shutdown()'s own cancel sees nothing to abandon --
    # the executor join has to consult the abandonment ledger or it blocks all over again.
    background = _StubBackground(spawn_config={"code": "x"}, run_delay=2.0, respect_abort=False)
    coordinator = BackgroundTaskCoordinator([_StubPlugin("permuter", background)], cancel_timeout=0.2)

    coordinator.on_attempt_complete(_ctx())
    _wait_until(lambda: coordinator.get_active_task_count() == 1)
    assert coordinator.cancel_all() == ["permuter-1"]

    start = time.monotonic()
    coordinator.shutdown()
    elapsed = time.monotonic() - start

    assert elapsed < 1.0


def test_cancel_all_emits_abandoned_event():
    events: list[dict] = []
    background = _StubBackground(spawn_config={"code": "x"}, run_delay=2.0, respect_abort=False)
    coordinator = BackgroundTaskCoordinator(
        [_StubPlugin("permuter", background)],
        events.append,
        cancel_timeout=0.2,
    )

    coordinator.on_attempt_complete(_ctx())
    _wait_until(lambda: coordinator.get_active_task_count() == 1)
    coordinator.cancel_all()

    abandoned_events = [event for event in events if event.get("type") == "background-task-abandoned"]
    assert abandoned_events == [{"type": "background-task-abandoned", "taskIds": ["permuter-1"]}]
    coordinator.shutdown()


def test_reset_clears_results_and_creates_fresh_abort_signal():
    background = _StubBackground(spawn_config={"code": "x"}, is_success=True)
    coordinator = BackgroundTaskCoordinator([_StubPlugin("permuter", background)])
    coordinator.on_attempt_complete(_ctx())
    _wait_until(lambda: coordinator.foreground_abort_event.is_set())
    old_signal = coordinator.foreground_abort_event

    coordinator.reset()

    assert background.reset_calls == 1
    assert coordinator.get_all_results() == []
    assert coordinator.get_success_result() is None
    assert coordinator.foreground_abort_event is not old_signal
    assert not coordinator.foreground_abort_event.is_set()
    coordinator.shutdown()
