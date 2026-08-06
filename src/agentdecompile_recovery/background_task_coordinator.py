"""Background task coordination for tasks running alongside the AI-powered phase.

Ports the upstream background-task-coordinator: a plugin-agnostic scheduler
that asks each registered background-capable plugin whether it wants to spawn
work after an attempt, runs spawned work on a thread pool, and fires a
foreground abort signal the first time a background task reports success --
so a synchronous foreground loop (e.g. the rewrite/Claude runner) can stop
early instead of burning its own retry budget.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Protocol

PipelineEventHandler = Callable[[dict[str, Any]], None]


@dataclass
class BackgroundSpawnContext:
    attempt_number: int
    will_retry: bool
    context: dict[str, Any]
    attempt_results: list[Any]


@dataclass
class BackgroundTaskResult:
    task_id: str
    plugin_id: str
    success: bool
    duration_ms: int
    triggered_by_attempt: int
    start_timestamp: str
    data: dict[str, Any] = field(default_factory=dict)


class BackgroundCapability(Protocol):
    def should_spawn(self, ctx: BackgroundSpawnContext) -> Any | None:
        """Return spawn config to start a task, or None to skip."""

    def run(self, config: Any, abort_event: threading.Event) -> Any:
        """Run the background task. Must poll/respect abort_event."""

    def is_success(self, result: Any) -> bool:
        """Whether a completed run() result constitutes pipeline success."""

    def to_background_task_result(
        self,
        result: Any,
        *,
        task_id: str,
        duration_ms: int,
        triggered_by_attempt: int,
        start_timestamp: str,
    ) -> BackgroundTaskResult:
        """Convert a plugin-specific run() result into the generic result type."""

    def reset(self) -> None:
        """Clear any per-prompt spawn-tracking state. Optional no-op by default."""


class BackgroundPlugin(Protocol):
    id: str
    background: BackgroundCapability


class BackgroundTaskCoordinator:
    """Coordinates background tasks (e.g. decomp-permuter) run alongside the AI phase."""

    def __init__(
        self,
        plugins: list[BackgroundPlugin],
        event_handler: PipelineEventHandler | None = None,
        *,
        max_workers: int = 4,
    ) -> None:
        self._plugins = list(plugins)
        self._event_handler = event_handler
        self._executor = ThreadPoolExecutor(max_workers=max(1, max_workers))
        self._lock = threading.Lock()
        self._tasks: dict[str, tuple[Future, threading.Event]] = {}
        self._results: list[BackgroundTaskResult] = []
        self._success_result: BackgroundTaskResult | None = None
        self._next_task_id = 1
        self._foreground_abort_event = threading.Event()

    @property
    def foreground_abort_event(self) -> threading.Event:
        """Fires the first time a background task reports success."""
        return self._foreground_abort_event

    def on_attempt_complete(self, spawn_context: BackgroundSpawnContext) -> None:
        """Ask each background-capable plugin whether it wants to spawn work."""
        for plugin in self._plugins:
            config = plugin.background.should_spawn(spawn_context)
            if config is not None:
                self._spawn(plugin, config, spawn_context.attempt_number)

    def reset(self) -> None:
        """Clear state between prompts and give each plugin a fresh abort signal."""
        for plugin in self._plugins:
            reset = getattr(plugin.background, "reset", None)
            if reset is not None:
                reset()
        with self._lock:
            self._results = []
            self._success_result = None
            self._next_task_id = 1
            self._foreground_abort_event = threading.Event()

    def _spawn(self, plugin: BackgroundPlugin, config: Any, triggered_by_attempt: int) -> None:
        with self._lock:
            task_id = f"{plugin.id}-{self._next_task_id}"
            self._next_task_id += 1
        start_timestamp = datetime.now(timezone.utc).isoformat()
        start_time = time.monotonic()
        abort_event = threading.Event()

        self._emit({"type": "background-task-start", "taskId": task_id, "triggeredByAttempt": triggered_by_attempt})

        def _work() -> BackgroundTaskResult:
            try:
                plugin_result = plugin.background.run(config, abort_event)
            except Exception as exc:  # noqa: BLE001 - isolate background-task failures from the coordinator.
                result = BackgroundTaskResult(
                    task_id=task_id,
                    plugin_id=plugin.id,
                    success=False,
                    duration_ms=int((time.monotonic() - start_time) * 1000),
                    triggered_by_attempt=triggered_by_attempt,
                    start_timestamp=start_timestamp,
                    data={"error": str(exc)},
                )
                self._finish(task_id, result, plugin, None)
                return result
            result = plugin.background.to_background_task_result(
                plugin_result,
                task_id=task_id,
                duration_ms=int((time.monotonic() - start_time) * 1000),
                triggered_by_attempt=triggered_by_attempt,
                start_timestamp=start_timestamp,
            )
            self._finish(task_id, result, plugin, plugin_result)
            return result

        future = self._executor.submit(_work)
        with self._lock:
            self._tasks[task_id] = (future, abort_event)

    def _finish(self, task_id: str, result: BackgroundTaskResult, plugin: BackgroundPlugin, plugin_result: Any) -> None:
        is_first_success = False
        with self._lock:
            self._results.append(result)
            self._tasks.pop(task_id, None)
            if plugin_result is not None and plugin.background.is_success(plugin_result) and self._success_result is None:
                self._success_result = result
                is_first_success = True
        self._emit(
            {
                "type": "background-task-complete",
                "taskId": task_id,
                "success": result.success,
                "durationMs": result.duration_ms,
            }
        )
        if is_first_success:
            self._foreground_abort_event.set()
            self._emit({"type": "background-task-success", "taskId": task_id})

    def cancel_all(self) -> None:
        """Abort all running tasks and wait for them to clean up."""
        with self._lock:
            active = list(self._tasks.values())
        for _future, abort_event in active:
            abort_event.set()
        for future, _abort_event in active:
            future.result()
        with self._lock:
            self._tasks.clear()

    def get_all_results(self) -> list[BackgroundTaskResult]:
        with self._lock:
            return list(self._results)

    def get_success_result(self) -> BackgroundTaskResult | None:
        with self._lock:
            return self._success_result

    def get_active_task_count(self) -> int:
        with self._lock:
            return len(self._tasks)

    def shutdown(self) -> None:
        """Cancel outstanding work and release the thread pool. Call once the pipeline ends."""
        self.cancel_all()
        self._executor.shutdown(wait=True)

    def _emit(self, event: dict[str, Any]) -> None:
        if self._event_handler is not None:
            self._event_handler(event)
