"""Background decomp-permuter capability for BackgroundTaskCoordinator.

Wraps the Tier 1 permuter CLI invocation (agentdecompile_cli.mcp_utils.decomp_match)
so it can run on a worker thread alongside the AI-powered (rewrite/Claude runner)
attempt loop, mirroring the upstream decomp-permuter plugin's background mode:
spawn only when the match improved over the best seen so far, and only once per
generated candidate source.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any, Callable

from .background_task_coordinator import BackgroundSpawnContext, BackgroundTaskResult

PLUGIN_ID = "decomp-permuter-background"

PermuterRunner = Callable[[dict[str, Any], threading.Event], dict[str, Any]]


class PermuterBackgroundCapability:
    def __init__(
        self,
        *,
        permuter_runner: PermuterRunner | None = None,
        jobs: int | None = None,
        timeout_ms: int = 300_000,
    ) -> None:
        self._permuter_runner = permuter_runner or _default_permuter_runner
        self._jobs = jobs
        self._timeout_ms = timeout_ms
        self._best_difference_count: float = float("inf")
        self._spawned_codes: set[str] = set()

    def should_spawn(self, ctx: BackgroundSpawnContext) -> dict[str, Any] | None:
        if not ctx.will_retry:
            return None
        permuter_dir = ctx.context.get("permuterDir")
        if not permuter_dir:
            return None
        difference_count = _best_difference_count_from_results(ctx.attempt_results)
        if difference_count is None or difference_count > self._best_difference_count:
            return None
        code = _generated_code(ctx.context)
        if not code or code in self._spawned_codes:
            return None
        self._best_difference_count = difference_count
        self._spawned_codes.add(code)
        return {"permuter_dir": Path(str(permuter_dir)), "jobs": self._jobs, "timeout_ms": self._timeout_ms}

    def run(self, config: dict[str, Any], abort_event: threading.Event) -> dict[str, Any]:
        return self._permuter_runner(config, abort_event)

    def is_success(self, result: dict[str, Any]) -> bool:
        return bool(result.get("matched")) and int(result.get("differences", 1)) == 0

    def to_background_task_result(
        self,
        result: dict[str, Any],
        *,
        task_id: str,
        duration_ms: int,
        triggered_by_attempt: int,
        start_timestamp: str,
    ) -> BackgroundTaskResult:
        return BackgroundTaskResult(
            task_id=task_id,
            plugin_id=PLUGIN_ID,
            success=self.is_success(result),
            duration_ms=duration_ms,
            triggered_by_attempt=triggered_by_attempt,
            start_timestamp=start_timestamp,
            data=result,
        )

    def reset(self) -> None:
        self._best_difference_count = float("inf")
        self._spawned_codes = set()


class BackgroundPermuterPlugin:
    """Adapter matching the BackgroundPlugin protocol expected by the coordinator."""

    id = PLUGIN_ID

    def __init__(self, capability: PermuterBackgroundCapability | None = None) -> None:
        self.background = capability or PermuterBackgroundCapability()


def _generated_code(context: dict[str, Any]) -> str:
    candidate = context.get("selectedSourceCandidate")
    source = getattr(candidate, "source", None)
    if source:
        return str(source)
    return str(context.get("generatedCode") or "")


def _best_difference_count_from_results(attempt_results: list[Any]) -> int | None:
    counts: list[int] = []
    for result in attempt_results:
        data = getattr(result, "data", None)
        if isinstance(data, dict) and isinstance(data.get("differenceCount"), int):
            counts.append(data["differenceCount"])
    return min(counts) if counts else None


def _default_permuter_runner(config: dict[str, Any], abort_event: threading.Event) -> dict[str, Any]:
    from agentdecompile_cli.mcp_utils.decomp_match import build_decomp_match_payload

    result = build_decomp_match_payload(
        tool="permuter",
        permuter_dir=config["permuter_dir"],
        jobs=config.get("jobs"),
        timeout_ms=config.get("timeout_ms", 300_000),
    )
    scan = result.get("scan") or {}
    matched = scan.get("exitCode") == 0 and "Found" in str(scan.get("stdout") or "")
    return {
        "matched": bool(matched),
        "differences": 0 if matched else 1,
        "raw": result,
    }
