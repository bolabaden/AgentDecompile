"""Bounded autonomy budgets for reconstruct --autonomous loops.

Keeps vacuum/repair from becoming unbounded API or wall-clock spend. Budgets are
receipts, not claims: exhausting a budget is a typed stop, not a match.
"""

from __future__ import annotations

import shlex
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .state import atomic_write_json, now

SCHEMA = "agentdecompile.autonomy-budget.v1"
DEFAULT_MAX_FUNCTIONS = 1
DEFAULT_MAX_ATTEMPTS_PER_FUNCTION = 3
CLAIM_BOUNDARY = (
    "autonomy budget bounds repair/vacuum loops only; it does not establish "
    "objdiff-verified-semantic recovery"
)


@dataclass(frozen=True)
class AutonomyBudget:
    """Hard caps for advanced --autonomous vacuum/repair."""

    max_functions: int = DEFAULT_MAX_FUNCTIONS
    max_attempts_per_function: int = DEFAULT_MAX_ATTEMPTS_PER_FUNCTION
    max_wall_seconds: int | None = None

    def __post_init__(self) -> None:
        if self.max_functions < 0:
            raise ValueError("max_functions must be >= 0")
        if self.max_attempts_per_function < 1:
            raise ValueError("max_attempts_per_function must be >= 1")
        if self.max_wall_seconds is not None and self.max_wall_seconds < 1:
            raise ValueError("max_wall_seconds must be >= 1 when set")

    def to_json(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.update(
            {
                "schema": SCHEMA,
                "claimBoundary": CLAIM_BOUNDARY,
            }
        )
        return payload

    def vacuum_bridge_args(
        self,
        *,
        queue: Path,
        prompts_dir: Path | None = None,
        work_dir: Path | None = None,
        runner_command: str | None = None,
    ) -> list[str] | None:
        """Args for decomp-cli vacuum start, or None when the function budget is zero."""

        if self.max_functions <= 0:
            return None
        args = [
            "vacuum",
            "start",
            "--queue",
            str(queue),
            "--max-functions",
            str(self.max_functions),
            "--max-attempts",
            str(self.max_attempts_per_function),
            "--no-sleep",
        ]
        if prompts_dir is not None:
            args.extend(["--prompts-dir", str(prompts_dir)])
        if work_dir is not None:
            args.extend(
                [
                    "--scores",
                    str(work_dir / "state" / "scores.json"),
                    "--log",
                    str(work_dir / "logs" / "vacuum-progress.log"),
                    "--session",
                    str(work_dir / "state" / "vacuum-session.json"),
                ]
            )
        if runner_command:
            args.extend(["--runner-command", runner_command])
        if self.max_wall_seconds is not None:
            # vacuum.sh accepts --timeout with a duration suffix (e.g. 120s).
            args.extend(["--timeout", f"{int(self.max_wall_seconds)}s"])
        return args


def reconstruct_vacuum_runner_command(work_dir: Path, *, max_attempts: int = 3) -> str:
    """Shell command template for vacuum.sh --runner-command placeholders.

    Placeholders stay quoted so vacuum's {{name}}/{{promptDir}} substitution remains
    safe under ``bash -lc`` when paths contain spaces.
    """

    work = str(work_dir.resolve())
    return (
        f"{shlex.quote(sys.executable)} -m agentdecompile_recovery.vacuum_runner "
        f"--work-dir {shlex.quote(work)} "
        f"--name {shlex.quote('{{name}}')} "
        f"--prompt-dir {shlex.quote('{{promptDir}}')} "
        f"--max-attempts {int(max_attempts)}"
    )


def ensure_vacuum_queue(queue: Path) -> Path:
    """Create an empty vacuum queue under the reconstruct work dir if missing."""

    queue.parent.mkdir(parents=True, exist_ok=True)
    if not queue.exists():
        atomic_write_json(
            queue,
            {
                "schema": "agentdecompile.vacuum-queue.v1",
                "pending": [],
                "matched": [],
                "integrated": [],
                "failed": [],
                "difficult": [],
                "attempts": {},
            },
        )
    return queue


def budget_from_args(
    *,
    max_functions: int | None = None,
    max_attempts_per_function: int | None = None,
    max_wall_seconds: int | None = None,
) -> AutonomyBudget:
    return AutonomyBudget(
        max_functions=DEFAULT_MAX_FUNCTIONS if max_functions is None else max_functions,
        max_attempts_per_function=(
            DEFAULT_MAX_ATTEMPTS_PER_FUNCTION
            if max_attempts_per_function is None
            else max_attempts_per_function
        ),
        max_wall_seconds=max_wall_seconds,
    )


def write_autonomy_budget_receipt(
    work_dir: Path,
    budget: AutonomyBudget,
    *,
    requested: bool,
    status: str,
    reason: str | None = None,
    bridge_args: list[str] | None = None,
    bridge_returncode: int | None = None,
) -> Path:
    """Persist autonomy budget + outcome under the run directory."""

    path = work_dir / "autonomy-budget.json"
    payload: dict[str, Any] = {
        **budget.to_json(),
        "requested": bool(requested),
        "status": status,
        "writtenAt": now(),
    }
    if reason:
        payload["reason"] = reason
    if bridge_args is not None:
        payload["bridgeArgs"] = list(bridge_args)
    if bridge_returncode is not None:
        payload["bridgeReturncode"] = int(bridge_returncode)
    atomic_write_json(path, payload)
    return path


def remaining_attempts(*, attempts_seen: int, budget: AutonomyBudget) -> int:
    return max(0, budget.max_attempts_per_function - max(0, attempts_seen))
