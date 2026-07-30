"""Best-effort work-dir I/O diagnostics (G16: rotational-disk work-dir guidance).

Per-function compile/objdiff cycles in the autonomous recovery loop are
I/O-bound; running against a spinning disk turned a ~1-2s cycle into
30s-17min in a real proof-scale smoke run (see
docs/solutions/workflow-learnings/2026-07-25-proof-scale-smoke-swkotor.md).
This module never blocks a run over disk type -- it is advisory only, and
returns None (no warning) on any platform or filesystem where the check
cannot be performed (containers, non-Linux, sandboxed /sys).
"""

from __future__ import annotations

import os
from pathlib import Path


def rotational_disk_warning(work_dir: Path, *, sys_block_root: Path = Path("/sys/dev/block")) -> str | None:
    """Return an advisory warning if `work_dir` resolves to a rotational disk.

    Linux-only (reads `<sys_block_root>/<major>:<minor>/queue/rotational`,
    walking up from a partition to its parent disk). `sys_block_root` defaults
    to the real `/sys/dev/block` and exists as a parameter purely for tests to
    inject a fake sysfs layout -- production callers should never pass it.
    Returns None on any error or on platforms without this /sys layout --
    callers should treat this as "nothing to warn about", not as confirmation
    the disk is fast.
    """

    try:
        stat_result = os.stat(work_dir)
        block_path = sys_block_root / f"{os.major(stat_result.st_dev)}:{os.minor(stat_result.st_dev)}"
        resolved = block_path.resolve()
        if (resolved / "partition").exists():
            resolved = resolved.parent
        rotational = (resolved / "queue" / "rotational").read_text(encoding="utf-8").strip()
    except (OSError, ValueError):
        return None
    if rotational != "1":
        return None
    return (
        f"work_dir {work_dir} appears to be on a rotational (spinning) disk "
        f"({resolved.name}) -- per-function compile/objdiff cycles are I/O-bound "
        "and can take 30s-17min instead of 1-2s on SSD/NVMe (G16, see "
        "docs/plans/2026-07-24-perf-recovery-one-shot-living-plan.md). Consider "
        "pointing --work-dir at a local SSD/NVMe path and archiving results afterward."
    )
