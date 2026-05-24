#!/usr/bin/env python3
"""Emit JSON metrics for /ce-optimize runs (program-analysis gate + unit health)."""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _run_pytest(args: list[str]) -> tuple[float, bool]:
    start = time.perf_counter()
    proc = subprocess.run(
        ["uv", "run", "pytest", *args],
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    elapsed = time.perf_counter() - start
    return elapsed, proc.returncode == 0


def main() -> int:
    gate_seconds, gate_ok = _run_pytest(
        ["tests/test_program_analysis_gate.py", "-m", "unit", "-q", "--timeout=60"]
    )
    unit_seconds, unit_ok = _run_pytest(["tests/", "-m", "unit", "-q", "--timeout=180"])

    payload = {
        "unit_pytest_seconds": round(unit_seconds, 4),
        "gate_pytest_seconds": round(gate_seconds, 4),
        "unit_tests_passed": 1 if unit_ok else 0,
        "gate_tests_passed": 1 if gate_ok else 0,
        "combined_pytest_seconds": round(unit_seconds + gate_seconds, 4),
    }
    print(json.dumps(payload))
    return 0 if gate_ok and unit_ok else 1


if __name__ == "__main__":
    sys.exit(main())
