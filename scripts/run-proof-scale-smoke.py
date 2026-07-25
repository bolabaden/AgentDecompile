#!/usr/bin/env python3
"""One-shot proof-scale smoke driver (plan U3)."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentdecompile_recovery.autonomy_budget import AutonomyBudget
from agentdecompile_recovery.frontdoor import run_decomp_cli_bridge
from agentdecompile_recovery.proof_campaign import run_proof_campaign_loop
from agentdecompile_recovery.proof_ladder import build_proof_ladder

WORK = ROOT / "target/agentdecompile-reconstruct/swkotor-parity"
LOG = WORK / "state/proof-scale-smoke.log"


def main() -> int:
    os.environ.setdefault(
        "WINEPREFIX",
        str(ROOT / "target/wine-smoke-prefix"),
    )
    os.environ.setdefault(
        "VC_ROOT",
        "/run/media/brunner56/MyBook/Toolchains/msvc8.0-main",
    )

    ladder_before = build_proof_ladder(WORK)
    budget = AutonomyBudget(
        max_functions=5,
        max_attempts_per_function=3,
        max_wall_seconds=7200,
        max_campaigns=3,
        stop_on_accept=False,
    )
    print("Starting proof campaign loop...", flush=True)
    print(json.dumps({"ladderBefore": {
        "numerator": ladder_before.get("numerator"),
        "denominator": ladder_before.get("denominator"),
        "functionsToNextRung": ladder_before.get("functionsToNextRung"),
    }}, indent=2), flush=True)

    result = run_proof_campaign_loop(
        WORK,
        budget,
        run_decomp_cli_bridge=run_decomp_cli_bridge,
    )
    print(json.dumps(result, indent=2, default=str), flush=True)
    return int(result.get("returncode") or 0)


if __name__ == "__main__":
    raise SystemExit(main())
