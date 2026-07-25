#!/usr/bin/env bash
# Machine-readable gate for the Recovery source-parity Ralph loop.
# Targets are supplied via env; this script does not hardcode product binaries.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PRIMARY_COVERAGE="${RALPH_PRIMARY_COVERAGE:-${ROOT}/target/recovered/coverage.json}"
PRIMARY_REPORT="${RALPH_PRIMARY_REPORT:-${ROOT}/target/source-parity-one-shot/default/report.json}"
PRIMARY_TARGET_RATIO="${RALPH_PRIMARY_TARGET:-0.90}"
SECONDARY_BINARY="${RALPH_SECONDARY_BINARY:-}"
SECONDARY_COVERAGE="${RALPH_SECONDARY_COVERAGE:-${ROOT}/target/secondary-pe-recovered/coverage.json}"
SECONDARY_INVENTORY="${RALPH_SECONDARY_INVENTORY:-${ROOT}/target/secondary-pe-unpack/facts/function-inventory.jsonl}"
SECONDARY_TARGET_RATIO="${RALPH_SECONDARY_TARGET:-0.90}"

export ROOT PRIMARY_COVERAGE PRIMARY_REPORT PRIMARY_TARGET_RATIO
export SECONDARY_BINARY SECONDARY_COVERAGE SECONDARY_INVENTORY SECONDARY_TARGET_RATIO

python3 - <<'PY'
import json
import os
import subprocess
import sys
from pathlib import Path

root = Path(os.environ["ROOT"])
primary_target = float(os.environ.get("PRIMARY_TARGET_RATIO", "0.90"))
secondary_target = float(os.environ.get("SECONDARY_TARGET_RATIO", "0.90"))
checks: list[dict] = []


def add(name: str, ok: bool, detail: dict) -> None:
    checks.append({"name": name, "ok": ok, **detail})


def read_ratio(path: Path) -> tuple[float, dict]:
    if not path.exists():
        return 0.0, {"missing": str(path)}
    data = json.loads(path.read_text(encoding="utf-8"))
    count = int(data.get("functionCount") or 0)
    verified = int(data.get("verifiedMatchedFunctionCount") or 0)
    ratio = float(data.get("verifiedRatio") or ((verified / count) if count else 0.0))
    return ratio, {
        "functionCount": count,
        "verifiedMatchedFunctionCount": verified,
        "verifiedRatio": ratio,
        "path": str(path),
    }


primary_ratio, primary_detail = read_ratio(Path(os.environ["PRIMARY_COVERAGE"]))
add("primary-coverage", primary_ratio >= primary_target, {"target": primary_target, **primary_detail})

secondary_binary = Path(os.environ.get("SECONDARY_BINARY") or "")
if str(secondary_binary):
    add("secondary-binary-present", secondary_binary.exists(), {"path": str(secondary_binary)})
    secondary_ratio, secondary_detail = read_ratio(Path(os.environ["SECONDARY_COVERAGE"]))
    inventory = Path(os.environ["SECONDARY_INVENTORY"])
    if not secondary_detail.get("functionCount") and inventory.exists():
        lines = sum(1 for line in inventory.read_text(encoding="utf-8").splitlines() if line.strip())
        secondary_detail["functionCount"] = lines
        secondary_detail["inventoryOnly"] = True
    add(
        "secondary-coverage",
        secondary_ratio >= secondary_target,
        {"target": secondary_target, **secondary_detail},
    )
else:
    add("secondary-binary-present", True, {"skipped": True, "reason": "RALPH_SECONDARY_BINARY unset"})

orch = root / "src/agentdecompile_recovery/source_parity_one_shot.py"
self_check_ok = False
self_check_detail: dict = {}
if orch.exists():
    proc = subprocess.run(
        [sys.executable, "-m", "agentdecompile_recovery.source_parity_one_shot", "--self-check"],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    try:
        self_check_detail = json.loads(proc.stdout or "{}")
        self_check_ok = bool(self_check_detail.get("ok")) and proc.returncode == 0
    except json.JSONDecodeError:
        self_check_detail = {"stdout": (proc.stdout or "")[:500], "stderr": (proc.stderr or "")[:500]}
add("source-parity-one-shot", self_check_ok, self_check_detail)

core_scripts = [
    "scripts/vacuum.sh",
    "scripts/decomp-cli.sh",
    "scripts/run-programmatic-phase.sh",
    "scripts/source-parity-synthesize.py",
    "scripts/ghidra/ExportFunctionInventory.java",
    "src/agentdecompile_recovery/source_parity_one_shot.py",
    "src/agentdecompile_recovery/source_parity_synthesize.py",
]
missing = [path for path in core_scripts if not (root / path).exists()]
add("core-scripts-present", not missing, {"missing": missing})

ok = all(item["ok"] for item in checks)
print(json.dumps({"ok": ok, "checks": checks}, indent=2, sort_keys=True))
raise SystemExit(0 if ok else 1)
PY
