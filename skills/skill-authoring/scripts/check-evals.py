#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# ///
"""Validate evals/evals.json and evals/triggers.json (no LLM).

Usage:
  python3 scripts/check-evals.py [--root DIR]

Exit 0 if every canonical skill has valid eval + trigger files.
Stdout is JSON. Diagnostics go to stderr.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _help() -> str:
    return __doc__ or ""


def check_evals(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"{path}: {exc}"]
    if payload.get("skill_name") != path.parents[1].name:
        errors.append(f"{path}: skill_name must be {path.parents[1].name!r}")
    evals = payload.get("evals")
    if not isinstance(evals, list) or len(evals) < 2:
        errors.append(f"{path}: need at least 2 evals")
        return errors
    for item in evals:
        for key in ("id", "prompt", "expected_output"):
            if key not in item:
                errors.append(f"{path}: eval missing {key}")
    return errors


def check_triggers(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"{path}: {exc}"]
    if not isinstance(rows, list) or len(rows) < 6:
        return [f"{path}: need at least 6 trigger queries"]
    yes = no = train = val = 0
    for row in rows:
        if "query" not in row or "should_trigger" not in row:
            errors.append(f"{path}: row needs query and should_trigger")
            continue
        if row["should_trigger"]:
            yes += 1
        else:
            no += 1
        split = row.get("split", "train")
        if split == "validation":
            val += 1
        else:
            train += 1
    if yes < 2 or no < 2:
        errors.append(f"{path}: need both should_trigger true and false (near-misses)")
    if train < 1 or val < 1:
        errors.append(f"{path}: need train and validation splits")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=_help().splitlines()[0])
    parser.add_argument("--root", type=Path, help="Repo root (default: three parents up from this script)")
    args = parser.parse_args(argv)
    here = Path(__file__).resolve()
    root = args.root or here.parents[3]
    errors: list[str] = []
    checked = 0
    for tree in (root / "skills", root / ".agents" / "skills"):
        if not tree.is_dir():
            continue
        for skill in sorted(p.parent for p in tree.glob("*/SKILL.md")):
            if skill.name == "skill-authoring" and tree.name == "skills":
                pass
            evals = skill / "evals" / "evals.json"
            triggers = skill / "evals" / "triggers.json"
            if not evals.is_file():
                errors.append(f"{evals}: missing")
                continue
            if not triggers.is_file():
                errors.append(f"{triggers}: missing")
                continue
            checked += 1
            errors.extend(check_evals(evals))
            errors.extend(check_triggers(triggers))
    report = {"ok": not errors, "checked": checked, "errors": errors}
    print(json.dumps(report, indent=2))
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
