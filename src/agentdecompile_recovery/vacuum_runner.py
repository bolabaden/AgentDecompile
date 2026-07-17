"""Vacuum runner for reconstruct work dirs: one seeded function → plugin pipeline.

Exit codes (for scripts/vacuum.sh):
  0 — objdiff-zero accept (or already verified)
  1 — attempted but not matched (near-miss / failed)
  2 — usage / missing task / infrastructure error
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .artifact_layout import publish_verified_artifact
from .source_parity_synthesize import iter_jsonl, source_task_to_queue_row
from .source_plugin_runner import SourcePluginRunConfig, run_source_plugin_pipeline
from .state import atomic_write_json, now
from .vacuum_queue import slugify_function_name


def find_source_task(work_dir: Path, name: str) -> dict[str, Any] | None:
    """Locate a source-generation task by queue name or original function name."""

    tasks_path = work_dir / "source-generation" / "tasks.jsonl"
    if not tasks_path.is_file():
        return None
    wanted = {name, slugify_function_name(name)}
    for task in iter_jsonl(tasks_path):
        if not isinstance(task, dict):
            continue
        task_name = str(task.get("name") or "")
        if task_name in wanted or slugify_function_name(task_name) in wanted:
            return task
    return None


def already_verified(work_dir: Path, name: str) -> bool:
    verified = work_dir / "verified"
    if not verified.is_dir():
        return False
    slug = slugify_function_name(name)
    source_suffixes = {".c", ".cpp", ".cc", ".h", ".hpp", ".s", ".asm"}
    for path in verified.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in source_suffixes:
            continue
        stem = path.stem
        if stem == name or stem == slug:
            return True
        for prefix in (slug, name):
            if not stem.startswith(f"{prefix}_"):
                continue
            suffix = stem[len(prefix) + 1 :]
            # Accept only exact stem_<hexaddr> artifacts, not prefix siblings (Draw vs DrawFrame).
            if suffix and all(ch in "0123456789abcdefABCDEF" for ch in suffix):
                return True
    return False


def run_vacuum_prompt(
    *,
    work_dir: Path,
    name: str,
    prompt_dir: Path | None = None,
    dry_run: bool = False,
    max_attempts: int = 3,
) -> dict[str, Any]:
    """Run bounded plugin synthesis for one vacuum queue entry."""

    work_dir = work_dir.resolve()
    task = find_source_task(work_dir, name)
    if task is None and prompt_dir is not None:
        candidate = Path(prompt_dir) / "candidate.json"
        if candidate.is_file():
            try:
                loaded = json.loads(candidate.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError, TypeError, ValueError):
                loaded = None
            if isinstance(loaded, dict):
                task = loaded
    if task is None:
        return {
            "schema": "agentdecompile.vacuum-runner.v1",
            "status": "missing-task",
            "exitCode": 2,
            "name": name,
            "workDir": str(work_dir),
            "claimBoundary": "runner could not locate a source-generation task; not a recovery claim",
        }

    if already_verified(work_dir, str(task.get("name") or name)):
        return {
            "schema": "agentdecompile.vacuum-runner.v1",
            "status": "already-verified",
            "exitCode": 0,
            "name": name,
            "workDir": str(work_dir),
            "claimBoundary": "existing verified/ artifact short-circuits vacuum; still requires objdiff receipt for semantic claims",
        }

    row = source_task_to_queue_row(task)
    if row is None:
        return {
            "schema": "agentdecompile.vacuum-runner.v1",
            "status": "unsuitable-task",
            "exitCode": 2,
            "name": name,
            "workDir": str(work_dir),
            "reason": "task missing complete target slice bytes",
            "claimBoundary": "incomplete target slice cannot be vacuum-matched",
        }

    out_dir = work_dir / "source-synthesis" / "vacuum" / slugify_function_name(name)
    out_dir.mkdir(parents=True, exist_ok=True)
    single_tasks = out_dir / "task.jsonl"
    single_tasks.write_text(json.dumps(task, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_source_plugin_pipeline(
        SourcePluginRunConfig(
            queue=None,
            source_tasks=[single_tasks],
            source_tasks_only=True,
            out_dir=out_dir,
            limit=1,
            max_variants_per_function=max(1, max_attempts),
            max_retries=max(1, max_attempts),
            dry_run=dry_run,
            clean=False,
            inventory=work_dir / "binary-inventory.json",
        )
    )
    succeeded = int(summary.get("successfulFunctions") or 0)
    exit_code = 0 if succeeded > 0 else 1
    status = "matched" if succeeded > 0 else "unmatched"

    # Best-effort promote first match row into verified/ for reconstruct layout.
    if succeeded > 0:
        matches_path = Path(str(summary.get("codeSliceMatchesPath") or out_dir / "plugin-code-slice-matches.jsonl"))
        if matches_path.is_file():
            for line in matches_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    match = json.loads(line)
                except json.JSONDecodeError:
                    continue
                source = match.get("source")
                if source and Path(str(source)).is_file():
                    publish_verified_artifact(
                        work_dir,
                        stem=f"{slugify_function_name(str(match.get('name') or name))}_{str(match.get('entry') or 'entry').replace('0x', '')}",
                        source=Path(str(source)),
                        metadata={
                            "name": match.get("name") or name,
                            "entry": match.get("entry"),
                            "differences": match.get("differences", 0),
                            "status": match.get("status") or "matched",
                            "proofTier": match.get("proofTier") or match.get("verificationTier"),
                            "vacuumRunner": True,
                        },
                    )
                    break

    result = {
        "schema": "agentdecompile.vacuum-runner.v1",
        "status": status,
        "exitCode": exit_code,
        "name": name,
        "workDir": str(work_dir),
        "outDir": str(out_dir),
        "writtenAt": now(),
        "successfulFunctions": succeeded,
        "pluginSummary": {
            "status": summary.get("status"),
            "failedFunctions": summary.get("failedFunctions"),
            "inspectedFunctions": summary.get("inspectedFunctions"),
        },
        "claimBoundary": (
            "exit 0 means plugin pipeline reported an objdiff-zero accept for this function; "
            "it is not whole-binary semantic recovery"
        ),
    }
    atomic_write_json(out_dir / "vacuum-runner.json", result)
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentdecompile-vacuum-runner")
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--name", required=True, help="Vacuum queue entry name")
    parser.add_argument("--prompt-dir", type=Path, default=None)
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = run_vacuum_prompt(
        work_dir=args.work_dir,
        name=args.name,
        prompt_dir=args.prompt_dir,
        dry_run=args.dry_run,
        max_attempts=args.max_attempts,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return int(result.get("exitCode") or 2)


if __name__ == "__main__":
    sys.exit(main())
