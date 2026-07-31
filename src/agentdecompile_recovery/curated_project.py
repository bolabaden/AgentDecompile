"""Extract curated project data into a run's work_dir, once (U13).

Bridges the read-only `ghidra_db` project reader (`GhidraProgram`, opened via
`ghidra_context.resolve_curated_program`) to two on-disk artifacts a
reconstruct run can reload later without reopening the project database:

    * `curated-names.json` -- the highest-priority naming tier consumed by
      `pyghidra_enrich.build_names_by_entry(curated_names=...)`.
    * `curated-hints.json` -- curated parameter names / header comments,
      the exact shape `curated_enrichment.curated_hints_to_json` produces,
      consumed by `source_dump.dump_source_tree(curated_hints=...)` and
      `source_cleanup.cleanup_recovered_source_package(curated_hints=...)`.

`extract_curated_project_data` never raises -- extraction is an optional
readability enhancement, so any failure (unreadable project, ambiguous
multi-program project, corrupt database) is reported in the returned
receipt's `status`/`reason` rather than aborting the caller's run. See
`frontdoor.run_one_shot`, which logs a warning to stderr on a failed receipt
and continues without curated data.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

CURATED_NAMES_FILENAME = "curated-names.json"
CURATED_HINTS_FILENAME = "curated-hints.json"

SCHEMA = "agentdecompile.curated-project-extract.v1"


def extract_curated_project_data(
    *,
    project: Path,
    work_dir: Path,
    project_program: str | None = None,
) -> dict[str, Any]:
    """Open `project` read-only and persist curated names + hints under `work_dir`.

    Returns a receipt dict with `status` "complete" or "failed" (+ `reason`
    on failure). Never raises.
    """

    from .curated_enrichment import build_curated_hints, curated_hints_to_json
    from .ghidra_context import resolve_curated_program

    try:
        with resolve_curated_program(source=project, program_name=project_program) as program:
            names = program.names_by_entry(curated_only=True)
            hints = build_curated_hints(program)
    except Exception as exc:  # noqa: BLE001 - optional enhancement, never hard-fails the run
        return {
            "schema": SCHEMA,
            "status": "failed",
            "reason": str(exc),
            "claimBoundary": "curated project extraction is an optional readability enhancement; its failure never blocks recovery",
        }

    work_dir.mkdir(parents=True, exist_ok=True)

    names_payload = {hex(entry): name for entry, name in sorted(names.items())}
    names_path = work_dir / CURATED_NAMES_FILENAME
    names_path.write_text(json.dumps(names_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    hints_payload = curated_hints_to_json(hints)
    hints_path = work_dir / CURATED_HINTS_FILENAME
    hints_path.write_text(json.dumps(hints_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return {
        "schema": SCHEMA,
        "status": "complete",
        "project": str(project),
        "namesPath": str(names_path),
        "hintsPath": str(hints_path),
        "nameCount": len(names_payload),
        "hintCount": len(hints_payload),
        "claimBoundary": "curated project read is naming/comment evidence only; compile and objdiff gates remain required",
    }


def load_curated_names(work_dir: Path) -> dict[int, str] | None:
    """Load `curated-names.json` from `work_dir` if present and valid, else `None`.

    Shared by both naming-tier call sites (PE `reconstruct_enrich.py`, ELF
    `source_parity_one_shot.py`) so "load curated names if present" logic is
    not duplicated between them.
    """

    path = work_dir / CURATED_NAMES_FILENAME
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    names: dict[int, str] = {}
    for key, value in payload.items():
        try:
            entry = int(str(key), 16) if str(key).lower().startswith("0x") else int(str(key))
        except (TypeError, ValueError):
            continue
        names[entry] = str(value)
    return names or None


def load_curated_hints(work_dir: Path) -> dict[str, dict[str, Any]] | None:
    """Load `curated-hints.json` from `work_dir` if present and valid, else `None`."""

    path = work_dir / CURATED_HINTS_FILENAME
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    return payload or None


__all__ = [
    "CURATED_HINTS_FILENAME",
    "CURATED_NAMES_FILENAME",
    "extract_curated_project_data",
    "load_curated_hints",
    "load_curated_names",
]
