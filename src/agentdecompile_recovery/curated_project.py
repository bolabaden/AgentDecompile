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
    * `curated-signatures.json` -- curated prototypes (calling convention,
      return type, parameter types), consumed by
      `pyghidra_enrich` so the decompiler emits `this` instead of an
      uninitialised `in_ECX` read for the ~8,600 `__thiscall` methods this
      corpus annotates. Only prototypes that survive the `ret N` arity gate
      appear with a `signature`; the rest keep their name and nothing else.

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
CURATED_SIGNATURES_FILENAME = "curated-signatures.json"

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

    from .curated_enrichment import (
        build_curated_hints,
        build_curated_signatures,
        curated_hints_to_json,
        curated_signatures_to_json,
    )
    from .ghidra_context import resolve_curated_program

    try:
        with resolve_curated_program(source=project, program_name=project_program) as program:
            names = program.names_by_entry(curated_only=True)
            hints = build_curated_hints(program)
            signatures = build_curated_signatures(program)
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

    signatures_payload = curated_signatures_to_json(signatures)
    signatures_path = work_dir / CURATED_SIGNATURES_FILENAME
    signatures_path.write_text(json.dumps(signatures_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return {
        "schema": SCHEMA,
        "status": "complete",
        "project": str(project),
        "namesPath": str(names_path),
        "hintsPath": str(hints_path),
        "signaturesPath": str(signatures_path),
        "nameCount": len(names_payload),
        "hintCount": len(hints_payload),
        "signatureCount": len(signatures_payload),
        "prototypeCount": sum(1 for row in signatures_payload.values() if row.get("signature")),
        "arityContradictedCount": sum(
            1 for row in signatures_payload.values() if row.get("arityCheck") == "contradicted"
        ),
        "thiscallCount": sum(
            1 for row in signatures_payload.values() if row.get("callingConvention") == "__thiscall"
        ),
        "claimBoundary": "curated project read is naming/prototype/comment evidence only; compile and objdiff gates remain required",
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


def load_curated_names_by_entry_hex(work_dir: Path) -> dict[str, str] | None:
    """`{entryHex8: name}` for `source_dump.dump_source_tree(curated_names=...)`.

    Keys are zero-padded to 8 hex digits via `int`, which is load-bearing: the
    file stores `hex(entry)` (`"0x401060"`) while facts rows carry
    `"00401060"`. `source_dump.normalize_entry_hex` strips the `0x` and returns
    `"401060"` unchanged (it is already valid hex), so keying off the raw
    string would miss every lookup silently.
    """

    names = load_curated_names(work_dir)
    if not names:
        return None
    return {f"{entry:08x}": name for entry, name in names.items()}


def load_curated_hints(work_dir: Path) -> dict[str, dict[str, Any]] | None:
    """Load `curated-hints.json` from `work_dir` if present and valid, else `None`."""

    return _load_entry_keyed_json(work_dir / CURATED_HINTS_FILENAME)


def load_curated_signatures(work_dir: Path) -> dict[int, dict[str, Any]] | None:
    """`{entryVA: signatureRecord}` from `curated-signatures.json`, else `None`.

    Keyed by int rather than by the stored hex string so callers can join
    against Ghidra entry points without re-deciding a text format; the
    on-disk keys are `curated_enrichment.normalize_entry_key` output
    (bare, zero-padded, lowercase hex).
    """

    payload = _load_entry_keyed_json(work_dir / CURATED_SIGNATURES_FILENAME)
    if not payload:
        return None
    signatures: dict[int, dict[str, Any]] = {}
    for key, value in payload.items():
        if not isinstance(value, dict):
            continue
        try:
            entry = int(str(key), 16)
        except (TypeError, ValueError):
            continue
        signatures[entry] = value
    return signatures or None


def _load_entry_keyed_json(path: Path) -> dict[str, Any] | None:
    """Read an entry-keyed JSON object, returning None for absent or unusable files."""

    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    return payload or None


def apply_curated_names_to_facts_jsonl(
    work_dir: Path,
    *,
    facts_path: Path | None = None,
) -> dict[str, Any]:
    """Overlay `curated-names.json` onto an existing facts JSONL without re-enrich.

    Used when curated names land *after* enrich (the K1 work dir case: facts
    2026-07-30, curated-names 2026-08-05). Updates `name` + `provenance` on
    matching rows; does **not** re-decompile, so bodies still carry Ghidra
    identifier shapes until a full enrich with `apply_name` before decompile.

    Returns a receipt with join/rename counts. No-op (status skipped) when
    curated names or facts are missing.
    """

    names = load_curated_names(work_dir)
    path = facts_path or (work_dir / "function-facts.jsonl")
    if not names:
        return {
            "schema": "agentdecompile.curated-names-overlay.v1",
            "status": "skipped",
            "reason": "no-curated-names",
            "factsPath": str(path),
        }
    if not path.is_file():
        alt = work_dir / "facts" / "function-facts.jsonl"
        if alt.is_file():
            path = alt
        else:
            return {
                "schema": "agentdecompile.curated-names-overlay.v1",
                "status": "skipped",
                "reason": "no-facts",
                "factsPath": str(path),
            }

    from .pyghidra_enrich import is_default_ghidra_name

    rows: list[dict[str, Any]] = []
    renamed = 0
    joined = 0
    unchanged = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        raw_entry = row.get("entryOffset")
        if raw_entry is None:
            raw_entry = row.get("entry") or row.get("entryAddress") or row.get("address")
        try:
            entry = (
                int(str(raw_entry), 16)
                if str(raw_entry).lower().startswith("0x")
                or (
                    isinstance(raw_entry, str)
                    and all(c in "0123456789abcdefABCDEF" for c in raw_entry)
                )
                else int(raw_entry)  # type: ignore[arg-type]
            )
        except (TypeError, ValueError):
            rows.append(row)
            unchanged += 1
            continue
        curated = names.get(entry)
        if not curated or is_default_ghidra_name(curated):
            rows.append(row)
            unchanged += 1
            continue
        joined += 1
        old = str(row.get("name") or "")
        if old != curated:
            row = {
                **row,
                "name": curated,
                "provenance": "curated-project",
                "priorName": old,
                "priorProvenance": row.get("provenance"),
            }
            if "::" in curated:
                row["qualifiedName"] = curated
            renamed += 1
        else:
            # Already correct name; still stamp curated provenance when it was
            # function-candidate/autogen noise.
            if str(row.get("provenance") or "") != "curated-project":
                row = {**row, "provenance": "curated-project"}
                renamed += 1
        rows.append(row)

    text = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
    path.write_text(text, encoding="utf-8")
    # Keep root + facts/ copies in sync when both exist.
    root = work_dir / "function-facts.jsonl"
    nested = work_dir / "facts" / "function-facts.jsonl"
    if path.resolve() == root.resolve() and nested.parent.is_dir():
        nested.write_text(text, encoding="utf-8")
    elif path.resolve() == nested.resolve() and work_dir.is_dir():
        root.write_text(text, encoding="utf-8")

    receipt = {
        "schema": "agentdecompile.curated-names-overlay.v1",
        "status": "complete",
        "factsPath": str(path),
        "curatedNameCount": len(names),
        "factCount": len(rows),
        "joined": joined,
        "renamed": renamed,
        "unchanged": unchanged,
        "claimBoundary": (
            "name/provenance overlay only; decompiled bodies unchanged until re-enrich"
        ),
    }
    (path.parent / "curated-names-overlay-receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return receipt


__all__ = [
    "CURATED_HINTS_FILENAME",
    "CURATED_NAMES_FILENAME",
    "CURATED_SIGNATURES_FILENAME",
    "apply_curated_names_to_facts_jsonl",
    "extract_curated_project_data",
    "load_curated_hints",
    "load_curated_names",
    "load_curated_names_by_entry_hex",
    "load_curated_signatures",
]
