"""Safe, headless Ghidra acquisition-context export.

Raw binaries and `.gzf` archives are imported into an ephemeral, disposable
Ghidra project via `analyzeHeadless` (JVM-based).  Existing `.gpr`/`.rep`
projects are opened read-only through `agentdecompile_recovery.ghidra_db`
instead -- a pure-Python reader with no JVM and no write path -- so a
curated project's names, comments, and signatures are visible without ever
touching project internals through Ghidra itself.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .ghidra_db import ProjectLayoutError, list_programs, open_project_program, resolve_project_root
from .ghidra_db.program import GhidraProgram


def resolve_analyze_headless(configured: Path | None = None) -> Path | None:
    if configured:
        candidate = configured.expanduser()
        if candidate.is_file():
            return candidate
        candidate = candidate / "support" / "analyzeHeadless"
        return candidate if candidate.exists() else None
    command = shutil.which("analyzeHeadless")
    if command:
        return Path(command)
    install = Path(str(__import__("os").environ.get("GHIDRA_INSTALL_DIR", "")))
    candidate = install / "support" / "analyzeHeadless"
    return candidate if candidate.exists() else None


def project_input_error(path: Path) -> str | None:
    """Human-readable reason `path` cannot be opened as a Ghidra project, or `None` if it can be."""

    resolved = path.expanduser()
    if not resolved.exists():
        return f"Ghidra project path does not exist: {resolved}"
    try:
        resolve_project_root(resolved)
    except ProjectLayoutError as exc:
        return str(exc)
    return None


def _is_ghidra_project_path(source: Path) -> bool:
    """True when `source` resolves to a readable `.gpr`/`.rep` project layout."""

    try:
        resolve_project_root(source)
    except ProjectLayoutError:
        return False
    return True


@contextmanager
def resolve_curated_program(
    *,
    source: Path,
    program_name: str | None = None,
) -> Iterator[GhidraProgram]:
    """Resolve and open a `.gpr`/`.rep` project's chosen program, read-only.

    Same project-root resolution and multi-program selection as
    `open_project_names_context` (raises `ValueError` for a bad project path
    or an ambiguous multi-program project with `program_name` unset) --
    callers that need direct `GhidraProgram` access, not just the
    names-only JSONL export that function writes, use this instead of
    re-deriving the resolution logic.
    """

    resolved_source = source.expanduser().resolve()
    try:
        project_root = resolve_project_root(resolved_source)
    except ProjectLayoutError as exc:
        raise ValueError(f"not a Ghidra project: {exc}") from exc

    programs = list_programs(project_root)
    if not programs:
        raise ValueError(f"{project_root}: project has no program items")

    chosen_name = program_name
    if chosen_name is None:
        if len(programs) > 1:
            available = ", ".join(entry.project_path for entry in programs)
            raise ValueError(
                f"{project_root}: multiple programs in project, pass --project-program to pick one (have: {available})"
            )
        chosen_name = programs[0].project_path

    program = open_project_program(project_root, chosen_name)
    try:
        yield program
    finally:
        program.close()


def open_project_names_context(
    *,
    source: Path,
    out_dir: Path,
    program_name: str | None = None,
) -> dict[str, Any]:
    """Open a `.gpr`/`.rep` project read-only via `ghidra_db` and export curated names.

    Reads only -- `ghidra_db.GhidraProgram` never writes to a project database.
    Raises `ValueError` (not a stack trace) for a path that does not resolve to
    a Ghidra project layout, and again if `program_name` does not match an item
    in the project (the available names are listed in the message).
    """

    source = source.expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        project_root = resolve_project_root(source)
    except ProjectLayoutError as exc:
        raise ValueError(f"not a Ghidra project: {exc}") from exc

    programs = list_programs(project_root)
    if not programs:
        raise ValueError(f"{project_root}: project has no program items")

    chosen_name = program_name
    if chosen_name is None:
        if len(programs) > 1:
            available = ", ".join(entry.project_path for entry in programs)
            raise ValueError(
                f"{project_root}: multiple programs in project, pass --project-program to pick one (have: {available})"
            )
        chosen_name = programs[0].project_path

    program = open_project_program(project_root, chosen_name)
    try:
        names = program.names_by_entry(curated_only=True)
    finally:
        program.close()

    output = out_dir / "ghidra-db-names.jsonl"
    with output.open("w", encoding="utf-8") as handle:
        for entry, name in sorted(names.items()):
            handle.write(json.dumps({"entryVirtualAddress": entry, "entry": hex(entry), "name": name}) + "\n")

    return {
        "schema": "agentdecompile.ghidra-db-project-read.v1",
        "status": "complete",
        "mode": "project-db-read-only",
        "source": str(source),
        "project": str(project_root),
        "program": chosen_name,
        "factsJsonl": str(output),
        "namesByEntry": {hex(entry): name for entry, name in names.items()},
        "factCount": len(names),
        "curatedOnly": True,
        "claimBoundary": "Ghidra project read is read-only curated-name evidence; compile and objdiff gates remain required.",
    }


def export_ghidra_context(
    *,
    source: Path,
    out_dir: Path,
    ghidra: Path | None = None,
    program_name: str | None = None,
    timeout: int = 600,
) -> dict[str, Any]:
    """Export normalized JSONL evidence with safe project and import modes."""

    source = source.expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # A real `.gpr`/`.rep` project layout is opened read-only through
    # `ghidra_db` -- no JVM, no write path -- instead of being refused or
    # shelled out to `analyzeHeadless`. A `.gpr`/`.rep`-suffixed input, or a
    # directory holding Ghidra project state, that does NOT resolve to a
    # readable project layout still gets a clear refusal rather than being
    # handed to the raw-binary import path below.
    if source.suffix.lower() in {".gpr", ".rep"} or source.is_dir():
        if _is_ghidra_project_path(source):
            return open_project_names_context(source=source, out_dir=out_dir, program_name=program_name)
        raise ValueError(
            "refusing to parse Ghidra .rep internals; source does not resolve to a "
            "readable Ghidra project layout (expected a .gpr file or a .rep directory)"
        )

    analyze = resolve_analyze_headless(ghidra)
    if analyze is None:
        raise RuntimeError("Ghidra analyzeHeadless is unavailable; set --ghidra or GHIDRA_INSTALL_DIR")
    script_dir = Path(__file__).resolve().parents[2] / "scripts" / "ghidra"
    script = script_dir / "ExportAcquisitionContext.java"
    if not script.exists():
        raise RuntimeError(f"Ghidra context exporter missing: {script}")
    output = out_dir / "ghidra-acquisition.jsonl"
    metadata = out_dir / "ghidra-acquisition-metadata.json"

    if not source.is_file():
        raise FileNotFoundError(f"Ghidra source does not exist: {source}")
    with tempfile.TemporaryDirectory(prefix="agentdecompile-ghidra-") as project_root:
        command = [
            str(analyze),
            project_root,
            "agentdecompile-ephemeral",
            "-import",
            str(source),
            "-scriptPath",
            str(script_dir),
            "-deleteProject",
            "-postScript",
            script.name,
            str(output),
            str(metadata),
        ]
        completed = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)
    if completed.returncode != 0 or not output.exists():
        raise RuntimeError(
            f"Ghidra export failed ({completed.returncode}): {completed.stderr[-2000:] or completed.stdout[-2000:]}"
        )
    return _export_receipt(source, output, metadata, "ephemeral-import", command, completed)


def _export_receipt(
    source: Path,
    output: Path,
    metadata: Path,
    mode: str,
    command: list[str],
    completed: subprocess.CompletedProcess[str],
) -> dict[str, Any]:
    rows = sum(1 for line in output.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip())
    payload: dict[str, Any] = {}
    if metadata.exists():
        try:
            payload = json.loads(metadata.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            payload = {"metadataStatus": "invalid-json"}
    return {
        "schema": "agentdecompile.ghidra-acquisition-export.v1",
        "status": "complete",
        "mode": mode,
        "source": str(source),
        "factsJsonl": str(output),
        "metadata": str(metadata),
        "factCount": rows,
        "runtime": payload,
        "command": command,
        "stdout": completed.stdout[-2000:],
        "claimBoundary": "Ghidra export is acquisition evidence only; compile and objdiff gates remain required.",
    }
