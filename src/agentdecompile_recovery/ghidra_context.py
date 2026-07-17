"""Safe, headless Ghidra acquisition-context export.

This adapter deliberately treats Ghidra projects as tool inputs.  It does not
parse project database internals and only imports raw binaries/GZF archives into
an ephemeral project.  Existing projects must be supplied as an explicit,
unlocked snapshot directory.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


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


def export_ghidra_context(
    *,
    source: Path,
    out_dir: Path,
    ghidra: Path | None = None,
    project_snapshot: Path | None = None,
    program_name: str | None = None,
    timeout: int = 600,
) -> dict[str, Any]:
    """Export normalized JSONL evidence with safe project and import modes."""

    source = source.expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    analyze = resolve_analyze_headless(ghidra)
    if analyze is None:
        raise RuntimeError("Ghidra analyzeHeadless is unavailable; set --ghidra or GHIDRA_INSTALL_DIR")
    script_dir = Path(__file__).resolve().parents[2] / "scripts" / "ghidra"
    script = script_dir / "ExportAcquisitionContext.java"
    if not script.exists():
        raise RuntimeError(f"Ghidra context exporter missing: {script}")
    output = out_dir / "ghidra-acquisition.jsonl"
    metadata = out_dir / "ghidra-acquisition-metadata.json"

    if source.suffix.lower() in {".rep"}:
        raise ValueError("refusing to parse Ghidra .rep internals; export a project snapshot or use a raw binary/GZF input")
    if source.is_dir():
        if project_snapshot is None:
            raise ValueError("Ghidra project input requires --project-snapshot; live/locked projects are not opened")
        snapshot = project_snapshot.expanduser().resolve()
        if not snapshot.is_dir():
            raise FileNotFoundError(f"Ghidra project snapshot does not exist: {snapshot}")
        command = [
            str(analyze),
            str(snapshot.parent),
            snapshot.name,
            "-readOnly",
            "-process",
            program_name or "*",
            "-scriptPath",
            str(script_dir),
            "-postScript",
            script.name,
            str(output),
            str(metadata),
        ]
        mode = "project-snapshot-read-only"
    else:
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

    completed = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)
    if completed.returncode != 0 or not output.exists():
        raise RuntimeError(f"Ghidra export failed ({completed.returncode}): {completed.stderr[-2000:] or completed.stdout[-2000:]}")
    return _export_receipt(source, output, metadata, mode, command, completed)


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
