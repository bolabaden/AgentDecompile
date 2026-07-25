"""Durable shared Ghidra analysis orchestration for recovery pipelines."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Callable

from .state import atomic_write_json, now, read_json
from .targets import sha256_file

try:
    from ghidrecomp.decompile import gen_proj_bin_name_from_path
except ImportError:  # pragma: no cover - optional in minimal test envs
    gen_proj_bin_name_from_path = None  # type: ignore[assignment,misc]

RECEIPT_SCHEMA = "agentdecompile.ghidra-analysis.v1"
SHARED_PROJECT_DIRNAME = "ghidra-shared"
EXPORT_SCRIPT = "ExportFunctionInventory.java"
RunSubprocess = Callable[..., subprocess.CompletedProcess[Any]]


def shared_project_root(unpack_dir: Path) -> Path:
    return unpack_dir / SHARED_PROJECT_DIRNAME


def resolve_project_name(binary_path: Path) -> str:
    path = binary_path.expanduser().resolve()
    if gen_proj_bin_name_from_path is not None:
        return str(gen_proj_bin_name_from_path(path))
    digest = sha256_file(path)
    return f"{path.stem}-{digest[:12]}".lower()


def resolve_program_name(binary_path: Path) -> str:
    return binary_path.expanduser().resolve().name


def analysis_receipt_path(project_path: Path, project_name: str) -> Path:
    return project_path / f"{project_name}.analysis-receipt.json"


def project_exists(project_path: Path, project_name: str) -> bool:
    return (project_path / f"{project_name}.gpr").exists()


def load_analysis_receipt(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        payload = read_json(path)
    except (OSError, ValueError):
        return None
    if payload.get("schema") != RECEIPT_SCHEMA:
        return None
    return payload


def receipt_matches_binary(receipt: dict[str, Any], binary_sha256: str) -> bool:
    return str(receipt.get("analysisBinarySha256") or "") == binary_sha256


def build_analyze_import_command(
    *,
    analyze_headless: Path,
    project_path: Path,
    project_name: str,
    binary_path: Path,
    script_dir: Path | None = None,
) -> list[str]:
    cmd = [
        str(analyze_headless),
        str(project_path),
        project_name,
        "-import",
        str(binary_path),
    ]
    if script_dir is not None:
        cmd.extend(["-scriptPath", str(script_dir)])
    return cmd


def build_inventory_export_command(
    *,
    analyze_headless: Path,
    project_path: Path,
    project_name: str,
    program_name: str,
    script_dir: Path,
    inventory_jsonl: Path,
) -> list[str]:
    return [
        str(analyze_headless),
        str(project_path),
        project_name,
        "-process",
        program_name,
        "-noanalysis",
        "-scriptPath",
        str(script_dir),
        "-postScript",
        EXPORT_SCRIPT,
        str(inventory_jsonl),
    ]


def ensure_analyzed_program(
    binary_path: Path,
    *,
    project_path: Path,
    project_name: str | None = None,
    analyze_headless: Path,
    script_dir: Path | None = None,
    run: RunSubprocess = subprocess.run,
    cwd: Path | None = None,
) -> dict[str, Any]:
    """Import and analyze once into a durable shared Ghidra project."""
    binary = binary_path.expanduser().resolve()
    if not binary.is_file():
        raise FileNotFoundError(f"analysis binary not found: {binary}")

    resolved_project_name = project_name or resolve_project_name(binary)
    project_path = project_path.expanduser().resolve()
    project_path.mkdir(parents=True, exist_ok=True)

    binary_sha256 = sha256_file(binary)
    program_name = resolve_program_name(binary)
    receipt_path = analysis_receipt_path(project_path, resolved_project_name)
    existing = load_analysis_receipt(receipt_path)
    if (
        existing is not None
        and receipt_matches_binary(existing, binary_sha256)
        and project_exists(project_path, resolved_project_name)
    ):
        return {
            **existing,
            "reused": True,
            "receiptPath": str(receipt_path),
        }

    cmd = build_analyze_import_command(
        analyze_headless=analyze_headless,
        project_path=project_path,
        project_name=resolved_project_name,
        binary_path=binary,
        script_dir=script_dir,
    )
    completed = run(cmd, cwd=cwd, check=False)
    if completed.returncode != 0 or not project_exists(project_path, resolved_project_name):
        stderr = getattr(completed, "stderr", "") or ""
        stdout = getattr(completed, "stdout", "") or ""
        detail = (stderr or stdout)[-2000:]
        raise RuntimeError(
            f"Ghidra analyze/import failed ({completed.returncode}) for {binary}: {detail}"
        )

    receipt: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "analysisBinarySha256": binary_sha256,
        "analysisBinary": str(binary),
        "projectPath": str(project_path),
        "projectName": resolved_project_name,
        "programName": program_name,
        "analyzedAt": now(),
        "analyzeCommand": cmd,
        "reused": False,
    }
    atomic_write_json(receipt_path, receipt)
    receipt["receiptPath"] = str(receipt_path)
    return receipt


def export_function_inventory(
    *,
    receipt: dict[str, Any],
    inventory_jsonl: Path,
    analyze_headless: Path,
    script_dir: Path,
    run: RunSubprocess = subprocess.run,
    cwd: Path | None = None,
) -> dict[str, Any]:
    """Export function inventory from an existing analyzed project without re-analysis."""
    project_path = Path(str(receipt["projectPath"]))
    project_name = str(receipt["projectName"])
    program_name = str(receipt.get("programName") or "")
    if not program_name:
        raise ValueError("analysis receipt is missing programName")

    inventory_jsonl = inventory_jsonl.expanduser().resolve()
    inventory_jsonl.parent.mkdir(parents=True, exist_ok=True)
    if inventory_jsonl.exists():
        inventory_jsonl.unlink()

    cmd = build_inventory_export_command(
        analyze_headless=analyze_headless,
        project_path=project_path,
        project_name=project_name,
        program_name=program_name,
        script_dir=script_dir,
        inventory_jsonl=inventory_jsonl,
    )
    completed = run(cmd, cwd=cwd, check=False)
    if completed.returncode != 0 or not inventory_jsonl.exists():
        stderr = getattr(completed, "stderr", "") or ""
        stdout = getattr(completed, "stdout", "") or ""
        detail = (stderr or stdout)[-2000:]
        raise RuntimeError(
            f"Ghidra inventory export failed ({completed.returncode}): {detail}"
        )

    return {
        "schema": "agentdecompile.ghidra-inventory-export.v1",
        "inventoryJsonl": str(inventory_jsonl),
        "exportCommand": cmd,
        "analysisReceiptPath": receipt.get("receiptPath"),
        "projectPath": str(project_path),
        "projectName": project_name,
        "programName": program_name,
    }


def validate_inventory_text_coverage(
    inventory_jsonl: Path,
    text_section: str,
    *,
    section_counter: Callable[[Path], dict[str, int]] | None = None,
) -> dict[str, int]:
    """Fail closed when a .text-class inventory has no functions in that section."""
    counter = section_counter or _default_section_counter
    section_counts = counter(inventory_jsonl)
    text_count = int(section_counts.get(text_section) or 0)
    has_section_metadata = any(bool(name) for name in section_counts)
    if text_section.startswith(".text") and has_section_metadata and text_count == 0:
        raise RuntimeError(
            f"inventory at {inventory_jsonl} has no functions in {text_section}; "
            "refusing to continue with a packed/stub-only function map"
        )
    return section_counts


def _default_section_counter(jsonl: Path) -> dict[str, int]:
    import json

    counts: dict[str, int] = {}
    if not jsonl.exists():
        return counts
    with jsonl.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            section = str(row.get("section") or "")
            counts[section] = counts.get(section, 0) + 1
    return counts
