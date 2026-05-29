"""Tier 1 batch gzf export — ghidrecomp.decompile with --gzf for cold-binary snapshots."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from agentdecompile_cli.mcp_utils.batch_decompile import build_ghidrecomp_namespace

try:
    from ghidrecomp.decompile import decompile as ghidrecomp_decompile
    from ghidrecomp.decompile import gen_proj_bin_name_from_path, get_bin_output_path
except ImportError:  # pragma: no cover - optional in minimal test envs
    ghidrecomp_decompile = None
    gen_proj_bin_name_from_path = None
    get_bin_output_path = None

logger = logging.getLogger(__name__)

_DEFAULT_OUTPUT_PATH = "ghidrecomps"
_DEFAULT_PROJECT_PATH = "ghidra_projects"
_DEFAULT_GZF_PATH = "gzfs"


def _collect_artifact_files(directory: Path, *, suffix: str) -> list[str]:
    if not directory.is_dir():
        return []
    return sorted(str(path.resolve()) for path in directory.rglob(f"*{suffix}") if path.is_file())


def _resolve_gzf_directory(output_root: Path, gzf_path: str) -> Path:
    """Mirror ghidrecomp.decompile gzf_path resolution."""
    if gzf_path == _DEFAULT_GZF_PATH:
        return output_root / gzf_path
    return Path(gzf_path).expanduser()


def _suggest_tier_escalation(*, gzf_count: int) -> dict[str, Any]:
    if gzf_count == 0:
        return {
            "recommendedTier": 2,
            "reason": "Batch gzf export produced no archives; verify binary path and try open-project.",
            "nextTools": ["run-file-triage", "open-project", "analyze-program"],
        }
    return {
        "recommendedTier": 2,
        "reason": "Packed project snapshot ready; open-project or import the .gzf for interactive RE.",
        "nextTools": ["open-project", "list-functions", "list-imports"],
    }


def build_batch_gzf_payload(
    binary_path: Path,
    *,
    output_path: str | Path = _DEFAULT_OUTPUT_PATH,
    gzf_path: str = _DEFAULT_GZF_PATH,
    project_path: str | Path = _DEFAULT_PROJECT_PATH,
    force_analysis: bool = False,
    skip_symbols: bool = True,
    decompile_runner: Any | None = None,
) -> dict[str, Any]:
    """Run ghidrecomp with gzf export enabled and return unified JSON artifact metadata."""
    path = binary_path.expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Binary not found or not a file: {path}")

    output_root = Path(output_path).expanduser().resolve()
    gzf_storage = _resolve_gzf_directory(output_root, gzf_path)

    args = build_ghidrecomp_namespace(
        path,
        output_path=output_root,
        project_path=project_path,
        force_analysis=force_analysis,
    )
    args.gzf = True
    args.gzf_path = gzf_path
    args.skip_symbols = skip_symbols

    runner = decompile_runner
    if runner is None:
        if ghidrecomp_decompile is None:
            raise RuntimeError("ghidrecomp is not installed")
        runner = ghidrecomp_decompile

    runner(args)

    if gen_proj_bin_name_from_path is None or get_bin_output_path is None:
        raise RuntimeError("ghidrecomp is not installed")

    bin_name = gen_proj_bin_name_from_path(path)
    bin_output = Path(get_bin_output_path(output_root, bin_name))
    gzf_files = _collect_artifact_files(gzf_storage.resolve(), suffix=".gzf")

    return {
        "action": "run-batch-export-gzf",
        "binaryPath": str(path),
        "outputPath": str(output_root),
        "gzfPath": str(gzf_storage.resolve()),
        "projectPath": str(Path(project_path).expanduser().resolve()),
        "binOutputPath": str(bin_output),
        "gzfFiles": gzf_files,
        "counts": {"gzfFiles": len(gzf_files)},
        "suggestedTierEscalation": _suggest_tier_escalation(gzf_count=len(gzf_files)),
    }
