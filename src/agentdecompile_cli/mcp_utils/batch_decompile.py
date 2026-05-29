"""Tier 1 batch decompile — ghidrecomp.decompile wrapper for offline export."""

from __future__ import annotations

import logging
from pathlib import Path
from types import SimpleNamespace
from typing import Any

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


def _collect_artifact_files(directory: Path, *, suffix: str) -> list[str]:
    if not directory.is_dir():
        return []
    return sorted(str(path.resolve()) for path in directory.rglob(f"*{suffix}") if path.is_file())


def _suggest_tier_escalation(*, decompiled_count: int, callgraph_count: int) -> dict[str, Any]:
    if decompiled_count == 0 and callgraph_count == 0:
        return {
            "recommendedTier": 2,
            "reason": "Batch export produced no artifacts; verify binary path and filters, then try open-project.",
            "nextTools": ["run-file-triage", "open-project", "analyze-program"],
        }
    return {
        "recommendedTier": 2,
        "reason": "Batch export complete; use Ghidra MCP list/search/decompile for interactive xref loops.",
        "nextTools": ["open-project", "list-functions", "get-references", "decompile-function"],
    }


def build_ghidrecomp_namespace(
    binary_path: Path,
    *,
    output_path: str | Path = _DEFAULT_OUTPUT_PATH,
    project_path: str | Path = _DEFAULT_PROJECT_PATH,
    function_filter: str | None = None,
    skip_cache: bool = False,
    force_analysis: bool = False,
    callgraphs: bool = False,
) -> SimpleNamespace:
    """Build argparse.Namespace-compatible args for ghidrecomp.decompile."""
    filters: list[str] = [function_filter] if function_filter else []
    return SimpleNamespace(
        bin=str(binary_path.resolve()),
        cppexport=False,
        filters=filters,
        project_path=str(Path(project_path)),
        gzf=False,
        gzf_path="gzfs",
        gdt=[],
        output_path=str(Path(output_path)),
        skip_cache=skip_cache,
        sym_file_path=None,
        symbols_path="symbols",
        skip_symbols=True,
        thread_count=2,
        va=False,
        fa=force_analysis,
        max_ram_percent=50.0,
        print_flags=False,
        callgraphs=callgraphs,
        callgraph_filter=".",
        max_display_depth=None,
        max_time_cg_gen=5,
        cg_direction="calling",
        no_call_refs=False,
        condense_threshold=50,
        top_layers=None,
        bottom_layers=None,
        bsim=False,
        bsim_sig_path="bsim-xmls",
        bsim_template="medium_nosize",
        bsim_cat=None,
        sast=False,
        semgrep_rules=None,
        codeql_rules=None,
    )


def build_batch_decompile_payload(
    binary_path: Path,
    *,
    output_path: str | Path = _DEFAULT_OUTPUT_PATH,
    project_path: str | Path = _DEFAULT_PROJECT_PATH,
    function_filter: str | None = None,
    skip_cache: bool = False,
    force_analysis: bool = False,
    callgraphs: bool = False,
    decompile_runner: Any | None = None,
) -> dict[str, Any]:
    """Run ghidrecomp batch decompile and return unified JSON artifact metadata."""
    path = binary_path.expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Binary not found or not a file: {path}")

    output_root = Path(output_path).expanduser().resolve()
    args = build_ghidrecomp_namespace(
        path,
        output_path=output_root,
        project_path=project_path,
        function_filter=function_filter,
        skip_cache=skip_cache,
        force_analysis=force_analysis,
        callgraphs=callgraphs,
    )

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
    decomp_dir = bin_output / "decomp"
    callgraph_dir = bin_output / "callgraphs"

    decompiled_files = _collect_artifact_files(decomp_dir, suffix=".c")
    callgraph_files = _collect_artifact_files(callgraph_dir, suffix=".md")

    return {
        "action": "run-batch-decompile",
        "binaryPath": str(path),
        "outputPath": str(output_root),
        "projectPath": str(Path(project_path).expanduser().resolve()),
        "binOutputPath": str(bin_output),
        "decompiledFiles": decompiled_files,
        "callgraphFiles": callgraph_files,
        "counts": {
            "decompiledFiles": len(decompiled_files),
            "callgraphFiles": len(callgraph_files),
        },
        "suggestedTierEscalation": _suggest_tier_escalation(
            decompiled_count=len(decompiled_files),
            callgraph_count=len(callgraph_files),
        ),
    }
