"""Tier 1 batch BSim signatures — ghidrecomp.decompile with --bsim."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable

from agentdecompile_cli.mcp_utils.batch_decompile import build_ghidrecomp_namespace

try:
    from ghidrecomp.bsim import has_bsim as _default_has_bsim
    from ghidrecomp.decompile import decompile as ghidrecomp_decompile
    from ghidrecomp.decompile import gen_proj_bin_name_from_path, get_bin_output_path
except ImportError:  # pragma: no cover - optional in minimal test envs
    _default_has_bsim = None
    ghidrecomp_decompile = None
    gen_proj_bin_name_from_path = None
    get_bin_output_path = None

logger = logging.getLogger(__name__)

_DEFAULT_OUTPUT_PATH = "ghidrecomps"
_DEFAULT_PROJECT_PATH = "ghidra_projects"
_DEFAULT_BSIM_SIG_PATH = "bsim-xmls"
_DEFAULT_BSIM_TEMPLATE = "medium_nosize"


def _resolve_bsim_sig_directory(output_root: Path, bsim_sig_path: str) -> Path:
    """Mirror ghidrecomp.decompile bsim_sig_path resolution."""
    if bsim_sig_path in {"bsim-xmls", "bsim_xmls"}:
        return output_root / bsim_sig_path
    return output_root / Path(bsim_sig_path)


def _collect_signature_files(directory: Path) -> list[str]:
    if not directory.is_dir():
        return []
    return sorted(str(path.resolve()) for path in directory.rglob("*") if path.is_file())


def _normalize_bsim_categories(categories: list[str] | None) -> list[str] | None:
    if not categories:
        return None
    normalized = [item.strip() for item in categories if item and item.strip()]
    return normalized or None


def _suggest_tier_escalation(*, signature_count: int, bsim_available: bool) -> dict[str, Any]:
    if not bsim_available:
        return {
            "recommendedTier": 2,
            "reason": "BSim is not available in this Ghidra install; use open-project and match-function for cross-binary correlation.",
            "nextTools": ["open-project", "match-function", "list-functions"],
        }
    if signature_count == 0:
        return {
            "recommendedTier": 2,
            "reason": "BSim run completed but no signature files were found; verify binary path and filters.",
            "nextTools": ["run-file-triage", "open-project", "analyze-program"],
        }
    return {
        "recommendedTier": 2,
        "reason": "BSim signatures exported; import into a BSim database or use match-function for cross-binary work.",
        "nextTools": ["open-project", "match-function", "list-functions"],
    }


def _default_bsim_checker() -> bool:
    if _default_has_bsim is None:
        return False
    return bool(_default_has_bsim())


def build_batch_bsim_payload(
    binary_path: Path,
    *,
    output_path: str | Path = _DEFAULT_OUTPUT_PATH,
    bsim_sig_path: str = _DEFAULT_BSIM_SIG_PATH,
    bsim_template: str = _DEFAULT_BSIM_TEMPLATE,
    bsim_categories: list[str] | None = None,
    project_path: str | Path = _DEFAULT_PROJECT_PATH,
    function_filter: str | None = None,
    force_analysis: bool = False,
    decompile_runner: Any | None = None,
    bsim_checker: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Run ghidrecomp with BSim enabled and return unified JSON artifact metadata."""
    path = binary_path.expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Binary not found or not a file: {path}")

    output_root = Path(output_path).expanduser().resolve()
    sig_storage = _resolve_bsim_sig_directory(output_root, bsim_sig_path)
    categories = _normalize_bsim_categories(bsim_categories)

    checker = bsim_checker or _default_bsim_checker
    bsim_available = bool(checker())

    if not bsim_available:
        return {
            "action": "run-batch-bsim-signatures",
            "binaryPath": str(path),
            "outputPath": str(output_root),
            "bsimSigPath": str(sig_storage.resolve()),
            "projectPath": str(Path(project_path).expanduser().resolve()),
            "bsimTemplate": bsim_template,
            "bsimCategories": categories or [],
            "bsim": {
                "available": False,
                "skipped": "BSim not present in Ghidra install",
            },
            "signatureFiles": [],
            "counts": {"signatureFiles": 0},
            "suggestedTierEscalation": _suggest_tier_escalation(
                signature_count=0,
                bsim_available=False,
            ),
        }

    args = build_ghidrecomp_namespace(
        path,
        output_path=output_root,
        project_path=project_path,
        function_filter=function_filter,
        force_analysis=force_analysis,
    )
    args.bsim = True
    args.bsim_sig_path = bsim_sig_path
    args.bsim_template = bsim_template
    args.bsim_cat = categories

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
    signature_files = _collect_signature_files(sig_storage.resolve())

    return {
        "action": "run-batch-bsim-signatures",
        "binaryPath": str(path),
        "outputPath": str(output_root),
        "bsimSigPath": str(sig_storage.resolve()),
        "projectPath": str(Path(project_path).expanduser().resolve()),
        "binOutputPath": str(bin_output),
        "bsimTemplate": bsim_template,
        "bsimCategories": categories or [],
        "bsim": {"available": True},
        "signatureFiles": signature_files,
        "counts": {"signatureFiles": len(signature_files)},
        "suggestedTierEscalation": _suggest_tier_escalation(
            signature_count=len(signature_files),
            bsim_available=True,
        ),
    }
