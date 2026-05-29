"""Tier 1 batch SAST scan — ghidrecomp.decompile with --sast."""

from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path
from typing import Any, Callable

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
_SAST_SUBDIR = "sast"
_KNOWN_SARIF_NAMES = ("semgrep.sarif", "codeql.sarif")
_SUMMARY_FILENAME = "sast_summary.json"


def _normalize_semgrep_rules(rules: list[str] | None) -> list[str] | None:
    if not rules:
        return None
    normalized: list[str] = []
    for item in rules:
        if not item:
            continue
        for part in str(item).split(","):
            stripped = part.strip()
            if stripped:
                normalized.append(stripped)
    return normalized or None


def _normalize_codeql_rules(codeql_rules: str | None) -> str | None:
    if not codeql_rules:
        return None
    parts = [part.strip() for part in str(codeql_rules).split(",") if part.strip()]
    return ",".join(parts) if parts else None


def _resolve_sast_directory(output_root: Path, binary_path: Path) -> Path:
    """Predict bin_output/sast path without running decompile (for skip payloads)."""
    if gen_proj_bin_name_from_path is not None and get_bin_output_path is not None:
        bin_name = gen_proj_bin_name_from_path(binary_path)
        bin_output = Path(get_bin_output_path(output_root, bin_name))
        return bin_output / _SAST_SUBDIR
    return output_root / "results" / "bins" / binary_path.name / _SAST_SUBDIR


def _collect_sarif_files(sast_directory: Path) -> list[str]:
    if not sast_directory.is_dir():
        return []
    collected: list[str] = []
    for name in _KNOWN_SARIF_NAMES:
        candidate = sast_directory / name
        if candidate.is_file():
            collected.append(str(candidate.resolve()))
    return collected


def _load_summary(sast_directory: Path) -> dict[str, Any] | None:
    summary_path = sast_directory / _SUMMARY_FILENAME
    if not summary_path.is_file():
        return None
    try:
        with summary_path.open(encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Failed to read SAST summary at %s: %s", summary_path, exc)
        return None
    return payload if isinstance(payload, dict) else None


def _suggest_tier_escalation(*, sarif_count: int, sast_available: bool) -> dict[str, Any]:
    if not sast_available:
        return {
            "recommendedTier": 2,
            "reason": "Semgrep is not on PATH; install semgrep or use run-batch-decompile then scan C files externally.",
            "nextTools": ["run-batch-decompile", "open-project", "decompile-function"],
        }
    if sarif_count == 0:
        return {
            "recommendedTier": 2,
            "reason": "SAST run completed but no SARIF artifacts were found; verify binary path and decompile output.",
            "nextTools": ["run-file-triage", "run-batch-decompile", "open-project"],
        }
    return {
        "recommendedTier": 2,
        "reason": "SAST SARIF exported; review findings or escalate to Ghidra MCP for interactive verification.",
        "nextTools": ["open-project", "decompile-function", "get-references"],
    }


def _default_semgrep_checker() -> bool:
    return shutil.which("semgrep") is not None


def build_batch_sast_payload(
    binary_path: Path,
    *,
    output_path: str | Path = _DEFAULT_OUTPUT_PATH,
    project_path: str | Path = _DEFAULT_PROJECT_PATH,
    function_filter: str | None = None,
    force_analysis: bool = False,
    semgrep_rules: list[str] | None = None,
    codeql_rules: str | None = None,
    decompile_runner: Any | None = None,
    semgrep_checker: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Run ghidrecomp with SAST enabled and return unified JSON artifact metadata."""
    path = binary_path.expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Binary not found or not a file: {path}")

    output_root = Path(output_path).expanduser().resolve()
    normalized_semgrep_rules = _normalize_semgrep_rules(semgrep_rules)
    normalized_codeql_rules = _normalize_codeql_rules(codeql_rules)

    checker = semgrep_checker or _default_semgrep_checker
    sast_available = bool(checker())

    sast_directory = _resolve_sast_directory(output_root, path)

    if not sast_available:
        return {
            "action": "run-batch-sast-scan",
            "binaryPath": str(path),
            "outputPath": str(output_root),
            "projectPath": str(Path(project_path).expanduser().resolve()),
            "sastPath": str(sast_directory.resolve()),
            "semgrepRules": normalized_semgrep_rules or [],
            "codeqlRules": normalized_codeql_rules,
            "sast": {
                "available": False,
                "skipped": "semgrep not found on PATH",
            },
            "sarifFiles": [],
            "counts": {"sarifFiles": 0},
            "suggestedTierEscalation": _suggest_tier_escalation(
                sarif_count=0,
                sast_available=False,
            ),
        }

    args = build_ghidrecomp_namespace(
        path,
        output_path=output_root,
        project_path=project_path,
        function_filter=function_filter,
        force_analysis=force_analysis,
    )
    args.sast = True
    args.semgrep_rules = normalized_semgrep_rules
    args.codeql_rules = normalized_codeql_rules

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
    sast_directory = _resolve_sast_directory(output_root, path)
    sarif_files = _collect_sarif_files(sast_directory)
    summary = _load_summary(sast_directory)

    payload: dict[str, Any] = {
        "action": "run-batch-sast-scan",
        "binaryPath": str(path),
        "outputPath": str(output_root),
        "projectPath": str(Path(project_path).expanduser().resolve()),
        "binOutputPath": str(bin_output),
        "sastPath": str(sast_directory.resolve()),
        "semgrepRules": normalized_semgrep_rules or [],
        "codeqlRules": normalized_codeql_rules,
        "sast": {"available": True},
        "sarifFiles": sarif_files,
        "counts": {"sarifFiles": len(sarif_files)},
        "suggestedTierEscalation": _suggest_tier_escalation(
            sarif_count=len(sarif_files),
            sast_available=True,
        ),
    }
    if summary is not None:
        payload["summary"] = summary
    return payload
