"""Tier 0 external RE tool scans — yara, capa, binwalk via subprocess."""

from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path
from typing import Any

from agentdecompile_cli.mcp_utils.static_triage import _run_command

logger = logging.getLogger(__name__)

_SUPPORTED_TOOLS = frozenset({"yara", "capa", "binwalk"})
_DEFAULT_OUTPUT_LIMIT = 100
_DEFAULT_TIMEOUT_MS = 60_000


def _normalize_tool_name(tool: str) -> str:
    normalized = (tool or "").strip().lower()
    if normalized not in _SUPPORTED_TOOLS:
        raise ValueError(f"Unsupported tool '{tool}'. Expected one of: yara, capa, binwalk.")
    return normalized


def _build_command(
    tool: str,
    binary_path: Path,
    *,
    rules_path: Path | None,
) -> list[str]:
    if tool == "yara":
        if rules_path is None:
            raise ValueError("rulesPath is required when tool is yara")
        if not rules_path.is_file():
            raise FileNotFoundError(f"YARA rules file not found: {rules_path}")
        return ["yara", "-s", str(rules_path), str(binary_path)]
    if tool == "capa":
        return ["capa", "--json", str(binary_path)]
    return ["binwalk", str(binary_path)]


def _parse_capa_json(stdout: str) -> dict[str, Any] | None:
    text = stdout.strip()
    if not text:
        return None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _suggest_tier_escalation(tool: str, *, line_count: int, capa_json: dict[str, Any] | None) -> dict[str, Any]:
    if tool == "capa" and capa_json:
        rules = capa_json.get("rules") or capa_json.get("matches")
        if isinstance(rules, dict) and rules:
            return {
                "recommendedTier": 2,
                "reason": "capa reported capability matches; use Ghidra MCP for function-level confirmation.",
                "nextTools": ["open-project", "list-functions", "decompile-function"],
            }
    if tool == "yara" and line_count > 0:
        return {
            "recommendedTier": 2,
            "reason": "yara reported rule matches; escalate for xref/decompile validation in Ghidra.",
            "nextTools": ["open-project", "list-functions", "get-references"],
        }
    if tool == "binwalk" and line_count > 1:
        return {
            "recommendedTier": 0,
            "reason": "binwalk found embedded signatures; extract/carve before Ghidra import when appropriate.",
            "nextTools": ["run-file-triage", "run-external-re-scan"],
        }
    return {
        "recommendedTier": 2,
        "reason": "External scan complete; open-project if interactive RE is still required.",
        "nextTools": ["open-project", "run-file-triage"],
    }


def build_external_re_scan_payload(
    binary_path: Path,
    *,
    tool: str,
    rules_path: str | Path | None = None,
    output_limit: int = _DEFAULT_OUTPUT_LIMIT,
    timeout_ms: int = _DEFAULT_TIMEOUT_MS,
    command_runner: Any | None = None,
) -> dict[str, Any]:
    """Run yara/capa/binwalk against a file and return unified Tier 0 JSON."""
    path = binary_path.expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Binary not found or not a file: {path}")

    tool_name = _normalize_tool_name(tool)
    rules_file = Path(rules_path).expanduser().resolve() if rules_path else None

    if shutil.which(tool_name) is None:
        return {
            "action": "run-external-re-scan",
            "binaryPath": str(path),
            "tool": tool_name,
            "scan": {
                "available": False,
                "skipped": "binary not on PATH",
            },
            "lines": [],
            "counts": {"lines": 0},
            "suggestedTierEscalation": {
                "recommendedTier": 0,
                "reason": f"{tool_name} is not installed; install it or use run-file-triage probes only.",
                "nextTools": ["run-file-triage"],
            },
        }

    command = _build_command(tool_name, path, rules_path=rules_file)
    runner = command_runner or _run_command
    scan_result = runner(command, timeout_ms=timeout_ms)

    stdout = scan_result.get("stdout") or ""
    stderr = scan_result.get("stderr") or ""
    combined_lines = [line for line in (stdout + "\n" + stderr).splitlines() if line.strip()]
    limit = max(0, output_limit)
    lines = combined_lines[:limit]

    capa_json = _parse_capa_json(stdout) if tool_name == "capa" else None

    payload: dict[str, Any] = {
        "action": "run-external-re-scan",
        "binaryPath": str(path),
        "tool": tool_name,
        "scan": scan_result,
        "lines": lines,
        "counts": {
            "lines": len(lines),
            "totalLines": len(combined_lines),
            "truncated": len(combined_lines) > len(lines),
        },
        "suggestedTierEscalation": _suggest_tier_escalation(
            tool_name,
            line_count=len(combined_lines),
            capa_json=capa_json,
        ),
    }
    if capa_json is not None:
        payload["parsed"] = capa_json
    if rules_file is not None:
        payload["rulesPath"] = str(rules_file)
    return payload
