"""Tier 1 decomp matching — m2c, objdiff, decomp-permuter without Ghidra MCP session."""

from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path
from typing import Any, Callable

from agentdecompile_cli.mcp_utils.static_triage import _run_command as _default_run_command

logger = logging.getLogger(__name__)

_SUPPORTED_TOOLS = frozenset({"m2c", "objdiff", "permuter"})
_DEFAULT_BUNDLE_TOOLS = ("objdiff", "m2c", "permuter")
_DEFAULT_OUTPUT_LIMIT = 200
_DEFAULT_TIMEOUT_MS = 120_000

CommandRunner = Callable[..., dict[str, Any]]


def _normalize_tool_name(tool: str) -> str:
    normalized = (tool or "").strip().lower()
    aliases = {
        "decomp-permuter": "permuter",
        "decomppermuter": "permuter",
        "objdiff-cli": "objdiff",
        "objdiffcli": "objdiff",
    }
    normalized = aliases.get(normalized, normalized)
    if normalized == "all":
        return "all"
    if normalized not in _SUPPORTED_TOOLS:
        raise ValueError(f"Unsupported tool '{tool}'. Expected one of: m2c, objdiff, permuter, all.")
    return normalized


def _normalize_tools_list(tools: list[str] | None) -> list[str] | None:
    if not tools:
        return None
    normalized: list[str] = []
    seen: set[str] = set()
    for item in tools:
        name = _normalize_tool_name(str(item))
        if name == "all":
            for bundled in _DEFAULT_BUNDLE_TOOLS:
                if bundled not in seen:
                    seen.add(bundled)
                    normalized.append(bundled)
        elif name not in seen:
            seen.add(name)
            normalized.append(name)
    return normalized or None


def _resolve_binary(*candidates: str) -> str | None:
    for name in candidates:
        path = shutil.which(name)
        if path:
            return path
    return None


def _truncate_lines(text: str, output_limit: int) -> tuple[list[str], int]:
    combined_lines = [line for line in text.splitlines() if line.strip()]
    limit = max(0, output_limit)
    lines = combined_lines[:limit]
    return lines, len(combined_lines)


def _missing_tool_result(tool: str, *, binaries: tuple[str, ...]) -> dict[str, Any]:
    names = ", ".join(binaries)
    return {
        "tool": tool,
        "scan": {
            "available": False,
            "skipped": f"binary not on PATH (tried: {names})",
        },
        "lines": [],
        "counts": {"lines": 0},
        "suggestedTierEscalation": {
            "recommendedTier": 1,
            "reason": f"Install {tool} on PATH to verify bytecode matches without Ghidra.",
            "nextTools": ["run-decomp-match"],
        },
    }


def _suggest_after_objdiff(
    *,
    match_percent: float | None,
    unit_name: str | None,
    nonmatching_functions: list[dict[str, Any]],
) -> dict[str, Any]:
    if match_percent is not None and match_percent >= 100.0:
        return {
            "recommendedTier": 1,
            "reason": "Object/unit reports 100% bytecode match; no Ghidra required for verification.",
            "nextTools": ["run-decomp-match"],
        }
    next_tools = ["run-decomp-match", "m2c", "permuter"]
    if nonmatching_functions:
        next_tools.extend(["manage-structures", "decompile-function"])
    reason = (
        f"Bytecode match below 100% for {unit_name or 'object'}; iterate with m2c/permuter before Ghidra."
        if unit_name
        else "Bytecode match below 100%; use m2c for asm→C and permuter for regalloc fixes before Ghidra."
    )
    return {
        "recommendedTier": 2,
        "reason": reason,
        "nextTools": next_tools,
        "note": (
            "match-function uses signature/name/call-graph only — not instruction-level bytecode matching. "
            "Use objdiff here for object verification; use Ghidra MCP for shared-project struct export/checkout."
        ),
    }


def _parse_objdiff_report(stdout: str) -> dict[str, Any] | None:
    text = stdout.strip()
    if not text:
        return None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _summarize_objdiff_report(report: dict[str, Any], *, unit_filter: str | None) -> dict[str, Any]:
    units = report.get("units")
    if not isinstance(units, list):
        return {"units": [], "overallMatchPercent": None, "nonmatchingFunctions": []}

    selected = []
    for entry in units:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or "")
        if unit_filter and name != unit_filter:
            continue
        measures = entry.get("measures") if isinstance(entry.get("measures"), dict) else {}
        match_percent = measures.get("matched_percent")
        if match_percent is None:
            match_percent = measures.get("fuzzy_match_percent")
        functions = entry.get("functions") if isinstance(entry.get("functions"), list) else []
        nonmatching: list[dict[str, Any]] = []
        for fn in functions:
            if not isinstance(fn, dict):
                continue
            pct = fn.get("fuzzy_match_percent")
            if isinstance(pct, (int, float)) and float(pct) < 100.0:
                nonmatching.append(
                    {
                        "name": fn.get("name"),
                        "fuzzyMatchPercent": float(pct),
                        "size": fn.get("size"),
                    }
        )
        selected.append(
            {
                "name": name,
                "matchPercent": float(match_percent) if isinstance(match_percent, (int, float)) else None,
                "totalFunctions": measures.get("total_functions"),
                "matchedFunctions": measures.get("matched_functions"),
                "nonmatchingCount": len(nonmatching),
                "nonmatchingFunctions": nonmatching[:50],
            }
        )

    percents = [u["matchPercent"] for u in selected if u.get("matchPercent") is not None]
    overall = sum(percents) / len(percents) if percents else None
    all_nonmatching: list[dict[str, Any]] = []
    for unit in selected:
        all_nonmatching.extend(unit.get("nonmatchingFunctions") or [])

    return {
        "units": selected,
        "overallMatchPercent": overall,
        "nonmatchingFunctions": all_nonmatching[:100],
    }


def _build_m2c_command(
    *,
    assembly_path: Path | None,
    function_name: str | None,
    target: str | None,
    context_path: Path | None,
    extra_args: list[str] | None,
) -> list[str]:
    binary = _resolve_binary("m2c")
    if binary is None:
        raise FileNotFoundError("m2c is not on PATH (pip install m2c or add m2c.py to PATH).")
    command = [binary]
    if target:
        command.extend(["-t", target])
    if context_path is not None:
        command.extend(["--context", str(context_path)])
    if function_name:
        command.extend(["-f", function_name])
    if extra_args:
        command.extend(extra_args)
    if assembly_path is not None:
        command.append(str(assembly_path))
    return command


def _build_objdiff_report_command(
    *,
    project_path: Path,
    output_path: Path | None,
    working_dir: Path | None,
) -> list[str]:
    binary = _resolve_binary("objdiff-cli")
    if binary is None:
        raise FileNotFoundError("objdiff-cli is not on PATH.")
    command = [binary, "report", "generate", "-p", str(project_path), "-f", "json"]
    if output_path is not None:
        command.extend(["-o", str(output_path)])
    return command


def _build_objdiff_diff_command(
    *,
    target_path: Path | None,
    base_path: Path | None,
    project_path: Path | None,
    unit_name: str | None,
    symbol: str | None,
    output_path: Path | None,
) -> list[str]:
    binary = _resolve_binary("objdiff-cli")
    if binary is None:
        raise FileNotFoundError("objdiff-cli is not on PATH.")
    command = [binary, "diff", "-f", "json"]
    if output_path is not None:
        command.extend(["-o", str(output_path)])
    if project_path is not None:
        command.extend(["-p", str(project_path)])
        if unit_name:
            command.extend(["-u", unit_name])
        if symbol:
            command.append(symbol)
    elif target_path is not None or base_path is not None:
        if target_path is not None:
            command.extend(["-1", str(target_path)])
        if base_path is not None:
            command.extend(["-2", str(base_path)])
        if symbol:
            command.append(symbol)
    else:
        raise ValueError("objdiff requires projectPath or targetObjectPath/baseObjectPath.")
    return command


def _build_permuter_command(
    *,
    permuter_dir: Path,
    permuter_script: Path | None,
    jobs: int | None,
    extra_args: list[str] | None,
) -> list[str]:
    script = permuter_script
    if script is None:
        script_path = _resolve_binary("permuter.py", "permuter")
        if script_path is None:
            raise FileNotFoundError("permuter.py is not on PATH.")
        script = Path(script_path)
    command = ["python3", str(script), str(permuter_dir)]
    if jobs is not None and jobs > 0:
        command.extend(["-j", str(jobs)])
    if extra_args:
        command.extend(extra_args)
    return command


def _run_with_cwd(
    command: list[str],
    *,
    cwd: Path | None,
    timeout_ms: int,
    command_runner: CommandRunner,
) -> dict[str, Any]:
    if cwd is None or command_runner is not _default_run_command:
        return command_runner(command, timeout_ms=timeout_ms)

    import subprocess

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=max(1.0, timeout_ms / 1000.0),
            check=False,
            cwd=str(cwd),
        )
        return {
            "command": command,
            "exitCode": completed.returncode,
            "stdout": (completed.stdout or "").strip(),
            "stderr": (completed.stderr or "").strip(),
            "available": True,
            "cwd": str(cwd),
        }
    except FileNotFoundError:
        return {
            "command": command,
            "exitCode": None,
            "stdout": "",
            "stderr": "",
            "available": False,
            "skipped": "binary not on PATH",
        }
    except subprocess.TimeoutExpired:
        return {
            "command": command,
            "exitCode": None,
            "stdout": "",
            "stderr": "",
            "available": True,
            "error": "timeout",
            "cwd": str(cwd),
        }


def _build_m2c_result(
    *,
    assembly_path: Path | None,
    assembly_text: str | None,
    function_name: str | None,
    target: str | None,
    context_path: Path | None,
    extra_args: list[str] | None,
    output_limit: int,
    timeout_ms: int,
    command_runner: CommandRunner,
) -> dict[str, Any]:
    asm_path = assembly_path
    if asm_path is None and assembly_text:
        raise ValueError("assemblyText requires assemblyPath for file-based m2c invocation.")
    if asm_path is None:
        raise ValueError("assemblyPath is required for m2c.")
    asm_path = asm_path.expanduser().resolve()
    if not asm_path.is_file():
        raise FileNotFoundError(f"Assembly file not found: {asm_path}")

    if _resolve_binary("m2c") is None:
        return _missing_tool_result("m2c", binaries=("m2c",))

    ctx = context_path
    if ctx is not None:
        ctx = ctx.expanduser().resolve()
        if not ctx.is_file():
            raise FileNotFoundError(f"Context file not found: {ctx}")

    command = _build_m2c_command(
        assembly_path=asm_path,
        function_name=function_name,
        target=target,
        context_path=ctx,
        extra_args=extra_args,
    )
    scan = command_runner(command, timeout_ms=timeout_ms)
    stdout = scan.get("stdout") or ""
    stderr = scan.get("stderr") or ""
    lines, total = _truncate_lines(stdout + "\n" + stderr, output_limit)

    return {
        "tool": "m2c",
        "scan": scan,
        "lines": lines,
        "counts": {"lines": len(lines), "totalLines": total, "truncated": total > len(lines)},
        "decompiledC": stdout if stdout else None,
        "suggestedTierEscalation": {
            "recommendedTier": 1,
            "reason": "m2c output is a starting point; verify with objdiff before opening Ghidra.",
            "nextTools": ["run-decomp-match", "permuter"],
        },
    }


def _build_objdiff_result(
    *,
    project_path: Path | None,
    unit_name: str | None,
    target_object_path: Path | None,
    base_object_path: Path | None,
    symbol: str | None,
    objdiff_mode: str,
    output_limit: int,
    timeout_ms: int,
    command_runner: CommandRunner,
) -> dict[str, Any]:
    mode = (objdiff_mode or "report").strip().lower()
    if mode not in {"report", "diff"}:
        raise ValueError("objdiffMode must be 'report' or 'diff'.")

    if mode == "report" and project_path is None:
        raise ValueError("projectPath is required for objdiff report mode.")

    if _resolve_binary("objdiff-cli") is None:
        return _missing_tool_result("objdiff", binaries=("objdiff-cli",))

    cwd: Path | None = None
    if mode == "report":
        proj = project_path.expanduser().resolve()  # type: ignore[union-attr]
        if not proj.is_dir():
            raise FileNotFoundError(f"Project directory not found: {proj}")
        cwd = proj
        command = _build_objdiff_report_command(project_path=Path("."), output_path=None, working_dir=proj)
    else:
        proj = project_path.expanduser().resolve() if project_path else None
        if proj is not None:
            if not unit_name and not symbol:
                raise ValueError(
                    "objdiff diff mode with projectPath requires unitName or symbol."
                )
            cwd = proj
            command = _build_objdiff_diff_command(
                target_path=None,
                base_path=None,
                project_path=Path("."),
                unit_name=unit_name,
                symbol=symbol,
                output_path=Path("-"),
            )
        else:
            target = target_object_path.expanduser().resolve() if target_object_path else None
            base = base_object_path.expanduser().resolve() if base_object_path else None
            if target is None and base is None:
                raise ValueError("objdiff diff mode requires projectPath or target/base object paths.")
            if target is not None and not target.is_file():
                raise FileNotFoundError(f"Target object not found: {target}")
            if base is not None and not base.is_file():
                raise FileNotFoundError(f"Base object not found: {base}")
            command = _build_objdiff_diff_command(
                target_path=target,
                base_path=base,
                project_path=None,
                unit_name=None,
                symbol=symbol,
                output_path=Path("-"),
            )

    scan = _run_with_cwd(command, cwd=cwd, timeout_ms=timeout_ms, command_runner=command_runner)
    stdout = scan.get("stdout") or ""
    stderr = scan.get("stderr") or ""
    lines, total = _truncate_lines(stdout + "\n" + stderr, output_limit)
    parsed = _parse_objdiff_report(stdout)
    summary: dict[str, Any] | None = None
    match_percent: float | None = None
    nonmatching: list[dict[str, Any]] = []
    if parsed is not None and mode == "report":
        summary = _summarize_objdiff_report(parsed, unit_filter=unit_name)
        match_percent = summary.get("overallMatchPercent")
        nonmatching = summary.get("nonmatchingFunctions") or []

    result: dict[str, Any] = {
        "tool": "objdiff",
        "objdiffMode": mode,
        "scan": scan,
        "lines": lines,
        "counts": {"lines": len(lines), "totalLines": total, "truncated": total > len(lines)},
        "suggestedTierEscalation": _suggest_after_objdiff(
            match_percent=float(match_percent) if isinstance(match_percent, (int, float)) else None,
            unit_name=unit_name,
            nonmatching_functions=nonmatching,
        ),
    }
    if parsed is not None:
        result["parsed"] = parsed
    if summary is not None:
        result["summary"] = summary
    if unit_name:
        result["unitName"] = unit_name
    return result


def _build_permuter_result(
    *,
    permuter_dir: Path,
    permuter_script: Path | None,
    jobs: int | None,
    extra_args: list[str] | None,
    output_limit: int,
    timeout_ms: int,
    command_runner: CommandRunner,
) -> dict[str, Any]:
    directory = permuter_dir.expanduser().resolve()
    if not directory.is_dir():
        raise FileNotFoundError(f"Permuter directory not found: {directory}")

    try:
        command = _build_permuter_command(
            permuter_dir=directory,
            permuter_script=permuter_script,
            jobs=jobs,
            extra_args=extra_args,
        )
    except FileNotFoundError:
        return _missing_tool_result("permuter", binaries=("permuter.py", "permuter"))

    scan = command_runner(command, timeout_ms=timeout_ms)
    stdout = scan.get("stdout") or ""
    stderr = scan.get("stderr") or ""
    lines, total = _truncate_lines(stdout + "\n" + stderr, output_limit)

    return {
        "tool": "permuter",
        "permuterDir": str(directory),
        "scan": scan,
        "lines": lines,
        "counts": {"lines": len(lines), "totalLines": total, "truncated": total > len(lines)},
        "suggestedTierEscalation": {
            "recommendedTier": 1,
            "reason": "After permuter finds a candidate, re-run objdiff to confirm bytecode match.",
            "nextTools": ["run-decomp-match"],
        },
    }


def _aggregate_tier_escalation(results: dict[str, dict[str, Any]]) -> dict[str, Any]:
    best: dict[str, Any] | None = None
    for entry in results.values():
        suggestion = entry.get("suggestedTierEscalation")
        if not isinstance(suggestion, dict):
            continue
        tier = suggestion.get("recommendedTier")
        if not isinstance(tier, int):
            continue
        if best is None or tier > int(best.get("recommendedTier", 0)):
            best = suggestion
    return best or {
        "recommendedTier": 1,
        "reason": "Decomp match bundle complete; use objdiff for bytecode verification before Ghidra.",
        "nextTools": ["run-decomp-match"],
    }


def build_decomp_match_payload(
    *,
    tool: str,
    assembly_path: str | Path | None = None,
    assembly_text: str | None = None,
    function_name: str | None = None,
    target: str | None = None,
    context_path: str | Path | None = None,
    project_path: str | Path | None = None,
    unit_name: str | None = None,
    target_object_path: str | Path | None = None,
    base_object_path: str | Path | None = None,
    symbol: str | None = None,
    objdiff_mode: str = "report",
    permuter_dir: str | Path | None = None,
    permuter_script: str | Path | None = None,
    jobs: int | None = None,
    extra_args: list[str] | None = None,
    output_limit: int = _DEFAULT_OUTPUT_LIMIT,
    timeout_ms: int = _DEFAULT_TIMEOUT_MS,
    command_runner: CommandRunner | None = None,
) -> dict[str, Any]:
    """Run one decomp-matching tool and return unified Tier 1 JSON."""
    tool_name = _normalize_tool_name(tool)
    runner = command_runner or _default_run_command

    if tool_name == "all":
        return build_decomp_match_bundle_payload(
            tools=list(_DEFAULT_BUNDLE_TOOLS),
            assembly_path=assembly_path,
            function_name=function_name,
            target=target,
            context_path=context_path,
            project_path=project_path,
            unit_name=unit_name,
            target_object_path=target_object_path,
            base_object_path=base_object_path,
            symbol=symbol,
            objdiff_mode=objdiff_mode,
            permuter_dir=permuter_dir,
            permuter_script=permuter_script,
            jobs=jobs,
            extra_args=extra_args,
            output_limit=output_limit,
            timeout_ms=timeout_ms,
            command_runner=runner,
        )

    asm = Path(assembly_path).expanduser().resolve() if assembly_path else None
    proj = Path(project_path).expanduser().resolve() if project_path else None
    perm = Path(permuter_dir).expanduser().resolve() if permuter_dir else None
    script = Path(permuter_script).expanduser().resolve() if permuter_script else None

    if tool_name == "m2c":
        single = _build_m2c_result(
            assembly_path=asm,
            assembly_text=assembly_text,
            function_name=function_name,
            target=target,
            context_path=Path(context_path) if context_path else None,
            extra_args=extra_args,
            output_limit=output_limit,
            timeout_ms=timeout_ms,
            command_runner=runner,
        )
    elif tool_name == "objdiff":
        single = _build_objdiff_result(
            project_path=proj,
            unit_name=unit_name,
            target_object_path=Path(target_object_path) if target_object_path else None,
            base_object_path=Path(base_object_path) if base_object_path else None,
            symbol=symbol,
            objdiff_mode=objdiff_mode,
            output_limit=output_limit,
            timeout_ms=timeout_ms,
            command_runner=runner,
        )
    else:
        if perm is None:
            raise ValueError("permuterDir is required when tool is permuter.")
        single = _build_permuter_result(
            permuter_dir=perm,
            permuter_script=script,
            jobs=jobs,
            extra_args=extra_args,
            output_limit=output_limit,
            timeout_ms=timeout_ms,
            command_runner=runner,
        )

    return {
        "action": "run-decomp-match",
        "mode": "single",
        "routing": {
            "ghidraRequired": False,
            "sharedProjectNote": (
                "For versioned/shared Ghidra Server projects, use open-project/checkout-program and "
                "manage-structures (Tier 2–3) only for struct export and check-in — not for bytecode verify."
            ),
            "bytecodeMatchTool": "objdiff",
            "notBytecodeMatch": "match-function",
        },
        **single,
    }


def build_decomp_match_bundle_payload(
    *,
    tools: list[str],
    assembly_path: str | Path | None = None,
    function_name: str | None = None,
    target: str | None = None,
    context_path: str | Path | None = None,
    project_path: str | Path | None = None,
    unit_name: str | None = None,
    target_object_path: str | Path | None = None,
    base_object_path: str | Path | None = None,
    symbol: str | None = None,
    objdiff_mode: str = "report",
    permuter_dir: str | Path | None = None,
    permuter_script: str | Path | None = None,
    jobs: int | None = None,
    extra_args: list[str] | None = None,
    output_limit: int = _DEFAULT_OUTPUT_LIMIT,
    timeout_ms: int = _DEFAULT_TIMEOUT_MS,
    command_runner: CommandRunner | None = None,
) -> dict[str, Any]:
    """Run multiple decomp-matching tools when inputs are available."""
    tool_names = _normalize_tools_list(tools)
    if not tool_names:
        raise ValueError("tools must include at least one of: m2c, objdiff, permuter")

    runner = command_runner or _default_run_command
    asm = Path(assembly_path).expanduser().resolve() if assembly_path else None
    proj = Path(project_path).expanduser().resolve() if project_path else None
    perm = Path(permuter_dir).expanduser().resolve() if permuter_dir else None
    script = Path(permuter_script).expanduser().resolve() if permuter_script else None

    scans: dict[str, dict[str, Any]] = {}
    ran = 0
    skipped = 0
    for name in tool_names:
        try:
            if name == "m2c":
                if asm is None:
                    scans[name] = {
                        "tool": name,
                        "scan": {"available": False, "skipped": "assemblyPath not provided"},
                        "lines": [],
                        "counts": {"lines": 0},
                    }
                    skipped += 1
                    continue
                scans[name] = _build_m2c_result(
                    assembly_path=asm,
                    assembly_text=None,
                    function_name=function_name,
                    target=target,
                    context_path=Path(context_path) if context_path else None,
                    extra_args=extra_args,
                    output_limit=output_limit,
                    timeout_ms=timeout_ms,
                    command_runner=runner,
                )
            elif name == "objdiff":
                if proj is None and target_object_path is None and base_object_path is None:
                    scans[name] = {
                        "tool": name,
                        "scan": {
                            "available": False,
                            "skipped": "projectPath or target/base object paths not provided",
                        },
                        "lines": [],
                        "counts": {"lines": 0},
                    }
                    skipped += 1
                    continue
                scans[name] = _build_objdiff_result(
                    project_path=proj,
                    unit_name=unit_name,
                    target_object_path=Path(target_object_path) if target_object_path else None,
                    base_object_path=Path(base_object_path) if base_object_path else None,
                    symbol=symbol,
                    objdiff_mode=objdiff_mode,
                    output_limit=output_limit,
                    timeout_ms=timeout_ms,
                    command_runner=runner,
                )
            else:
                if perm is None:
                    scans[name] = {
                        "tool": name,
                        "scan": {"available": False, "skipped": "permuterDir not provided"},
                        "lines": [],
                        "counts": {"lines": 0},
                    }
                    skipped += 1
                    continue
                scans[name] = _build_permuter_result(
                    permuter_dir=perm,
                    permuter_script=script,
                    jobs=jobs,
                    extra_args=extra_args,
                    output_limit=output_limit,
                    timeout_ms=timeout_ms,
                    command_runner=runner,
                )
            if scans[name].get("scan", {}).get("available", True):
                ran += 1
            else:
                skipped += 1
        except (FileNotFoundError, ValueError) as exc:
            scans[name] = {
                "tool": name,
                "scan": {"available": False, "error": str(exc)},
                "lines": [],
                "counts": {"lines": 0},
            }
            skipped += 1

    return {
        "action": "run-decomp-match",
        "mode": "bundle",
        "scans": scans,
        "counts": {"ran": ran, "skipped": skipped, "total": len(tool_names)},
        "routing": {
            "ghidraRequired": False,
            "sharedProjectNote": (
                "Shared/versioned projects: Ghidra MCP for checkout, struct export, check-in only."
            ),
            "bytecodeMatchTool": "objdiff",
            "notBytecodeMatch": "match-function",
        },
        "suggestedTierEscalation": _aggregate_tier_escalation(scans),
    }
