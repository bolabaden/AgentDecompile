"""Shared AgentDecompile MCP tool-seq bridge for recovery executors."""

from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .state import atomic_write_json, now

SCHEMA = "agentdecompile.mcp-tool-seq-last.v1"
CLAIM_BOUNDARY = "advisory MCP execution only; does not establish objdiff-verified-semantic proof"


def resolve_mcp_server_url() -> str | None:
    for key in (
        "AGENTDECOMPILE_MCP_SERVER_URL",
        "AGENT_DECOMPILE_MCP_SERVER_URL",
        "AGENTDECOMPILE_SERVER_URL",
    ):
        value = os.environ.get(key, "").strip()
        if value:
            return value
    return None


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def resolve_import_binary_path(work_dir: Path) -> str | None:
    """Filesystem path to import/open in Ghidra for this reconstruct work dir."""

    work_dir = work_dir.resolve()
    analysis = _load_json(work_dir / "analysis-target.json")
    for key in ("analysisBinaryPath", "originalBinaryPath"):
        value = str(analysis.get(key) or "").strip()
        if value and Path(value).is_file():
            return value
    target = _load_json(work_dir / "target.json")
    for key in ("binaryPath", "inputPath"):
        value = str(target.get(key) or "").strip()
        if value and Path(value).is_file():
            return value
    return None


def resolve_program_path(work_dir: Path) -> str | None:
    work_dir = work_dir.resolve()
    override = os.environ.get("AGENTDECOMPILE_PROGRAM_PATH", "").strip()
    if override:
        return override
    analysis = _load_json(work_dir / "analysis-target.json")
    for key in ("programPath", "ghidraProgramPath"):
        value = str(analysis.get(key) or "").strip()
        if value:
            return value
    import_path = resolve_import_binary_path(work_dir)
    if import_path:
        return Path(import_path).name
    target = _load_json(work_dir / "target.json")
    for key in ("programPath", "preferredName", "stableId"):
        value = str(target.get(key) or "").strip()
        if value:
            return value
    binary = str(target.get("binaryPath") or target.get("inputPath") or "").strip()
    if binary:
        return Path(binary).name
    return None


def bootstrap_local_program_steps(work_dir: Path) -> list[dict[str, Any]]:
    """Prepend open-project for local PyGhidra CLI when no remote MCP server is configured."""

    if os.environ.get("AGENTDECOMPILE_SKIP_PROGRAM_BOOTSTRAP", "").strip().lower() in {"1", "true", "yes"}:
        return []
    import_path = resolve_import_binary_path(work_dir)
    if not import_path:
        return []
    enrich = _load_json(work_dir / "facts" / "enrich-receipt.json")
    enrich_complete = str(enrich.get("status") or "") == "complete"
    steps: list[dict[str, Any]] = [
        {
            "name": "open-project",
            "arguments": {
                "path": import_path,
                "analyzeAfterImport": not enrich_complete,
            },
        },
    ]
    if not enrich_complete:
        steps.append({"name": "analyze-program", "arguments": {}})
    return steps


def resolve_enrich_ghidra_project_name(work_dir: Path) -> str | None:
    enrich = _load_json(work_dir.resolve() / "facts" / "enrich-receipt.json")
    name = str(enrich.get("ghidraProjectName") or "").strip()
    return name or None


def subprocess_env_for_work_dir(work_dir: Path) -> dict[str, str]:
    env = os.environ.copy()
    project_root = work_dir.resolve() / "pyghidra-project"
    project_root.mkdir(parents=True, exist_ok=True)
    env.setdefault("AGENTDECOMPILE_PROJECT_PATH", str(project_root))
    project_name = resolve_enrich_ghidra_project_name(work_dir)
    if project_name:
        env.setdefault("AGENTDECOMPILE_PROJECT_NAME", project_name)
    return env


_SKIP_PROGRAM_PATH_TOOLS = frozenset(
    {
        "open",
        "open-project",
        "import-binary",
        "analyze-program",
    }
)


def ensure_program_path_on_steps(steps: list[dict[str, Any]], program_path: str | None) -> list[dict[str, Any]]:
    if not program_path:
        return steps
    enriched: list[dict[str, Any]] = []
    for step in steps:
        if not isinstance(step, dict):
            enriched.append(step)
            continue
        tool_name = str(step.get("name") or "")
        if tool_name in _SKIP_PROGRAM_PATH_TOOLS:
            enriched.append(step)
            continue
        args = dict(step.get("arguments") or {})
        if "programPath" not in args and "program_path" not in args:
            args["programPath"] = program_path
        enriched.append({**step, "arguments": args})
    return enriched


def _parse_tool_seq_shell_stdout(stdout: str) -> dict[str, Any] | None:
    """Parse agentdecompile-cli ``tool-seq`` shell-format output."""

    success: bool | None = None
    steps: list[dict[str, Any]] | None = None
    for line in (stdout or "").splitlines():
        if line.startswith("success:"):
            token = line.split(":", 1)[1].strip().lower()
            success = token in {"true", "1", "yes"}
        elif line.startswith("steps:"):
            payload = line.split(":", 1)[1].strip()
            try:
                parsed = ast.literal_eval(payload)
            except (SyntaxError, ValueError):
                parsed = None
            if isinstance(parsed, list):
                steps = [row for row in parsed if isinstance(row, dict)]
    if success is None and steps is None:
        return None
    return {"success": success, "steps": steps or []}


def _parse_step_outcome(stdout: str, stderr: str, returncode: int, *, step_index: int = 0, step_name: str | None = None) -> dict[str, Any]:
    conflict_id: str | None = None
    error: str | None = None
    parsed = _parse_tool_seq_shell_stdout(stdout)
    if parsed and parsed.get("steps"):
        steps = parsed["steps"]
        if 0 <= step_index < len(steps):
            row = steps[step_index]
            ok = bool(row.get("success"))
            result = row.get("result") if isinstance(row.get("result"), dict) else {}
            content = result.get("content") if isinstance(result.get("content"), list) else []
            text = ""
            if content and isinstance(content[0], dict):
                text = str(content[0].get("text") or "")
            if result.get("isError") or "## Error" in text or "## Modification conflict" in text:
                ok = False
                error = text.strip()[:500] or None
            return {"ok": ok, "conflictId": conflict_id, "error": error}
        ok = bool(parsed.get("success")) and returncode == 0
        return {"ok": ok, "conflictId": conflict_id, "error": error}

    ok = returncode == 0
    text = f"{stdout}\n{stderr}"
    if "## Modification conflict" in text or "conflictId" in text:
        for line in text.splitlines():
            if "conflictId" in line:
                try:
                    if line.strip().startswith("{"):
                        payload = json.loads(line)
                        conflict_id = str(payload.get("conflictId") or payload.get("conflict_id") or "")
                    else:
                        for token in line.replace('"', " ").split():
                            if token.startswith("conflict"):
                                conflict_id = token
                except (json.JSONDecodeError, TypeError, ValueError):
                    pass
        ok = False
    if "## Error" in text or (returncode != 0 and not conflict_id):
        error = (stderr or stdout or "tool-seq step failed").strip()[:500]
        ok = False
    try:
        payload = json.loads(stdout)
        if isinstance(payload, dict):
            if payload.get("isError") or payload.get("success") is False:
                ok = False
            conflict_id = conflict_id or str(payload.get("conflictId") or "") or None
    except (json.JSONDecodeError, TypeError, ValueError):
        pass
    return {"ok": ok, "conflictId": conflict_id, "error": error}


def default_run_subprocess(cmd: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


def run_tool_seq(
    steps: list[dict[str, Any]],
    *,
    work_dir: Path,
    server_url: str | None = None,
    program_path: str | None = None,
    timeout: int = 120,
    run_subprocess: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> dict[str, Any]:
    """Execute MCP tool-seq steps via agentdecompile-cli."""

    work_dir = work_dir.resolve()
    if not steps:
        return {
            "schema": SCHEMA,
            "status": "skipped:empty",
            "writtenAt": now(),
            "workDir": str(work_dir),
            "steps": [],
            "claimBoundary": CLAIM_BOUNDARY,
        }

    if shutil.which("uv") is None and shutil.which("agentdecompile-cli") is None:
        return {
            "schema": SCHEMA,
            "status": "skipped:no-cli",
            "writtenAt": now(),
            "workDir": str(work_dir),
            "steps": [],
            "claimBoundary": CLAIM_BOUNDARY,
        }

    resolved_url = server_url or resolve_mcp_server_url()
    resolved_program = program_path or resolve_program_path(work_dir)
    steps_to_run = list(steps)
    if not resolved_url:
        steps_to_run = bootstrap_local_program_steps(work_dir) + steps_to_run
    enriched = ensure_program_path_on_steps(steps_to_run, resolved_program)

    cmd = ["uv", "run", "agentdecompile-cli"]
    if resolved_url:
        cmd.extend(["--server-url", resolved_url])
    cmd.extend(["tool-seq", json.dumps(enriched)])

    runner = run_subprocess or default_run_subprocess
    env = subprocess_env_for_work_dir(work_dir)
    try:
        if run_subprocess is None:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env=env,
            )
        else:
            proc = runner(cmd, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        receipt = {
            "schema": SCHEMA,
            "status": "error",
            "writtenAt": now(),
            "workDir": str(work_dir),
            "error": str(exc),
            "steps": [],
            "claimBoundary": CLAIM_BOUNDARY,
        }
        atomic_write_json(work_dir / "state" / "mcp-tool-seq-last.json", receipt)
        return receipt

    step_results: list[dict[str, Any]] = []
    overall_ok = proc.returncode == 0
    for index, step in enumerate(enriched):
        name = str(step.get("name") or f"step-{index}")
        outcome = _parse_step_outcome(
            proc.stdout or "",
            proc.stderr or "",
            proc.returncode,
            step_index=index,
            step_name=name,
        )
        step_results.append({"name": name, **outcome})
        if not outcome["ok"]:
            overall_ok = False

    status = "complete" if overall_ok else "failed"
    if any(row.get("conflictId") for row in step_results):
        status = "conflict"

    receipt = {
        "schema": SCHEMA,
        "status": status,
        "writtenAt": now(),
        "workDir": str(work_dir),
        "returncode": proc.returncode,
        "serverUrl": resolved_url,
        "programPath": resolved_program,
        "bootstrapSteps": len(steps_to_run) - len(steps),
        "steps": step_results,
        "toolsInvoked": [str(s.get("name") or "") for s in enriched],
        "claimBoundary": CLAIM_BOUNDARY,
    }
    state_dir = work_dir / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "mcp-tool-seq-last.stderr").write_text(proc.stderr or "", encoding="utf-8")
    (state_dir / "mcp-tool-seq-last.stdout").write_text(proc.stdout or "", encoding="utf-8")
    atomic_write_json(state_dir / "mcp-tool-seq-last.json", receipt)
    return receipt


def conflict_resolution_default() -> str:
    if os.environ.get("AGENTDECOMPILE_AUTO_CONFLICT_OVERWRITE", "").strip().lower() in {"1", "true", "yes"}:
        return "overwrite"
    return "skip"
