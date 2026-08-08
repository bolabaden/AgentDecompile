"""Scan a C source tree for function definitions via the `ast-grep` CLI.

Produces the `decomp_indexer.CFunctionRecord` list that `index_codebase()`
takes as an input seam (see that module's docstring: it deliberately doesn't
parse C itself). Follows the same external-tool-wrapper pattern as
decomp_match.py and ast_grep_context.py: guarded `shutil.which`, graceful
degradation when the binary is missing, an injectable command runner.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Callable

from .ast_grep_cli import resolve_ast_grep_binary
from .decomp_indexer import CFunctionRecord

CommandRunner = Callable[..., dict[str, Any]]

_FUNCTION_PATTERN = "$RET $NAME($$$PARAMS) { $$$BODY }"


def _resolve_binary() -> str | None:
    return resolve_ast_grep_binary()


def _default_run_command(command: list[str], *, cwd: Path) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            command, cwd=str(cwd), capture_output=True, text=True, timeout=120, check=False
        )
        return {"exitCode": completed.returncode, "stdout": completed.stdout, "stderr": completed.stderr}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"exitCode": None, "stdout": "", "stderr": str(exc)}


def scan_c_functions(
    project_root: Path,
    source_dirs: list[str],
    *,
    command_runner: CommandRunner | None = None,
) -> list[CFunctionRecord]:
    """Scan `project_root/<dir>` for each dir in source_dirs for C function definitions.

    Returns an empty list (rather than raising) when ast-grep isn't on PATH,
    matching this project's convention for optional external tools.
    """
    binary = _resolve_binary()
    if binary is None:
        return []
    runner = command_runner or _default_run_command

    records: list[CFunctionRecord] = []
    for source_dir in source_dirs:
        scan_dir = project_root / source_dir
        if not scan_dir.is_dir():
            continue
        result = runner(
            [binary, "run", "--pattern", _FUNCTION_PATTERN, "--lang", "c", "--json"],
            cwd=scan_dir,
        )
        stdout = result.get("stdout") or ""
        try:
            matches = json.loads(stdout) if stdout.strip() else []
        except json.JSONDecodeError:
            continue
        if not isinstance(matches, list):
            continue
        for match in matches:
            if not isinstance(match, dict):
                continue
            meta_vars = match.get("metaVariables", {}).get("single", {})
            name_node = meta_vars.get("NAME")
            name = name_node.get("text") if isinstance(name_node, dict) else None
            text = match.get("text")
            file_path = match.get("file")
            if not name or not isinstance(text, str) or not file_path:
                continue
            module_path = str((scan_dir / file_path).relative_to(project_root)) if not Path(file_path).is_absolute() else file_path
            records.append(CFunctionRecord(name=str(name), c_code=text, c_module_path=module_path))
    return records
