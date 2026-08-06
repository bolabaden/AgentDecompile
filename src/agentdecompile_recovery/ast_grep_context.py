"""Find C function declarations and type definitions via the `ast-grep` CLI.

Ports the AST-based half of the upstream prompt-builder's codebase-context
module (see `codebase_context.py`'s module docstring) that walks a real C
source tree to auto-populate `asm_declaration`, `called_functions_declarations`,
and `type_definitions` for a target function.

Upstream uses `@ast-grep/napi`, a native Node binding for the ast-grep engine,
to run two structural queries directly against in-memory `SgNode` trees:

1. Find `identifier` nodes matching the target/callee function names `inside`
   a `function_declarator`, then walk up each match to its nearest enclosing
   `declaration` ancestor and take that node's source text.
2. Collect `type_identifier` names referenced in those declarations (minus a
   handful of known primitive typedefs), then find `type_identifier` nodes
   matching those names `inside` a `type_definition`, walking up to the
   enclosing `type_definition` node.

There is no Python binding for the ast-grep engine, so this module shells out
to the `ast-grep` (or `sg`) CLI instead and gets the same two lookups via
`ast-grep scan --inline-rules ... --json`, using `has: {kind: ..., stopBy:
end}` rules rather than napi's `inside` + manual parent-walk -- `has` with a
descendant match expresses "this declaration/type_definition contains a
matching identifier somewhere inside it" directly, which is exactly the
declaration/type_definition node upstream ends up with after its walk-up, so
no separate ancestor-walk step is needed on the Python side.

One deliberate simplification: because the CLI returns whole declaration node
text rather than the individual `identifier` node upstream inspects via
`node.text()`, phase 1 can't tell *which* queried name matched a given
declaration node directly from the JSON. Instead, each declaration's source
text is checked with a `name(` substring/regex probe against the queried
names to decide whether it's the target function's declaration or a called
function's declaration. This is safe for ordinary C declarators (the
identifier immediately precedes the `(` of a `function_declarator`) but,
unlike upstream's node-exact match, could misfire on a contrived declaration
whose text happens to contain another queried name followed by `(` outside
the declarator position (e.g. inside a comment or an unrelated string
literal in the same statement) -- not something valid C declarations do in
practice, so it is not expected to matter here.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)

CommandRunner = Callable[..., dict[str, Any]]

# Primitive typedefs excluded from the type-definition lookup, matching
# upstream's ignoreTypes set exactly.
_IGNORE_TYPES = frozenset({"u8", "u16", "u32", "u64", "s8", "s16", "s32", "s64"})

_SOURCE_GLOBS = ("*.c", "*.h")


@dataclass
class AstGrepCodebaseContext:
    """Result of the two-phase ast-grep lookup, mirroring upstream's `CodebaseContext`."""

    asm_declaration: str | None = None
    called_functions_declarations: dict[str, str] = field(default_factory=dict)
    type_definitions: list[str] = field(default_factory=list)


def _resolve_binary() -> str | None:
    for name in ("ast-grep", "sg"):
        path = shutil.which(name)
        if path:
            return path
    return None


def _default_run_command(
    command: list[str],
    *,
    timeout_ms: int = 30_000,
    input_text: str | None = None,
) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            command,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=max(1.0, timeout_ms / 1000.0),
            check=False,
        )
        return {
            "command": command,
            "exitCode": completed.returncode,
            "stdout": completed.stdout or "",
            "stderr": completed.stderr or "",
            "available": True,
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
        }


def _name_regex(names: list[str]) -> str:
    return "|".join(f"({re.escape(name)})" for name in names)


def _run_scan(
    binary: str,
    rule_yaml: str,
    *,
    project_root: Path | None,
    stdin_text: str | None,
    command_runner: CommandRunner,
) -> list[dict[str, Any]]:
    command = [binary, "scan", "--inline-rules", rule_yaml, "--json"]
    if stdin_text is not None:
        command.append("--stdin")
        result = command_runner(command, timeout_ms=30_000, input_text=stdin_text)
    else:
        for pattern in _SOURCE_GLOBS:
            command.extend(["--globs", pattern])
        command.append(str(project_root))
        result = command_runner(command, timeout_ms=30_000)

    if not result.get("available", True):
        return []

    stdout = (result.get("stdout") or "").strip()
    if not stdout:
        return []
    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError:
        logger.warning("ast-grep produced non-JSON output: %r", stdout[:200])
        return []
    if not isinstance(parsed, list):
        return []
    return [item for item in parsed if isinstance(item, dict)]


def _find_function_declarations(
    all_function_names: list[str],
    project_root: Path,
    *,
    binary: str,
    command_runner: CommandRunner,
) -> list[str]:
    rule_yaml = (
        "id: find-func-decl\n"
        "language: c\n"
        "rule:\n"
        "  kind: declaration\n"
        "  has:\n"
        "    kind: function_declarator\n"
        "    has:\n"
        "      kind: identifier\n"
        f'      regex: "^({_name_regex(all_function_names)})$"\n'
        "      stopBy: end\n"
        "    stopBy: end\n"
    )
    matches = _run_scan(
        binary,
        rule_yaml,
        project_root=project_root,
        stdin_text=None,
        command_runner=command_runner,
    )
    return [item.get("text", "") for item in matches if item.get("text")]


def _match_declaration_to_name(declaration_text: str, candidate_names: list[str]) -> str | None:
    for name in candidate_names:
        if re.search(rf"\b{re.escape(name)}\s*\(", declaration_text):
            return name
    return None


def _extract_type_identifiers(
    declaration_text: str,
    *,
    binary: str,
    command_runner: CommandRunner,
) -> set[str]:
    rule_yaml = "id: find-type-ids\nlanguage: c\nrule:\n  kind: type_identifier\n"
    matches = _run_scan(
        binary,
        rule_yaml,
        project_root=None,
        stdin_text=declaration_text,
        command_runner=command_runner,
    )
    names = {item.get("text", "") for item in matches if item.get("text")}
    return {name for name in names if name and name not in _IGNORE_TYPES}


def _find_type_definitions(
    type_names: set[str],
    project_root: Path,
    *,
    binary: str,
    command_runner: CommandRunner,
) -> list[str]:
    if not type_names:
        return []

    rule_yaml = (
        "id: find-type-def\n"
        "language: c\n"
        "rule:\n"
        "  kind: type_definition\n"
        "  has:\n"
        "    kind: type_identifier\n"
        f'    regex: "^({_name_regex(sorted(type_names))})$"\n'
        "    stopBy: end\n"
    )
    matches = _run_scan(
        binary,
        rule_yaml,
        project_root=project_root,
        stdin_text=None,
        command_runner=command_runner,
    )

    seen: set[str] = set()
    result: list[str] = []
    for item in matches:
        text = item.get("text")
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def find_codebase_context(
    function_name: str,
    called_function_names: list[str],
    project_root: Path,
    *,
    command_runner: CommandRunner | None = None,
) -> AstGrepCodebaseContext:
    """Look up C declarations and type definitions for a function via ast-grep.

    Returns an empty (all-defaults) `AstGrepCodebaseContext` when the
    `ast-grep`/`sg` CLI is not on PATH, rather than raising -- callers should
    treat this as "no AST context available" and fall back to whatever was
    passed manually, matching the graceful-degradation convention used by
    `agentdecompile_cli.mcp_utils.decomp_match`.
    """
    runner = command_runner or _default_run_command
    binary = _resolve_binary()
    if binary is None:
        logger.info("ast-grep/sg not found on PATH; skipping AST codebase-context lookup.")
        return AstGrepCodebaseContext()

    all_function_names = [function_name, *called_function_names]
    declaration_texts = _find_function_declarations(
        all_function_names,
        project_root,
        binary=binary,
        command_runner=runner,
    )

    result = AstGrepCodebaseContext()
    for declaration_text in declaration_texts:
        matched_name = _match_declaration_to_name(declaration_text, all_function_names)
        if matched_name is None:
            continue
        if matched_name == function_name:
            result.asm_declaration = declaration_text
        else:
            result.called_functions_declarations[matched_name] = declaration_text

    if not declaration_texts:
        return result

    types_from_declarations: set[str] = set()
    for declaration_text in declaration_texts:
        types_from_declarations |= _extract_type_identifiers(
            declaration_text,
            binary=binary,
            command_runner=runner,
        )

    result.type_definitions = _find_type_definitions(
        types_from_declarations,
        project_root,
        binary=binary,
        command_runner=runner,
    )
    return result
