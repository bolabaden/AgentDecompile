"""Assemble per-function decompilation context from a DecompFunctionCorpus.

Ports the corpus-driven half of the upstream prompt-builder's
codebase-context module: given a target function id, gather nearby
already-decompiled examples (via vector similarity) and functions that call
it, for use as few-shot context in craft_prompt.craft_prompt().

The upstream module also has an AST-based half (finding C declarations and
type definitions for the target/callee functions via ast-grep) -- that now
lives in `ast_grep_context.find_codebase_context` (ported via the `ast-grep`
CLI, since there's no Python binding for the ast-grep engine). `get_func_context`
below accepts an optional `project_root` to auto-populate `asm_declaration` /
`called_functions_declarations` / `type_definitions` from that lookup;
callers without a real C source tree (or who already have this information)
can keep passing the three fields in directly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .ast_grep_context import CommandRunner, find_codebase_context
from .craft_prompt import SamplingCFunction
from .decomp_function_corpus import DecompFunctionCorpus


@dataclass
class DecompFuncContext:
    sampling: list[SamplingCFunction] = field(default_factory=list)
    asm_declaration: str | None = None
    called_functions_declarations: dict[str, str] = field(default_factory=dict)
    type_definitions: list[str] = field(default_factory=list)


def get_func_context(
    corpus: DecompFunctionCorpus,
    function_id: str,
    *,
    asm_declaration: str | None = None,
    called_functions_declarations: dict[str, str] | None = None,
    type_definitions: list[str] | None = None,
    similarity_limit: int = 50,
    project_root: Path | None = None,
    ast_grep_command_runner: CommandRunner | None = None,
) -> DecompFuncContext:
    func = corpus.get_function_by_id(function_id)
    if func is None:
        raise ValueError(f"Function not found: {function_id}")

    # Auto-populate the AST-derived fields from a real C source tree when the
    # caller hands us `project_root` and hasn't already supplied them
    # explicitly. This is the seam this module's docstring used to flag as a
    # TODO -- `ast_grep_context.find_codebase_context` now does the ast-grep
    # walk that upstream's codebase-context.ts performs via @ast-grep/napi.
    if project_root is not None and asm_declaration is None and called_functions_declarations is None:
        called_function_names = [
            callee.name for callee in (corpus.get_function_by_id(cid) for cid in func.calls_functions) if callee
        ]
        ast_context = find_codebase_context(
            func.name,
            called_function_names,
            project_root,
            command_runner=ast_grep_command_runner,
        )
        asm_declaration = ast_context.asm_declaration
        called_functions_declarations = ast_context.called_functions_declarations
        if type_definitions is None:
            type_definitions = ast_context.type_definitions

    result = DecompFuncContext(
        asm_declaration=asm_declaration,
        called_functions_declarations=dict(called_functions_declarations or {}),
        type_definitions=list(type_definitions or []),
    )

    # Similar functions from vector search -- filter to those with C code.
    for similar in corpus.find_similar(function_id, similarity_limit):
        if not similar.function.c_code:
            continue
        result.sampling.append(
            SamplingCFunction(
                name=similar.function.name,
                c_code=similar.function.c_code,
                asm_code=similar.function.asm_code,
                calls_target=function_id in similar.function.calls_functions,
            )
        )

    # Functions that call the target -- filter to those with C code, dedup by name.
    existing_names = {sample.name for sample in result.sampling}
    for caller in corpus.get_called_by(function_id):
        if not caller.c_code:
            continue
        if caller.name in existing_names:
            continue
        result.sampling.append(
            SamplingCFunction(
                name=caller.name,
                c_code=caller.c_code,
                asm_code=caller.asm_code,
                calls_target=True,
            )
        )
        existing_names.add(caller.name)

    return result
