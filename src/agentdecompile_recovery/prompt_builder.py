"""Compose the final decompile prompt for a corpus function.

Ports the upstream prompt-builder's top-level entry point: resolve a
function's codebase context (examples, callers, declarations) and feed it
into craft_prompt.craft_prompt().
"""

from __future__ import annotations

from pathlib import Path

from .codebase_context import get_func_context
from .craft_prompt import craft_prompt
from .decomp_function_corpus import DecompFunctionCorpus


def create_decompile_prompt(
    *,
    corpus: DecompFunctionCorpus,
    function_id: str,
    platform: str,
    project_root: Path | None = None,
) -> str:
    func = corpus.get_function_by_id(function_id)
    if func is None:
        raise ValueError(f"Function not found: {function_id}")

    context = get_func_context(corpus, function_id, project_root=project_root)

    return craft_prompt(
        platform=platform,
        module_path=func.asm_module_path,
        asm_name=func.name,
        asm_declaration=context.asm_declaration,
        asm_code=func.asm_code,
        called_functions_declarations=context.called_functions_declarations,
        sampling=context.sampling,
        type_definitions=context.type_definitions,
    )
