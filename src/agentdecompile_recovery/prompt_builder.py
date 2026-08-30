"""Compose the final decompile prompt for a corpus function.

Ports the upstream prompt-builder's top-level entry point: resolve a
function's codebase context (examples, callers, declarations) and feed it
into craft_prompt.craft_prompt().
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .c_rendering import c_identifier, safe_c_type
from .codebase_context import get_func_context
from .craft_prompt import craft_prompt
from .curated_project import load_curated_signatures, load_curated_type_definitions
from .decomp_function_corpus import DecompFunctionCorpus, DecompFunctionDoc

_TYPE_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_:]*")
_PRIMITIVE_TYPES = {
    "void", "char", "short", "int", "long", "float", "double", "signed",
    "unsigned", "const", "volatile", "bool", "size_t", "undefined",
    "undefined1", "undefined2", "undefined4", "undefined8", "byte", "word",
    "dword", "qword", "uchar", "ushort", "uint", "ulong", "struct", "union",
    "enum", "typedef",
}
_MAX_PROMPT_TYPES = 24
_MAX_PROMPT_TYPE_CHARS = 8_000


@dataclass(frozen=True)
class CuratedPromptContext:
    target_declaration: str | None
    callee_declarations: dict[str, str]
    type_definitions: list[str]


def _curated_declaration(
    record: dict[str, Any],
    *,
    output_name: str,
) -> str | None:
    """Render a trusted curated signature as compilable C prompt evidence."""

    if not record.get("signature"):
        return None
    name = c_identifier(output_name, fallback="recoveredFunction")
    curated_name = c_identifier(
        record.get("qualifiedName") or record.get("name"), fallback=name
    )
    return_type = safe_c_type(record.get("returnType"), fallback="void")
    convention = str(record.get("callingConvention") or "").strip()
    if convention not in {"", "__cdecl", "__stdcall", "__fastcall", "__thiscall"}:
        convention = ""
    parameters: list[str] = []
    for index, item in enumerate(record.get("parameters") or []):
        if not isinstance(item, dict):
            continue
        type_name = safe_c_type(item.get("type"), fallback="undefined")
        param_name = c_identifier(item.get("name"), fallback=f"param{index + 1}")
        parameters.append(f"{type_name} {param_name}")
    if convention == "__thiscall":
        # A free C function cannot spell __thiscall. __fastcall reproduces its
        # ECX `this` input; the unused EDX slot keeps stack arguments aligned.
        convention = "__fastcall"
        parameters = ["void * thisEcx", "int edxUnused", *parameters]
    convention_text = f"{convention} " if convention else ""
    identity = f"/* curated identity: {curated_name} */ " if curated_name != name else ""
    return f"{identity}{return_type} {convention_text}{name}({', '.join(parameters) or 'void'})"


def _curated_prompt_context(
    corpus: DecompFunctionCorpus,
    target: DecompFunctionDoc,
    project_root: Path,
) -> CuratedPromptContext:
    signatures = load_curated_signatures(project_root) or {}
    type_definitions = load_curated_type_definitions(project_root) or {}
    target_record = signatures.get(target.rom_address) if target.rom_address is not None else None
    target_decl = (
        _curated_declaration(target_record, output_name=target.name)
        if target_record is not None
        else None
    )
    declarations: dict[str, str] = {}
    relevant_records = [target_record] if target_record is not None else []
    for callee_id in target.calls_functions:
        callee = corpus.get_function_by_id(callee_id)
        if callee is None or callee.rom_address is None:
            continue
        record = signatures.get(callee.rom_address)
        if record is None:
            continue
        declaration = _curated_declaration(record, output_name=callee.name)
        if declaration:
            declarations[callee_id] = f"extern {declaration};"
            relevant_records.append(record)

    wanted: list[str] = []
    pending: deque[str] = deque()
    seen: set[str] = set()

    def collect(text: str) -> None:
        for token in _TYPE_TOKEN_RE.findall(text):
            if token in _PRIMITIVE_TYPES or "::" in token or token in seen:
                continue
            if token in type_definitions:
                seen.add(token)
                wanted.append(token)
                pending.append(token)
                if len(wanted) >= _MAX_PROMPT_TYPES:
                    return

    for record in relevant_records:
        collect(str(record.get("signature") or ""))
    # Definitions can depend on other recovered composites. Expand only the
    # reachable closure and keep the prompt bounded.
    while pending:
        name = pending.popleft()
        collect(type_definitions[name])

    ordered: list[str] = []
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(name: str) -> None:
        if name in visited or name in visiting:
            return
        visiting.add(name)
        for dependency in _TYPE_TOKEN_RE.findall(type_definitions[name]):
            if dependency in seen and dependency != name:
                visit(dependency)
        visiting.remove(name)
        visited.add(name)
        ordered.append(name)

    for name in wanted:
        visit(name)

    rendered: list[str] = []
    used = 0
    for name in ordered:
        definition = type_definitions[name]
        if used + len(definition) > _MAX_PROMPT_TYPE_CHARS:
            break
        rendered.append(definition)
        used += len(definition)
    return CuratedPromptContext(target_decl, declarations, rendered)


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
    if project_root is not None:
        curated = _curated_prompt_context(corpus, func, project_root)
        if curated.target_declaration:
            context.asm_declaration = curated.target_declaration
        context.called_functions_declarations.update(curated.callee_declarations)
        existing_types = set(context.type_definitions)
        context.type_definitions.extend(
            item for item in curated.type_definitions if item not in existing_types
        )

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
