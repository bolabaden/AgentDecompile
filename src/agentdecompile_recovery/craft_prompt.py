"""Craft an assembly-to-C decompilation prompt from bounded context.

Ports the upstream prompt-builder's craft-prompt module: a pure string
template that assembles a target function's assembly, its callers/callees'
C declarations, nearby example decompilations, and type definitions into one
prompt. Feeds the rewrite/subagent dispatch path (rewrite_context.py) as an
alternative, richer prompt-construction option to the existing pack builder.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

PlatformTarget = str

_ASM_COMMENT_ONLY_RE = re.compile(r"^(@|#|//|;)")


def strip_trailing_asm_lines(asm: str) -> str:
    """Strip blank/comment-only lines trailing the last real assembly content.

    Assembly snippets sometimes include trailing section-separator comments
    (e.g. `@ --- End of Character Select ---`) and blank lines that are not
    part of the function. Walks backwards from the end and removes any line
    that is empty or comment-only, stopping at the last real content.
    """
    lines = asm.split("\n")

    end = len(lines)
    while end > 0:
        line = lines[end - 1].strip()
        if line == "" or _ASM_COMMENT_ONLY_RE.match(line):
            end -= 1
        else:
            break

    return "\n".join(lines[:end])


@dataclass
class SamplingCFunction:
    name: str
    c_code: str
    asm_code: str
    calls_target: bool
    # objdiff similarity this decompilation achieved against its own target,
    # 0-100, when it was ever verified. Rendered next to the example so the
    # model can tell a proven reconstruction from an unverified guess.
    match_percent: float | None = None


_TEMPLATE_EXAMPLE = "# Examples\n\n"
_TEMPLATE_FUNCTIONS_CALLING_TARGET = "# Functions that call the target assembly\n\n"
_TEMPLATE_TARGET_ASSEMBLY_DECLARATION = "# Function declaration for the target assembly\n\n`{targetAssemblyDeclaration}`"
_TEMPLATE_DECLARATIONS_FOR_FUNCTIONS_CALLED_FROM_TARGET = (
    "# Declarations for the functions called from the target assembly\n\n"
)
_TEMPLATE_TYPE_DEFINITIONS = "# Types definitions used in the declarations\n\n"

_RULES = (
    "# Rules\n\n"
    "- In order to decompile this function, you may need to create new types. Include them on the result.\n\n"
    "- SHOW THE ENTIRE CODE WITHOUT CROPPING."
)

_TEMPLATE_DECOMPILE = """You are decompiling an assembly function called `{assemblyFunctionName}` in {assemblyLanguage} from a {platformName} game.

{examplePrompts}

{functionsCallingTargetPrompt}

{targetAssemblyDeclarationPrompt}

{functionDeclarationsPrompt}

{typeDefinitionsPrompt}

# Primary Objective

Decompile the following target assembly function from `{modulePath}` into clean, readable C code that compiles to an assembly matching EXACTLY the original one.

```asm
{assemblyCode}
```

{rules}
"""

_PLATFORM_INFO: dict[PlatformTarget, tuple[str, str]] = {
    "gba": ("Game Boy Advance", "ARMv4T"),
    "nds": ("Nintendo DS", "ARMv5TE"),
    "n3ds": ("Nintendo 3DS", "ARMv6K"),
    "n64": ("Nintendo 64", "MIPS"),
    "gc": ("GameCube", "PowerPC"),
    "wii": ("Wii", "PowerPC"),
    "ps1": ("PlayStation", "MIPS"),
    "ps2": ("PlayStation 2", "MIPS"),
    "psp": ("PlayStation Portable", "MIPS"),
    "win32": ("Windows (32-bit)", "x86"),
    "switch": ("Nintendo Switch", "AArch64"),
    "android_x86": ("Android (x86)", "x86"),
    "irix": ("IRIX", "MIPS"),
    "saturn": ("Sega Saturn", "SuperH"),
    "dreamcast": ("Dreamcast", "SuperH"),
}


def _render_sample(sample: SamplingCFunction) -> str:
    return (
        f"## `{sample.name}`{_outcome_label(sample.match_percent)}\n\n"
        f"```c\n{sample.c_code}\n```\n\n```asm\n{sample.asm_code}\n```"
    )


def _outcome_label(match_percent: float | None) -> str:
    """How much this example is worth as evidence, stated plainly."""
    if match_percent is None:
        return ""
    if match_percent >= 100.0:
        return " -- verified: this C compiles to the assembly below, byte for byte"
    return f" -- {match_percent:.1f}% of instructions match; the rest still differ"


def craft_prompt(
    *,
    platform: PlatformTarget,
    module_path: str,
    asm_name: str,
    asm_code: str,
    called_functions_declarations: dict[str, str],
    sampling: list[SamplingCFunction],
    type_definitions: list[str],
    asm_declaration: str | None = None,
    example_limit: int = 5,
) -> str:
    # `sampling` arrives pre-ranked (see codebase_context.get_func_context),
    # so taking the head takes the most useful examples rather than arbitrary
    # ones. This is the sampling strategy the upstream port left as a TODO.
    examples = [sample for sample in sampling if not sample.calls_target][: max(0, example_limit)]
    example_prompts = (
        _TEMPLATE_EXAMPLE + "\n\n".join(_render_sample(sample) for sample in examples) if examples else ""
    )

    c_functions_calling_target = [sample for sample in sampling if sample.calls_target]
    functions_calling_target_prompt = (
        _TEMPLATE_FUNCTIONS_CALLING_TARGET
        + "\n\n".join(_render_sample(sample) for sample in c_functions_calling_target)
        if c_functions_calling_target
        else ""
    )

    target_assembly_declaration_prompt = (
        _TEMPLATE_TARGET_ASSEMBLY_DECLARATION.replace("{targetAssemblyDeclaration}", asm_declaration)
        if asm_declaration
        else ""
    )

    declaration_values = list(called_functions_declarations.values())
    function_declarations_prompt = (
        _TEMPLATE_DECLARATIONS_FOR_FUNCTIONS_CALLED_FROM_TARGET
        + "\n".join(f"- `{decl}`" for decl in declaration_values)
        if declaration_values
        else ""
    )

    type_definitions_prompt = (
        _TEMPLATE_TYPE_DEFINITIONS + "\n\n".join(f"```c\n{type_def}\n```" for type_def in type_definitions)
        if type_definitions
        else ""
    )

    platform_info = _PLATFORM_INFO.get(platform)
    if platform_info is None:
        raise ValueError(f"Unsupported platform: {platform}. Known: {', '.join(sorted(_PLATFORM_INFO))}")
    platform_name, assembly_language = platform_info

    return (
        _TEMPLATE_DECOMPILE.replace("{assemblyLanguage}", assembly_language)
        .replace("{platformName}", platform_name)
        .replace("{assemblyFunctionName}", asm_name)
        .replace("{modulePath}", module_path)
        .replace("{examplePrompts}", example_prompts)
        .replace("{functionsCallingTargetPrompt}", functions_calling_target_prompt)
        .replace("{targetAssemblyDeclarationPrompt}", target_assembly_declaration_prompt)
        .replace("{functionDeclarationsPrompt}", function_declarations_prompt)
        .replace("{typeDefinitionsPrompt}", type_definitions_prompt)
        .replace("{assemblyCode}", strip_trailing_asm_lines(asm_code))
        .replace("{rules}", _RULES)
    )
