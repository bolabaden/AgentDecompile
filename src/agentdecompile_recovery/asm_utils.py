"""Assembly utility functions for parsing ARM/MIPS assembly files.

Ports the upstream indexer's asm-utils: function-call extraction, per-function
splitting of a whole assembly module, function-body isolation, and comment
stripping. These target the ARM/MIPS-era decomp toolchains (GBA/N64-style
projects) that m2c/decomp-permuter originate from -- a different ISA surface
than this project's primary Ghidra/MSVC x86 target, but part of the same
generic decomp-toolkit surface those external tools already bring in.
"""

from __future__ import annotations

import re

ArmOrMips = str  # "arm" | "mips"


def extract_function_calls_from_assembly(platform: ArmOrMips, assembly: str) -> list[str]:
    if platform == "arm":
        return _arm_extract_function_calls(assembly)
    if platform == "mips":
        return _mips_extract_function_calls(assembly)
    raise ValueError(f"Unsupported platform: {platform}")


_BL_RE = re.compile(r"bl\s+(\w+)")
_ARM_REF_RE = re.compile(r"@\s*=(\w+)")
_ARM_DIRECT_RE = re.compile(r"(?:ldr|add|mov).*=(\w+)")


def _arm_extract_function_calls(assembly: str) -> list[str]:
    function_calls: dict[str, None] = {}
    for line in assembly.split("\n"):
        trimmed = line.strip()
        bl_match = _BL_RE.search(trimmed)
        if bl_match:
            function_calls[bl_match.group(1)] = None
        ref_match = _ARM_REF_RE.search(trimmed)
        if ref_match:
            function_calls[ref_match.group(1)] = None
        direct_match = _ARM_DIRECT_RE.search(trimmed)
        if direct_match:
            function_calls[direct_match.group(1)] = None
    return list(function_calls.keys())


_JAL_RE = re.compile(r"jal\s+(\w+)")
_MIPS_REF_RE = re.compile(r";\s*=(\w+)")
_MIPS_DIRECT_RE = re.compile(r"(?:la|lw|lui).*\b(\w+)(?:\s*\+|$)")
_MIPS_REG_RE = re.compile(r"^\$\w+$")
_HEX_LITERAL_RE = re.compile(r"^0x[0-9a-fA-F]+$")


def _mips_extract_function_calls(assembly: str) -> list[str]:
    function_calls: dict[str, None] = {}
    for line in assembly.split("\n"):
        trimmed = line.strip()
        if line.startswith("glabel") or line.startswith("endlabel"):
            continue
        jal_match = _JAL_RE.search(trimmed)
        if jal_match:
            function_calls[jal_match.group(1)] = None
        ref_match = _MIPS_REF_RE.search(trimmed)
        if ref_match:
            function_calls[ref_match.group(1)] = None
        direct_match = _MIPS_DIRECT_RE.search(trimmed)
        if direct_match:
            name = direct_match.group(1)
            if not _MIPS_REG_RE.match(name) and not _HEX_LITERAL_RE.match(name):
                function_calls[name] = None
    return list(function_calls.keys())


def list_functions_from_asm_module(platform: ArmOrMips, assembly_content: str) -> list[dict[str, str]]:
    if platform == "arm":
        return _arm_list_functions_from_asm_module(assembly_content)
    if platform == "mips":
        return _mips_list_functions_from_asm_module(assembly_content)
    raise ValueError(f"Unsupported platform: {platform}")


_THUMB_START_RE = re.compile(r"thumb_func_start\s+(\w+)")
_ARM_START_RE = re.compile(r"arm_func_start\s+(\w+)")
_THUMB_END_RE = re.compile(r"thumb_func_end\s+(\w+)")
_ARM_END_RE = re.compile(r"arm_func_end\s+(\w+)")
_LABEL_RE = re.compile(r"^([a-zA-Z_][a-zA-Z0-9_]*):(\s*@.*)?$")
_IDENT_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


def _arm_list_functions_from_asm_module(assembly_content: str) -> list[dict[str, str]]:
    functions: list[dict[str, str]] = []
    lines = assembly_content.split("\n")
    current: dict[str, object] | None = None

    def push_current(end_index: int) -> None:
        assert current is not None
        code = "\n".join(lines[current["startIndex"] : end_index])  # type: ignore[arg-type]
        functions.append({"name": str(current["name"]), "code": code})

    for i, raw_line in enumerate(lines):
        line = raw_line.strip()
        thumb_start_match = _THUMB_START_RE.search(line)
        arm_start_match = _ARM_START_RE.search(line)

        if thumb_start_match or arm_start_match:
            if current is not None:
                push_current(i)
            name = thumb_start_match.group(1) if thumb_start_match else arm_start_match.group(1)  # type: ignore[union-attr]
            current = {"name": name, "startIndex": i}
        elif current is None:
            label_match = _LABEL_RE.match(line)
            if label_match:
                name = label_match.group(1)
                if not name.startswith("_08") and not name.startswith(".") and name != "gUnknown" and "Unknown" not in name:
                    current = {"name": name, "startIndex": i}
        else:
            thumb_end_match = _THUMB_END_RE.search(line)
            arm_end_match = _ARM_END_RE.search(line)
            if (thumb_end_match and thumb_end_match.group(1) == current["name"]) or (
                arm_end_match and arm_end_match.group(1) == current["name"]
            ):
                push_current(i + 1)
                current = None
            elif "thumb_func_start" in line or "arm_func_start" in line:
                push_current(i)
                new_thumb_match = _THUMB_START_RE.search(line)
                new_arm_match = _ARM_START_RE.search(line)
                name = new_thumb_match.group(1) if new_thumb_match else new_arm_match.group(1)  # type: ignore[union-attr]
                current = {"name": name, "startIndex": i}
            elif line.endswith(":") and not line.startswith(".") and not line.startswith("_08"):
                label_name = line[:-1]
                if _IDENT_RE.match(label_name) and label_name != current["name"] and "Unknown" not in label_name:
                    push_current(i)
                    current = {"name": label_name, "startIndex": i}

    if current is not None:
        push_current(len(lines))

    return functions


_GLABEL_RE = re.compile(r"glabel\s+(\w+)")
_SIZE_RE = re.compile(r"\.size\s+(\w+)")


def _mips_list_functions_from_asm_module(assembly_content: str) -> list[dict[str, str]]:
    functions: list[dict[str, str]] = []
    lines = assembly_content.split("\n")
    current: dict[str, object] | None = None

    def push_current(end_index: int) -> None:
        assert current is not None
        code = "\n".join(lines[current["startIndex"] : end_index])  # type: ignore[arg-type]
        functions.append({"name": str(current["name"]), "code": code})

    for i, raw_line in enumerate(lines):
        line = raw_line.strip()
        glabel_match = _GLABEL_RE.search(line)

        if glabel_match:
            if current is not None:
                push_current(i)
            current = {"name": glabel_match.group(1), "startIndex": i}
        elif current is None:
            label_match = _LABEL_RE.match(line)
            if label_match:
                name = label_match.group(1)
                if not name.startswith("_") and not name.startswith(".") and name != "gUnknown" and "Unknown" not in name:
                    current = {"name": name, "startIndex": i}
        else:
            size_match = _SIZE_RE.search(line)
            if size_match and size_match.group(1) == current["name"]:
                push_current(i + 1)
                current = None
            elif "glabel" in line:
                push_current(i)
                new_glabel_match = _GLABEL_RE.search(line)
                current = {"name": new_glabel_match.group(1), "startIndex": i}  # type: ignore[union-attr]
            elif line.endswith(":") and not line.startswith("."):
                label_name = line[:-1]
                if (
                    _IDENT_RE.match(label_name)
                    and label_name != current["name"]
                    and "Unknown" not in label_name
                    and not label_name.startswith("_")
                ):
                    push_current(i)
                    current = {"name": label_name, "startIndex": i}

    if current is not None:
        push_current(len(lines))

    return functions


def extract_asm_function_body(platform: ArmOrMips, asm_code: str) -> str:
    if platform == "arm":
        return _arm_extract_function_body(asm_code)
    if platform == "mips":
        return _mips_extract_function_body(asm_code)
    raise ValueError(f"Unsupported platform: {platform}")


def _arm_extract_function_body(asm_code: str) -> str:
    lines = asm_code.split("\n")
    body_lines: list[str] = []
    saw_function_start = False
    skipped_function_label = False
    has_instructions = False

    for raw_line in lines:
        trimmed = raw_line.strip()
        if trimmed == "":
            continue

        if "thumb_func_start" in trimmed or "arm_func_start" in trimmed:
            saw_function_start = True
            continue
        if "thumb_func_end" in trimmed or "arm_func_end" in trimmed:
            break

        if saw_function_start and not skipped_function_label:
            colon_index = trimmed.find(":")
            if colon_index != -1:
                label_name = trimmed[:colon_index]
                if not label_name.startswith("_") and not label_name.startswith("."):
                    skipped_function_label = True
                    continue

        if trimmed.startswith(".align"):
            continue

        is_label = ":" in trimmed
        is_constant_def = is_label and ".4byte" in trimmed
        if not is_label or is_constant_def:
            if not is_constant_def:
                has_instructions = True
        elif is_label and not is_constant_def:
            has_instructions = True

        body_lines.append(trimmed)

    return "\n".join(body_lines) if has_instructions else ""


def _mips_extract_function_body(asm_code: str) -> str:
    lines = asm_code.split("\n")
    body_lines: list[str] = []

    for raw_line in lines:
        trimmed = raw_line.strip()
        if trimmed == "":
            continue
        if trimmed.startswith("glabel") or trimmed.startswith("endlabel"):
            continue
        if trimmed.startswith(".size"):
            continue

        processed = trimmed
        comment_index = processed.find(";")
        if comment_index != -1:
            processed = processed[:comment_index].strip()

        processed = re.sub(r"\s+", " ", processed).strip()

        if processed:
            body_lines.append(processed)

    return "\n".join(body_lines)


def strip_commentaries(asm_code: str) -> str:
    stripped_lines: list[str] = []

    for line in asm_code.split("\n"):
        stripped_line = line

        block_comment_start = stripped_line.find("/*")
        while block_comment_start != -1:
            block_comment_end = stripped_line.find("*/", block_comment_start + 2)
            if block_comment_end != -1:
                stripped_line = stripped_line[:block_comment_start] + stripped_line[block_comment_end + 2 :]
                block_comment_start = stripped_line.find("/*")
            else:
                stripped_line = stripped_line[:block_comment_start]
                break

        arm_comment_index = stripped_line.find("@")
        if arm_comment_index != -1:
            stripped_line = stripped_line[:arm_comment_index]

        if arm_comment_index == -1:
            mips_comment_index = stripped_line.find(";")
            if mips_comment_index != -1:
                stripped_line = stripped_line[:mips_comment_index]

        if arm_comment_index == -1:
            c_style_comment_index = stripped_line.find("//")
            if c_style_comment_index != -1:
                stripped_line = stripped_line[:c_style_comment_index]

        stripped_lines.append(stripped_line.rstrip())

    return "\n".join(stripped_lines)


def count_body_lines_from_asm_function(platform: ArmOrMips, asm_code: str) -> int:
    body_code = extract_asm_function_body(platform, asm_code)
    return len([line for line in body_code.split("\n") if line.strip() != ""])
