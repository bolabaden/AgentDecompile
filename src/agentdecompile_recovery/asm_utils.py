"""Assembly utility functions for parsing ARM/MIPS/x86 assembly files.

Ports the upstream indexer's asm-utils: function-call extraction, per-function
splitting of a whole assembly module, function-body isolation, and comment
stripping. The ARM/MIPS halves target the decomp toolchains (GBA/N64-style
projects) that m2c/decomp-permuter originate from.

The x86 half is not part of the upstream port -- it exists because this
project's own target is a Win32 PE built by MSVC, and the retrieval layer
cannot index that target without it. Two Intel-syntax dialects appear in this
repository and both are handled:

  1. **objdiff** (`objdiff-cli diff --format json` -> `instruction.formatted`,
     which is also what lands in a work dir's `verify.json` `alignedDiff`
     rows). Lowercase mnemonics, lowercase `dword ptr`, `0x`-prefixed
     immediates, `short 0x2a` branch targets, `st`/`st(0)` x87 operands, and
     `(bad)` for anything the decoder rejected.
  2. **MASM listings** as emitted by `cl /FAs` and by this repo's own
     `.asm` candidates. `NAME PROC`/`NAME ENDP`, `_TEXT SEGMENT`/`ENDS`,
     uppercase `DWORD PTR`, `OFFSET FLAT:sym`, `SHORT $L562`, `;` comments,
     tab separators, and `EXTRN`/`PUBLIC`/`INCLUDELIB` directives.

Stated boundary -- what the x86 parser does NOT do:
  - It does not decode instruction semantics. Mnemonic classification is by
    a name table, so an unknown mnemonic counts as a plain instruction rather
    than being rejected.
  - Numeric branch and call targets (`call 0x1e4c20`, `je short 0x2a`) are
    intra-object relative offsets in this corpus, not callee identities, so
    call extraction ignores them and reports only *symbolic* targets. A
    module assembled without relocations therefore yields no call edges.
  - MASM conditional assembly (`if @Version gt 510` / `else` / `endif`) is
    treated as directive noise and dropped wholesale rather than evaluated;
    both arms' contents are skipped only insofar as they are themselves
    directives.
  - 16-bit / real-mode MASM, AT&T syntax, and VEX/EVEX (AVX) operand forms
    are out of scope. `x86_64` shares this parser and adds only the 64-bit
    register names; nothing here is width-aware beyond that.
"""

from __future__ import annotations

import re
from typing import Iterator

AsmPlatform = str  # "arm" | "mips" | "x86" | "x86_64"
ArmOrMips = AsmPlatform  # Back-compat alias from the ARM/MIPS-only port.

X86_PLATFORMS = frozenset({"x86", "x86_64"})


def extract_function_calls_from_assembly(platform: AsmPlatform, assembly: str) -> list[str]:
    if platform == "arm":
        return _arm_extract_function_calls(assembly)
    if platform == "mips":
        return _mips_extract_function_calls(assembly)
    if platform in X86_PLATFORMS:
        return _x86_extract_function_calls(assembly)
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


def list_functions_from_asm_module(platform: AsmPlatform, assembly_content: str) -> list[dict[str, str]]:
    if platform == "arm":
        return _arm_list_functions_from_asm_module(assembly_content)
    if platform == "mips":
        return _mips_list_functions_from_asm_module(assembly_content)
    if platform in X86_PLATFORMS:
        return _x86_list_functions_from_asm_module(assembly_content)
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


def extract_asm_function_body(platform: AsmPlatform, asm_code: str) -> str:
    if platform == "arm":
        return _arm_extract_function_body(asm_code)
    if platform == "mips":
        return _mips_extract_function_body(asm_code)
    if platform in X86_PLATFORMS:
        return _x86_extract_function_body(asm_code)
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


# --- x86 (Intel syntax: objdiff `formatted` output and MASM listings) --------

# MSVC decorates symbols with characters an ARM/MIPS `\w+` never sees:
# `__free@4` (stdcall), `??_C@_0BG@FNMOODNL@shadowradius?$AA@` (C++ mangling),
# `__real@3ff0000000000000` (float pool), `$LN15` (compiler-local label).
# The lookbehind stops `0x4` from yielding a bogus `x4` symbol.
_X86_SYMBOL_RE = re.compile(r"(?<![A-Za-z0-9_?$@])[A-Za-z_?$@][A-Za-z0-9_?$@]*")
_X86_LOCAL_LABEL_RE = re.compile(r"^\$L")
_X86_CALL_RE = re.compile(r"^(?:call|jmp)\b(.*)$", re.IGNORECASE)
_X86_OFFSET_RE = re.compile(r"\bOFFSET\s+(?:FLAT\s*:\s*)?([A-Za-z_?$@][A-Za-z0-9_?$@]*)", re.IGNORECASE)

# String-operation and lock prefixes carry the real mnemonic in what looks
# like operand position (`rep movsd [edi], [esi]`).
_X86_PREFIXES = frozenset({"rep", "repe", "repz", "repne", "repnz", "lock", "bnd"})

# Control transfers other than `call`. `call` is an instruction but not a
# branch, matching the ARM path's treatment of `bl`.
_X86_CONDITIONAL_BRANCHES = frozenset(
    {
        "je", "jz", "jne", "jnz", "jl", "jnge", "jle", "jng", "jg", "jnle",
        "jge", "jnl", "jb", "jnae", "jc", "jbe", "jna", "ja", "jnbe",
        "jae", "jnb", "jnc", "jo", "jno", "js", "jns", "jp", "jpe",
        "jnp", "jpo", "jcxz", "jecxz", "jrcxz",
        "loop", "loope", "loopz", "loopne", "loopnz",
    }
)
_X86_UNCONDITIONAL_BRANCHES = frozenset({"jmp"})
_X86_BRANCH_MNEMONICS = _X86_CONDITIONAL_BRANCHES | _X86_UNCONDITIONAL_BRANCHES

# Every mnemonic observed in this project's corpus (an objdiff dump of 6,160
# MSVC-compiled x86 verifications), plus the common MSVC-era instructions
# that corpus happens not to reach. Used to keep a mnemonic sitting in
# operand position -- after a prefix, or as `(bad)` -- from being mistaken
# for a symbol reference.
_X86_MNEMONICS = (
    _X86_BRANCH_MNEMONICS
    | _X86_PREFIXES
    | frozenset(
        {
            "mov", "movzx", "movsx", "movsxd", "lea", "push", "pusha", "pushad", "pushf", "pushfd",
            "pop", "popa", "popad", "popf", "popfd", "xchg", "cmpxchg", "xadd", "bswap",
            "add", "adc", "sub", "sbb", "inc", "dec", "neg", "cmp", "test",
            "and", "or", "xor", "not", "shl", "sal", "shr", "sar", "rol", "ror", "rcl", "rcr",
            "shld", "shrd", "bt", "bts", "btr", "btc", "bsf", "bsr",
            "imul", "mul", "idiv", "div", "cbw", "cwd", "cwde", "cdq", "cdqe", "cqo",
            "call", "ret", "retn", "retf", "iret", "iretd", "enter", "leave", "int", "into",
            # `(bad)` is objdiff's marker for bytes its decoder rejected. It is
            # a known token, not an unknown mnemonic; bare `bad` keeps the
            # inner word from being read as a symbol reference.
            "nop", "hlt", "wait", "fwait", "cpuid", "rdtsc", "ud2", "bad", "(bad)",
            "clc", "stc", "cmc", "cld", "std", "cli", "sti", "lahf", "sahf",
            "movsb", "movsw", "movsd", "movsq", "stosb", "stosw", "stosd", "stosq",
            "lodsb", "lodsw", "lodsd", "lodsq", "scasb", "scasw", "scasd", "scasq",
            "cmpsb", "cmpsw", "cmpsd", "cmpsq", "insb", "insw", "insd",
            "outsb", "outsw", "outsd", "in", "out",
            "lds", "les", "lfs", "lgs", "lss", "arpl", "bound", "xlat", "xlatb",
            "seta", "setae", "setb", "setbe", "setc", "sete", "setg", "setge",
            "setl", "setle", "setna", "setnae", "setnb", "setnbe", "setnc",
            "setne", "setng", "setnge", "setnl", "setnle", "setno", "setnp",
            "setns", "setnz", "seto", "setp", "setpe", "setpo", "sets", "setz",
            "cmova", "cmovae", "cmovb", "cmovbe", "cmove", "cmovg", "cmovge",
            "cmovl", "cmovle", "cmovne", "cmovno", "cmovnp", "cmovns", "cmovo",
            "cmovp", "cmovs",
            # x87
            "fld", "fld1", "fldz", "fldpi", "fldl2e", "fldl2t", "fldlg2", "fldln2",
            "fldcw", "fldenv", "fst", "fstp", "fstcw", "fstenv", "fstsw", "fnstcw",
            "fnstsw", "fnstenv", "fnclex", "fclex", "fninit", "finit", "fsave", "fnsave", "frstor",
            "fild", "fist", "fistp", "fisttp", "fbld", "fbstp",
            "fadd", "faddp", "fiadd", "fsub", "fsubp", "fsubr", "fsubrp", "fisub", "fisubr",
            "fmul", "fmulp", "fimul", "fdiv", "fdivp", "fdivr", "fdivrp", "fidiv", "fidivr",
            "fcom", "fcomp", "fcompp", "fcomi", "fcomip", "fucom", "fucomp", "fucompp",
            "fucomi", "fucomip", "ficom", "ficomp", "ftst", "fxam",
            "fabs", "fchs", "fsqrt", "fscale", "fprem", "fprem1", "frndint", "fxtract",
            "fsin", "fcos", "fsincos", "fptan", "fpatan", "f2xm1", "fyl2x", "fyl2xp1",
            "fxch", "fincstp", "fdecstp", "ffree", "fnop",
        }
    )
)

# Operand-position words that look like symbols but are not: registers, size
# specifiers, segment names, and the branch-distance keywords.
_X86_NON_SYMBOL_WORDS = frozenset(
    {
        # 8/16/32-bit
        "al", "ah", "bl", "bh", "cl", "ch", "dl", "dh",
        "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip", "eflags",
        # 64-bit (x86_64 shares this parser)
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
        "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
        "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
        "sil", "dil", "bpl", "spl",
        # segments, x87, SIMD
        "cs", "ds", "es", "fs", "gs", "ss", "st",
        "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
        "mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7",
        # size / distance / linkage keywords
        "byte", "word", "dword", "qword", "tbyte", "xmmword", "ymmword",
        "ptr", "near", "far", "short", "offset", "flat", "bad",
    }
)

# MASM structural keywords. `PROC`/`ENDP` delimit functions; the rest is the
# module scaffolding a listing carries around them.
_X86_PROC_RE = re.compile(r"^([A-Za-z_?$@][A-Za-z0-9_?$@]*)\s+PROC\b", re.IGNORECASE)
_X86_ENDP_RE = re.compile(r"^([A-Za-z_?$@][A-Za-z0-9_?$@]*)\s+ENDP\b", re.IGNORECASE)
_X86_LABEL_RE = re.compile(r"^([A-Za-z_?$@][A-Za-z0-9_?$@]*)\s*:\s*$")
_X86_GLOBL_RE = re.compile(r"^\.(?:globl|global)\s+([A-Za-z_?$@][A-Za-z0-9_?$@]*)", re.IGNORECASE)
_X86_EQUATE_RE = re.compile(r"^[A-Za-z_?$@][A-Za-z0-9_?$@]*\s*=")
_X86_DIRECTIVE_WORDS = frozenset(
    {
        "segment", "ends", "end", "proc", "endp", "public", "extrn", "extern",
        "includelib", "include", "assume", "group", "title", "subtitle",
        "if", "ifdef", "ifndef", "ife", "else", "elseif", "endif", "org", "even",
        "comm", "option", "model", "record", "struc", "align", "alias",
    }
)
_X86_DATA_DEFINITION_RE = re.compile(r"^(?:db|dw|dd|dq|dt)\b", re.IGNORECASE)


def _x86_strip_comment(line: str) -> str:
    """Drop a trailing comment.

    `;` is the MASM marker, `#` the GAS one, `//` common to both. `@` is
    deliberately NOT a marker: unlike ARM, an x86 line legitimately contains
    it inside MSVC-decorated symbols (`__free@4`, `??_C@_0BG@...`), and the
    ARM rule would truncate every one of them mid-name. `;` inside a quoted
    string is left alone -- MASM listings quote segment classes as `'CODE'`.
    """
    in_single = False
    in_double = False
    for index, char in enumerate(line):
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif not in_single and not in_double:
            if char in ";#":
                return line[:index]
            if char == "/" and line[index + 1 : index + 2] == "/":
                return line[:index]
    return line


def _x86_normalize_line(raw_line: str) -> str:
    """Comment-free, whitespace-collapsed form of one x86 source line."""
    return re.sub(r"\s+", " ", _x86_strip_comment(raw_line).replace("\t", " ")).strip()


def _x86_is_directive(line: str) -> bool:
    if not line:
        return True
    if line.startswith("."):
        return True
    if _X86_EQUATE_RE.match(line):
        return True
    if _X86_PROC_RE.match(line) or _X86_ENDP_RE.match(line):
        return True
    if _X86_LABEL_RE.match(line):
        return True
    words = line.split()
    first = words[0].lower()
    if first in _X86_DIRECTIVE_WORDS:
        return True
    # `_TEXT SEGMENT ...`, `_TEXT ENDS`, `FLAT GROUP ...`: the keyword is the
    # second word, with the symbol it applies to first.
    if len(words) >= 2 and words[1].lower() in {"segment", "ends", "group", "equ", "label"}:
        return True
    return False


def _x86_operand_symbols(text: str) -> list[str]:
    """Symbolic (non-register, non-keyword, non-numeric) names in an operand string."""
    found: list[str] = []
    for match in _X86_SYMBOL_RE.finditer(text):
        name = match.group(0)
        lowered = name.lower()
        if lowered in _X86_NON_SYMBOL_WORDS or lowered in _X86_MNEMONICS:
            continue
        if _X86_LOCAL_LABEL_RE.match(name):
            # `$L562` / `$LN15` are compiler-local jump targets, not callees.
            continue
        if name.endswith("$"):
            # MASM stack-frame equates (`_param_1$[esp]`), declared by the
            # listing's own `_param_1$ = 8` lines. Not an inter-function edge.
            continue
        found.append(name)
    return found


def _x86_mnemonic(line: str) -> str:
    """Mnemonic of one normalized x86 line, seeing through prefixes."""
    words = line.split(" ", 2)
    head = words[0].lower()
    if head in _X86_PREFIXES and len(words) > 1:
        return words[1].lower()
    return head


def _x86_extract_function_calls(assembly: str) -> list[str]:
    """Symbolic call/jump targets and referenced data symbols, in first-seen order.

    Numeric targets are deliberately excluded -- see the module docstring.
    Data symbols are included for the same reason the ARM path records
    `@ =gSomeGlobal`: a reference to `_DAT_007a6990` or `__real@3ff...` is a
    real edge in the corpus graph even though it is not a call.
    """
    function_calls: dict[str, None] = {}
    for raw_line in assembly.split("\n"):
        line = _x86_normalize_line(raw_line)
        if not line or _x86_is_directive(line):
            continue

        for name in _X86_OFFSET_RE.findall(line):
            function_calls[name] = None

        call_match = _X86_CALL_RE.match(line)
        if call_match:
            for name in _x86_operand_symbols(call_match.group(1)):
                function_calls[name] = None
            continue

        space_index = line.find(" ")
        if space_index == -1:
            continue
        for name in _x86_operand_symbols(line[space_index + 1 :]):
            function_calls[name] = None
    return list(function_calls.keys())


def _x86_list_functions_from_asm_module(assembly_content: str) -> list[dict[str, str]]:
    """Split an x86 module into functions.

    MASM `PROC`/`ENDP` pairs are authoritative when present. Otherwise a
    `.globl NAME` (GAS) or a bare `NAME:` label opens a function that runs
    until the next such opener.
    """
    functions: list[dict[str, str]] = []
    lines = assembly_content.split("\n")
    current: dict[str, object] | None = None

    def push_current(end_index: int) -> None:
        assert current is not None
        code = "\n".join(lines[int(current["startIndex"]) : end_index])
        functions.append({"name": str(current["name"]), "code": code})

    pending_globl: str | None = None

    for index, raw_line in enumerate(lines):
        line = _x86_normalize_line(raw_line)
        if not line:
            continue

        proc_match = _X86_PROC_RE.match(line)
        if proc_match:
            if current is not None:
                push_current(index)
            current = {"name": proc_match.group(1), "startIndex": index}
            pending_globl = None
            continue

        endp_match = _X86_ENDP_RE.match(line)
        if endp_match and current is not None:
            push_current(index + 1)
            current = None
            continue

        globl_match = _X86_GLOBL_RE.match(line)
        if globl_match:
            pending_globl = globl_match.group(1)
            continue

        label_match = _X86_LABEL_RE.match(line)
        if label_match:
            name = label_match.group(1)
            if _X86_LOCAL_LABEL_RE.match(name):
                continue
            # Only a label that a `.globl` announced, or any label when no
            # PROC/ENDP framing exists, opens a new function. This keeps
            # MASM local labels inside their enclosing PROC.
            if current is not None and current.get("framed"):
                continue
            if current is not None:
                push_current(index)
            current = {"name": name, "startIndex": index, "framed": False}
            if pending_globl == name:
                pending_globl = None
            continue

    if current is not None:
        push_current(len(lines))

    return functions


def iter_x86_instructions(asm_code: str) -> Iterator[tuple[str, str]]:
    """Yield `(normalized line, mnemonic)` for each x86 instruction line.

    Directives, labels, comments, blank lines, and `DB`-style byte blobs are
    skipped. Public because asm_metrics counts the same lines this splits.
    """
    for raw_line in asm_code.split("\n"):
        line = _x86_normalize_line(raw_line)
        if not line or _x86_is_directive(line):
            continue
        if _X86_DATA_DEFINITION_RE.match(line):
            # `DB 06ah, 0ffh, ...` byte blobs carry no instruction structure.
            continue
        yield line, _x86_mnemonic(line)


def is_x86_branch_mnemonic(mnemonic: str) -> bool:
    """True for control transfers other than `call` (which is not a branch)."""
    return mnemonic.lower() in _X86_BRANCH_MNEMONICS


def x86_label_name(raw_line: str) -> str | None:
    """Label defined by this line (`$L562:` -> `$L562`), or None."""
    match = _X86_LABEL_RE.match(_x86_normalize_line(raw_line))
    return match.group(1) if match else None


def is_x86_local_label(name: str) -> bool:
    """True for a compiler-local branch target (`$L562`, `$LN15`, `.L2`).

    The ARM and MIPS metrics count only local labels, not the global symbol
    naming the function itself; this is the x86 spelling of the same rule.
    """
    return bool(_X86_LOCAL_LABEL_RE.match(name)) or name.startswith(".L")


def _x86_extract_function_body(asm_code: str) -> str:
    """Instruction lines only: no directives, labels, comments, or PROC framing."""
    return "\n".join(line for line, _mnemonic in iter_x86_instructions(asm_code))


def strip_commentaries(asm_code: str, platform: AsmPlatform | None = None) -> str:
    """Remove comments from assembly text.

    `platform` is optional for back-compatibility with the ARM/MIPS port,
    which called this with one argument. It matters for x86: MSVC-decorated
    symbols contain `@` (`__free@4`, `??_C@_0BG@...`), and the ARM rule that
    `@` starts a comment would truncate them mid-name.
    """
    if platform in X86_PLATFORMS:
        return "\n".join(_x86_strip_comment(line).rstrip() for line in asm_code.split("\n"))

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


def count_body_lines_from_asm_function(platform: AsmPlatform, asm_code: str) -> int:
    body_code = extract_asm_function_body(platform, asm_code)
    return len([line for line in body_code.split("\n") if line.strip() != ""])
