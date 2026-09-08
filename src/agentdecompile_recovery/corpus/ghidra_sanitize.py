"""Mechanical Ghidra-C cleanup measured in the kotorxid compile pass.

These transforms exist so Ghidra decompilation can be compiled as C without
an LLM. Do not add a spelling fix unless a compiler diagnostic asked for it.
Known process-wide globals are *not* hardcoded here: pass them on the corpus
as `knownGlobals` after a failure log names them.
"""

from __future__ import annotations

import re

QUALIFIED_RE = re.compile(r"\b([A-Za-z_]\w*(?:::~?[A-Za-z_]\w*)+)\b")
THISCALL_RE = re.compile(r"\b__thiscall\b")
FIELD_NAME_RE = re.compile(r"\bfield\d+_0x([0-9a-fA-F]+)\b")
BARE_DTOR_RE = re.compile(r"(?<![:\w])~([A-Za-z_]\w*)\s*\(")
TEMPLATE_RE = re.compile(
    r"((?:[A-Za-z_]\w*::)*[A-Za-z_]\w*)<([A-Za-z0-9_:*\s,]+)>"
)

INTRINSIC_MACROS = r"""
#define true 1
#define false 0
#define CONCAT11(a,b) ((unsigned short)(((unsigned short)(unsigned char)(a) << 8) | (unsigned char)(b)))
#define CONCAT12(a,b) ((unsigned int)(((unsigned int)(unsigned char)(a) << 16) | (unsigned short)(b)))
#define CONCAT13(a,b) ((unsigned int)(((unsigned int)(unsigned char)(a) << 24) | ((unsigned int)(b) & 0xFFFFFFu)))
#define CONCAT14(a,b) ((unsigned __int64)(((unsigned __int64)(unsigned char)(a) << 32) | (unsigned int)(b)))
#define CONCAT21(a,b) ((unsigned int)(((unsigned int)(unsigned short)(a) << 8) | (unsigned char)(b)))
#define CONCAT22(a,b) ((unsigned int)(((unsigned int)(unsigned short)(a) << 16) | (unsigned short)(b)))
#define CONCAT44(a,b) ((unsigned __int64)(((unsigned __int64)(unsigned int)(a) << 32) | (unsigned int)(b)))
#define SUB41(a,off) ((unsigned char)((unsigned int)(a) >> ((off)*8)))
#define SUB42(a,off) ((unsigned short)((unsigned int)(a) >> ((off)*8)))
#define SUB84(a,off) ((unsigned int)((unsigned __int64)(a) >> ((off)*8)))
#define ZEXT14(a) ((unsigned int)(unsigned char)(a))
#define ZEXT24(a) ((unsigned int)(unsigned short)(a))
"""

STUB_TYPES = r"""
typedef struct _CONTEXT _CONTEXT;
typedef struct _iobuf FILE;
typedef int BOOL;
typedef long time_t;
typedef void *PROC;
typedef long HRESULT;
extern void *ExceptionList;
"""


def c_name(name: str) -> str:
    """`Class::method` is not a C identifier."""
    return re.sub(r"[^A-Za-z_0-9]", "_", name)


def flatten_names(code: str) -> str:
    return QUALIFIED_RE.sub(lambda m: c_name(m.group(1)), code)


def fix_thiscall(code: str) -> str:
    """`__thiscall` → `__fastcall(this, edx_unused, ...)` for C-only compilers."""
    m = THISCALL_RE.search(code)
    if not m:
        return code
    paren_start = code.find("(", m.end())
    if paren_start == -1:
        return code
    depth, i = 0, paren_start
    while i < len(code):
        if code[i] == "(":
            depth += 1
        elif code[i] == ")":
            depth -= 1
            if depth == 0:
                break
        i += 1
    if i >= len(code):
        return code
    params = code[paren_start + 1 : i].strip()
    parts = [p.strip() for p in params.split(",")] if params else []
    if not parts:
        return code
    new_params = ", ".join([parts[0], "int edx_unused"] + parts[1:])
    return code[: m.start()] + "__fastcall" + code[m.end() : paren_start + 1] + new_params + code[i:]


def fix_field_names(code: str) -> str:
    return FIELD_NAME_RE.sub(lambda m: f"field_{m.group(1)}", code)


def fix_bare_destructor(code: str) -> str:
    return BARE_DTOR_RE.sub(lambda m: f"{c_name('~' + m.group(1))}(", code)


def flatten_templates(code: str) -> str:
    def sub(m: re.Match) -> str:
        inner = re.sub(r"[^A-Za-z0-9]+", "_", m.group(2)).strip("_")
        return f"{m.group(1)}_{inner}"

    prev = None
    while prev != code:
        prev = code
        code = TEMPLATE_RE.sub(sub, code)
    return code


def sanitize_body(code: str) -> str:
    """Compile-path spelling via HighFacts + Clang. No GhidraBlob / ghidra_call."""
    from .normalize_pipeline import NormalizeMode, normalize_decompiled

    return normalize_decompiled(code, mode=NormalizeMode.COMPILE_ONLY).text


def global_externs(body: str, known_globals: dict[str, str]) -> str:
    """`extern Type *Name;` for singletons the body names. Empty unless configured."""
    if not body or not known_globals:
        return ""
    idents = set(re.findall(r"\b[A-Za-z_]\w*\b", body))
    lines = []
    for gname, tname in known_globals.items():
        if gname in idents:
            lines.append(f"extern {tname} *{gname};")
    return "\n".join(lines)


def compile_preamble(*, known_globals: dict[str, str] | None = None, body: str = "") -> str:
    extras = global_externs(body, known_globals or {})
    return "\n".join(part for part in (INTRINSIC_MACROS, STUB_TYPES, extras) if part.strip())
