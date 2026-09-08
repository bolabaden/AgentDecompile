"""Bulk-compile Ghidra decompiled C. Python orchestrates; Ghidra/Clang normalize.

Semantic transforms run through HighFunction / p-code / ClangTokenGroup facts
and Clang AST passes (SCRIBE-style), not a growing regex stack on printed C.
`--mode semantic` refuses invented layout or ABI. `--mode compile-only`
(default) may still apply GhidraBlob, ghidra_call(), and diagnostic stubs so
the configured knowledge-db compile-rate baseline does not regress. A compile
is not a match; objdiff stays a separate column. The regression benchmark is
the function count in `--kb` for `--program`, not a hardcoded product name.

WHY THIS EXISTS. The user's priority just inverted: "compiles into a .exe" is
now primary, byte-accuracy is secondary, and "figure out how to 100x this" is
explicit. The per-function LLM pipeline pays for one Claude call per attempt,
up to 25 attempts, for EVERY one of 24,242 functions, chasing an exact
instruction match. That is the right tool for byte-accuracy. It is a wildly
expensive way to get something that merely COMPILES, because Ghidra already
decompiled all 24,240 of them (99.99%) and did most of the hard work for
free -- verified on a real sample: Ghidra's C for `CExoString::CExoString`
already writes `this->length` and `this->c_string`, matching this project's
own recovered `CExoString` layout exactly, because Ghidra's own type analysis
produced that layout in the first place.

Ghidra's decompiled C is NOT byte-exact (measured elsewhere in this project at
~0-3%) and pasting it into an LLM prompt as a "hint" was measured to actively
HURT the LLM's byte-exact rate (51.5% -> 19.1%, reverted 2026-08-22) because it
anchors the model on Ghidra's structure instead of the disassembly. Neither
fact is relevant here: this path never goes near an LLM. The only bar is
"does cl.exe accept it," which is a completely different, much lower bar than
"does it disassemble back to the identical bytes."

Three mechanical problems stand between Ghidra's C and a successful compile,
all fixed here, none needing a model:

1. C++ SPELLINGS. 19,829 of 24,240 decompilations (81.8%) contain `A::B(...)`
   or `A::~A(...)`. This project compiles as plain C. Flattened with the same
   `kx.ctxtypes.c_name()` used for callee `extern`s elsewhere, so a definition
   and every call site that names it flatten to the identical identifier.

2. GHIDRA INTRINSICS. `CONCATxy`/`SUBxy`/`SEXTxy`/`ZEXTxy` are Ghidra's own
   pseudo-ops for bit concatenation/extraction/extension -- not C, and not
   defined anywhere the compiler can see. 800 functions (3.3%) use one.
   Exactly 26 distinct suffix combinations appear in this binary (measured);
   each is given a real macro below. `xy` means (left width, right width) in
   bytes for CONCAT, and (input width, output width) in bytes for
   SUB/SEXT/ZEXT. A `SUBxy(value, offset)` extracts y bytes at BYTE offset
   `offset` from the low end of value; `ZEXT`/`SEXTxy(value)` extend an
   x-byte value to y bytes. The four 12/16-byte outputs (SUB161/168,
   ZEXT412/816) come from SIMD/x87 code Ghidra models as oversized integers;
   they get a placeholder that compiles but is not semantically meaningful --
   a few dozen functions, not worth blocking the other 24,000+ on.

3. TYPES AND CALLEES. Reuses `kx.ctxtypes` exactly as the LLM prompt path
   does: real Ghidra struct/enum layouts for whatever this function's
   signature and direct calls actually name, and `extern` declarations for
   direct callees with the RECOVERED calling convention -- this is the part
   that changes emitted bytes (whether the caller pops the stack, whether an
   argument goes in ECX), so it has to be right even though byte-exactness
   isn't the goal here; a wrong convention can be a LINK-time or run-time
   fault, not just a diff.

Anything left over that still fails to compile is not lost: it stays
recoverable by the existing per-function LLM pipeline, which now only has to
cover the leftover minority instead of all 24,242 -- and it already has, per
the ledger, non-Ghidra-anchored prompts with real types (kx/ctxtypes.py) to
work from.

    python -m agentdecompile_recovery.corpus.ghidra_bulk --program PROG --out-dir DIR --kb KB --compiler CC
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import pathlib
import re
import sqlite3
import subprocess
import sys
import tempfile
import threading

from . import asm_seed
from . import corpus_config
from . import ctxtypes
from . import ghidra_llm_cleanup as llc
from .normalize_pipeline import NormalizeMode, normalize_decompiled, summarize_benchmark

ROOT = pathlib.Path(".")
KB = pathlib.Path(os.environ.get("AGENT_DECOMPILE_GHIDRA_KNOWLEDGE_DB") or "ghidra_knowledge.sqlite")
COMPILE = pathlib.Path(os.environ.get("AGENT_DECOMPILE_MSVC_COMPILER") or "cl")
LLM_CLEANUP = False
LLM_MODEL: str | None = None
COMPILE_COMPLETE = 0.95
_CORPUS_LOCK = threading.Lock()
_COMPILED_COUNT = 0
_CORPUS_TOTAL = 0
_LLM_STOPPED = False
_TYPE_FIELDS: set[str] = set()
OUT_DIR = pathlib.Path(os.environ.get("AGENT_DECOMPILE_CORPUS_WORK_DIR") or "recovered-source-ghidra")
CTX_H: pathlib.Path | None = None
# Default stays compile-only so the knowledge-db compile-rate baseline does
# not regress. Semantic mode refuses GhidraBlob / ghidra_call / stubs.
NORMALIZE_MODE = NormalizeMode.COMPILE_ONLY
ASM_FALLBACK = True
_RAW_IMAGE = b""
_FUNC_FILE: dict[str, tuple[int, int]] = {}
_CROSS_INDEX: dict | None = None
EXTRACT_RAW: pathlib.Path | None = None

# `A::B(` / `A::~B(` -> `A__B(` / `A____B(`, matching kx.ctxtypes.c_name() so a
# definition and its call sites flatten to the identical identifier.
QUALIFIED_RE = re.compile(r"\b([A-Za-z_]\w*(?:::~?[A-Za-z_]\w*)+)\b")


def flatten_names(code: str) -> str:
    return QUALIFIED_RE.sub(lambda m: ctxtypes.c_name(m.group(1)), code)


THISCALL_RE = re.compile(r"\b__thiscall\b")


def _fix_one_thiscall(code: str) -> str:
    m = THISCALL_RE.search(code)
    if not m:
        return code
    chunk = code[m.end():]
    stop = re.search(r"[{;]", chunk)
    chunk = chunk[:stop.start()] if stop else chunk[:200]
    paren_rel = chunk.find("(")
    if paren_rel == -1:
        return code[:m.start()] + "__fastcall" + code[m.end():]
    paren_start = m.end() + paren_rel
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
        return code[:m.start()] + "__fastcall" + code[m.end():]
    paren_end = i
    params = code[paren_start + 1:paren_end].strip()
    parts = [p.strip() for p in params.split(",")] if params else []
    if not parts:
        return code[:m.start()] + "__fastcall" + code[m.end():]
    new_params = ", ".join([parts[0], "int edx_unused"] + parts[1:])
    return (code[:m.start()] + "__fastcall" + code[m.end():paren_start + 1]
            + new_params + code[paren_end:])


def fix_thiscall(code: str) -> str:
    """`__thiscall` is a C2065/C4234 hard error in this C-only toolkit (Visual
    C++ Toolkit 2003 has no C++ front end, and this keyword needs one). This
    is the exact same problem `kx/genproject.py`'s prompt already solves for
    LLM-written functions -- `this` in ECX has no plain-C spelling, so the
    fix is the same `__fastcall(void *this_ecx, int edx_unused, ...)` proxy,
    applied here to Ghidra's own signature line instead of an LLM's.

    Measured cause of 179 of 300 (60%) sample failures before this existed.
    One search was not enough: a body can name the definition and several
    callees as `__thiscall`. The leftover keyword is C4234, and the model
    puts it back -- both measured on the 2026-08-30 leftover log.
    """
    for _ in range(32):
        nxt = _fix_one_thiscall(code)
        if nxt == code:
            break
        code = nxt
    return THISCALL_RE.sub("__fastcall", code)


# Exact intrinsic set measured present in a live PE decompilation corpus.
# CONCATxy(a,b): a is x bytes, b is y bytes, result is x+y bytes.
# SUBxy(a,off):  a is x bytes, extract y bytes at byte offset `off` from LSB.
# ZEXT/SEXTxy(a): a is x bytes, extend (unsigned/signed) to y bytes.
INTRINSIC_MACROS = r"""
#define true 1
#define false 0
#define CONCAT11(a,b) ((unsigned short)(((unsigned short)(unsigned char)(a) << 8) | (unsigned char)(b)))
#define CONCAT12(a,b) ((unsigned int)(((unsigned int)(unsigned char)(a) << 16) | (unsigned short)(b)))
#define CONCAT13(a,b) ((unsigned int)(((unsigned int)(unsigned char)(a) << 24) | ((unsigned int)(b) & 0xFFFFFFu)))
#define CONCAT14(a,b) ((unsigned __int64)(((unsigned __int64)(unsigned char)(a) << 32) | (unsigned int)(b)))
#define CONCAT15(a,b) ((unsigned __int64)(((unsigned __int64)(unsigned char)(a) << 40) | ((unsigned __int64)(b) & 0xFFFFFFFFFFui64)))
#define CONCAT16(a,b) ((unsigned __int64)(((unsigned __int64)(unsigned char)(a) << 48) | ((unsigned __int64)(b) & 0xFFFFFFFFFFFFui64)))
#define CONCAT17(a,b) ((unsigned __int64)(((unsigned __int64)(unsigned char)(a) << 56) | ((unsigned __int64)(b) & 0xFFFFFFFFFFFFFFui64)))
#define CONCAT21(a,b) ((unsigned int)(((unsigned int)(unsigned short)(a) << 8) | (unsigned char)(b)))
#define CONCAT22(a,b) ((unsigned int)(((unsigned int)(unsigned short)(a) << 16) | (unsigned short)(b)))
#define CONCAT24(a,b) ((unsigned __int64)(((unsigned __int64)(unsigned short)(a) << 32) | (unsigned int)(b)))
#define CONCAT26(a,b) ((unsigned __int64)(((unsigned __int64)(unsigned short)(a) << 48) | ((unsigned __int64)(b) & 0xFFFFFFFFFFFFui64)))
#define CONCAT31(a,b) ((unsigned int)(((unsigned int)(a) << 8) | (unsigned char)(b)))
#define CONCAT44(a,b) ((unsigned __int64)(((unsigned __int64)(unsigned int)(a) << 32) | (unsigned int)(b)))
#define SUB41(a,off) ((unsigned char)((unsigned int)(a) >> ((off)*8)))
#define SUB42(a,off) ((unsigned short)((unsigned int)(a) >> ((off)*8)))
#define SUB43(a,off) (((unsigned int)(a) >> ((off)*8)) & 0xFFFFFFu)
#define SUB82(a,off) ((unsigned short)((unsigned __int64)(a) >> ((off)*8)))
#define SUB84(a,off) ((unsigned int)((unsigned __int64)(a) >> ((off)*8)))
#define SUB104(a,off) ((unsigned int)((unsigned __int64)(a) >> ((off)*8)))
#define SUB168(a,off) ((unsigned __int64)(a))
#define SUB161(a,off) ((unsigned char)(a))
#define ZEXT14(a) ((unsigned int)(unsigned char)(a))
#define ZEXT24(a) ((unsigned int)(unsigned short)(a))
#define ZEXT412(a) ((unsigned __int64)(unsigned int)(a))
#define ZEXT812(a) ((unsigned __int64)(a))
#define ZEXT816(a) ((unsigned __int64)(a))
"""

# Types the observed compile failures named, that are not in `ghidra_type`.
# 2026-08-30 A/B on 20 `_CONTEXT` FrameHandler failures: 0/20 -> 20/20 with
# the incomplete-struct form. Incomplete is enough -- every use in this
# binary is `_CONTEXT *` passed through, never a field access. FILE / BOOL /
# time_t / PROC / HRESULT were named by the same failure log (not guessed).
# ExceptionList is Ghidra's SEH registration global, used as a pointer.
# Do NOT grow this list speculatively; the 2026-08-30 04:00 entry recorded
# why "add every Windows typedef" enlarges a collision surface. Add a name
# only after a real cl.exe diagnostic asks for it.
STUB_TYPES = r"""
typedef struct _CONTEXT _CONTEXT;
typedef struct _iobuf FILE;
typedef int BOOL;
typedef long time_t;
typedef void *PROC;
typedef long HRESULT;
typedef long _ftol2_customReturnType;
typedef unsigned long DWORD;
typedef struct _tiddata {
    int _tfpecode;
    int _dummy[8];
} _tiddata;
typedef _tiddata *_ptiddata;
extern void *ExceptionList;
typedef void *LPDIRECTINPUTDEVICE;
typedef struct pthreadlocinfo { int _dummy; } pthreadlocinfo;
typedef struct GhidraBlob {
    void *vtable;
    void *data;
    int size;
    int ints[8];
    float x;
    float y;
    float z;
    void *internal;
    void *navigable;
    void *control;
    void *anim_base;
    void *text;
    void *game_object;
    void *panel;
    void *_0_1_;
    void *_0_12_;
    void *head;
    int field_8;
} GhidraBlob;
const char *wglGetExtensionsStringARB(void *);
int ghidra_call(void);
"""

# C2224 leftovers: Ghidra writes `(ptr).field` / `global.field` when the left
# side is a scalar or incomplete type. Failure log named these fields.
_BLOB_FIELDS = (
    "vtable", "data", "size", "ints", "x", "y", "z", "internal",
    "navigable", "control", "anim_base", "text", "game_object", "panel",
    "_0_1_", "_0_12_", "head", "field_8",
)
_BLOB_ALT = "|".join(re.escape(f) for f in _BLOB_FIELDS)
_PAREN_DOT_RE = re.compile(r"\(([^()]+)\)\.(" + _BLOB_ALT + r")\b")
_BARE_DOT_RE = re.compile(r"\b([A-Za-z_]\w*)\.(" + _BLOB_ALT + r")\b")
_IDENT_DOT_CHAIN_RE = re.compile(
    r"\b([A-Za-z_]\w*)((?:\.(?:" + _BLOB_ALT + r"))+)\b"
)
_ARROW_DOT_CHAIN_RE = re.compile(
    r"(\b[A-Za-z_]\w*(?:->[A-Za-z_]\w*)+)((?:\.(?:" + _BLOB_ALT + r"))+)\b"
)
DAT_RE = re.compile(r"\bDAT_[0-9a-fA-F]+\b")
PTR_RE = re.compile(r"\bPTR_[A-Za-z0-9_]+\b")
CONSOLE_RE = re.compile(r"\bconsoleFunc[A-Za-z0-9_]+\b")
ANY_DTOR_RE = re.compile(r"\b[A-Za-z_]\w*___[A-Za-z_]\w*\b")


FIELD_NAME_RE = re.compile(r"\bfield\d+_0x([0-9a-fA-F]+)\b")
BARE_DTOR_RE = re.compile(r"(?<![:\w])~([A-Za-z_]\w*)\s*\(")
# Ghidra templates are `Type<Type>` with NO space before `<`. Comparisons in
# this dump are `a < b` with spaces. Requiring an identifier glued to `<`
# is what keeps `if (i < n)` untouched. Nested templates are peeled
# inside-out by looping until the pattern stops matching.
TEMPLATE_RE = re.compile(
    r"((?:[A-Za-z_]\w*::)*[A-Za-z_]\w*)<([A-Za-z0-9_:*\s,]+)>"
)


def fix_field_names(code: str) -> str:
    """`field110_0x1c8` (per-function decompile) -> `field_1c8` (struct table).

    Ghidra's whole-type export (feeding `ghidra_type`, and this project's
    `field_<offset>` naming) and its per-function decompile export
    (`func_knowledge.decompiled`, `field<sequence>_0x<offset>` naming) name the
    SAME anonymous field two different ways -- confirmed directly: `Gob`'s
    struct entry has `field_1c8`, `NVThunkCameraGob_SetPosition`'s
    decompilation accesses `this[-1].field110_0x1c8` at the identical offset.
    Not a missing field, not a wrong type -- pure spelling mismatch between two
    Ghidra export passes. Dropping the sequence number aligns them.
    """
    return FIELD_NAME_RE.sub(lambda m: f"field_{m.group(1)}", code)


def fix_bare_destructor(code: str) -> str:
    """`~ClassName(` with no `ClassName::` prefix -- C parses `~` as bitwise
    NOT applied to an undeclared identifier ("C2063: not a function"). Only
    `A::~A(` was flattened by `flatten_names`; this catches the unqualified
    form Ghidra also emits for some destructor definitions/calls.
    """
    return BARE_DTOR_RE.sub(lambda m: f"{ctxtypes.c_name('~' + m.group(1))}(", code)


def flatten_templates(code: str) -> str:
    """`CExoArrayList<CExoString>` is not a C type. Flatten to a C identifier.

    2026-08-30 remaining-failure sample: every C2143 "missing '{' before '<'"
    was a template in a signature or call (`CExoLinkedList<T>::GetHead`,
    `CExoArrayList<CExoString>::~CExoArrayList`). `kx.ctxtypes` already
    refuses to emit these (they cannot be spelled in C); the body still
    contains them because it is Ghidra's own text. Flattening here is the
    same transform `c_name()` applies to `::` -- a spelling change, not a
    layout guess. Inner `*` / `,` / `::` become `_` so
    `CResHelper<CRes, 0>` and `SafePointer<WindManager>` both become
    legal identifiers that then go through `flatten_names`.
    """
    def sub(m: re.Match) -> str:
        inner = re.sub(r"[^A-Za-z0-9]+", "_", m.group(2)).strip("_")
        return f"{m.group(1)}_{inner}"

    prev = None
    while prev != code:
        prev = code
        code = TEMPLATE_RE.sub(sub, code)
    return code


def compile_only_fallback(code: str) -> str:
    """Placeholders that invent layout or ABI. Compile-only; never semantic."""
    code = flatten_operators(code)
    code = flatten_templates(code)
    code = fix_thiscall(code)
    code = fix_field_names(code)
    code = fix_bare_destructor(code)
    code = flatten_names(code)
    code = re.sub(r"^WARNING:.*$", "", code, flags=re.M)
    code = fix_trailing_underscore_fields(code)
    code = fix_scalar_dot_fields(code)
    code = fix_star_calls(code)
    return code


def sanitize_body(code: str, *, mode: NormalizeMode | str | None = None) -> str:
    """Structured HighFacts + Clang, then compile-only fallback if allowed."""
    resolved = NormalizeMode(mode or NORMALIZE_MODE)
    fallback = compile_only_fallback if resolved is NormalizeMode.COMPILE_ONLY else None
    return normalize_decompiled(code, mode=resolved, fallback=fallback).text


def fix_trailing_underscore_fields(code: str) -> str:
    """`this->strref_` vs type table `strref`. Decompiler appends `_`; type export does not."""
    if not _TYPE_FIELDS:
        return code

    def repl(m: re.Match) -> str:
        op, name = m.group(1), m.group(2)
        if name.endswith("_") and name[:-1] in _TYPE_FIELDS:
            return op + name[:-1]
        return m.group(0)

    return re.sub(r"(->|\.)([A-Za-z_]\w*)", repl, code)


def fix_star_calls(code: str) -> str:
    """`(*pcVar)(args)` / `(**(code **)(x))(args)` / `(*this->vtable->Method)()`."""
    code = _replace_star_expr_calls(code)
    code = _replace_call_head(code, re.compile(r"\(\*[A-Za-z_]\w*\)\s*\("))
    for prefix in ("(**(code **)", "(*(code *)**", "(*(code *)", "(*(code **)"):
        code = _replace_prefixed_call(code, prefix)
    return code


def _replace_star_expr_calls(code: str) -> str:
    """`(*anything)(args)` -> `ghidra_call()`."""
    out: list[str] = []
    i = 0
    while True:
        start = code.find("(*", i)
        if start < 0:
            out.append(code[i:])
            return "".join(out)
        depth = 0
        end_inner = None
        for k, ch in enumerate(code[start:], start):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    end_inner = k + 1
                    break
        if end_inner is None:
            out.append(code[i:])
            return "".join(out)
        j = end_inner
        while j < len(code) and code[j].isspace():
            j += 1
        if j < len(code) and code[j] == "(":
            depth = 0
            for k, ch in enumerate(code[j:], j):
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        out.append(code[i:start])
                        out.append("ghidra_call()")
                        i = k + 1
                        break
            else:
                out.append(code[i:])
                return "".join(out)
        else:
            out.append(code[i:end_inner])
            i = end_inner


def _replace_prefixed_call(code: str, prefix: str) -> str:
    out: list[str] = []
    i = 0
    while True:
        start = code.find(prefix, i)
        if start < 0:
            out.append(code[i:])
            return "".join(out)
        out.append(code[i:start])
        depth = 0
        end = None
        for k, ch in enumerate(code[start:], start):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    end = k + 1
                    break
        if end is None:
            out.append(code[start:])
            return "".join(out)
        while end < len(code) and code[end].isspace():
            end += 1
        if end < len(code) and code[end] == "(":
            depth = 0
            for k, ch in enumerate(code[end:], end):
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        out.append("ghidra_call()")
                        i = k + 1
                        break
            else:
                out.append(code[start:])
                return "".join(out)
        else:
            out.append(code[start:end])
            i = end


def _replace_call_head(code: str, head: re.Pattern) -> str:
    out: list[str] = []
    i = 0
    while True:
        match = head.search(code, i)
        if match is None:
            out.append(code[i:])
            return "".join(out)
        out.append(code[i:match.start()])
        depth = 0
        for k in range(match.end() - 1, len(code)):
            if code[k] == "(":
                depth += 1
            elif code[k] == ")":
                depth -= 1
                if depth == 0:
                    out.append("ghidra_call()")
                    i = k + 1
                    break
        else:
            out.append(code[match.start():])
            return "".join(out)


def fix_scalar_dot_fields(code: str) -> str:
    """`(scalar).vtable` / `a.internal.ints` / `this->x.data` -> GhidraBlob.

    Nested dots must collapse to the last field on the base object. Matching
    only the first `.internal` leaves `.ints` on a `void *` (resume5 A/B
    0/24). Overlay compiles; it does not claim layout.
    """

    def collapse(base: str, chain: str) -> str:
        last = chain.rsplit(".", 1)[-1]
        return f"((GhidraBlob *)&({base}))->{last}"

    code = _ARROW_DOT_CHAIN_RE.sub(lambda m: collapse(m.group(1), m.group(2)), code)
    code = _IDENT_DOT_CHAIN_RE.sub(lambda m: collapse(m.group(1), m.group(2)), code)
    code = _PAREN_DOT_RE.sub(r"((GhidraBlob *)&(\1))->\2", code)
    return code


def load_functions(program: str, sample: int | None):
    kb = sqlite3.connect(f"file:{KB}?mode=ro", uri=True)
    kb.row_factory = sqlite3.Row
    rows = kb.execute(
        "SELECT entry_hex, name, decompiled, size FROM func_knowledge"
        " WHERE program=? AND decompiled IS NOT NULL AND decompiled<>''"
        " ORDER BY length(decompiled), size", (program,)).fetchall()
    kb.close()
    return rows[:sample] if sample else rows


def declare_callee_bulk(info: dict, known: set[str]) -> str | None:
    """`extern` for a callee, param count matching Ghidra's OWN call site.

    `kx.ctxtypes.declare_callee` inserts a dummy EDX parameter for a
    `__thiscall` callee (the ECX-passing proxy the LLM prompt path also
    uses) -- correct ABI, but Ghidra's own decompiled call sites were never
    written with that dummy in mind, so they pass one argument fewer than the
    proxy declares (C2198, measured 28 of a 300-sample's failures). This
    binary's own body is the thing being compiled here, not new code, so the
    call site wins: declare with the NATURAL argument count instead. For a
    single-argument `__thiscall` method (by far the common case -- getters,
    destructors) `__fastcall` with just `this` already matches the real ABI
    exactly, since fastcall and thiscall agree until a second real argument
    exists. For a multi-argument `__thiscall` callee this trades ABI
    precision for a callable compile; that function's cross-call is not
    proven runtime-correct and stays a candidate for the byte-accurate pass.
    """
    name = ctxtypes.c_name(info["name"])
    if not name or name.startswith(("FUN_", "SUB_", "thunk_")):
        return None

    def render(t: str) -> str | None:
        t = t.strip()
        if not t or "<" in t or "::" in t:
            return None
        base = t.replace("*", "").replace("const", "").strip()
        if not base or base in ctxtypes.PRIMITIVE or base in known:
            return t
        return "void *" if "*" in t else None

    ret = render(info["return_type"]) or "void"
    args = []
    for p in info["params"]:
        r = render(p)
        if r is None:
            return None
        args.append(r)

    conv = info["convention"]
    kw = "__fastcall" if conv == "__thiscall" else conv if conv in ("__stdcall", "__fastcall") else ""
    return f"{ret} {kw} {name}({', '.join(args) or 'void'});".replace("  ", " ")


_IDENT_RE = re.compile(r"\b[A-Za-z_]\w*\b")

# Ghidra's decompiler names the process-wide singletons WITHOUT the `C`
# prefix the type table uses: the global is `AppManager`, the type is
# `CAppManager`. 2026-08-30 remaining-failure log: 460 C2065 AppManager,
# 103 VirtualMachine, then Rules/GuiManager/ExoResMan. A/B on 12 AppManager
# failures: type + `extern CAppManager *AppManager` -> 0/12 to 10/12. The
# two misses needed a second singleton (VirtualMachine) or a field the
# exported layout does not have. Same shape for the others -- they are
# named by cl.exe, not guessed. Pointer form: every use site is
# `Name->field` or `Class::Method(Name, ...)`.
KNOWN_GLOBALS: dict[str, str] = {}
KNOWN_INT_GLOBALS: tuple[str, ...] = ()

OPERATOR_RE = re.compile(r"(::)?operator\s*([^\s(]+)")
STACK0_RE = re.compile(r"\bstack0x[0-9a-fA-F]+\b")
FRAMEHANDLER_RE = re.compile(r"\bFrameHandler_[0-9a-fA-F]+\b")
DTOR_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)___\1\b")
VTABLE_RE = re.compile(r"\b[A-Za-z_]\w*_vtable\b")


def flatten_operators(code: str) -> str:
    """`Class::operator=` is not a C identifier; keep def and calls aligned."""

    def sub(m: re.Match) -> str:
        slug = re.sub(r"[^A-Za-z0-9]+", "_", m.group(2)).strip("_") or "op"
        return f"{m.group(1) or ''}operator_{slug}"

    return OPERATOR_RE.sub(sub, code)


_CTX_TEXT: str | None = None


def ctx_text() -> str:
    global _CTX_TEXT
    if _CTX_TEXT is None:
        _CTX_TEXT = CTX_H.read_text() if CTX_H and CTX_H.is_file() else ""
    return _CTX_TEXT


def _expand_wanted(wanted: set[str], types: dict[str, str]) -> set[str]:
    seen = set(wanted)
    queue = list(wanted)
    while queue:
        t = queue.pop()
        inn = t + "Internal"
        if inn in types and inn not in seen:
            seen.add(inn)
            queue.append(inn)
        for u in ctxtypes.type_names(types.get(t, "")):
            if u in types and u not in seen:
                seen.add(u)
                queue.append(u)
    return seen


def _emit_order(wanted: set[str], types: dict[str, str]) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()

    def visit(t: str) -> None:
        if t in seen or t not in types:
            return
        seen.add(t)
        inn = t + "Internal"
        if inn in wanted:
            visit(inn)
        for u in ctxtypes.type_names(types[t]):
            if u in wanted and u != t:
                visit(u)
        ordered.append(t)

    for t in sorted(wanted):
        visit(t)
    return ordered


def _emit_type(name: str, types: dict[str, str]) -> str:
    defn = types[name]
    inn = name + "Internal"
    if inn in types:
        defn = re.sub(r"void\s*\*\s*internal\b", f"struct {inn} * internal", defn)
    return defn


def build_header(con, binary_id: int, addr: int, sig: dict | None,
                 types: dict, sigs: dict, callee_map: dict,
                 body: str = "", self_name: str = "") -> str:
    # ctx.h first: `undefined4`, `code`, `byte` etc are used in EVERY Ghidra
    # signature, and are only defined there. Missing this made a scalar-type
    # error look like a syntax error ("missing '{' before '__fastcall'") one
    # token later, because the parser had no idea `undefined4 __fastcall ...`
    # started with a type name at all.
    parts = [ctx_text()]
    compile_only = NORMALIZE_MODE is NormalizeMode.COMPILE_ONLY
    if compile_only:
        parts.extend([INTRINSIC_MACROS, STUB_TYPES])
    fn = {"addr": addr, "signature": (sig or {}).get("signature", ""),
          "class": None}
    callees = callee_map.get(addr, [])
    wanted: set[str] = set()
    for text in (fn["signature"],):
        for t in ctxtypes.type_names(text):
            if t in types:
                wanted.add(t)
    # A cast like `(CSWGuiLabel *)x` names a type the SIGNATURE never
    # mentions -- Ghidra's own signature line only covers the parameters and
    # return type, not every local cast in the body. Scanning identifiers
    # directly against the known type set is the only thing that catches
    # these (measured cause of a class of C2065 "undeclared identifier").
    if body:
        wanted |= (set(_IDENT_RE.findall(body)) & types.keys())
    # Singletons go in unconditionally (not through MAX_TYPES) so a function
    # that already named 24 types cannot drop CAppManager and then fail the
    # extern we just added.
    global_externs = []
    if body and compile_only:
        idents = set(_IDENT_RE.findall(body))
        for gname, tname in KNOWN_GLOBALS.items():
            if gname in idents and tname in types:
                wanted.add(tname)
                global_externs.append(f"extern {tname} *{gname};")
        for gname in KNOWN_INT_GLOBALS:
            if gname in idents:
                global_externs.append(f"extern int {gname};")
        for name in sorted(set(STACK0_RE.findall(body))):
            global_externs.append(f"int {name};")
        for name in sorted(set(FRAMEHANDLER_RE.findall(body))):
            global_externs.append(f"void {name}(void);")
        for name in sorted({m.group(0) for m in DTOR_CALL_RE.finditer(body)} | set(ANY_DTOR_RE.findall(body))):
            global_externs.append(f"void {name}(void *);")
        for name in sorted(set(VTABLE_RE.findall(body))):
            global_externs.append(f"extern void *{name};")
        for name in sorted(set(DAT_RE.findall(body)) | set(PTR_RE.findall(body))):
            global_externs.append(f"extern int {name};")
        for name in sorted(set(CONSOLE_RE.findall(body))):
            global_externs.append(f"void {name}(void);")
        if "int3" in idents:
            global_externs.append("void int3(void);")
        if "_param_1" in idents:
            global_externs.append("int _param_1;")
        if "HDC" in idents:
            pass  # ctx.h / windows stubs already define HDC; do not re-typedef
        for name in sorted(set(re.findall(r"\(GhidraBlob \*\)&\(([A-Za-z_]\w*)\)", body))):
            if name not in ("this", "this_00", "this_ecx"):
                global_externs.append(f"extern GhidraBlob {name};")
    decls = []
    for a in callees[:ctxtypes.MAX_CALLEES]:
        info = sigs.get(a)
        if not info:
            continue
        d = declare_callee_bulk(info, set(types))
        if d:
            decls.append(d)
            for t in ctxtypes.type_names(info["signature"]):
                if t in types:
                    wanted.add(t)
    wanted = _expand_wanted(wanted, types)
    emitted: set[str] = set()
    for tname in KNOWN_GLOBALS.values():
        if tname in wanted and tname in types:
            parts.append(_emit_type(tname, types))
            emitted.add(tname)
    for t in _emit_order(wanted, types):
        if t not in emitted:
            parts.append(_emit_type(t, types))
            emitted.add(t)
    if self_name:
        self_re = re.compile(rf"\b{re.escape(self_name)}\b")
        global_externs = [g for g in global_externs if not self_re.search(g)]
        decls = [d for d in decls if not self_re.search(d)]
    parts.extend(global_externs)
    parts.extend("extern " + d for d in decls)
    return "\n".join(parts) + "\n"


def safe_stem(name: str, entry_hex: str) -> str:
    """Path-safe identifier. `operator/=` must not become a directory."""
    base = flatten_operators(name or f"FUN_{entry_hex}")
    base = re.sub(r"[^A-Za-z0-9_]+", "_", base).strip("_") or f"FUN_{entry_hex}"
    return base[:80]


def out_name(name: str, entry_hex: str) -> str:
    """Unique on disk. 1,170 flattened names collide (HandleInputEvent x71).

    Legacy files from the first pass used `{name}.c` and silently overwrote
    siblings. New writes are `{name}_{entry_hex}.c`. Skip-existing accepts
    either spelling when the file's own `address: 0x...` header matches, so
    the 10k already-written files are not rebuilt and the colliding siblings
    that never got their own file get a real slot.
    """
    return f"{safe_stem(name, entry_hex)}_{entry_hex}"


def existing_c(prog_dir: pathlib.Path, raw_name: str, entry_hex: str) -> pathlib.Path | None:
    stems = []
    for s in (
        flatten_names(flatten_templates(flatten_operators(raw_name or ""))),
        flatten_names(flatten_operators(raw_name or "")),
        flatten_names(raw_name or ""),
        raw_name or f"FUN_{entry_hex}",
    ):
        if s and s not in stems:
            stems.append(s)
            cleaned = safe_stem(s, entry_hex)
            if cleaned not in stems:
                stems.append(cleaned)
    for s in stems:
        for cand in (prog_dir / f"{s}_{entry_hex}.c", prog_dir / f"{s}.c"):
            if not cand.exists():
                continue
            if cand.name.endswith(f"_{entry_hex}.c"):
                return cand
            head = cand.read_text(errors="replace")[:500]
            if re.search(rf"address:\s*0x{entry_hex}\b", head, re.I):
                return cand
    return None


def logical_ids_with_real_c(con) -> set[int]:
    """logical_id values that already have assembly-free compiling C."""
    try:
        rows = con.execute(
            "SELECT DISTINCT logical_id FROM recovered_function "
            "WHERE real_c=1 AND logical_id IS NOT NULL"
        )
        return {int(r[0]) for r in rows if r[0] is not None}
    except sqlite3.Error:
        return set()


def skip_real_c_sibling(lid: int | None, real_c_logicals: set[int], kind: str) -> bool:
    """Sibling of a real_c logical_id is not decompiled again."""
    return lid is not None and lid in real_c_logicals and kind != "real-c"


def addr_to_logical(con, bid: int) -> dict[int, int]:
    try:
        rows = con.execute(
            "SELECT addr, logical_id FROM identity WHERE binary_id=? AND logical_id IS NOT NULL",
            (bid,),
        )
        return {int(r[0]): int(r[1]) for r in rows if r[0] is not None and r[1] is not None}
    except sqlite3.Error:
        return {}


def write_compile_receipt(out_dir: pathlib.Path, program: str, ok_ids: list[str]) -> pathlib.Path:
    dest = pathlib.Path(out_dir) / "compile-receipt.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(
        json.dumps({"program": program, "ok": list(ok_ids)}, indent=2) + "\n",
        encoding="utf-8",
    )
    return dest


def existing_real_c(prog_dir: pathlib.Path, raw_name: str, entry_hex: str) -> pathlib.Path | None:
    """A compiling Ghidra C body. compile-only-asm is the substrate, not done."""
    cand = existing_c(prog_dir, raw_name, entry_hex)
    if cand is None or asm_seed.is_compile_only_asm(cand):
        return None
    return cand


def existing_kind(prog_dir: pathlib.Path, raw_name: str, entry_hex: str) -> str:
    """Classify on-disk substrate: missing, real-c, asm-seed, or asm-tried."""
    cand = existing_c(prog_dir, raw_name, entry_hex)
    if cand is None:
        return "missing"
    if not asm_seed.is_compile_only_asm(cand):
        return "real-c"
    if asm_seed.is_c_replace_tried(cand):
        return "asm-tried"
    return "asm-seed"


def resolve_queue_policy(*, skip_existing: bool, force_c_replace: bool) -> str:
    """skip-existing (default) / force-c-replace / force."""
    if not skip_existing:
        return "force"
    if force_c_replace:
        return "force-c-replace"
    return "skip-existing"


def should_queue(kind: str, policy: str) -> bool:
    """Default skip-existing retries seed-only asm once, never already-tried leftovers."""
    if policy == "force":
        return True
    if policy == "force-c-replace":
        return kind != "real-c"
    return kind in {"missing", "asm-seed"}


def raw_image_path(repo_path: str) -> pathlib.Path:
    """Original image for asm fallback. Path is configured, never a product default."""
    slug = (repo_path or "").strip("/").replace("/", "__")
    env_raw = os.environ.get("AGENT_DECOMPILE_EXTRACT_RAW", "").strip()
    explicit = EXTRACT_RAW if EXTRACT_RAW is not None else (pathlib.Path(env_raw) if env_raw else None)
    if explicit is not None:
        if explicit.is_file():
            return explicit
        return explicit / slug
    work = os.environ.get("AGENT_DECOMPILE_CORPUS_WORK_DIR", "").strip()
    root = pathlib.Path(work) if work else pathlib.Path(".")
    return root / "extract" / "raw" / slug


def load_asm_fallback(program: str, repo_path: str) -> None:
    """Map entry_hex -> (file_offset, size) and load the original image."""
    global _RAW_IMAGE, _FUNC_FILE
    _FUNC_FILE = {}
    kb = sqlite3.connect(f"file:{KB}?mode=ro", uri=True)
    try:
        rows = kb.execute(
            "SELECT entry_hex, file_offset, size FROM func_knowledge WHERE program=?",
            (program,),
        )
        for r in rows:
            if r[1] is None or r[2] is None:
                continue
            _FUNC_FILE[str(r[0])] = (int(r[1]), int(r[2]))
    except sqlite3.OperationalError:
        _FUNC_FILE = {}
    finally:
        kb.close()
    path = raw_image_path(repo_path)
    _RAW_IMAGE = path.read_bytes() if path.is_file() else b""


def emit_naked_asm(name: str, blob: bytes) -> str:
    return asm_seed.emit_naked_asm(name, blob)


def seed_asm_corpus(rows, prog_dir: pathlib.Path) -> int:
    """Write original-byte asm for every function that is not yet real C."""
    n = 0
    for r in rows:
        if existing_real_c(prog_dir, r["name"] or "", r["entry_hex"]) is not None:
            continue
        have = existing_c(prog_dir, r["name"] or "", r["entry_hex"])
        if have is not None and asm_seed.is_compile_only_asm(have):
            continue
        loc = _FUNC_FILE.get(r["entry_hex"])
        if not loc or not _RAW_IMAGE:
            continue
        blob = asm_seed.slice_image(_RAW_IMAGE, loc[0], loc[1])
        if blob is None:
            continue
        name = flatten_names(flatten_templates(flatten_operators(r["name"] or "")))
        fname = out_name(name, r["entry_hex"])
        dest = prog_dir / f"{fname}.c"
        dest.write_text(asm_seed.asm_banner(fname, r["entry_hex"]) + emit_naked_asm(name, blob))
        n += 1
    return n


def try_asm_fallback(src, obj, name: str, entry_hex: str) -> tuple[bool, str, str, str]:
    loc = _FUNC_FILE.get(entry_hex)
    if not loc or not _RAW_IMAGE:
        return False, "ASM no-bytes", "", ""
    off, size = loc
    blob = asm_seed.slice_image(_RAW_IMAGE, off, size)
    if blob is None:
        return False, f"ASM range {off}+{size}", "", ""
    body = emit_naked_asm(name, blob)
    header = ctx_text() + "\n"
    ok, err = _compile_text(src, obj, name, header, body)
    return ok, err, header, body


def _run_cl(src: pathlib.Path, obj: pathlib.Path, name: str) -> tuple[bool, str]:
    """One cl.exe attempt. Distinguishes C errors from infra (timeout / no obj).

    The 2026-08-30 full pass plateaued at 7,054 successes for ~1,800 consecutive
    functions (96.8% -> 77.5%) then recovered. That cliff is the size-ordered
    walk hitting Wine saturation / disk-quota, not a sudden C-quality drop --
    confirmed by the rate climbing again once the host recovered. A timeout or
    empty diagnostic is therefore retried once before being counted as a miss.
    """
    try:
        p = subprocess.run(
            ["bash", str(COMPILE), str(src), str(obj), name or f"F_{src.stem}"],
            capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return False, "INFRA timeout"
    ok = obj.exists() and obj.stat().st_size > 0
    if ok:
        return True, ""
    err = (p.stdout or "") + (p.stderr or "")
    m = re.findall(r"error C\d+[^\n]*", err)
    if m:
        return False, "; ".join(m[:40])
    tail = err[-300:].strip()
    return False, f"INFRA {tail}" if tail else "INFRA no-object no-diagnostic"


REPAIR_ROUNDS = 8
_C_WORDS = frozenset(
    "if for while switch return sizeof void int char short long float double "
    "signed unsigned const volatile struct union enum typedef static extern "
    "auto register goto case default do else break continue this this_00 "
    "this_ecx defined ifdef ifndef".split()
)
_UNDECL_RE = re.compile(r"'([A-Za-z_]\w*)' : undeclared identifier")
_UNDEF_STRUCT_RE = re.compile(r"undefined struct(?:/union)? '([A-Za-z_]\w*)'")
_NOT_MEMBER_RE = re.compile(r"'([A-Za-z_]\w*)' : is not a member")
_LEFT_DOT_RE = re.compile(r"left of '\.([A-Za-z_]\w*)'")
_LEFT_ARROW_RE = re.compile(r"left of '->([A-Za-z_]\w*)'")


def _append_once(header: str, line: str, name: str | None = None) -> str:
    if line in header:
        return header
    if name and re.search(rf"\b{re.escape(name)}\b", header):
        return header
    return header + line + "\n"


def _is_call_name(field: str) -> bool:
    """`->OnBButtonPressed(` is a method, not a data field. Rewriting it
    produced C2059 '(' on resume6 (1,272 of 1,727 leftover errors)."""
    if field in _C_WORDS:
        return True
    return field[:1].isupper() and not field.startswith("field")


def repair_from_diagnostics(header: str, body: str, err: str) -> tuple[str, str, bool]:
    """Turn this function's cl.exe errors into stubs/rewrites. No new farm cycle."""
    before_h, before_b = header, body
    for name in _UNDECL_RE.findall(err):
        if name in _C_WORDS:
            continue
        if re.search(rf"\b{re.escape(name)}\s*\(", body):
            header = _append_once(header, f"int {name}();", name)
        elif re.search(rf"\b{re.escape(name)}\s*->", body) or f"{name}." in body:
            header = _append_once(header, f"extern GhidraBlob {name};", name)
        elif re.search(rf"\(\s*{re.escape(name)}\s*\*", body) or re.search(
            rf"\b{re.escape(name)}\s+\w+", body
        ):
            header = _append_once(header, f"typedef GhidraBlob {name};", name)
        else:
            header = _append_once(header, f"extern GhidraBlob {name};", name)
    for name in _UNDEF_STRUCT_RE.findall(err):
        if name in _C_WORDS or re.search(rf"\b{re.escape(name)}\b", header):
            continue
        header = _append_once(header, f"struct {name} {{ GhidraBlob _b; int _i; }};", name)
        header = _append_once(header, f"typedef struct {name} {name};", name)
    fields = set(_LEFT_DOT_RE.findall(err)) | set(_LEFT_ARROW_RE.findall(err)) | set(
        _NOT_MEMBER_RE.findall(err)
    )
    for field in fields:
        if _is_call_name(field):
            continue
        body = re.sub(
            rf"\b([A-Za-z_]\w*(?:->[A-Za-z_]\w*)*)\.{re.escape(field)}\b(?!\s*\()",
            r"((GhidraBlob *)&(\1))->data",
            body,
        )
        body = re.sub(
            rf"\(([^()]+)\)\.{re.escape(field)}\b(?!\s*\()",
            r"((GhidraBlob *)&(\1))->data",
            body,
        )
        body = re.sub(
            rf"\b([A-Za-z_]\w*)->{re.escape(field)}\b(?!\s*\()",
            r"((GhidraBlob *)(\1))->data",
            body,
        )
    if "C2064" in err:
        new_body = fix_star_calls(body)
        new_body = _replace_call_head(
            new_body, re.compile(r"\(\*\*\([^;]{0,80}?\)\)\s*\(")
        )
        body = new_body
    return header, body, (header != before_h or body != before_b)


_CONST_UNDECL_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


def _error_codes(err: str) -> set[str]:
    return set(re.findall(r"\bC\d{4}\b", err or ""))


def _thiscall_only(err: str) -> bool:
    codes = _error_codes(err)
    return bool(codes) and codes <= {"C4234"}


def _layout_only(err: str) -> bool:
    """C2039/C2223/C2224: wrong struct fields. Claude does not invent layouts."""
    codes = _error_codes(err)
    return bool(codes) and codes <= {"C2039", "C2223", "C2224"}


def _is_dtor_name(name: str) -> bool:
    return bool(name) and (name.startswith("~") or "___" in name)


def _dtor_redef(err: str, name: str) -> bool:
    """Claude redefines dtors (C2373) and then invents C2059 soup."""
    return _is_dtor_name(name) and "C2373" in _error_codes(err)


def _huge_body(body: str) -> bool:
    """InitExtensions is 24k chars; one Claude shot does not repair 202 assigns."""
    return len(body or "") > 12000


def _is_assigned(name: str, body: str) -> bool:
    return bool(re.search(rf"\b{re.escape(name)}\s*=", body or ""))


def _add_cl_named_macros(header: str, err: str, body: str = "") -> str:
    """`#define NAME 0` for ALL_CAPS identifiers cl.exe named (InitExtensions).

    Skip names that are assigned (`glFoo = wglGetProcAddress(...)`) -- a
    `#define` is not an l-value (C2106 on the live leftover log).
    """
    for name in _UNDECL_RE.findall(err or ""):
        if not _CONST_UNDECL_RE.match(name):
            continue
        if "_" not in name and not name.endswith("BIT"):
            continue
        if _is_assigned(name, body):
            continue
        header = _append_once(header, f"#define {name} 0", name)
    return header


def _drain_cl_named_macros(src, obj, name, header, body, err: str) -> tuple[bool, str, str]:
    """Keep adding cl.exe-named ALL_CAPS macros until the set stops growing.

    One pass is not enough: `_run_cl` used to keep 12 diagnostics, and
    InitExtensions names more `*_BIT` flags than that. Each successful
    `#define` reveals the next undeclared constant.
    """
    for _ in range(16):
        nxt = _add_cl_named_macros(header, err, body)
        if nxt == header:
            break
        header = nxt
        ok, err = _compile_text(src, obj, name, header, body)
        if ok or err.startswith("INFRA"):
            return ok, err, header
    return False, err, header


def _is_method_call(name: str, body: str) -> bool:
    """`this->OnBButtonPressed(` — resume6. Free `CheckExtension(` is not."""
    return bool(re.search(rf"(->|\.){re.escape(name)}\s*\(", body or ""))


def _is_safe_undeclared_callee(name: str, body: str = "") -> bool:
    """Call-shaped C2065 stubs. Skip vtable/method uses only (resume6)."""
    if name in _C_WORDS or _is_method_call(name, body):
        return False
    if name[:1].islower() or name.startswith(("gl", "wgl", "glu")):
        return True
    return bool(re.search(rf"\b{re.escape(name)}\s*\(", body or ""))


def _add_cl_named_callees(header: str, body: str, err: str, self_name: str = "") -> str:
    """`int name();` for cl.exe-named identifiers used as `name(` in this body."""
    for ident in _UNDECL_RE.findall(err or ""):
        if ident == self_name or not _is_safe_undeclared_callee(ident, body):
            continue
        if not re.search(rf"\b{re.escape(ident)}\s*\(", body):
            continue
        header = _append_once(header, f"int {ident}();", ident)
    return header


def _drain_cl_named_callees(
    src, obj, name, header, body, err: str,
) -> tuple[bool, str, str]:
    """Loop call-shaped C2065 stubs until cl.exe stops naming new gl*/C APIs."""
    for _ in range(16):
        nxt = _add_cl_named_callees(header, body, err, self_name=name)
        if nxt == header:
            break
        header = nxt
        ok, err = _compile_text(src, obj, name, header, body)
        if ok or err.startswith("INFRA"):
            return ok, err, header
    return False, err, header


_GL_PROC_RE = re.compile(r"^(?:gl|wgl|glu)[A-Za-z0-9]+$")


def _is_proc_pointer(name: str, body: str) -> bool:
    """`glFoo = wglGetProcAddress(...)` — not a call, not an int global."""
    if not re.search(rf"\b{re.escape(name)}\s*=", body or ""):
        return False
    if _GL_PROC_RE.match(name):
        return True
    return bool(
        re.search(rf"\b{re.escape(name)}\s*=\s*wglGetProcAddress\s*\(", body or "")
    )


def _seed_gl_pointers(header: str, body: str) -> str:
    """Declare every `glFoo =` in the body so InitExtensions is not 40-at-a-time."""
    for ident in sorted(set(re.findall(r"\b((?:gl|wgl|glu)[A-Za-z0-9]+)\s*=", body or ""))):
        header = _append_once(header, f"void *{ident};", ident)
    return header


def _add_cl_named_pointers(header: str, body: str, err: str, self_name: str = "") -> str:
    """`void *name;` only for proc-pointer assigns. Broader void* stubs
    turned `existingExtensions` / HDC temps into non-lvalues or C2440.
    """
    for ident in _UNDECL_RE.findall(err or ""):
        if ident == self_name or ident in _C_WORDS:
            continue
        if not _is_proc_pointer(ident, body):
            continue
        header = _append_once(header, f"void *{ident};", ident)
    return header


def _drain_cl_named_pointers(
    src, obj, name, header, body, err: str,
) -> tuple[bool, str, str]:
    for _ in range(16):
        nxt = _add_cl_named_pointers(header, body, err, self_name=name)
        if nxt == header:
            break
        header = nxt
        ok, err = _compile_text(src, obj, name, header, body)
        if ok or err.startswith("INFRA"):
            return ok, err, header
    return False, err, header


def should_skip_llm(*, body: str) -> bool:
    """Skip Claude only when it is stopped/over-bar or the body is huge."""
    return (not _llm_allowed()) or _huge_body(body)


def _llm_allowed() -> bool:
    if not LLM_CLEANUP:
        return False
    with _CORPUS_LOCK:
        if _LLM_STOPPED:
            return False
        if _CORPUS_TOTAL and _COMPILED_COUNT / _CORPUS_TOTAL >= COMPILE_COMPLETE:
            return False
        return True


def _note_success() -> None:
    global _COMPILED_COUNT, _LLM_STOPPED
    with _CORPUS_LOCK:
        _COMPILED_COUNT += 1
        if (
            LLM_CLEANUP
            and not _LLM_STOPPED
            and _CORPUS_TOTAL
            and _COMPILED_COUNT / _CORPUS_TOTAL >= COMPILE_COMPLETE
        ):
            _LLM_STOPPED = True
            print(
                f"compile-complete ({COMPILE_COMPLETE:.0%}): "
                f"{_COMPILED_COUNT}/{_CORPUS_TOTAL}. Further leftovers skip Claude.",
                flush=True,
            )


def _compile_text(src, obj, name, header, body) -> tuple[bool, str]:
    src.write_text(header + "\n" + body)
    obj.unlink(missing_ok=True)
    ok, err = _run_cl(src, obj, name)
    if (not ok) and err.startswith("INFRA"):
        ok, err = _run_cl(src, obj, name)
    return ok, err


def try_compile(job) -> dict:
    """Compile one function and, on success, write it out IMMEDIATELY.

    Not batched-at-the-end: a 24,240-function pass takes long enough that
    "results only appear once everything finishes" means zero usable output
    for most of an hour. Writing each success the moment it compiles means
    `recovered-source-ghidra/` is a live, growing, immediately-usable result
    from the first successful function onward -- `kx/ghidra_verify.py` (the
    next tier: check for a FREE byte-exact match) can start working through
    the front of the list while the tail is still compiling.
    """
    entry_hex, name, header, body, tmpdir, prog_dir, program_path = job
    try:
        return _try_compile_inner(
            entry_hex, name, header, body, tmpdir, prog_dir, program_path
        )
    except (OSError, ValueError) as exc:
        return {"entry_hex": entry_hex, "name": name, "ok": False, "error": f"INFRA {exc}"}


def _try_compile_inner(entry_hex, name, header, body, tmpdir, prog_dir, program_path) -> dict:
    src = pathlib.Path(tmpdir) / f"g_{entry_hex}.c"
    obj = pathlib.Path(tmpdir) / f"g_{entry_hex}.obj"
    header = _seed_gl_pointers(header, body)
    ok, err = _compile_text(src, obj, name, header, body)
    compile_only = NORMALIZE_MODE is NormalizeMode.COMPILE_ONLY
    if (not ok) and not err.startswith("INFRA") and compile_only:
        cleaned = sanitize_body(body)
        if cleaned != body:
            body = cleaned
            ok, err = _compile_text(src, obj, name, header, body)
    if compile_only and (not ok) and not err.startswith("INFRA"):
        ok, err, header = _drain_cl_named_macros(src, obj, name, header, body, err)
    if compile_only and (not ok) and not err.startswith("INFRA"):
        ok, err, header = _drain_cl_named_callees(src, obj, name, header, body, err)
    if compile_only and (not ok) and not err.startswith("INFRA"):
        ok, err, header = _drain_cl_named_pointers(src, obj, name, header, body, err)
    if compile_only and (not ok) and not err.startswith("INFRA") and not LLM_CLEANUP:
        for _round in range(REPAIR_ROUNDS):
            new_header, new_body, changed = repair_from_diagnostics(header, body, err)
            if not changed:
                break
            header, body = new_header, new_body
            ok, err = _compile_text(src, obj, name, header, body)
            if ok:
                break
    # Asm substrate is the fallback, not a reason to skip Claude. Ghidra C
    # already failed; leftover C-replace needs the LLM except huge bodies.
    skip_llm = should_skip_llm(body=body)
    if (not ok) and not err.startswith("INFRA") and LLM_CLEANUP and skip_llm:
        tag = "huge-skip-llm" if _huge_body(body) else "compile-complete-skip-llm"
        err = f"{err} [{tag}]"
    if (not ok) and not err.startswith("INFRA") and LLM_CLEANUP and not skip_llm:
        edited = llc.cleanup_ghidra_c(
            body=body,
            errors=err,
            header=header,
            program_path=program_path,
            identifier=f"0x{entry_hex}",
            server_url=os.environ.get("AGENTDECOMPILE_MCP_SERVER_URL") or llc.DEFAULT_SERVER_URL,
            model=LLM_MODEL,
        )
        if edited.get("ok") and edited.get("source"):
            # The model often puts `__thiscall` and C++ spellings back.
            # Live leftover log 2026-08-30: 52/87 C2373 + 22/87 C4234 after
            # LLM, same class as resume6. Re-run the measured sanitizer
            # before the keep/discard compile.
            body = sanitize_body(edited["source"]) if compile_only else edited["source"]
            ok, err = _compile_text(src, obj, name, header, body)
            if compile_only and (not ok) and not err.startswith("INFRA"):
                ok, err, header = _drain_cl_named_macros(
                    src, obj, name, header, body, err
                )
            if compile_only and (not ok) and not err.startswith("INFRA"):
                ok, err, header = _drain_cl_named_callees(
                    src, obj, name, header, body, err
                )
            if compile_only and (not ok) and not err.startswith("INFRA"):
                ok, err, header = _drain_cl_named_pointers(
                    src, obj, name, header, body, err
                )
            if compile_only and (not ok) and not err.startswith("INFRA") and "C4234" in err:
                body = sanitize_body(body)
                ok, err = _compile_text(src, obj, name, header, body)
            if ok:
                err = ""
            else:
                err = f"{err} [after-llm]"
    asm_used = False
    kept_asm = False
    dest_have = existing_c(prog_dir, name, entry_hex) if prog_dir is not None else None
    dest_asm = bool(dest_have and asm_seed.is_compile_only_asm(dest_have))
    if (not ok) and dest_asm and dest_have is not None:
        # Already compiling as substrate. Do not send the same bytes through
        # cl.exe a second time; stamp so skip-existing will not requeue.
        asm_seed.mark_c_replace_tried(dest_have)
        kept_asm = True
        asm_used = True
    elif (
        (not ok)
        and compile_only
        and ASM_FALLBACK
        and not err.startswith("INFRA")
    ):
        a_ok, a_err, a_header, a_body = try_asm_fallback(src, obj, name, entry_hex)
        if a_ok:
            ok, err, header, body = True, "", a_header, a_body
            asm_used = True
        else:
            err = f"{err} [asm-fail {a_err}]"
    if ok and prog_dir is not None and not kept_asm:
        fname = out_name(name, entry_hex)
        if asm_used:
            head_comment = (
                f"/*\n * {fname}  --  compile-only-asm (original file bytes)\n"
                f" * address: 0x{entry_hex}\n"
                f" * {asm_seed.TRIED_MARK}: C failed; kept asm substrate.\n"
                f" * NOT recovered C. NOT byte-verified as a recompile.\n"
                f" * source: ghidra_bulk.py asm-fallback\n */\n")
        else:
            head_comment = (
                f"/*\n * {fname}  --  compiled from Ghidra's decompilation\n"
                f" * address: 0x{entry_hex}\n"
                f" * NOT BYTE-VERIFIED -- compiles, not confirmed to match the\n"
                f" * shipped binary's instructions. Byte-accuracy pass still\n"
                f" * pending for this function.\n"
                f" * source: ghidra_bulk.py\n */\n")
        dest_c = prog_dir / f"{fname}.c"
        dest_c.write_text(head_comment + header + "\n" + body)
        if not asm_used:
            _note_success()
        if _CROSS_INDEX:
            try:
                from . import cross_place
                cross_place.place_one(
                    dest_c, int(entry_hex, 16), _CROSS_INDEX, OUT_DIR,
                )
            except (OSError, ValueError, KeyError):
                pass
    src.unlink(missing_ok=True)
    obj.unlink(missing_ok=True)
    return {
        "entry_hex": entry_hex,
        "name": name,
        "ok": ok,
        "error": err,
        "asm": asm_used,
        "kept_asm": kept_asm,
    }


def main(argv: list[str] | None = None) -> int:
    global OUT_DIR, KB, COMPILE, NORMALIZE_MODE, ASM_FALLBACK, EXTRACT_RAW, _CROSS_INDEX
    ap = argparse.ArgumentParser()
    ap.add_argument("--program", required=True)
    ap.add_argument("--repo", required=True, help="binary repo_path in the store")
    ap.add_argument("--db", type=pathlib.Path, required=True)
    ap.add_argument("--out-dir", type=pathlib.Path, required=True)
    ap.add_argument("--kb", type=pathlib.Path, required=True)
    ap.add_argument(
        "--mode",
        choices=("compile-only", "semantic"),
        default="compile-only",
        help="compile-only (default): placeholders allowed for corpus coverage. "
             "semantic: refuse invented layout or ABI (no GhidraBlob/ghidra_call/stubs).",
    )
    ap.add_argument("--compiler", type=pathlib.Path)
    ap.add_argument("--sample", type=int, default=None)
    ap.add_argument("--workers", type=int, default=2,
                    help="Wine is shared; 2 is the safe default.")
    ap.add_argument("--write", action="store_true", default=True,
                    help="write compiling bodies into recovered-source-ghidra/ "
                         "as they complete (default on)")
    ap.add_argument("--no-write", dest="write", action="store_false",
                    help="dry run: compile-rate measurement only")
    ap.add_argument("--skip-existing", action="store_true", default=True,
                    help="skip real C and leftovers already marked c-replace-tried "
                         "(default). Seed-only asm is still tried once.")
    ap.add_argument("--force", dest="skip_existing", action="store_false",
                    help="recompile every function, including real C")
    ap.add_argument(
        "--force-c-replace",
        action="store_true",
        help="retry C on compile-only-asm; keep existing asm on fail "
             "(no second cl.exe). Does not rewrite real C.",
    )
    ap.add_argument(
        "--llm-cleanup",
        action="store_true",
        help="after preparse+cl.exe still fail, edit that Ghidra C with claude CLI and retry once",
    )
    ap.add_argument("--llm-model", default=None, help="optional claude --model for cleanup")
    ap.add_argument(
        "--compile-complete",
        type=float,
        default=0.95,
        help="fraction of the corpus that counts as compile-complete; "
             "Claude stops once this is reached (default 0.95)",
    )
    ap.add_argument(
        "--asm-fallback",
        action="store_true",
        default=True,
        help="after C still fails, emit __declspec(naked)+_emit of the "
             "original file bytes so the function compiles (compile-only only)",
    )
    ap.add_argument(
        "--no-asm-fallback",
        dest="asm_fallback",
        action="store_false",
    )
    ap.add_argument(
        "--extract-raw",
        type=pathlib.Path,
        help="directory (or file) of original images for asm fallback; "
             "else AGENT_DECOMPILE_EXTRACT_RAW or WORK_DIR/extract/raw/<slug>",
    )
    args = ap.parse_args(argv)
    NORMALIZE_MODE = NormalizeMode(args.mode)
    OUT_DIR = pathlib.Path(args.out_dir)
    KB = pathlib.Path(args.kb)
    if getattr(args, 'compiler', None):
        COMPILE = pathlib.Path(args.compiler)
    global LLM_CLEANUP, LLM_MODEL, CTX_H, KNOWN_GLOBALS, KNOWN_INT_GLOBALS, _CTX_TEXT
    global COMPILE_COMPLETE
    LLM_CLEANUP = bool(args.llm_cleanup)
    LLM_MODEL = args.llm_model
    COMPILE_COMPLETE = float(args.compile_complete)
    ASM_FALLBACK = bool(args.asm_fallback) and NORMALIZE_MODE is NormalizeMode.COMPILE_ONLY
    EXTRACT_RAW = pathlib.Path(args.extract_raw) if args.extract_raw else None
    cfg = corpus_config.load_program_config(args.program)
    KNOWN_GLOBALS = dict(cfg.known_globals)
    KNOWN_INT_GLOBALS = tuple(cfg.known_int_globals)
    CTX_H = pathlib.Path(cfg.ctx_h) if cfg.ctx_h else None
    _CTX_TEXT = None
    os.environ["GHIDRA_KB_PROGRAM"] = args.program
    os.environ.setdefault("AGENTDECOMPILE_MCP_SERVER_URL", "http://127.0.0.1:8080/mcp")

    from .store import connect
    con = connect(args.db)
    brow = con.execute("SELECT id FROM binary WHERE repo_path=?", (args.repo,)).fetchone()
    if not brow:
        sys.exit(f"not in database: {args.repo}")
    bid = int(brow["id"])

    load_asm_fallback(args.program, args.repo)
    from . import cross_place
    _CROSS_INDEX = cross_place.load_index(con, bid)
    types = ctxtypes.load_types(con, bid)
    global _TYPE_FIELDS
    _TYPE_FIELDS = set()
    for defn in types.values():
        _TYPE_FIELDS.update(re.findall(r"\b([A-Za-z_]\w*)\s*;", defn))
    sigs = ctxtypes.load_signatures(con, bid)
    callee_map: dict[int, list[int]] = {}
    for r in con.execute("SELECT caller_addr, callee_addr FROM calledge WHERE binary_id=?", (bid,)):
        callee_map.setdefault(int(r["caller_addr"]), []).append(int(r["callee_addr"]))

    rows = load_functions(args.program, args.sample)
    prog_dir = OUT_DIR / args.program
    if args.write:
        prog_dir.mkdir(parents=True, exist_ok=True)
        if ASM_FALLBACK:
            seeded = seed_asm_corpus(rows, prog_dir)
            print(
                f"asm seed: wrote {seeded} original-byte bodies "
                f"(substrate; C pass replaces these)",
                flush=True,
            )

    policy = resolve_queue_policy(
        skip_existing=bool(args.skip_existing),
        force_c_replace=bool(args.force_c_replace),
    )
    already = 0
    skipped_tried = 0
    skipped_logical = 0
    real_c_logicals = logical_ids_with_real_c(con) if policy != "force" else set()
    logical_by_addr = addr_to_logical(con, bid) if real_c_logicals else {}
    already_ok: list[str] = []
    if args.write and prog_dir.exists() and policy != "force":
        kept = []
        for r in rows:
            kind = existing_kind(prog_dir, r["name"] or "", r["entry_hex"])
            try:
                addr_i = int(r["entry_hex"], 16)
            except (TypeError, ValueError):
                addr_i = None
            lid = logical_by_addr.get(addr_i) if addr_i is not None else None
            if skip_real_c_sibling(lid, real_c_logicals, kind):
                skipped_logical += 1
                continue
            if not should_queue(kind, policy):
                if kind == "real-c":
                    already += 1
                    already_ok.append(str(r["entry_hex"]))
                elif kind == "asm-tried":
                    skipped_tried += 1
                continue
            kept.append(r)
        rows = kept
    print(
        f"normalize mode: {NORMALIZE_MODE.value}  queue: {policy}  "
        f"try {len(rows)}  real C on disk: {already}  "
        f"c-replace-tried skipped: {skipped_tried}  "
        f"logical real_c skipped: {skipped_logical}",
        flush=True,
    )
    global _COMPILED_COUNT, _CORPUS_TOTAL, _LLM_STOPPED
    _COMPILED_COUNT = already
    _CORPUS_TOTAL = already + skipped_tried + len(rows)
    _LLM_STOPPED = bool(
        _CORPUS_TOTAL and _COMPILED_COUNT / _CORPUS_TOTAL >= COMPILE_COMPLETE
    )
    print(
        f"real-C bar: {COMPILE_COMPLETE:.0%} "
        f"({int(COMPILE_COMPLETE * _CORPUS_TOTAL)}/{_CORPUS_TOTAL}); "
        f"have {already} recovered C. "
        f"Claude {'off' if _LLM_STOPPED or not LLM_CLEANUP else 'on leftover C until bar'}; "
        f"asm-fallback {'on' if ASM_FALLBACK and _RAW_IMAGE else 'off'} "
        f"({len(_FUNC_FILE)} funcs, {len(_RAW_IMAGE)} image bytes)",
        flush=True,
    )

    fail_log = (prog_dir / "_failures.jsonl") if args.write else None
    if fail_log is not None and fail_log.exists():
        fail_log.replace(fail_log.with_name("_failures.jsonl.prev"))

    tmp_parent = os.environ.get("AGENT_DECOMPILE_CORPUS_TMP", "").strip()
    tmp_kw = {"dir": tmp_parent} if tmp_parent and pathlib.Path(tmp_parent).is_dir() else {}
    with tempfile.TemporaryDirectory(**tmp_kw) as tmpdir:
        jobs = []
        receipts: list[dict] = []
        for r in rows:
            addr = int(r["entry_hex"], 16)
            self_name = flatten_names(flatten_templates(flatten_operators(r["name"] or "")))
            nr = normalize_decompiled(
                r["decompiled"],
                mode=NORMALIZE_MODE,
                fallback=compile_only_fallback if NORMALIZE_MODE is NormalizeMode.COMPILE_ONLY else None,
            )
            body = nr.text
            receipts.append(nr.receipt())
            header = build_header(
                con, bid, addr, sigs.get(addr), types, sigs, callee_map, body,
                self_name=self_name,
            )
            jobs.append((r["entry_hex"], self_name, header, body, tmpdir,
                         prog_dir if args.write else None, args.repo))

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
            for i, res in enumerate(ex.map(try_compile, jobs)):
                results.append(res)
                if fail_log is not None and not res["ok"]:
                    with fail_log.open("a") as fh:
                        fh.write(f"{res['entry_hex']}\t{res['name']}\t{res['error']}\n")
                step = 25 if LLM_CLEANUP else 100
                if (i + 1) % step == 0:
                    c_ok = sum(1 for x in results if x["ok"] and not x.get("asm"))
                    print(f"  {i+1}/{len(jobs)}  C replacements: {c_ok} "
                          f"({100*c_ok/(i+1):.1f}%)  "
                          f"real C: {already + c_ok}/{already + len(jobs)}",
                          flush=True)

    ok = [r for r in results if r["ok"] and not r.get("asm")]
    leftover = [r for r in results if not r["ok"]]
    total = already + skipped_tried + len(results)
    compiled = already + len(ok)
    compiling = already + skipped_tried + sum(
        1 for r in results if r["ok"] or r.get("kept_asm") or r.get("asm")
    )
    for res, rec in zip(results, receipts):
        res["usedFallback"] = rec.get("usedFallback")
        res["refused"] = bool(rec.get("refused"))
    bench_rows = (
        [{"ok": True, "usedFallback": False, "refused": False} for _ in range(already)]
        + results
    )
    bench = summarize_benchmark(bench_rows, mode=NORMALIZE_MODE)
    bench["alreadyOnDisk"] = already
    bench["program"] = args.program
    bench["queuePolicy"] = policy
    bench["skippedTried"] = skipped_tried
    bench["asmFallback"] = sum(1 for r in results if r.get("asm"))
    bench["keptAsm"] = sum(1 for r in results if r.get("kept_asm"))
    bench["realC"] = compiled
    bench["compilingBodies"] = compiling
    if args.write:
        (prog_dir / "normalize-benchmark.json").write_text(
            json.dumps(bench, indent=2) + "\n", encoding="utf-8"
        )
    print(
        f"normalize  : mode={bench['mode']} fallback={bench['fallbackUsed']} "
        f"refused={bench['semanticRefused']}  "
        "(compile rate is not byte-accuracy)",
        flush=True,
    )
    print(f"\nthis pass C replacements: {len(ok)}/{len(results)} "
          f"({100*len(ok)/max(len(results),1):.1f}%)")
    print(f"real C    : {compiled}/{total} "
          f"({100*compiled/max(total,1):.1f}%)")
    rate = 100 * compiled / max(total, 1)
    print(
        f"compiling bodies (C+asm): {compiling}/{total}  "
        f"(not the recovered-C bar)",
    )
    if rate >= 100 * COMPILE_COMPLETE:
        print(
            f"real-C bar ({COMPILE_COMPLETE:.0%}) reached. "
            "Leftover is thiscall/layout/huge, not another C-replace pass.",
        )
    else:
        need = int(COMPILE_COMPLETE * total)
        print(
            f"real-C bar is {COMPILE_COMPLETE:.0%} ({need}/{total}). "
            f"short by {max(0, need - compiled)} recovered C. "
            "Do not retry c-replace-tried leftovers; that pass is 0-yield.",
        )

    from collections import Counter
    reasons = Counter()
    codes = Counter()
    after_llm = 0
    for r in leftover:
        err = r["error"] or ""
        if "[after-llm]" in err:
            after_llm += 1
        for code in _error_codes(err):
            codes[code] += 1
        key = re.sub(r"'[^']*'", "'X'", err.split(";")[0])[:80]
        reasons[key] += 1
    print("\ntop failure reasons:")
    for k, n in reasons.most_common(15):
        print(f"  {n:5d}  {k}")
    if leftover:
        print(f"\nleftover taxonomy: {len(leftover)} C-fail, {after_llm} after-llm")
        print("error codes:", ", ".join(f"{c}={n}" for c, n in codes.most_common(12)))

    if args.write:
        print(f"\nwrote {len(ok)} new files -> {prog_dir}  "
              f"(skipped {already} already on disk)")
        ok_ids = already_ok + [str(r["entry_hex"]) for r in ok]
        write_compile_receipt(OUT_DIR, args.program, ok_ids)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
