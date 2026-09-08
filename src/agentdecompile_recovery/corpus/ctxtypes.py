"""Real types and callee signatures for recovery prompts.

Shown in the prompt, not in ctx.h: putting Ghidra layouts into the compile
context collides with bodies that define the same structs themselves.
"""

from __future__ import annotations

import json
import re

from .ghidra_sanitize import c_name

PRIMITIVE = {
    "void", "int", "char", "float", "double", "long", "short", "signed",
    "unsigned", "bool", "const", "volatile",
    "undefined", "undefined1", "undefined2", "undefined3", "undefined4",
    "undefined5", "undefined6", "undefined7", "undefined8",
    "byte", "sbyte", "word", "dword", "qword", "uchar", "ushort", "uint",
    "ulong", "ulonglong", "longlong", "code", "unicode", "wchar16", "wchar32",
    "size_t", "ptrdiff_t", "float10", "pointer",
}

_TYPE_TOKEN = re.compile(r"[A-Za-z_][A-Za-z_0-9:]*")
MAX_TYPES = 24
MAX_TYPE_CHARS = 8000
MAX_CALLEES = 24


def type_names(text: str) -> list[str]:
    if not text or "<" in text:
        return []
    out = []
    for m in _TYPE_TOKEN.finditer(text):
        t = m.group(0)
        if t in PRIMITIVE or "::" in t:
            continue
        out.append(t)
    return out


def load_types(con, binary_id: int) -> dict[str, str]:
    types: dict[str, str] = {}
    try:
        for r in con.execute(
                "SELECT name, definition FROM ghidra_type"
                " WHERE binary_id=? AND definition IS NOT NULL AND definition<>''",
                (binary_id,)):
            types[str(r["name"])] = str(r["definition"]).strip()
    except Exception:
        return {}
    return types


def load_signatures(con, binary_id: int) -> dict[int, dict]:
    out: dict[int, dict] = {}
    for r in con.execute(
            "SELECT addr, COALESCE(canon_key, name) AS nm, signature,"
            "       return_type, param_types, calling_convention"
            "  FROM func WHERE binary_id=?", (binary_id,)):
        try:
            params = json.loads(r["param_types"] or "[]")
        except (ValueError, TypeError):
            params = []
        out[int(r["addr"])] = {
            "name": str(r["nm"] or ""),
            "signature": r["signature"] or "",
            "return_type": r["return_type"] or "void",
            "params": [str(p) for p in params],
            "convention": (r["calling_convention"] or "").lower(),
        }
    return out


def declare_callee(info: dict, known: set[str]) -> str | None:
    name = c_name(info["name"])
    if not name or name.startswith(("FUN_", "SUB_", "thunk_")):
        return None

    def render(t: str) -> str | None:
        t = t.strip()
        if not t or "<" in t or "::" in t:
            return None
        base = t.replace("*", "").replace("const", "").strip()
        if not base or base in PRIMITIVE or base in known:
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
    if conv == "__thiscall":
        rest = args[1:] if args else []
        args = ["void *this_ecx", "int edx_unused"] + rest
        decl = f"{ret} __fastcall {name}({', '.join(args) or 'void'});"
    elif conv in ("__stdcall", "__fastcall"):
        decl = f"{ret} {conv} {name}({', '.join(args) or 'void'});"
    else:
        decl = f"{ret} {name}({', '.join(args) or 'void'});"
    return decl


def prompt_section(fn: dict, callee_addrs: list[int], types: dict[str, str],
                   sigs: dict[int, dict]) -> str:
    wanted: list[str] = []
    seen: set[str] = set()

    def want(text: str) -> None:
        for t in type_names(text):
            if t in types and t not in seen:
                seen.add(t)
                wanted.append(t)

    want(fn.get("signature") or "")
    want(fn.get("class") or "")
    own = sigs.get(fn.get("addr", -1))
    if own:
        want(own["signature"])

    decls: list[str] = []
    for a in callee_addrs[:MAX_CALLEES]:
        info = sigs.get(a)
        if not info:
            continue
        d = declare_callee(info, set(types))
        if d:
            decls.append(d)
            want(info["signature"])

    if not wanted and not decls:
        return ""

    shown, used = [], 0
    for t in wanted[:MAX_TYPES]:
        d = types[t]
        if used + len(d) > MAX_TYPE_CHARS:
            break
        shown.append(d)
        used += len(d)

    out = ["\n## Types and declarations recovered from this binary\n"]
    if shown:
        out.append(
            "These are the REAL layouts, taken from analysis of this exact\n"
            "binary -- field names, offsets and sizes.\n\n"
            "```c\n" + "\n\n".join(shown) + "\n```\n")
    if decls:
        out.append(
            "\nThese are the functions this one calls, with the calling\n"
            "convention recovered from the binary.\n\n"
            "```c\n" + "\n".join("extern " + d for d in decls) + "\n```\n")
    return "".join(out)
