"""Turn whatever name evidence a binary carries into one canonical identity.

The corpus exposes names in four different shapes:

1. Itanium mangled symbols    `_ZN19CSWGuiMainInterface12AddHelpPanelEib`
2. Ghidra namespace + name    ns=`CSWGuiMainInterface` name=`AddHelpPanel`
3. Plate-comment signatures   `CSWGuiManager::PlayGuiSound(char)`
4. MSVC-demangled signatures  `public: void __thiscall Foo::Bar(int)`

All four reduce to `Class::method` plus a normalized parameter list, so a
function named in a K2 Android `.so` and the same function named by hand in
Lane's K1 Windows database land on the same key.
"""

from __future__ import annotations

import re

_STRIP_PREFIX = re.compile(
    r"^(?:public|private|protected|virtual|static|__thiscall|__cdecl|"
    r"__stdcall|__fastcall)\s*:?\s*",
    re.I,
)
_WS = re.compile(r"\s+")
_DEFAULT = re.compile(
    r"^(FUN_|SUB_|thunk_FUN_|UndefinedFunction_|LAB_|caseD_|switchD_|"
    r"Ordinal_|entry$|_?start$)"
)
_LIBRARY_CLASS = re.compile(
    r"^(std\b|__gnu_cxx|__cxxabiv1|boost\b|SDL|_?Unwind|__|"
    r"operator[ _](new|delete)|_?malloc|_?free|_?memcpy|_?memset|_?strlen)"
)


def strip_templates(s: str) -> str:
    """Remove template argument lists entirely: `map<int,Foo>::x` -> `map::x`."""
    out = []
    depth = 0
    for ch in s:
        if ch == "<":
            depth += 1
        elif ch == ">":
            if depth:
                depth -= 1
                continue
        if depth == 0:
            out.append(ch)
    return _WS.sub(" ", "".join(out)).strip()


_TYPE_WORDS = {
    "unsigned", "signed", "long", "short", "int", "char", "float", "double",
    "void", "bool", "wchar_t", "__int64", "int64_t", "uint64_t", "size_t",
}


def _drop_param_name(t: str) -> tuple[str, str | None]:
    """`CVirtualMachine *this` -> ('CVirtualMachine*', 'this')."""
    t = re.sub(r"\s*([*&])\s*", r"\1 ", strip_templates(t)).strip()
    t = re.sub(r"([*&]) (?=[*&])", r"\1", t)
    toks = t.split()
    if len(toks) > 1 and re.fullmatch(r"[A-Za-z_]\w*", toks[-1]) and toks[-1] not in _TYPE_WORDS:
        return " ".join(toks[:-1]), toks[-1]
    return t, None


def _clean_type(t: str) -> str:
    """Normalize a parameter type so toolchain spelling differences vanish."""
    t, _ = _drop_param_name(t)
    t = re.sub(r"\b(class|struct|enum|const|volatile|__restrict)\b", "", t)
    t = t.replace("&&", "&")
    t = _WS.sub("", t)
    stars = t.count("*") + t.count("&")
    base = t.replace("*", "").replace("&", "").replace("[]", "")
    base = re.sub(r"^(unsigned|signed)", "", base)
    base = {
        "int": "i", "uint": "i", "long": "i", "ulong": "i", "short": "i", "ushort": "i",
        "longlong": "i8", "ulonglong": "i8", "__int64": "i8", "int64_t": "i8",
        "uint64_t": "i8", "char": "c", "uchar": "c", "schar": "c", "bool": "b",
        "float": "f", "double": "d", "void": "v", "wchar_t": "w",
        "undefined": "?", "undefined1": "?", "undefined2": "?",
        "undefined4": "?", "undefined8": "?", "": "?",
    }.get(base, base)
    return base + "*" * stars


def _split_params(args: str) -> list[str]:
    params, depth, cur = [], 0, ""
    for c in args:
        if c in "<([":
            depth += 1
        elif c in ">)]":
            depth -= 1
        if c == "," and depth == 0:
            params.append(cur)
            cur = ""
        else:
            cur += c
    if cur.strip():
        params.append(cur)
    out = []
    for i, p in enumerate(params):
        if not p.strip() or p.strip() in ("void", "..."):
            continue
        _, pname = _drop_param_name(p)
        # A leading `this` is an ABI artifact, not part of the source signature;
        # mangled Itanium names never include it, so drop it everywhere.
        if i == 0 and pname == "this":
            continue
        out.append(_clean_type(p))
    return out


def split_signature(sig: str) -> tuple[str | None, list[str]]:
    """`void Foo::Bar(int, char *)` -> (`Foo::Bar`, ['i','c*'])."""
    if not sig:
        return None, []
    sig = _STRIP_PREFIX.sub("", sig.strip())
    depth, open_idx = 0, None
    for i in range(len(sig) - 1, -1, -1):
        if sig[i] == ")":
            depth += 1
        elif sig[i] == "(":
            depth -= 1
            if depth == 0:
                open_idx = i
                break
    if open_idx is None:
        return strip_templates(sig).split(" ")[-1], []
    head = strip_templates(sig[:open_idx]).strip()
    params = _split_params(sig[open_idx + 1 : sig.rfind(")")])
    toks = head.split()
    head = toks[-1] if toks else head  # drop return type
    return head, params


def split_qualified(qual: str) -> tuple[str, str]:
    """`A::B::method` -> ('A::B', 'method'); operator names stay intact."""
    qual = strip_templates(qual).strip()
    m = re.search(r"(?:^|::)(operator\b.*|operator[^\w\s].*)$", qual)
    if m:
        return qual[: m.start()].rstrip(":"), m.group(1)
    if "::" not in qual:
        return "", qual
    idx = qual.rfind("::")
    return qual[:idx], qual[idx + 2 :]


NULL = {
    "canon_class": None, "canon_method": None, "canon_key": None,
    "canon_arity": None, "canon_params": None, "name_origin": "none",
}


def canonicalize(
    name: str,
    namespace: str | None = None,
    plate: str | None = None,
    dm_name: str | None = None,
    dm_namespace: str | None = None,
    dm_params: list[str] | None = None,
) -> dict:
    """Best-effort canonical identity for one function."""
    if not name or is_default_name(name):
        return dict(NULL)

    cls = method = None
    params: list[str] = []
    origin = "none"

    # 1. mangled symbol: most reliable, carries parameter types
    if dm_name:
        cls = strip_templates(dm_namespace or "")
        method = strip_templates(dm_name)
        params = [_clean_type(p) for p in (dm_params or [])]
        origin = "mangled"

    # 2. plate-comment signature (Mac / Lane / Xbox builds carry these)
    if method is None and plate:
        line = plate.strip().splitlines()[0].strip()
        bad = ("Library Function", "Function Stack Size", "WARNING", "NOTE")
        if "(" in line and not line.startswith(bad):
            head, params = split_signature(line)
            if head:
                cls, method = split_qualified(head)
                origin = "plate"

    # 3. Ghidra namespace + short name
    if method is None:
        ns = strip_templates((namespace or "").strip())
        ns = ns.replace("<EXTERNAL>::", "").replace("<EXTERNAL>", "")
        nm = strip_templates(name.strip())
        if "::" in nm:
            c2, nm = split_qualified(nm)
            ns = ns or c2
        cls, method = ns, nm
        origin = "namespace" if ns else "bare"

    if not method:
        return dict(NULL)

    cls = (cls or "").strip(": ")
    method = method.strip()
    # Ghidra disambiguates duplicate symbols with an address suffix; drop it.
    method = re.sub(r"_[0-9a-fA-F]{6,8}$", "", method)
    if not method:
        return dict(NULL)
    key = f"{cls}::{method}" if cls else method

    return {
        "canon_class": cls or None,
        "canon_method": method,
        "canon_key": key,
        "canon_arity": len(params) if dm_name or origin == "plate" else None,
        "canon_params": ",".join(params) if params else None,
        "name_origin": origin,
    }


def is_default_name(name: str) -> bool:
    return bool(_DEFAULT.match(name or ""))


_EH_CLONE = re.compile(r"\[clone \.eh\]")


def is_eh_clone(name: str | None, plate: str | None) -> bool:
    """True for GCC/Apple `[clone .eh]` exception-frame entries.

    Ghidra materialises these as zero-instruction functions carrying the same
    name as the real function, which silently doubles every name in the Mac
    builds and destroys name uniqueness. They are not code.
    """
    return bool(_EH_CLONE.search(plate or "") or _EH_CLONE.search(name or ""))


# Binaries whose .text is DRM ciphertext (measured entropy 8.000). Ghidra still
# produces "functions" over the encrypted bytes and Function-ID still matches
# some of them, but none of it is real code, so they are excluded everywhere
# rather than left to contribute noise.
# Encrypted or otherwise unreadable images belong in the corpus file
# (`exclude: true` / `drm: true`), not in this module. Product paths are
# not defaults.
DRM_EXCLUDED: set[str] = set()


def from_fid(plate: str | None) -> bool:
    """True when the name came from Ghidra's Function ID (library) database.

    These are real names, but they identify CRT/MFC/STL code that exists in every
    build. Counting them as KotOR identity would flatter every metric.
    """
    return bool(plate) and plate.lstrip().startswith("Library Function")


def is_library(canon_key: str | None) -> bool:
    """True for runtime/library code that carries no KotOR-specific identity."""
    if not canon_key:
        return False
    return bool(_LIBRARY_CLASS.match(canon_key))
