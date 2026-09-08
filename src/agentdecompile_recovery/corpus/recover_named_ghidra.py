"""Recover independently named functions from cached Ghidra C, no API.

Highest-ranked no-API path: take Ghidra decompiled C for functions that
already have an independent logical name, compile with the era toolchain,
and ingest only bodies that are real C and byte-exact. Permuter is used
only when the base compiles but the bytes differ.

    python -m agentdecompile_recovery.corpus.recover_named_ghidra --db DB --out-dir DIR --recovered-dir R --limit 40
"""

from __future__ import annotations

import argparse
import os
import json
import pathlib
import re
import sqlite3
import time

from . import canon
from . import permuter_harness as ph
from .export_types import definitions_for
from .genproject import pe_va_mapper
from .source_claims import is_real_c
from .seed_validation import destination_bytes

RECOVERED = pathlib.Path(os.environ.get("AGENT_DECOMPILE_EXTERNAL_RECOVERY_ROOT") or ".") / "recovered-source"
COVERAGE = pathlib.Path(os.environ.get("AGENT_DECOMPILE_EXTERNAL_RECOVERY_ROOT") or ".") / "reports" / "coverage"
OUT = pathlib.Path(os.environ.get("AGENT_DECOMPILE_CORPUS_WORK_DIR") or ".")
RESULTS = OUT / "ghidra_named_recovery.jsonl"
SUMMARY = OUT / "ghidra_named_recovery_summary.json"

PLACEHOLDER = re.compile(
    r"^(FUN_|SUB_|thunk_FUN_|UndefinedFunction_|LAB_|caseD_|switchD_|"
    r"Ordinal_|Unwind[_@]|Catch[_@]|FrameHandler[_@]|entry$|_?start$)",
    re.I,
)

# Compiler-generated exception-handling machinery: unwind funclets, catch
# blocks and frame handlers. Ghidra lists them as functions, but they were
# never standalone functions in the original source -- they are fragments the
# compiler emitted, entered mid-frame with live registers their C can only
# model as fake `unaff_EBP`-style locals. They cannot be reproduced as
# standalone C and must not be counted in "percent of the binary recovered":
# on k1_win_gog they are **13,626 of 24,181 entries (56.4%)**, so including
# them silently halves any coverage figure.
EH_FRAGMENT_RE = re.compile(r"^(Unwind[_@]|Catch[_@]|FrameHandler[_@])", re.I)

# Ghidra data-table symbols the small preamble can't resolve: a plain global
# (DAT_), a pointer-sized table slot (PTR_), or a vtable slot holding a
# function pointer (PTR_FUN_). Declaring these as generic externs lets MSVC
# emit them as DIR32 relocations in the .obj instead of erroring out; the
# comparison against original bytes is reloc-masked, so the placeholder
# declaration doesn't need to know the real type.
DATA_SYM_RE = re.compile(r"\bPTR_FUN_[0-9a-fA-F]+\b|\bPTR_[0-9a-fA-F]+\b|\bDAT_[0-9a-fA-F]+\b")

def program_for_repo(repo_path: str) -> str:
    return pathlib.Path(repo_path).name


PROGRAM_FOR_REPO: dict[str, str] = {}


def _hex_keys(addr: int) -> list[str]:
    return [f"{addr:08x}", f"{addr:x}", f"{addr:08X}", f"{addr:X}"]


def knowledge_c(program: str, addr: int) -> tuple[str, str] | None:
    con = sqlite3.connect(f"file:{ph.KNOWLEDGE_CACHE}?mode=ro", uri=True)
    try:
        for key in _hex_keys(addr):
            row = con.execute(
                "SELECT name, decompiled FROM func_knowledge "
                "WHERE program=? AND entry_hex=? AND decompiled IS NOT NULL",
                (program, key),
            ).fetchone()
            if row and row[1]:
                return str(row[0] or ""), str(row[1])
    except sqlite3.Error:
        return None
    finally:
        con.close()
    return None


def candidates(con, repo_path: str, limit: int, min_size: int = 16) -> list[dict]:
    program = program_for_repo(repo_path)
    rows = con.execute(
        """
        SELECT l.id AS lid, l.canon_key, l.canon_class, l.source_file,
               b.id AS binary_id, b.repo_path, b.slug,
               i.addr, f.size, f.name, f.calling_convention, f.n_instr
          FROM logical_function l
          JOIN identity i ON i.logical_id = l.id
          JOIN func f ON f.binary_id = i.binary_id AND f.addr = i.addr
          JOIN binary b ON b.id = i.binary_id
         WHERE b.repo_path = ?
           AND b.arch = 'x86' AND b.bits = 32
           AND f.size BETWEEN ? AND 64
           AND f.is_thunk = 0
           AND f.n_instr >= 1
           AND l.canon_key IS NOT NULL
           AND NOT EXISTS (
                 SELECT 1 FROM recovered_function r
                  WHERE r.binary_id = i.binary_id
                    AND r.addr = i.addr
                    AND r.real_c = 1
               )
         ORDER BY f.size ASC, l.id
        """,
        (repo_path, min_size),
    ).fetchall()
    out = []
    for r in rows:
        key = r["canon_key"]
        if PLACEHOLDER.match(key or "") or canon.is_default_name(key or "") \
                or canon.is_library(key):
            continue
        out.append({
            "logical_id": int(r["lid"]),
            "canon_key": key,
            "canon_class": r["canon_class"],
            "source_file": r["source_file"],
            "binary_id": int(r["binary_id"]),
            "repo_path": r["repo_path"],
            "slug": r["slug"],
            "program": program,
            "addr": int(r["addr"]),
            "size": int(r["size"]),
            "name": r["name"],
            "convention": r["calling_convention"],
        })
        if len(out) >= limit:
            break
    return out


def write_recovered(program: str, name: str, text: str) -> pathlib.Path:
    dest_dir = RECOVERED / program
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f"{name}.c"
    dest.write_text(text)
    return dest


def merge_coverage(program: str, row: dict) -> None:
    ledger = COVERAGE / f"{program}.jsonl"
    existing = []
    if ledger.exists():
        for line in ledger.read_text().splitlines():
            if not line.strip():
                continue
            try:
                existing.append(json.loads(line))
            except ValueError:
                continue
    existing = [r for r in existing if r.get("function") != row["function"]]
    existing.append(row)
    existing.sort(key=lambda r: str(r.get("function") or ""))
    ledger.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in existing))


def header(name: str, program: str, size: int, convention: str | None,
           hex_bytes: str, canon_key: str) -> str:
    conv = convention or "unknown"
    return (
        f"/*\n"
        f" * {name}  --  recovered from {program}\n"
        f" * size: {size} bytes   calling convention: {conv}\n"
        f" * canonical name: {canon_key}\n"
        f" * original machine code: {hex_bytes}\n"
        f" * VERIFIED BYTE-EXACT: recompiled Ghidra C matched the original bytes\n"
        f" * evidence: ghidra-c-named-recovery-2026-08-15\n"
        f" */\n"
    )


MINIMAL_CTX = (
    ph.GHIDRA_TYPES
    + ph.WIN32_TYPES
    + "typedef unsigned char undefined;\n"
    "typedef unsigned char undefined1;\n"
    "typedef unsigned short undefined2;\n"
    "typedef unsigned int undefined4;\n"
    "typedef unsigned long long undefined8;\n"
    "typedef int bool;\n"
    "typedef unsigned char byte;\n"
    "typedef unsigned short word;\n"
    "typedef unsigned int dword;\n"
    "typedef unsigned short ushort;\n"
    "typedef long double float10;\n"
)


def declare_data_symbols(base_c: str, exclude: set[str]) -> str:
    """Declare Ghidra DAT_/PTR_/PTR_FUN_ symbols the minimal preamble omits.

    The small preamble (unlike the full ctx.h) carries no per-address extern
    table, so any reference to an unresolved global or vtable slot is an
    undeclared identifier. A generic `extern int` placeholder is enough: the
    comparison against original bytes is reloc-masked, so the placeholder's
    type and link address don't need to match reality, only its presence.
    """
    found = {m for m in DATA_SYM_RE.findall(base_c) if m not in exclude}
    return "".join(f"extern int {sym};\n" for sym in sorted(found))


OPERATOR_WORDS = {
    "+": "add", "-": "sub", "*": "mul", "/": "div", "%": "mod",
    "=": "eq", "<": "lt", ">": "gt", "!": "not", "&": "and", "|": "or",
    "^": "xor", "~": "inv", "[": "idx", "]": "", "(": "call", ")": "",
    ",": "comma", " ": "_",
}

# An identifier followed by one or more `::`-qualified segments, where a
# trailing segment may be a destructor (~Name) or an operator (operator+=).
QUALIFIED_RE = re.compile(
    r"\b[A-Za-z_]\w*"
    r"(?:::(?:~[A-Za-z_]\w*"
    r"|operator(?:\s*(?:new|delete)(?:\s*\[\s*\])?|[^\w\s(,;]{1,3})"
    r"|[A-Za-z_]\w*))+"
)


def _flatten_qualified(token: str) -> str:
    parts = token.split("::")
    out = []
    for p in parts:
        p = p.strip()
        if p.startswith("~"):
            out.append("dtor_" + p[1:])
        elif p.startswith("operator"):
            suffix = p[len("operator"):].strip()
            if suffix[:1].isalpha():
                # `operator new` / `operator delete[]` -- already words, and
                # mapping them through the punctuation table would collide
                # with `operator()`.
                word = re.sub(r"\W+", "_", suffix).strip("_")
            else:
                word = "".join(OPERATOR_WORDS.get(ch, "") for ch in suffix)
            out.append("op_" + (word or "call"))
        elif p:
            out.append(p)
    return "__".join(out)


def flatten_cpp_names(base_c: str) -> str:
    """Rewrite Ghidra's C++ qualified names into plain C identifiers.

    Ghidra emits `CExoString::~CExoString(&local_40)` and `Vector::operator-=(x)`
    even in its C output. The harness compiles with MSVC's /TC (C, not C++),
    where `::` is a hard syntax error -- measured at **82-95% of all functions**
    on k1_win_gog, k2_win_gog_aspyr, k1_mac and k2_mac, which is what made
    `base_c_does_not_compile` the dominant outcome across the whole recovery
    effort. (k2_win_CD is the outlier at 0.1%, because it carries almost no
    class names -- which is why its batches were the only ones ever landing
    hits.)

    Renaming callees is safe for byte-exactness: every one of these is reached
    by `call rel32`, and rel32 displacements are linker-owned and already
    masked out by `mask_x86_rel32` before the comparison. The instruction
    encoding is identical whatever the symbol is called.
    """
    return QUALIFIED_RE.sub(lambda m: _flatten_qualified(m.group(0)), base_c)


# Identifiers used as a pointee type: `CFoo *p`, `(CFoo *)x`, `CFoo **pp`.
TYPE_USE_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\*")

# Anything the preamble, C itself, or build_case's own prototypes already give
# a meaning. Declaring these again would be a conflicting redeclaration.
_KNOWN_TYPES = {
    "void", "char", "short", "int", "long", "float", "double", "signed",
    "unsigned", "const", "volatile", "struct", "union", "enum", "static",
    "extern", "return", "sizeof", "typedef", "if", "else", "while", "for",
    "switch", "case", "do", "goto", "break", "continue", "register", "inline",
    "undefined", "undefined1", "undefined2", "undefined4", "undefined8",
    "byte", "word", "dword", "ushort", "uint", "ulong", "bool", "code",
    "unicode", "float10", "DWORD", "WORD", "BYTE", "BOOL", "UINT", "ULONG",
    "LONG", "HANDLE", "HWND", "HINSTANCE", "HMODULE", "LPVOID", "LPSTR",
    "LPCSTR", "SIZE_T", "HRESULT", "WCHAR", "LPARAM", "WPARAM", "ULONG_PTR",
}


def declare_unknown_types(base_c: str, already: set[str]) -> str:
    """Declare Ghidra's class/struct types that the small preamble omits.

    After `flatten_cpp_names` the next wall is `CSWGuiQuickPanel *this` -- a
    pointer to a type nothing ever declared, because struct/datatype
    definitions are not exported from the Ghidra project at all.

    They are declared as `unsigned char`, not as opaque structs, on purpose:
    Ghidra emits byte offsets against these pointers (`*(int *)(this + 0x135c)`)
    and C forbids arithmetic on an incomplete type, so `struct X;` would still
    not compile. A one-byte pointee makes `p + N` mean "N bytes along", which
    is exactly Ghidra's intent, and pointer arithmetic scaling is the only
    thing the choice affects in the emitted code.
    """
    found = {
        t for t in TYPE_USE_RE.findall(base_c)
        if t not in _KNOWN_TYPES and t not in already
    }
    return "".join(f"typedef unsigned char {t};\n" for t in sorted(found))


# MSVC diagnostics that name a single missing symbol, and what it must be.
# Letting the compiler say what is missing generalises past the DAT_/PTR_
# naming guess: hand-labelled globals like `AppManager` or `ConfirmCancel`
# match no pattern, but cl names them exactly.
_ERR_UNDECLARED_VALUE = re.compile(r"error C2065: '(\w+)' : undeclared identifier")
_ERR_UNKNOWN_TYPE = re.compile(
    r"error C2061: syntax error : identifier '(\w+)'"
    r"|error C2081: '(\w+)' : name in formal parameter list illegal"
    r"|error C2146: syntax error : missing '\)' before identifier '(\w+)'"
)
# Not repairable by declaration: the real struct layout decides the offsets
# that end up in the instruction stream, so guessing one would produce
# confidently wrong bytes rather than a compile error.
_ERR_NEEDS_STRUCT = re.compile(r"error C2223: left of '->(\w+)' must point to struct/union")


def compile_with_repair(built: pathlib.Path, name: str, compiler: str,
                        max_rounds: int = 4) -> tuple[bytes | None, dict]:
    """Compile, and let cl's own diagnostics drive declaration repair.

    Each round adds only what the compiler explicitly named as missing, then
    retries. Stops early when a round adds nothing (nothing left that a
    declaration can fix) or when the failure is a struct-layout one, which no
    declaration can honestly satisfy.
    """
    import subprocess
    import tempfile

    src_path = built / "base.c"
    info = {"rounds": 0, "added_values": 0, "added_types": 0, "needs_struct": False}

    for rnd in range(max_rounds):
        info["rounds"] = rnd + 1
        with tempfile.TemporaryDirectory() as td:
            obj = pathlib.Path(td) / "o.o"
            try:
                proc = subprocess.run(
                    [str(ph.COMPILERS[compiler]), str(src_path), str(obj), f"_{name}"],
                    capture_output=True, text=True, timeout=400,
                )
            except subprocess.TimeoutExpired:
                info["timeout"] = True
                return None, info
            if obj.exists():
                return _symbol_bytes(obj, name), info

            diag = (proc.stderr or "") + (proc.stdout or "")

        if _ERR_NEEDS_STRUCT.search(diag):
            info["needs_struct"] = True

        src = src_path.read_text()
        declared = set(re.findall(
            r"^\s*(?:extern|typedef)\s+[\w \*]+?\b(\w+)\s*;", src, re.M))

        types = {m for grp in _ERR_UNKNOWN_TYPE.findall(diag) for m in grp if m}
        types -= declared | _KNOWN_TYPES
        values = set(_ERR_UNDECLARED_VALUE.findall(diag)) - declared - types
        if not (types or values):
            return None, info                      # nothing a declaration fixes

        info["added_types"] += len(types)
        info["added_values"] += len(values)
        src_path.write_text(
            "".join(f"typedef unsigned char {t};\n" for t in sorted(types))
            + "".join(f"extern int {v};\n" for v in sorted(values))
            + src)

    return None, info


def _symbol_bytes(obj: pathlib.Path, name: str) -> bytes | None:
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "ec", pathlib.Path(os.environ.get("AGENT_DECOMPILE_EXACT_CORPUS") or "exact_corpus.py"))
    ec = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ec)
    try:
        data = obj.read_bytes()
        syms: dict[str, bytes] = {}
        for pref in ("_", "@"):
            try:
                syms.update(ec.coff_functions(data, prefix=pref))
            except Exception:
                continue
        from .seed_validation import select_object_symbol
        return select_object_symbol(syms, name)[1]
    except Exception:
        return None


def inject_data_symbols(built: pathlib.Path, type_source=None) -> int:
    """Add missing DAT_/PTR_ externs to a base.c that build_case already wrote.

    Done as a post-pass rather than inside `build_case` because that function is
    shared with the full-ctx path, where the 10k-line context already declares
    every symbol as extern data -- re-declaring there would be a conflicting
    redeclaration, not a fix. Symbols already declared in the file are skipped
    for the same reason. Returns how many declarations were added.
    """
    src_path = built / "base.c"
    src = src_path.read_text()
    declared = set(re.findall(r"^\s*(?:extern|typedef)\s+[\w \*]+?\b(\w+)\s*;",
                              src, re.M))

    # Real Ghidra layouts first, where they exist. Only types with no exported
    # layout fall back to `unsigned char` -- that fallback keeps pointer
    # arithmetic working but cannot satisfy `->member`, so preferring the real
    # definition is what turns `needs_struct` into a compile.
    real, resolved = "", set()
    if type_source is not None:
        con, binary_id = type_source
        wanted = {
            t for t in TYPE_USE_RE.findall(src)
            if t not in _KNOWN_TYPES and t not in declared
        }
        real, resolved = definitions_for(con, binary_id, wanted)

    types = declare_unknown_types(src, declared | resolved)
    decls = declare_data_symbols(src, declared | resolved)
    if not (real or types or decls):
        return 0
    types = real + types
    # Both blocks rest only on builtins, so they are safe above the Ghidra
    # typedefs rather than needing to be threaded in after them.
    src_path.write_text(types + decls + src)
    return (types + decls).count("\n")


def compiled_bytes_timeout(
    cfile: pathlib.Path, name: str, compiler: str, timeout: int = 400
) -> bytes | None:
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        obj = pathlib.Path(td) / "o.o"
        try:
            subprocess.run(
                [str(ph.COMPILERS[compiler]), str(cfile), str(obj), f"_{name}"],
                capture_output=True, text=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return None
        if not obj.exists():
            return None
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "ec", pathlib.Path(os.environ.get("AGENT_DECOMPILE_EXACT_CORPUS") or "exact_corpus.py"))
        ec = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ec)
        try:
            data = obj.read_bytes()
            syms: dict[str, bytes] = {}
            for pref in ("_", "@"):
                try:
                    syms.update(ec.coff_functions(data, prefix=pref))
                except Exception:
                    continue
            from .seed_validation import select_object_symbol
            return select_object_symbol(syms, name)[1]
        except Exception:
            return None


def mask_x86_rel32(data: bytes) -> bytes:
    """Zero linker-owned x86 relative displacements (call/jmp/jcc rel32)."""
    buf = bytearray(data)
    i = 0
    while i < len(buf):
        if buf[i] in (0xE8, 0xE9) and i + 5 <= len(buf):
            buf[i + 1:i + 5] = b"\0\0\0\0"
            i += 5
            continue
        if i + 6 <= len(buf) and buf[i] == 0x0F and 0x80 <= buf[i + 1] <= 0x8F:
            buf[i + 2:i + 6] = b"\0\0\0\0"
            i += 6
            continue
        i += 1
    return bytes(buf)


def prepare_context(repo_path: str, compiler: str) -> None:
    """Use a small preamble. Full ctx.h repair starts Wine on a 10k-line
    header and has been observed to sit in wineserver writeback for >15 min
    after the object already exists."""
    if repo_path in ph.CONTEXT_CACHE:
        return
    ph.CONTEXT_CACHE[repo_path] = MINIMAL_CTX
    print("  using minimal context (no 10k-line ctx repair)", flush=True)


def evaluate_one(case: dict, compiler: str, permuter_seconds: int,
                 raw_cache: dict) -> dict:
    rec = knowledge_c(case["program"], case["addr"])
    if rec is None:
        return {**case, "outcome": "no_ghidra_c", "accepted": False}
    ghidra_name, base_c = rec
    if not is_real_c(base_c):
        return {**case, "outcome": "ghidra_shim", "ghidra_name": ghidra_name,
                "accepted": False}
    try:
        raw_dir = pathlib.Path(os.environ.get("AGENT_DECOMPILE_CORPUS_WORK_DIR") or ".") / "extract" / "raw"
        target = destination_bytes(
            case["slug"], f"{case['addr']:08x}", case["size"], raw_cache,
            raw_dir=raw_dir,
            mapper_for=lambda raw: ((m, "pe") if (m := pe_va_mapper(raw)) else (None, None)),
        )
    except ValueError as exc:
        return {**case, "outcome": "no_target_bytes", "detail": str(exc),
                "accepted": False}

    prepare_context(case["repo_path"], compiler)
    work = ph.WORK / case["repo_path"].strip("/").replace("/", "__") / "named"
    built = ph.build_case(case["repo_path"], case["addr"], case["size"],
                          ghidra_name or case["name"], base_c, compiler, work)
    if built is None:
        return {**case, "outcome": "build_case_failed", "ghidra_name": ghidra_name,
                "accepted": False}

    name = (built / "function.txt").read_text().strip().lstrip("_")
    src_path = built / "base.c"
    src = src_path.read_text()
    got = compiled_bytes_timeout(src_path, name, compiler)
    compiles = got is not None
    exact = False
    if got is not None:
        raw = got[:len(target)]
        exact = raw == target or (
            len(got) >= len(target)
            and mask_x86_rel32(raw) == mask_x86_rel32(target)
        )
    outcome = "ghidra_c_matched" if exact else (
        "base_compiles" if compiles else "base_c_does_not_compile"
    )
    used_src = src
    if compiles and not exact and permuter_seconds > 0 and ph.PERMUTER.exists():
        try:
            ev = ph.evaluate(built, name, compiler, permuter_seconds)
        except Exception as exc:
            ev = {"outcome": f"permuter_error:{type(exc).__name__}"}
        outcome = ev.get("outcome", outcome)
        exact = bool(ev.get("byte_exact") or ev.get("real_c_and_byte_exact"))
        best = sorted(built.glob("output-*/*.c")) or sorted(built.glob("output*/*.c"))
        if best:
            used_src = best[-1].read_text()

    accepted = bool(exact and is_real_c(used_src))
    result = {
        **case,
        "ghidra_name": ghidra_name,
        "defined_name": name,
        "outcome": outcome,
        "accepted": accepted,
        "base_compiles": compiles,
        "byte_exact": exact,
        "real_c": is_real_c(used_src),
    }
    if not accepted:
        return result

    file_name = name if name else (ghidra_name or case["name"])
    file_name = re.sub(r"[^A-Za-z0-9_]", "_", file_name)
    dest = write_recovered(
        case["program"], file_name,
        header(file_name, case["program"], case["size"], case["convention"],
               target.hex(), case["canon_key"]) + used_src,
    )
    merge_coverage(case["program"], {
        "batch": "ghidra-c-named-recovery-2026-08-15",
        "byteExact": True,
        "byteExactVerified": True,
        "convention": case["convention"],
        "error": "",
        "function": file_name,
        "matched": True,
        "originalBytes": target.hex(),
        "size": case["size"],
        "symbol": f"_{name}",
        "canonicalName": case["canon_key"],
        "readableC": True,
        "path": str(dest),
    })
    result["path"] = str(dest)
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=40)
    ap.add_argument("--min-size", type=int, default=16)
    ap.add_argument("--compiler", default="vc8", choices=sorted(ph.COMPILERS))
    ap.add_argument("--permuter-seconds", type=int, default=0)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--program", default=None)
    ap.add_argument("--db", type=pathlib.Path, required=True)
    ap.add_argument("--out-dir", type=pathlib.Path)
    ap.add_argument("--recovered-dir", type=pathlib.Path)
    ap.add_argument("--results", default="")
    ap.add_argument("--replay-jsonl", default="")
    args = ap.parse_args(argv)
    global RESULTS, SUMMARY, OUT, RECOVERED
    if args.out_dir:
        OUT = pathlib.Path(args.out_dir)
        RESULTS = OUT / "ghidra_named_recovery.jsonl"
        SUMMARY = OUT / "ghidra_named_recovery_summary.json"
    if args.recovered_dir:
        RECOVERED = pathlib.Path(args.recovered_dir)
    if args.results:
        RESULTS = pathlib.Path(args.results)
        SUMMARY = RESULTS.with_name(RESULTS.stem + "_summary.json")
    if args.replay_jsonl:
        raw = [
            json.loads(line)
            for line in pathlib.Path(args.replay_jsonl).read_text().splitlines()
            if line.strip()
        ]
        keep = (
            "logical_id", "canon_key", "canon_class", "source_file",
            "binary_id", "repo_path", "slug", "program", "addr", "size",
            "name", "convention",
        )
        cases = [{k: row[k] for k in keep if k in row} for row in raw]
        print(f"replaying {len(cases)} rows from {args.replay_jsonl}", flush=True)
    else:
        from .store import connect
        con = connect(args.db)
        cases = candidates(con, args.repo, args.limit, args.min_size)
        print(f"named unrecovered candidates: {len(cases)} from {args.repo} "
              f"min_size={args.min_size}",
              flush=True)
    OUT.mkdir(parents=True, exist_ok=True)
    raw_cache: dict = {}
    results = []
    t0 = time.time()
    with RESULTS.open("w") as fh:
        for i, case in enumerate(cases, 1):
            row = evaluate_one(case, args.compiler, args.permuter_seconds,
                               raw_cache)
            results.append(row)
            fh.write(json.dumps(row, default=str) + "\n")
            fh.flush()
            print(
                f"  {i}/{len(cases)} {case['canon_key']} "
                f"size={case['size']} -> {row['outcome']} "
                f"accepted={row['accepted']}",
                flush=True,
            )
    accepted = [r for r in results if r.get("accepted")]
    summary = {
        "repo": args.repo,
        "attempted": len(results),
        "accepted": len(accepted),
        "outcomes": {},
        "seconds": round(time.time() - t0, 1),
        "accepted_names": [r["canon_key"] for r in accepted],
    }
    for r in results:
        summary["outcomes"][r.get("outcome", "?")] = (
            summary["outcomes"].get(r.get("outcome", "?"), 0) + 1
        )
    SUMMARY.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
