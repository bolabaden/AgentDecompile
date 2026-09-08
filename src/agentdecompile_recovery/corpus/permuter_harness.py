#!/usr/bin/env python3
"""Ghidra C -> decomp-permuter -> byte-exact real C.

This is the pipeline that actually recovers source, and it contains no language
model at all:

    Ghidra decompiler  ->  C that behaves right but compiles to different bytes
    decomp-permuter    ->  mutates that C (reorders, retypes, rephrases) and
                           recompiles each variant with the era-exact compiler
    byte comparison    ->  keep a variant only if its bytes match the original

For MIPS/PowerPC/ARM projects the first stage is m2c. m2c has no x86 backend
(only `arch_mips.py`, `arch_ppc.py`, `arch_arm.py`), so on this corpus Ghidra
fills that role.

Two properties are recorded separately for every function, because conflating
them is what produced months of misleading results:

* `real_c`     — the source contains no `__asm` / `naked` / `_emit`
* `byte_exact` — the compiled bytes equal the original function's bytes

Only functions with BOTH are progress. A byte-exact `__asm` shim is the machine
code copied into a C wrapper and is worth nothing.
"""

from __future__ import annotations

import os

import argparse
import json
import pathlib
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

from . import store

EXTERNAL_ROOT = pathlib.Path(os.environ.get("AGENT_DECOMPILE_EXTERNAL_RECOVERY_ROOT") or ".")
CONTEXT_CACHE: dict[str, str] = {}

# Types ctx.h defines, plus C primitives. Anything else in a global declaration
# is a Windows/Ghidra type the compiler has never heard of.
GHIDRA_TYPES = (
    # `code` is Ghidra's generic function type, used for every indirect call
    # regardless of the callee's real return type (typically a vtable slot
    # whose exact signature Ghidra didn't resolve). Declaring it `void(void)`
    # matches calls used as bare statements, but MSVC hard-errors (C2120) the
    # moment one of those calls is assigned to a variable — "'void' illegal
    # with all types". `int` avoids that: an int result silently discarded in
    # a bare-statement call is legal C, an int result assigned to a variable
    # is legal C, and since x86 cdecl/stdcall/thiscall return in EAX either
    # way, the declared type never changes what code the compiler emits.
    "typedef int code(void);\ntypedef void unicode;\n")

FUNC_TYPEDEF_RE = re.compile(r"\b(_func_[A-Za-z0-9_]*)\b")


def func_typedefs(base_c: str) -> str:
    """Declare Ghidra's synthetic function-pointer typedef names.

    Ghidra names an unresolved function-pointer type `_func_<ret>_<args>_ptr`
    (e.g. `_func_void_void_ptr`) inline in the decompiled text, with no
    typedef ever emitted for it — CppExporter's header only covers named
    struct/enum types, not these synthetic ones. They always appear used as
    `(_func_..._ptr *)expr`, i.e. as a pointer type in a cast, so declaring
    each as an alias for a generic function pointer is enough to compile:
    the exact parameter/return types don't affect codegen for a cast-and-call
    through an address, only the call sequence (which is already fixed by the
    surrounding `code` cast one level out).
    """
    names = sorted(set(FUNC_TYPEDEF_RE.findall(base_c)))
    return "".join(f"typedef code *{n};\n" for n in names)

WIN32_TYPES = (
    "typedef unsigned long  DWORD;\ntypedef unsigned short WORD;\n"
    "typedef unsigned char  BYTE;\ntypedef int            BOOL;\n"
    "typedef unsigned int   UINT;\ntypedef unsigned long  ULONG;\n"
    "typedef long           LONG;\ntypedef void          *HANDLE;\n"
    "typedef void          *HWND;\ntypedef void          *HINSTANCE;\n"
    "typedef void          *HMODULE;\ntypedef void          *LPVOID;\n"
    "typedef char          *LPSTR;\ntypedef const char    *LPCSTR;\n"
    "typedef unsigned int   SIZE_T;\ntypedef long           HRESULT;\n"
    "typedef unsigned short WCHAR;\ntypedef long           LPARAM;\n"
    "typedef unsigned int   WPARAM;\ntypedef unsigned int   ULONG_PTR;\n")

# VC8 rejects __thiscall on a free function in C. __fastcall with a dummy second
# argument is ABI-identical to __thiscall: thiscall puts `this` in ECX and the
# rest on the stack; fastcall puts arg1 in ECX, arg2 in EDX, rest on the stack.
# Inserting an unused EDX argument therefore reproduces thiscall exactly, and
# both conventions clean up in the callee.
THISCALL_RE = re.compile(
    r"^(\w[\w \t\*]*?)\b__thiscall\s+(\w+)\s*\(", re.M)


def fix_thiscall(src: str) -> str:
    def sub(m):
        return f"{m.group(1)}__fastcall {m.group(2)}(int __edx_pad, "
    out = THISCALL_RE.sub(sub, src)
    # A no-argument thiscall becomes `(int __edx_pad, )` — drop the comma.
    return re.sub(r"\(int __edx_pad, \s*\)", "(int __edx_pad)", out)


IDENT_RE = re.compile(r"[A-Za-z_]\w*")
CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
DEF_NAME_RE = re.compile(r"^[\w \*]+?\b([A-Za-z_]\w*)\s*\(")


def defined_name(base_c: str, fallback: str) -> str:
    """The identifier the compiler will actually emit for this function.

    Ghidra's per-function metadata names the exception-unwind pseudo-functions
    with `@` (`Unwind@007896d0`) — not a valid C identifier — while the
    decompiled body always defines the valid-C spelling (`Unwind_007896d0`).
    Building the compile symbol, function.txt, or a callee prototype off the
    metadata name silently diverges from what the body actually defines: the
    call-site scan matches the function's own definition line, emits a
    prototype for `Unwind_007896d0` ahead of the real `void Unwind_007896d0
    (void) {...}` definition, and MSVC rejects the two conflicting
    declarations (C2371 redefinition). Reading the identifier out of the body
    itself is the only source that can't diverge from what gets compiled.
    """
    for line in base_c.splitlines():
        line = line.strip()
        if not line or line.endswith((";", ",")):
            continue
        m = DEF_NAME_RE.match(line)
        if m:
            return m.group(1)
    return fallback
C_KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "do", "else",
              "case", "break", "continue", "goto", "default", "typedef",
              "struct", "union", "enum", "static", "extern", "const"}

KNOWN_TYPES = {
    "void", "char", "short", "int", "long", "float", "double", "signed",
    "unsigned", "__int64", "size_t", "wchar_t",
    "undefined", "undefined1", "undefined2", "undefined3", "undefined4",
    "undefined5", "undefined6", "undefined7", "undefined8",
    "byte", "sbyte", "word", "dword", "qword", "uchar", "ushort", "uint",
    "ulong", "ulonglong", "longlong", "bool", "float10", "code", "unicode",
    "wchar16", "wchar32", "pointer32", "pointer64",
}
# Confirmed present 2026-08-30 on the mounted MyBook tree. The old
# `.claude/worktrees/...` path is a leftover from a MizuchiRE checkout and
# is not what this host actually runs.
PERMUTER = pathlib.Path(os.environ.get("AGENT_DECOMPILE_PERMUTER") or "decomp-permuter")
MKOBJ = pathlib.Path(os.environ.get("AGENT_DECOMPILE_MKOBJ") or "mkobj.py")
WORK = pathlib.Path(os.environ.get("AGENT_DECOMPILE_CORPUS_WORK_DIR") or ".") / "permuter"
from .source_claims import is_real_c

# Compilers, in preference order. VC7.1 is era-exact (it emits the `ff 20`
# virtual dispatch the shipped binaries actually use); VC8 is MizuchiRE's
# proven fallback.
COMPILERS = {
    "vc71": pathlib.Path(os.environ.get("AGENT_DECOMPILE_MSVC71") or "compile-msvc71.sh"),
    "vc8": pathlib.Path(os.environ.get("AGENT_DECOMPILE_MSVC8") or str(EXTERNAL_ROOT / "tools" / "compile-msvc-x86.sh")),
}
GHIDRA_SRC = pathlib.Path(os.environ.get("AGENT_DECOMPILE_GHIDRA_SRC") or "recovered-source-ghidra")


def export_paths(repo_path: str) -> tuple[pathlib.Path | None, pathlib.Path | None]:
    """Locate the whole-program .c and its companion .h, mine or MizuchiRE's."""
    slug = repo_path.strip("/").replace("/", "__")
    base = pathlib.PurePosixPath(repo_path).name
    for c in (pathlib.Path(os.environ.get("AGENT_DECOMPILE_CORPUS_WORK_DIR") or ".") / "extract" / "cexport" / slug / f"{slug}.c",
              EXTERNAL_ROOT / "binaries" / base / "ghidra_knowledge" / f"{base}.c"):
        if c.exists() and c.stat().st_size > 1024:
            h = c.with_suffix(".h")
            return c, (h if h.exists() else None)
    return None, None


def knowledge_dir(repo_path: str) -> pathlib.Path | None:
    """`$R/binaries/<program>/ghidra_knowledge`, matched by file name."""
    leaf = repo_path.rstrip("/").split("/")[-1]
    root = EXTERNAL_ROOT / "binaries"
    for cand in (leaf,):
        if cand and (root / cand / "ghidra_knowledge").is_dir():
            return root / cand / "ghidra_knowledge"
    return None


KNOWLEDGE_CACHE = pathlib.Path(os.environ.get("AGENT_DECOMPILE_GHIDRA_KNOWLEDGE_DB") or "ghidra_knowledge.sqlite")


def per_function_json_c(repo_path: str) -> dict[str, str]:
    """{function name: decompiled C} from the per-function knowledge export.

    This is the complete source: one JSON per function under
    `functions/<shard>/<entry-hex>.json` carrying `decompiled`, `asm`, the full
    instruction list with bytes and relocations, and the calling convention.

    500,000+ of those files live on a shared spinning disk, so a live per-call
    scan is seek-bound — tens of minutes for one binary, repeated on every cold
    call. `kx/ingest_ghidra_knowledge.py` pays that cost once per binary in a
    single sequential walk and writes the result to `db/ghidra_knowledge.sqlite`
    (one indexed file); that cache is checked first and is what every normal
    call actually hits. The live JSON walk below is the fallback for a binary
    not yet ingested — correct, just slow.
    """
    program = knowledge_dir(repo_path)
    if program is not None and KNOWLEDGE_CACHE.exists():
        program_name = program.parent.name
        con = sqlite3.connect(f"file:{KNOWLEDGE_CACHE}?mode=ro", uri=True)
        try:
            rows = con.execute(
                "SELECT name, decompiled FROM func_knowledge "
                "WHERE program=? AND decompiled IS NOT NULL", (program_name,)
            ).fetchall()
        except sqlite3.Error:
            rows = []
        con.close()
        if rows:
            return {name: code for name, code in rows if name and code}

    k = program
    if k is None:
        return {}
    idx_path = k / "functions" / "index.json"
    if not idx_path.exists():
        return {}
    idx = json.loads(idx_path.read_text())
    base = k / "functions"
    out: dict[str, str] = {}
    for entry, meta in idx.get("functions", {}).items():
        rel = meta.get("path", "")
        p = base / rel
        if not p.exists():
            p = k / rel
            if not p.exists():
                continue
        try:
            d = json.loads(p.read_text(errors="replace"))
        except (OSError, ValueError):
            continue
        code = d.get("decompiled")
        name = d.get("name")
        if code and name:
            out[name] = code
    return out


def ghidra_c_for(repo_path: str) -> dict[str, str]:
    """Map function name -> its C body.

    Two sources, and the difference between them is large. The whole-program
    CppExporter dump is the convenient one, but on `k2_win_CD_1.0` it holds
    8,718 distinct `FUN_*` names against 22,438 real functions in the database
    — 13,482 of its entries are `Unwind_*` exception funclets rather than
    functions. Measuring off that dump alone would silently ignore 62% of the
    binary and report the result as if it covered all of it.

    `kx/decompile_text.py` decompiles every function individually into
    `db/ctext/<slug>.sqlite`, so it has no such gap. It is preferred wherever it
    exists; the dump remains the fallback for binaries not yet processed.
    """
    out = per_function_json_c(repo_path)
    if out:
        return out
    slug = repo_path.strip("/").replace("/", "__")
    ct = pathlib.Path(os.environ.get("AGENT_DECOMPILE_CORPUS_WORK_DIR") or ".") / "ctext" / f"{slug}.sqlite"
    if ct.exists():
        con = sqlite3.connect(f"file:{ct}?mode=ro", uri=True)
        try:
            rows = con.execute(
                "SELECT addr, code FROM ctext WHERE repo_path=? AND ok=1",
                (repo_path,)).fetchall()
        except sqlite3.Error:
            rows = []
        con.close()
        main = store.connect(pathlib.Path(os.environ['AGENT_DECOMPILE_CORPUS_DB']))
        b = main.execute("SELECT id FROM binary WHERE repo_path=?",
                         (repo_path,)).fetchone()
        if b:
            names = {r["addr"]: r["name"] for r in main.execute(
                "SELECT addr, name FROM func WHERE binary_id=?", (b["id"],))}
            for addr, code in rows:
                n = names.get(addr)
                if n and code:
                    out[n] = code
    if out:
        return out
    c, _h = export_paths(repo_path)
    return split_functions(c.read_text(errors="replace")) if c else {}


def split_functions(text: str) -> dict[str, str]:
    """Split a CppExporter dump into {function_name: source}.

    The format is a signature line at column 0, a blank line, then a `{` alone
    on its own line, then the body, closed by `}` at column 0. Brace-counting
    from the signature line does not work because the opening brace is two lines
    below it, so the scan explicitly waits for that lone `{` first.
    """
    out: dict[str, str] = {}
    sig_re = re.compile(r"^[A-Za-z_][\w \*&:<>,\[\]]*?([A-Za-z_]\w*)\s*\([^;]*\)\s*$")
    lines = text.splitlines()
    i, n = 0, len(lines)
    while i < n:
        m = sig_re.match(lines[i])
        if not m:
            i += 1
            continue
        j = i + 1
        while j < n and not lines[j].strip():
            j += 1
        if j >= n or lines[j].strip() != "{":
            i += 1
            continue
        depth, k = 0, j
        while k < n:
            depth += lines[k].count("{") - lines[k].count("}")
            if depth == 0:
                break
            k += 1
        if k < n:
            out[m.group(1)] = "\n".join(lines[i:k + 1])
            i = k + 1
        else:
            i = j + 1
    return out


# A verified-compiling ctx.h already exists per program in MizuchiRE's projects.
# gen-project.py builds it (typedefs + externs + callee prototypes) and then
# compiles it, dropping any declaration the compiler rejects until it is clean.
# Reusing that is far more reliable than feeding MSVC the 937 KB raw exporter
# header, which contains struct forms MSVC will not parse.
def _ctx_project(repo_path: str) -> str:
    return pathlib.Path(repo_path).name


def context_ghidra_bulk(con, repo_path: str, addr: int, body: str) -> str:
    """Header that already compiles Ghidra C -- reuse ghidra_bulk, not ctx.h.

    The older `context_for()` below walks a possibly-stale MizuchiRE tree and
    a whole-program dump, then `repair_context` deletes whatever cl.exe
    rejects. That is how this harness got `base_c_does_not_compile` as its
    dominant outcome. `kx/ghidra_bulk.py` already solved the same problem
    with measured sanitizers (thiscall proxy, field-name spelling, templates,
    `_CONTEXT`, singleton globals) and `kx/ctxtypes` layouts. One source of
    truth: if bulk can compile the function, the permuter starts from that
    exact text.
    """
    from . import ctxtypes
    from . import ghidra_bulk as gb

    brow = con.execute("SELECT id FROM binary WHERE repo_path=?", (repo_path,)).fetchone()
    if not brow:
        return ""
    bid = int(brow["id"])
    types = ctxtypes.load_types(con, bid)
    sigs = ctxtypes.load_signatures(con, bid)
    callee_map: dict[int, list[int]] = {}
    for r in con.execute(
            "SELECT caller_addr, callee_addr FROM calledge WHERE binary_id=?",
            (bid,)):
        callee_map.setdefault(int(r["caller_addr"]), []).append(int(r["callee_addr"]))
    return gb.build_header(con, bid, addr, sigs.get(addr), types, sigs, callee_map, body)


def existing_ghidra_c(program: str, addr: int) -> str | None:
    """Already-compiling body from the ghidra-bulk tree, if any."""
    src_dir = GHIDRA_SRC / program
    if not src_dir.is_dir():
        return None
    marker = f"address: 0x{addr:08x}"
    marker_short = f"address: 0x{addr:x}"
    for p in src_dir.glob("*.c"):
        head = p.read_text(errors="replace")[:400]
        if marker in head or marker_short in head:
            text = p.read_text(errors="replace")
            if text.startswith("/*"):
                end = text.find("*/\n")
                if end != -1:
                    text = text[end + 3:]
            return text
    return None


def context_for(repo_path: str) -> str:
    """Types + declarations a single extracted function needs to compile.

    A function lifted out of the whole-program dump references Ghidra's
    synthetic types (`undefined4`, `uint`) and file-scope globals (`DAT_...`,
    `ExceptionList`). The per-program ctx.h supplies the types and the common
    externs; the globals this particular export mentions are appended so the
    function stands alone.
    """
    proj = _ctx_project(repo_path)
    parts: list[str] = []
    if proj:
        ctx = EXTERNAL_ROOT / "projects" / proj / "ctx.h"
        if ctx.exists():
            text = ctx.read_text(errors="replace")
            # Ghidra declares `code` as a byte, then emits `code *fp; (*fp)();`
            # — a call through a char pointer, which MSVC rejects. Its own
            # typedef is removed here so the function-type one below wins; it
            # has to go in first because ctx.h uses `code` further down.
            text = re.sub(r"^typedef\s+[\w ]+\s+(?:code|unicode)\s*;\s*$",
                          "", text, flags=re.M)
            parts.append(GHIDRA_TYPES + WIN32_TYPES + text)
    if not parts:
        parts.append("typedef unsigned char undefined;\n"
                     "typedef unsigned char undefined1;\n"
                     "typedef unsigned short undefined2;\n"
                     "typedef unsigned int undefined4;\n"
                     "typedef unsigned __int64 undefined8;\n"
                     "typedef unsigned int uint;\n"
                     "typedef unsigned char byte;\n"
                     "typedef void code(void);\n"
                     "typedef void unicode;\n" if False else
                     "typedef void code(void);\n"
                     + WIN32_TYPES)

    # File-scope globals from the top of the .c, as externs.
    c, _h = export_paths(repo_path)
    if c:
        decls, seen = [], set()
        for line in c.read_text(errors="replace").splitlines():
            t = line.strip()
            if not t or not (t[0].isalpha() or t[0] == "_"):
                continue
            if not t.endswith(";") or "(" in t or t.startswith(
                    ("typedef", "struct", "union", "enum", "#")):
                continue
            toks = t[:-1].split()
            name = toks[-1].lstrip("*")
            # MSVC-decorated names (PTR__BinkOpenMiles@4_007b545c) are not valid
            # C identifiers; a declaration for one is a guaranteed parse error.
            if name in seen or len(toks) < 2 or not IDENT_RE.fullmatch(name):
                continue
            seen.add(name)
            # Globals carry Windows/Ghidra types (HWND, IMAGE_DOS_HEADER, ...)
            # that ctx.h does not define. The declaration only has to satisfy
            # the compiler and give the right storage class, so unknown types
            # collapse to a machine word.
            base_type = toks[0]
            stars = "*" * t.count("*")
            if base_type not in KNOWN_TYPES:
                decls.append(f"extern undefined4 {stars}{name};")
            else:
                decls.append("extern " + t)
            if len(decls) >= 30000:
                break
        parts.append("\n".join(decls))
    return "\n".join(parts) + "\n"


ERR_LINE_RE = re.compile(r"\.c\((\d+)\)\s*:\s*(?:fatal\s+)?error", re.I)


def repair_context(ctx: str, compiler: str, rounds: int = 12) -> str:
    """Compile the context and delete whatever the compiler rejects, repeatedly.

    Ghidra's exported declarations contain plenty MSVC will not accept: types it
    has never heard of, decorated symbol names, pointer forms it parses
    differently. Rather than enumerate those cases one at a time, this compiles
    the header and comments out every line the compiler flags, until it is clean
    or nothing more can be removed. This mirrors gen-project.py's verify_ctx.
    """
    lines = ctx.splitlines()
    probe = "\nvoid __kx_probe(void) {}\n"
    for _ in range(rounds):
        with tempfile.TemporaryDirectory() as td:
            src = pathlib.Path(td) / "ctx_probe.c"
            src.write_text("\n".join(lines) + probe)
            r = subprocess.run(
                [str(COMPILERS[compiler]), str(src), str(pathlib.Path(td) / "o.o"),
                 "___kx_probe"], capture_output=True, text=True)
            if (pathlib.Path(td) / "o.o").exists():
                return "\n".join(lines) + "\n"
            bad = {int(m.group(1)) for m in ERR_LINE_RE.finditer(r.stdout + r.stderr)}
        if not bad:
            break
        for ln in bad:
            if 1 <= ln <= len(lines):
                lines[ln - 1] = "/* dropped: " + lines[ln - 1].replace("*/", "* /") + " */"
    return "\n".join(lines) + "\n"


def build_case(repo_path: str, addr: int, size: int, name: str, base_c: str,
               compiler: str, workdir: pathlib.Path) -> pathlib.Path | None:
    """Lay out one permuter working directory."""
    d = workdir / f"{addr:08x}"
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)

    slug = repo_path.strip("/").replace("/", "__")
    raw = pathlib.Path(os.environ.get("AGENT_DECOMPILE_CORPUS_WORK_DIR") or ".") / "extract" / "raw" / slug
    fb = pathlib.Path(os.environ.get("AGENT_DECOMPILE_CORPUS_WORK_DIR") or ".") / "extract" / "funcbytes" / f"{slug}.jsonl"
    data = None
    if fb.exists():
        for line in open(fb):
            r = json.loads(line)
            if r["a"] == addr:
                data = bytes.fromhex(r["b"])
                break
    if data is None and raw.exists():
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "eu", pathlib.Path(os.environ.get("AGENT_DECOMPILE_EXACT_UNIVERSAL") or "exact_universal.py"))
        eu = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(eu)
        blob = raw.read_bytes()
        m, _ = eu.mapper_for(blob)
        if m:
            o = m(addr)
            if o is not None and o + size <= len(blob):
                data = blob[o:o + size]
    if data is None:
        return None
    (d / "target_bytes.bin").write_bytes(data)

    name = defined_name(base_c, name)

    r = subprocess.run(
        [sys.executable, str(MKOBJ), "--bytes", data.hex(), "--name", name,
         "--symbol-prefix", "_", "--format", "coff-i386",
         "-o", str(d / "target.o")], capture_output=True, text=True)
    if not (d / "target.o").exists():
        return None

    # Anything the body calls needs a prototype, or MSVC treats the extern data
    # declaration as the definition and rejects the call ("not a function").
    called = {f for f in CALL_RE.findall(base_c)
              if f not in C_KEYWORDS and f != name}
    ctx = CONTEXT_CACHE.get(repo_path, "")
    # The context declares every symbol as data. For anything the body actually
    # calls, that data declaration wins and the call is rejected, so those lines
    # are removed and replaced by real prototypes. The function being defined is
    # excluded entirely or its own declaration conflicts with the definition.
    drop = {name} | called
    kept = []
    for line in ctx.splitlines():
        t = line.strip()
        if re.match(r"typedef\s+[\w ]+\s+(?:code|unicode)\s*;", t):
            continue
        if t.startswith("extern ") and t.endswith(";"):
            sym = t[:-1].split()[-1].lstrip("*")
            if sym in drop:
                continue
        kept.append(line)
    protos = [f"undefined4 {fn}();" for fn in sorted(called)]
    (d / "base.c").write_text(
        "\n".join(kept) + "\n" + func_typedefs(base_c) + "\n".join(protos)
        + "\n\n" + fix_thiscall(base_c))
    (d / "function.txt").write_text(f"_{name}\n")
    cc = COMPILERS[compiler]
    (d / "compile.sh").write_text(
        "#!/bin/sh\n"
        "# permuter calls: compile.sh <input.c> -o <output.o>\n"
        "set -eu\n"
        'IN="$1"; shift\n'
        'OUT="out.o"\n'
        'while [ $# -gt 0 ]; do case "$1" in -o) OUT="$2"; shift 2;; *) shift;; esac; done\n'
        f'exec "{cc}" "$IN" "$OUT" "_{name}"\n')
    (d / "compile.sh").chmod(0o755)
    (d / "settings.toml").write_text('compiler_type = "base"\n')
    return d


def compiled_bytes(cfile: pathlib.Path, name: str, compiler: str) -> bytes | None:
    with tempfile.TemporaryDirectory() as td:
        obj = pathlib.Path(td) / "o.o"
        subprocess.run([str(COMPILERS[compiler]), str(cfile), str(obj), f"_{name}"],
                       capture_output=True, text=True)
        if not obj.exists():
            return None
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "ec", pathlib.Path(os.environ.get("AGENT_DECOMPILE_EXACT_CORPUS") or "exact_corpus.py"))
        ec = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ec)
        try:
            # prefix="" so `@F_xxxx@N` and `_F_xxxx@N` both look up as written
            # in function.txt (ghidra_verify / symbol_for), not forced `_name`.
            syms = ec.coff_functions(obj.read_bytes(), prefix="")
        except Exception:
            return None
        return syms.get(name) or syms.get(f"_{name}")


def evaluate(d: pathlib.Path, name: str, compiler: str, seconds: int) -> dict:
    """Compile base.c as-is, then let the permuter search. Report both."""
    target = (d / "target_bytes.bin").read_bytes()
    base_src = (d / "base.c").read_text()
    res = {"addr": d.name, "size": len(target),
           "base_real_c": is_real_c(base_src)}

    # function.txt holds the name build_case() actually resolved via
    # defined_name() — the identifier the compiler emits, which can differ
    # from the caller's `name` (e.g. Ghidra's `Unwind@<addr>` metadata name vs
    # the valid-C `Unwind_<addr>` the decompiled body defines).
    ft = (d / "function.txt").read_text().strip()
    name = ft[1:] if ft.startswith("_") else ft

    got = compiled_bytes(d / "base.c", name, compiler)
    res["base_compiles"] = got is not None
    res["base_byte_exact"] = bool(got and got[:len(target)] == target)

    if res["base_byte_exact"]:
        res["outcome"] = "ghidra_c_matched"
        res["real_c_and_byte_exact"] = res["base_real_c"]
        return res

    if not res["base_compiles"]:
        res["outcome"] = "base_c_does_not_compile"
        res["real_c_and_byte_exact"] = False
        return res

    t0 = time.time()
    p = subprocess.run(
        [sys.executable, str(PERMUTER), str(d), "--stop-on-zero", "--best-only",
         "-j", "2"], capture_output=True, text=True, timeout=seconds)
    res["permuter_seconds"] = round(time.time() - t0, 1)
    out = (p.stdout or "") + (p.stderr or "")
    res["permuter_found"] = "found match" in out.lower() or "score 0" in out.lower()

    best = sorted(d.glob("output-*/*.c")) or sorted(d.glob("output*/*.c"))
    if best:
        src = best[-1].read_text()
        got = compiled_bytes(best[-1], name, compiler)
        res["real_c"] = is_real_c(src)
        res["byte_exact"] = bool(got and got[:len(target)] == target)
        res["outcome"] = "permuter_matched" if res["byte_exact"] else "permuter_close"
        res["real_c_and_byte_exact"] = bool(res["real_c"] and res["byte_exact"])
    else:
        res["outcome"] = "permuter_no_output"
        res["real_c_and_byte_exact"] = False
    return res


BANDS = [(1, 8), (9, 16), (17, 32), (33, 64), (65, 128), (129, 10 ** 9)]


def sample(con, per_band: int, binaries: list[str]) -> list[dict]:
    """Stratified sample across size bands and binaries."""
    rows = []
    for repo in binaries:
        b = con.execute("SELECT id FROM binary WHERE repo_path=?", (repo,)).fetchone()
        if not b:
            continue
        for lo, hi in BANDS:
            for r in con.execute(
                """SELECT addr, size, name, canon_key FROM func
                    WHERE binary_id=? AND n_instr>0 AND size BETWEEN ? AND ?
                      AND is_thunk=0
                    ORDER BY addr LIMIT ?""", (b["id"], lo, hi, per_band)):
                rows.append({"repo_path": repo, "addr": r["addr"], "size": r["size"],
                             "name": r["name"], "band": f"{lo}-{hi if hi < 10**8 else '+'}"})
    return rows


def run_from_ghidra_bulk(args) -> int:
    """Permute already-compiling Ghidra C. Zero LLM. Does not rebuild context."""
    from . import genproject as gp

    program = args.from_ghidra_bulk
    con = store.connect(pathlib.Path(os.environ['AGENT_DECOMPILE_CORPUS_DB']))
    repo = args.repo if getattr(args, "repo", None) else program
    src_dir = GHIDRA_SRC / program
    files = sorted(p for p in src_dir.glob("*.c") if not p.name.startswith("_"))
    if args.limit:
        files = files[: args.limit]
    print(f"ghidra-bulk compiled inputs: {len(files)}  permuter={PERMUTER.exists()}",
          flush=True)
    if not files or not PERMUTER.exists():
        return 1

    brow = con.execute("SELECT id FROM binary WHERE repo_path=?", (repo,)).fetchone()
    if not brow:
        print(f"not in database: {repo}")
        return 1
    bid = int(brow["id"])
    slug = repo.strip("/").replace("/", "__")
    raw_path = pathlib.Path(os.environ.get("AGENT_DECOMPILE_CORPUS_WORK_DIR") or ".") / "extract" / "raw" / slug
    raw = raw_path.read_bytes()
    va2off = gp.pe_va_mapper(raw)

    meta = {}
    for r in con.execute(
            "SELECT addr, canon_key, size, calling_convention, stack_param_size, name"
            " FROM func WHERE binary_id=?", (bid,)):
        meta[int(r["addr"])] = dict(r)

    WORK.mkdir(parents=True, exist_ok=True)
    wd = WORK / f"{program}_bulk"
    results = []
    addr_re = re.compile(r"address:\s*0x([0-9a-fA-F]+)")
    for i, f in enumerate(files, 1):
        head = f.read_text(errors="replace")[:400]
        m = addr_re.search(head)
        if not m:
            continue
        addr = int(m.group(1), 16)
        info = meta.get(addr)
        if not info:
            results.append({"addr": addr, "outcome": "no_db_row",
                            "real_c_and_byte_exact": False})
            continue
        off = va2off(addr)
        if off is None or off + info["size"] > len(raw):
            results.append({**info, "outcome": "no_target_bytes",
                            "real_c_and_byte_exact": False})
            continue
        target = raw[off:off + info["size"]]
        info["ret_imm"] = gp.popped_bytes(target)
        info["addr"] = addr
        body = f.read_text(errors="replace")
        if body.startswith("/*"):
            end = body.find("*/\n")
            if end != -1:
                body = body[end + 3:]
        d = wd / f"{addr:08x}"
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)
        (d / "target_bytes.bin").write_bytes(target)
        (d / "base.c").write_text(body)
        sym_name, sym = gp.symbol_for(info)
        (d / "function.txt").write_text(sym + "\n")
        prefix = sym[:1] if sym[:1] in "@_" else "_"
        r = subprocess.run(
            [sys.executable, str(MKOBJ), "--bytes", target.hex(),
             "--name", sym_name, "--symbol-prefix", prefix,
             "--format", "coff-i386", "-o", str(d / "target.o")],
            capture_output=True, text=True)
        if not (d / "target.o").exists():
            results.append({**info, "outcome": "mkobj_failed",
                            "real_c_and_byte_exact": False})
            continue
        cc = COMPILERS[args.compiler]
        (d / "compile.sh").write_text(
            "#!/bin/sh\nset -eu\n"
            'IN="$1"; shift\nOUT="out.o"\n'
            'while [ $# -gt 0 ]; do case "$1" in -o) OUT="$2"; shift 2;; *) shift;; esac; done\n'
            f'exec "{cc}" "$IN" "$OUT" "{sym_name}"\n')
        (d / "compile.sh").chmod(0o755)
        (d / "settings.toml").write_text('compiler_type = "base"\n')
        try:
            res = evaluate(d, sym_name, args.compiler, args.seconds)
        except subprocess.TimeoutExpired:
            res = {"outcome": "permuter_timeout", "real_c_and_byte_exact": False}
        results.append({**info, **res})
        if i % 10 == 0:
            print(f"  {i}/{len(files)}", flush=True)

    pathlib.Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(args.out).write_text(json.dumps(results, indent=1, default=str))
    report(results)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-band", type=int, default=3)
    ap.add_argument("--binaries", nargs="*")
    ap.add_argument("--compiler", default="vc71", choices=sorted(COMPILERS))
    ap.add_argument("--seconds", type=int, default=120)
    ap.add_argument("--db", type=pathlib.Path, required=True)
    ap.add_argument("--out", type=pathlib.Path, required=True)
    ap.add_argument("--work-dir", type=pathlib.Path)
    ap.add_argument("--from-ghidra-bulk", metavar="PROGRAM",
                    help="tier-3: permute functions that ghidra_bulk already "
                         "compiled for PROGRAM. Uses ctxtypes/ghidra_bulk "
                         "headers, not a product-specific ctx.h.")
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args(argv)
    global WORK
    if args.work_dir:
        WORK = pathlib.Path(args.work_dir)

    if args.from_ghidra_bulk:
        raise SystemExit(run_from_ghidra_bulk(args))

    con = store.connect(args.db)
    bins = args.binaries or [
        r[0] for r in con.execute(
            "SELECT repo_path FROM binary WHERE arch='x86' AND bits=32 "
            "ORDER BY repo_path")]
    cases = sample(con, args.per_band, bins)
    print(f"sampled {len(cases)} functions across {len(bins)} binaries", flush=True)

    WORK.mkdir(parents=True, exist_ok=True)
    results = []
    cfuncs: dict[str, dict[str, str]] = {}
    for i, c in enumerate(cases, 1):
        if c["repo_path"] not in cfuncs:
            cfuncs[c["repo_path"]] = ghidra_c_for(c["repo_path"])
            raw_ctx = context_for(c["repo_path"])
            print("  repairing context (compile-and-drop)...", flush=True)
            CONTEXT_CACHE[c["repo_path"]] = repair_context(raw_ctx, args.compiler)
            print(f"  context ready: {len(CONTEXT_CACHE[c['repo_path']].splitlines())} lines",
                  flush=True)
            print(f"  [{c['repo_path']}] ghidra C functions: "
                  f"{len(cfuncs[c['repo_path']])}", flush=True)
        base = cfuncs[c["repo_path"]].get(c["name"])
        if not base:
            results.append({**c, "outcome": "no_ghidra_c",
                            "real_c_and_byte_exact": False})
            continue
        wd = WORK / c["repo_path"].strip("/").replace("/", "__")
        d = build_case(c["repo_path"], c["addr"], c["size"], c["name"], base,
                       args.compiler, wd)
        if d is None:
            results.append({**c, "outcome": "no_target_bytes",
                            "real_c_and_byte_exact": False})
            continue
        try:
            r = evaluate(d, c["name"], args.compiler, args.seconds)
        except subprocess.TimeoutExpired:
            r = {"outcome": "permuter_timeout", "real_c_and_byte_exact": False}
        results.append({**c, **r})
        if i % 10 == 0:
            print(f"  {i}/{len(cases)}", flush=True)

    pathlib.Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(args.out).write_text(json.dumps(results, indent=1))
    report(results)
    return 0


def report(results: list[dict]) -> None:
    from collections import Counter, defaultdict
    per = defaultdict(lambda: [0, 0])
    for r in results:
        per[r.get("band", "?")][0] += 1
        per[r.get("band", "?")][1] += bool(r.get("real_c_and_byte_exact"))
    print(f"\n{'band (bytes)':<16}{'sampled':>9}{'real C + byte-exact':>22}{'rate':>8}")
    for b, (n, ok) in sorted(per.items()):
        print(f"{b:<16}{n:>9}{ok:>22}{ok/max(n,1):>8.0%}")
    tot = len(results)
    ok = sum(1 for r in results if r.get("real_c_and_byte_exact"))
    print(f"{'TOTAL':<16}{tot:>9}{ok:>22}{ok/max(tot,1):>8.0%}")
    print("\noutcomes:", dict(Counter(r.get("outcome", "?") for r in results)))


if __name__ == "__main__":
    main()
