"""Generate a recovery project tree from the logical-function work queue.

Ranks by logical function: recover once, and sibling builds become verify
work. Prompts carry the resolved name, signature, and STABS source file when
known. All output lands under the caller-supplied ``out_dir``.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sqlite3
import struct
import subprocess
import sys

from . import prompt_evidence
from .ghidra_sanitize import c_name

DECOMP_HINT_LIMIT = 12000
FORMAT = {32: "coff-i386", 64: "coff-x86-64"}


def entry_hex_map(fns: list[dict]) -> dict[str, int]:
    """Map both database key widths to the same exact function address."""
    out = {}
    for fn in fns:
        addr = int(fn["addr"])
        out[f"{addr:08x}"] = addr
        out[f"{addr:016x}"] = addr
    return out


def pe_va_mapper(raw: bytes):
    if raw[:2] != b"MZ":
        return None
    pe = struct.unpack_from("<I", raw, 0x3C)[0]
    nsec = struct.unpack_from("<H", raw, pe + 6)[0]
    opt = struct.unpack_from("<H", raw, pe + 20)[0]
    base = struct.unpack_from("<I", raw, pe + 24 + 28)[0]
    secs = []
    for i in range(nsec):
        o = pe + 24 + opt + i * 40
        vsize, vaddr, rsize, roff = struct.unpack_from("<IIII", raw, o + 8)
        secs.append((vaddr, max(vsize, rsize), roff))

    def va2off(va: int):
        r = va - base
        for vaddr, size, roff in secs:
            if vaddr <= r < vaddr + size:
                return roff + (r - vaddr)
        return None

    return va2off


def load_queue(
    repo_path: str,
    limit: int | None,
    max_size: int,
    min_size: int,
    *,
    queue_path: pathlib.Path,
    slug: str | None = None,
) -> list[dict]:
    """Pull this program's instances out of the logical queue, in queue order."""
    picked = []
    seen: set[int] = set()
    with open(queue_path) as fh:
        for line in fh:
            g = json.loads(line)
            instances = g.get("instances") or []
            if not instances and g.get("members"):
                instances = [
                    {
                        "repo_path": m.get("repo_path") or repo_path,
                        "slug": m.get("slug"),
                        "address": f"{int(m['addr']):08x}" if not isinstance(m.get("addr"), str) else m["addr"],
                        "addr": m.get("addr"),
                        "size": m.get("size"),
                        "calling_convention": m.get("calling_convention"),
                        "confidence": m.get("confidence"),
                    }
                    for m in g["members"]
                ]
            for inst in instances:
                inst_repo = inst.get("repo_path")
                inst_slug = inst.get("slug")
                if inst_repo not in (None, repo_path) and inst_slug not in (None, slug):
                    continue
                if inst_repo is not None and inst_repo != repo_path:
                    if slug is None or inst_slug != slug:
                        continue
                size = inst.get("size") or 0
                if not (min_size <= size <= max_size):
                    continue
                raw_addr = inst.get("addr")
                addr = int(raw_addr if raw_addr is not None else inst["address"], 16)
                if addr in seen:
                    continue
                seen.add(addr)
                picked.append(
                    {
                        "logical_id": g.get("logical_id"),
                        "canonical_name": g.get("canonical_name") or g.get("canon_key"),
                        "class": g.get("class") or g.get("canon_class"),
                        "signature": g.get("signature"),
                        "source_file": g.get("source_file"),
                        "object_file": g.get("object_file"),
                        "n_instances": g.get("n_instances") or g.get("n_members") or 1,
                        "addr": addr,
                        "size": size,
                        "calling_convention": inst.get("calling_convention"),
                        "confidence": inst.get("confidence"),
                    }
                )
                break
    picked.sort(key=lambda f: (f["size"], f["addr"]))
    return picked if limit is None else picked[:limit]


def popped_bytes(body: bytes) -> int | None:
    """Stack bytes the callee pops, read off the function's own last instruction."""
    b = body.rstrip(b"\xcc")
    if len(b) >= 3 and b[-3] == 0xC2:
        return int.from_bytes(b[-2:], "little")
    if b and b[-1] == 0xC3:
        return 0
    return None


def stack_bytes(fn: dict) -> int:
    """Callee-popped stack bytes: the machine code first, Ghidra as fallback."""
    ret_n = fn.get("ret_imm")
    if ret_n is not None:
        return int(ret_n)
    sps = int(fn.get("stack_param_size") or 0)
    return ((sps + 3) // 4) * 4


def fastcall_decoration(fn: dict) -> int:
    """Bytes MSVC encodes into a ``__fastcall`` symbol's ``@N`` suffix."""
    return 8 + stack_bytes(fn)


def symbol_for(fn: dict) -> tuple[str, str]:
    """(prompt dir name, emitted symbol)."""
    base = f"F_{fn['addr']:08x}"
    conv = (fn.get("calling_convention") or "").lower()

    if conv == "__thiscall":
        return base, f"@{base}@{fastcall_decoration(fn)}"
    if conv == "__fastcall":
        return base, f"@{base}@{fastcall_decoration(fn)}"
    if (fn.get("derived_class") or "") == "ecx":
        n = fn.get("derived_n")
        if n is not None:
            return base, f"@{base}@{int(n)}"
    if conv == "__stdcall":
        return base, f"_{base}@{stack_bytes(fn)}"
    return base, f"_{base}"


def build_target(
    fn: dict,
    raw_path: pathlib.Path,
    off: int,
    outdir: pathlib.Path,
    bits: int,
    *,
    mkobj: pathlib.Path | None = None,
) -> pathlib.Path | None:
    name, sym = symbol_for(fn)
    obj = outdir / "target" / f"{name}.o"
    obj.parent.mkdir(parents=True, exist_ok=True)
    prefix, bare = sym[0], sym[1:]
    tmp = obj.with_suffix(obj.suffix + ".tmp")
    tmp.unlink(missing_ok=True)
    script = mkobj or pathlib.Path(os.environ.get("AGENT_DECOMPILE_MKOBJ") or "mkobj.py")
    r = subprocess.run(
        [sys.executable, str(script),
         "--binary", str(raw_path), "--offset", str(off), "--size", str(fn["size"]),
         "--name", bare, "--symbol-prefix", prefix,
         "--format", FORMAT.get(bits, "coff-i386"), "-o", str(tmp)],
        capture_output=True, text=True,
    )
    if r.returncode != 0 or not tmp.exists():
        tmp.unlink(missing_ok=True)
        if r.stderr.strip():
            print(f"mkobj failed for {name}: {r.stderr.strip()}", file=sys.stderr)
        return None
    tmp.replace(obj)
    return obj


def disasm_text(obj: pathlib.Path, bits: int = 32) -> str:
    """Disassemble the target object, naming the format explicitly."""
    fmt = FORMAT.get(bits, "coff-i386")
    last_err = ""
    for args in (["objdump", "-b", fmt, "-d", str(obj)],
                 ["objdump", "-d", str(obj)]):
        p = subprocess.run(args, capture_output=True, text=True)
        if p.stdout.strip():
            return p.stdout
        last_err = p.stderr.strip()
    raise RuntimeError(
        f"objdump produced no disassembly for {obj}: {last_err[:200]}")


def annotate_calls(asm: str, fn: dict, raw: bytes, va2off,
                   names: dict) -> tuple[str, list[int]]:
    """Name every ``call``/``jmp rel32`` target inline in the disassembly."""
    off = va2off(fn["addr"])
    if off is None:
        return asm, []
    body = raw[off:off + fn["size"]]
    out: list[str] = []
    targets: list[int] = []
    for line in asm.splitlines():
        m = re.match(r"^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2} )+)\s*(call|jmp)\s", line)
        if not m:
            out.append(line)
            continue
        ins_off = int(m.group(1), 16)
        enc = bytes.fromhex(m.group(2).replace(" ", ""))
        if not enc or enc[0] not in (0xE8, 0xE9) or len(enc) < 5 or ins_off + 5 > len(body):
            out.append(line)
            continue
        disp = int.from_bytes(body[ins_off + 1:ins_off + 5], "little", signed=True)
        target = (fn["addr"] + ins_off + 5 + disp) & 0xFFFFFFFF
        if target not in targets:
            targets.append(target)
        nm = names.get(target)
        out.append(f"{line}   ; -> {nm} (0x{target:08x})" if nm
                   else f"{line}   ; -> 0x{target:08x}")
    return "\n".join(out), targets


def _evidence_lines(evidence: dict) -> list[str]:
    """Render only evidence actually present; never invent project context."""
    function = evidence.get("function") or {}
    pyghidra = evidence.get("pyghidra") or {}
    relationships = evidence.get("relationships") or {}
    lines = []
    metrics = []
    for label, key in (("instructions", "n_instr"), ("basic blocks", "n_blocks"),
                       ("CFG edges", "n_edges"), ("cyclomatic complexity", "cyclomatic")):
        if function.get(key) is not None:
            metrics.append(f"{label}: {function[key]}")
    if metrics:
        lines.append("- Control-flow measurements: " + ", ".join(metrics))
    for label, key in (("Referenced strings", "strings"), ("Constants", "consts"),
                       ("External calls", "ext_calls"), ("Data references", "data_refs")):
        values = function.get(key) or []
        if values:
            lines.append(f"- {label}: " + ", ".join(f"`{v}`" for v in values[:12]))
    for direction in ("callers", "callees"):
        rows = relationships.get(direction) or []
        if rows:
            rendered = ", ".join(
                f"`{row.get('name') or row['address']}` ({row['address']})"
                for row in rows[:12]
            )
            lines.append(f"- Direct {direction}: {rendered}")
    if pyghidra.get("status") == "complete":
        lines.append(
            "- Live-analysis cache: indexed PyGhidra export at this exact program/address "
            f"({pyghidra.get('n_instructions', 'unknown')} instructions, "
            f"{pyghidra.get('n_refs', 'unknown')} references)"
        )
    agent = evidence.get("agentdecompile") or {}
    if agent.get("status") == "complete":
        live_fn = agent.get("function") or {}
        if live_fn.get("signature"):
            lines.append(f"- AgentDecompile `get-functions:info` signature: `{live_fn['signature']}`")
        live_calls = agent.get("calls") or {}
        lines.append(
            "- AgentDecompile call relationships: "
            f"{live_calls.get('callerCount', 0)} callers and "
            f"{live_calls.get('calleeCount', 0)} callees"
        )
        for direction in ("callers", "callees"):
            rows = live_calls.get(direction) or []
            if rows:
                rendered = ", ".join(
                    f"`{row.get('name') or row.get('address')}` ({row.get('address', 'unknown')})"
                    for row in rows[:12]
                )
                lines.append(f"- AgentDecompile {direction}: {rendered}")
        live_refs = agent.get("references") or {}
        lines.append(
            "- AgentDecompile `get-references:both` rows returned: "
            f"{live_refs.get('incomingRowsReturned', len(live_refs.get('to') or []))} incoming and "
            f"{live_refs.get('outgoingRowsReturned', len(live_refs.get('from') or []))} outgoing "
            "(bounded evidence rows, not claimed as complete totals)"
        )
        lines.append(
            f"- AgentDecompile provenance: `{agent.get('collection', 'unknown')}` collection via "
            "`get-functions` and `get-references`; compact exact outputs are in `evidence.json`"
        )
    elif agent.get("status"):
        lines.append(
            f"- AgentDecompile live query status: `{agent['status']}`; rely on the indexed PyGhidra facts above for this prompt"
        )
    return lines


def write_prompt(fn: dict, outdir: pathlib.Path, obj: pathlib.Path, asm: str,
                 decomp: str | None, evidence: dict | None = None,
                 types_section: str = "") -> None:
    name, sym = symbol_for(fn)
    conv_hint = ""
    conv = (fn.get("calling_convention") or "").lower()
    ecx = (conv == "__thiscall" or (fn.get("derived_class") or "") == "ecx")
    if ecx:
        conv_hint = (
            f"\n\n## Target ABI\n\n`this` arrives in ECX. For this C-mode compiler harness, declare `{name}`\n"
            f"as `__fastcall` with `void *this_ecx` first and a dummy EDX parameter\n"
            f"second, followed by the evidenced stack parameters. The required emitted\n"
            f"symbol is `{sym}`."
        )
    elif conv == "__fastcall":
        conv_hint = (
            f"\n\n## Target ABI\n\nThis is a genuine `__fastcall` function. Its first parameter arrives in ECX\n"
            f"and its second parameter arrives in EDX; both are real parameters. Declare it\n"
            f"`__fastcall` as written in the recovered signature. MSVC will emit `{sym}`.\n"
            f"Do not add the dummy EDX parameter used for a C proxy of `__thiscall`."
        )
    elif sym.startswith("_") and "@" in sym:
        n = sym.rsplit("@", 1)[1]
        epilogue = (f"ends in `ret {n}`" if int(n) else
                    "ends in a plain `ret` (there are no stack arguments to pop)")
        conv_hint = (
            f"\n\n## Target ABI\n\nThis is a `__stdcall` function: the callee removes its own arguments,\n"
            f"and this target {epilogue}. Declare it\n"
            f"`__stdcall` and MSVC will both emit that epilogue and name the symbol\n"
            f"`{sym}`, which is what the target object expects:\n\n"
            f"```c\nvoid __stdcall {name}(/* {n} bytes of stack arguments */);\n```\n\n"
            f"Do not use `__cdecl` here -- it emits `_{name}` without the `@{n}`\n"
            f"suffix and therefore cannot match the target symbol."
        )
    pdir = outdir / "prompts" / name
    pdir.mkdir(parents=True, exist_ok=True)

    known = [f"- Canonical name: `{fn.get('canonical_name') or name}`"]
    if fn.get("class"):
        known.append(f"- Class: `{fn['class']}`")
    if fn.get("signature"):
        known.append(f"- Signature (from an independently-symbolised build): "
                     f"`{fn['signature']}`")
    if fn.get("source_file"):
        known.append(f"- Original source file: `{fn['source_file']}`")
    if fn.get("object_file"):
        known.append(f"- Original object file: `{fn['object_file']}`")
    if fn.get("calling_convention"):
        known.append(f"- Calling convention: `{fn['calling_convention']}`")
    known.append(f"- Cross-build identity members: **{fn.get('n_instances', 1)}** "
                 f"(binding confidence {fn.get('confidence')})")
    tool_evidence = _evidence_lines(evidence) if evidence else []

    body = f"""# Recover `{fn.get('canonical_name') or name}`

Recover readable, high-level C/C++ for this exact function and compile it with
the configured target compiler until the generated code is **byte-identical**.
Inline assembly, naked functions, emitted opcodes, `.byte`, copied machine-code
arrays, and assembly wrappers are forbidden: they do not recover source. A body
built from `__asm` or `_emit` is rejected automatically even if it matches
byte-for-byte, and this function is then handed back out for another attempt --
so emitting opcodes cannot finish the task, it only wastes the attempt.

**Calls do not need exact displacements.** Where the disassembly shows
`call`/`jmp` with a `; -> name` annotation, write an ordinary C call to that
name and declare it `extern` with the signature the operands imply. The four
displacement bytes read `00 00 00 00` on purpose: they are a relocation the
linker fills in, and the comparison ignores them. Never try to reproduce a
call's displacement by hand.

Compile the implementation under the bare C identifier `{name}`. The compiler
must emit `{sym}`; do not write the decorated symbol yourself.{conv_hint}

## Exact target identity

{chr(10).join(known)}

## Evidence collected for these exact bytes

{chr(10).join(tool_evidence) if tool_evidence else '- No auxiliary analysis facts were available; use the target disassembly.'}

These are observations from this target's database row, exact-address indexed
PyGhidra export, cross-build identity bindings, and (when marked complete) an
AgentDecompile CLI sequence. They are evidence, not recovered source. Full
compact outputs and provider status are in `evidence.json`. Treat absent fields
as unknown. Do not infer a platform, project, subsystem, or API from generic
examples. The identifier to compile is `{name}`.
{types_section}
## Target disassembly

```
{asm.strip()}
```
"""
    if decomp:
        body += f"""
## Ghidra's decompilation (a starting point, not the answer)

This is Ghidra's automatic output for these exact bytes. It is usually right
about the structure and often wrong about the details, and it does **not**
compile to the target as written. Two things to fix before using it:

- It contains C++ spellings such as `A::B(...)` and `A::~A(...)`. This project
  compiles as C, so rewrite those as plain identifiers.
- Types Ghidra invented (`undefined4`, `code *`, bare offsets like
  `*(int *)(this + 0x135c)`) need real declarations or equivalent casts.

Match the disassembly above, not this listing.

```c
{decomp.strip()}
```
"""
    (pdir / "prompt.md").write_text(body)
    if evidence:
        (pdir / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True))
    settings = (
        f"asm: {json.dumps(chr(10) + asm)}\n"
        f"functionName: {json.dumps(sym)}\n"
        f"targetObjectPath: {json.dumps(str(obj.resolve()))}\n"
    )
    (pdir / "settings.yaml").write_text(settings)


def collect_prompt_evidence_batch(con: sqlite3.Connection, *, binary_id: int,
                                  repo_path: str,
                                  fns: list[dict]) -> dict[int, dict]:
    """Bind one live AgentDecompile batch back to its exact prompt addresses."""
    agent_by_addr = prompt_evidence.collect_agentdecompile_batch(
        repo_path, [f["addr"] for f in fns],
    )
    if any(packet.get("status") == "busy" for packet in agent_by_addr.values()):
        raise RuntimeError(
            "AgentDecompile evidence collector is busy; defer this prompt batch "
            "instead of finalizing prompts without live evidence"
        )
    return {
        fn["addr"]: prompt_evidence.collect(
            con, binary_id=binary_id, repo_path=repo_path, fn=fn,
            agent_context=agent_by_addr.get(fn["addr"]),
        )
        for fn in fns
    }


def generate_project(
    *,
    con: sqlite3.Connection,
    repo_path: str,
    out_dir: pathlib.Path,
    queue_path: pathlib.Path,
    raw_path: pathlib.Path,
    limit: int = 25,
    max_size: int = 256,
    min_size: int = 4,
    base_project: pathlib.Path | None = None,
    mkobj: pathlib.Path | None = None,
    coverage_ledger: pathlib.Path | None = None,
    skip_manifests: list[pathlib.Path] | None = None,
    skip_recovered: bool = False,
    leftover_only: bool = True,
) -> dict:
    """Write a prompt project under *out_dir* from the logical queue."""
    outdir = pathlib.Path(out_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    brow = con.execute(
        "SELECT id, bits, slug FROM binary WHERE repo_path=?", (repo_path,)
    ).fetchone()
    if brow is None:
        raise ValueError(f"not in database: {repo_path}")
    raw = pathlib.Path(raw_path).read_bytes()
    va2off = pe_va_mapper(raw)
    if va2off is None:
        raise ValueError("not a PE image (only x86/x64 PE is in scope)")

    func_names: dict[int, str] = {}
    for r in con.execute(
            "SELECT addr, COALESCE(canon_key, name) AS nm FROM func"
            " WHERE binary_id=? AND nm IS NOT NULL", (brow["id"],)):
        nm = str(r["nm"])
        if nm.startswith(("FUN_", "SUB_", "Unwind@", "FrameHandler", "Catch@")):
            continue
        func_names[int(r["addr"])] = c_name(nm)

    if base_project is not None:
        base = pathlib.Path(base_project)
        yaml_name = "atlas.yaml" if (base / "atlas.yaml").exists() else "mizuchi.yaml"
        if (base / yaml_name).exists():
            (outdir / yaml_name).write_text(
                (base / yaml_name).read_text().replace(str(base), str(outdir))
            )
        if (base / "project.map").exists():
            (outdir / "project.map").write_text((base / "project.map").read_text())
        if (base / "ctx.h").exists():
            (outdir / "ctx.h").write_text((base / "ctx.h").read_text())
        else:
            (outdir / "ctx.h").write_text("")
    else:
        (outdir / "ctx.h").write_text("")
        (outdir / "project.map").write_text("")
    (outdir / "asm").mkdir(exist_ok=True)

    all_fns = load_queue(
        repo_path, None, max_size, min_size,
        queue_path=pathlib.Path(queue_path), slug=brow["slug"],
    )
    skip: set[int] = set()
    skip_names: set[str] = set()
    for md in skip_manifests or []:
        mp = pathlib.Path(md) / "manifest.json"
        if not mp.exists():
            continue
        for f in json.loads(mp.read_text()).get("functions") or []:
            try:
                skip.add(int(f["address"], 16))
            except (KeyError, ValueError, TypeError):
                pass
            nm = f.get("canonical_name") or f.get("name")
            if nm:
                skip_names.add(str(nm))
    if skip_recovered:
        try:
            for r in con.execute(
                    "SELECT addr, name FROM recovered_function WHERE binary_id=?",
                    (brow["id"],)):
                if r["addr"] is not None:
                    skip.add(int(r["addr"]))
                if r["name"]:
                    skip_names.add(str(r["name"]))
        except sqlite3.Error:
            pass
    if coverage_ledger is not None and pathlib.Path(coverage_ledger).is_file():
        for line in pathlib.Path(coverage_ledger).read_text(errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            fn = row.get("function")
            if fn and row.get("byteExact"):
                skip_names.add(str(fn))

    real_c_lids: set[int] = set()
    tried_lids: set[int] = set()
    if leftover_only:
        from .leftover import leftover_store_sets

        real_c_lids, tried_lids = leftover_store_sets(con)

    fns = []
    taken_names: set[str] = set()
    for f in all_fns:
        nm = f.get("canonical_name") or ""
        if f["addr"] in skip or (nm and nm in skip_names):
            continue
        if leftover_only:
            from .leftover import keep_leftover_queue_row

            if not keep_leftover_queue_row(f, real_c_lids, tried_lids):
                continue
        if nm:
            if nm in taken_names:
                continue
            taken_names.add(nm)
        fns.append(f)
        if len(fns) >= limit:
            break
    if leftover_only and not fns:
        from .leftover import explain_empty

        (outdir / "manifest.json").write_text(json.dumps(
            {"program": repo_path, "generator": "agentdecompile_recovery.corpus.genproject",
             "selection": "leftover",
             "functions": [],
             "reason": explain_empty()}, indent=1))
        return {"prompts": 0, "out_dir": str(outdir), "functions": [], "reason": explain_empty()}
    if fns:
        qs = ",".join("?" * len(fns))
        sizes = {
            int(r["addr"]): r["stack_param_size"]
            for r in con.execute(
                f"SELECT addr, stack_param_size FROM func"
                f" WHERE binary_id=? AND addr IN ({qs})",
                (brow["id"], *[f["addr"] for f in fns]))
        }
        for f in fns:
            f["stack_param_size"] = sizes.get(f["addr"], 0)

    evidence_by_addr = collect_prompt_evidence_batch(
        con, binary_id=int(brow["id"]), repo_path=repo_path, fns=fns,
    ) if fns else {}

    made = 0
    manifest = []
    for fn in fns:
        off = va2off(fn["addr"])
        if off is None or off + fn["size"] > len(raw):
            continue
        fn["ret_imm"] = popped_bytes(raw[off:off + fn["size"]])
        obj = build_target(fn, pathlib.Path(raw_path), off, outdir, brow["bits"], mkobj=mkobj)
        if obj is None:
            continue
        try:
            asm = disasm_text(obj, brow["bits"])
        except RuntimeError:
            asm = ""
        asm, _callees = annotate_calls(asm, fn, raw, va2off, func_names)
        name, _ = symbol_for(fn)
        (outdir / "asm" / f"{name}.txt").write_text(asm)
        write_prompt(
            fn, outdir, obj, asm, None,
            evidence_by_addr.get(fn["addr"]),
        )
        manifest.append({
            "prompt": name,
            "logical_id": fn["logical_id"],
            "canonical_name": fn["canonical_name"],
            "address": f"{fn['addr']:08x}",
            "size": fn["size"],
            "covers_builds": fn["n_instances"],
            "source_file": fn.get("source_file"),
        })
        made += 1

    (outdir / "manifest.json").write_text(json.dumps(
        {"program": repo_path, "generator": "agentdecompile_recovery.corpus.genproject",
         "selection": "logical-function queue",
         "functions": manifest}, indent=1))
    return {"prompts": made, "out_dir": str(outdir), "functions": manifest}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("program")
    ap.add_argument("--db", type=pathlib.Path, required=True)
    ap.add_argument("--out", type=pathlib.Path, required=True)
    ap.add_argument("--queue", type=pathlib.Path, required=True)
    ap.add_argument("--raw", type=pathlib.Path, required=True)
    ap.add_argument("--limit", type=int, default=25)
    ap.add_argument("--max-size", type=int, default=256)
    ap.add_argument("--min-size", type=int, default=4)
    ap.add_argument("--base-project", type=pathlib.Path)
    ap.add_argument("--mkobj", type=pathlib.Path)
    ap.add_argument("--coverage-ledger", type=pathlib.Path)
    ap.add_argument("--skip-manifests", nargs="*", action="extend", default=[],
                    type=pathlib.Path)
    ap.add_argument("--skip-recovered", action="store_true")
    ap.add_argument("--leftover-only", action="store_true", default=True)
    ap.add_argument("--all-queue", dest="leftover_only", action="store_false")
    args = ap.parse_args(argv)
    from .store import connect
    con = connect(args.db)
    generate_project(
        con=con,
        repo_path=args.program,
        out_dir=args.out,
        queue_path=args.queue,
        raw_path=args.raw,
        limit=args.limit,
        max_size=args.max_size,
        min_size=args.min_size,
        base_project=args.base_project,
        mkobj=args.mkobj,
        coverage_ledger=args.coverage_ledger,
        skip_manifests=args.skip_manifests,
        skip_recovered=args.skip_recovered,
        leftover_only=args.leftover_only,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
