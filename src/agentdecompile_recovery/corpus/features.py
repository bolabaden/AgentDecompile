"""Per-function feature extraction.

Two tiers:

* **tier 1 (cheap)** — identity, size, thunk state, namespace, signature, and the
  call graph.
* **tier 2 (structural)** — basic-block topology, normalized mnemonic profile,
  referenced strings / constants / globals. Addresses and registers are
  normalized away.

Nothing here uses the decompiler. `tier1` / `tier2` need a live Ghidra program.
`mnemonic_class` is usable without Ghidra.
"""

from __future__ import annotations

from collections import Counter

# Mnemonics collapsed into equivalence classes so that x86/ARM/PPC builds of the
# same source produce comparable profiles, and so that branch inversion and
# register allocation do not change the vector.
_CLASSES = {
    "mov": "MOV", "movl": "MOV", "movq": "MOV", "movw": "MOV", "movb": "MOV",
    "movzx": "MOV", "movsx": "MOV", "movsxd": "MOV", "lea": "LEA",
    "ldr": "MOV", "ldrb": "MOV", "ldrh": "MOV", "ldp": "MOV", "ldur": "MOV",
    "str": "STORE", "strb": "STORE", "strh": "STORE", "stp": "STORE", "stur": "STORE",
    "push": "PUSH", "pop": "POP",
    "add": "ARITH", "sub": "ARITH", "adds": "ARITH", "subs": "ARITH",
    "imul": "MUL", "mul": "MUL", "idiv": "DIV", "div": "DIV", "sdiv": "DIV", "udiv": "DIV",
    "and": "LOGIC", "or": "LOGIC", "xor": "LOGIC", "not": "LOGIC",
    "orr": "LOGIC", "eor": "LOGIC", "bic": "LOGIC",
    "shl": "SHIFT", "shr": "SHIFT", "sar": "SHIFT", "sal": "SHIFT",
    "lsl": "SHIFT", "lsr": "SHIFT", "asr": "SHIFT", "ror": "SHIFT",
    "cmp": "CMP", "test": "CMP", "tst": "CMP", "cmn": "CMP", "ucomiss": "FCMP",
    "call": "CALL", "bl": "CALL", "blr": "CALL", "blx": "CALL",
    "ret": "RET", "retn": "RET", "leave": "LEAVE",
    "jmp": "JMP", "b": "JMP", "br": "JMP",
    "nop": "NOP",
    "fld": "FLOAT", "fstp": "FLOAT", "fadd": "FLOAT", "fmul": "FLOAT",
    "fsub": "FLOAT", "fdiv": "FLOAT", "fcom": "FCMP", "fcomp": "FCMP",
    "movss": "FLOAT", "movsd": "FLOAT", "addss": "FLOAT", "mulss": "FLOAT",
    "cvtsi2ss": "FCVT", "cvttss2si": "FCVT", "cvtss2sd": "FCVT",
    "fcvt": "FCVT", "scvtf": "FCVT", "fcvtzs": "FCVT",
}


def mnemonic_class(m: str) -> str:
    m = m.lower()
    if m in _CLASSES:
        return _CLASSES[m]
    if m.startswith(("j", "b.")) and m not in ("jmp",):
        return "CBRANCH"
    if m.startswith(("cb", "tb")):
        return "CBRANCH"
    if m.startswith("set") or m.startswith("cmov") or m.startswith("csel") or m.startswith("cset"):
        return "COND"
    if m.startswith("f"):
        return "FLOAT"
    if m.startswith("rep"):
        return "STRINGOP"
    return "OTHER"


def mnemonic_profile(counts: dict[str, int]) -> dict[str, float]:
    total = max(sum(counts.values()), 1)
    return {key: round(value / total, 5) for key, value in counts.items()}


def _demangler():
    from ghidra.app.util.demangler.gnu import GnuDemangler

    return GnuDemangler()


def tier1(program) -> list[dict]:
    dem = _demangler()
    fm = program.getFunctionManager()
    rows = []
    for f in fm.getFunctions(True):
        if f.isExternal():
            continue
        ep = f.getEntryPoint()
        body = f.getBody()
        sym = f.getSymbol()
        ns = f.getParentNamespace()
        thunked = f.getThunkedFunction(True)
        sig = f.getSignature()
        raw = str(f.getName())
        dm_name = dm_ns = None
        dm_params = None
        if raw.startswith("_Z"):
            try:
                obj = dem.demangle(raw)
                if obj is not None:
                    dm_name = str(obj.getName())
                    dns = obj.getNamespace()
                    dm_ns = None if dns is None else str(dns.getNamespaceString())
                    try:
                        dm_params = [str(p.getType()) for p in obj.getParameters()]
                    except Exception:
                        dm_params = None
            except Exception:
                pass
        rows.append(
            {
                "addr": int(ep.getOffset()),
                "name": raw,
                "dm_name": dm_name,
                "dm_namespace": dm_ns,
                "dm_params": dm_params,
                "namespace": ""
                if ns is None or ns.isGlobal()
                else str(ns.getName(True)),
                "source": str(sym.getSource()) if sym is not None else "NONE",
                "size": int(body.getNumAddresses()),
                "ranges": int(body.getNumAddressRanges()),
                "is_thunk": bool(f.isThunk()),
                "thunked_to": int(thunked.getEntryPoint().getOffset())
                if thunked is not None
                else None,
                "calling_convention": str(f.getCallingConventionName()),
                "return_type": str(f.getReturnType().getName()),
                "param_count": int(f.getParameterCount()),
                "param_types": [str(p.getDataType().getName()) for p in f.getParameters()],
                "stack_frame_size": int(f.getStackFrame().getFrameSize()),
                "stack_param_size": int(f.getStackFrame().getParameterSize()),
                "stack_local_size": int(f.getStackFrame().getLocalSize()),
                "varargs": bool(f.hasVarArgs()),
                "no_return": bool(f.hasNoReturn()),
                "plate": str(f.getComment()) if f.getComment() else None,
                "signature": str(sig.getPrototypeString(True)) if sig is not None else None,
            }
        )
    return rows


def tier2(program, monitor, addrs=None) -> dict[int, dict]:
    """Structural + reference features, keyed by function entry offset."""
    from ghidra.program.model.block import BasicBlockModel

    fm = program.getFunctionManager()
    listing = program.getListing()
    bbm = BasicBlockModel(program)
    data_at = program.getListing().getDataAt

    out: dict[int, dict] = {}
    want = set(addrs) if addrs is not None else None

    for f in fm.getFunctions(True):
        if f.isExternal():
            continue
        ep = f.getEntryPoint()
        off = int(ep.getOffset())
        if want is not None and off not in want:
            continue
        body = f.getBody()

        mn: Counter[str] = Counter()
        n_instr = 0
        callees: list[int] = []
        strings: list[str] = []
        consts: Counter[int] = Counter()
        data_refs = 0
        ext_calls: list[str] = []
        indirect_calls = 0

        for instr in listing.getInstructions(body, True):
            n_instr += 1
            mn[mnemonic_class(str(instr.getMnemonicString()))] += 1
            for i in range(instr.getNumOperands()):
                for obj in instr.getOpObjects(i):
                    try:
                        v = int(obj.getValue())
                    except Exception:
                        continue
                    if 0x100 <= abs(v) < 0x7FFFFFFF:
                        consts[v] += 1
            for ref in instr.getReferencesFrom():
                rt = ref.getReferenceType()
                to = ref.getToAddress()
                if rt.isCall():
                    tf = fm.getFunctionAt(to)
                    if tf is not None and tf.isExternal():
                        ext_calls.append(str(tf.getName()))
                    elif tf is not None:
                        callees.append(int(to.getOffset()))
                    else:
                        indirect_calls += 1
                elif rt.isData():
                    data_refs += 1
                    d = data_at(to)
                    if d is not None and d.hasStringValue():
                        try:
                            s = str(d.getValue())
                            if 3 <= len(s) <= 200:
                                strings.append(s)
                        except Exception:
                            pass

        nblocks = 0
        nedges = 0
        back_edges = 0
        try:
            it = bbm.getCodeBlocksContaining(body, monitor)
            while it.hasNext():
                blk = it.next()
                nblocks += 1
                bs = int(blk.getFirstStartAddress().getOffset())
                dit = blk.getDestinations(monitor)
                while dit.hasNext():
                    d = dit.next()
                    dst = d.getDestinationAddress()
                    if body.contains(dst):
                        nedges += 1
                        if int(dst.getOffset()) <= bs:
                            back_edges += 1
        except Exception:
            pass

        total = max(n_instr, 1)
        profile = {k: round(v / total, 5) for k, v in mn.items()}
        out[off] = {
            "n_instr": n_instr,
            "mnemonic_counts": dict(mn),
            "mnemonic_profile": profile,
            "n_blocks": nblocks,
            "n_edges": nedges,
            "back_edges": back_edges,
            "cyclomatic": nedges - nblocks + 2 if nblocks else 0,
            "callees": sorted(set(callees)),
            "n_callees": len(set(callees)),
            "indirect_calls": indirect_calls,
            "ext_calls": sorted(set(ext_calls)),
            "strings": sorted(set(strings)),
            "consts": sorted(consts),
            "data_refs": data_refs,
        }
    return out


def merge_tiers(t1: list[dict], t2: dict[int, dict]) -> list[dict]:
    """Join cheap identity rows with structural features for a snapshot."""
    rows = []
    for row in t1:
        merged = dict(row)
        extra = t2.get(int(row["addr"])) or {}
        merged.update(extra)
        if extra.get("mnemonic_counts") and "mnem" not in merged:
            merged["mnem"] = extra["mnemonic_counts"]
        merged["id"] = f"0x{int(row['addr']):x}"
        rows.append(merged)
    return rows
