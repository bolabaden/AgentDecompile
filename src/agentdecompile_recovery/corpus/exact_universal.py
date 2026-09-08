"""Byte-exact, verified, compilable reconstruction for every architecture.

``exact_corpus`` covers x86 PE via MSVC ``_emit``. This covers ELF and Mach-O
(i386/x86_64/ARM/AArch64) by emitting GNU ``.byte`` directives. Store path,
raw directory, and output directory are required. There is no product-binary
default.
"""

from __future__ import annotations

import concurrent.futures as cf
import json
import pathlib
import struct
import subprocess
import tempfile
import time

from .canon import DRM_EXCLUDED
from .extract import slugify
from .store import connect

BATCH = 400

TARGET = {
    ("x86", 32): "i386-linux-gnu",
    ("x86", 64): "x86_64-linux-gnu",
    ("ARM", 32): "arm-linux-gnueabi",
    ("AARCH64", 64): "aarch64-linux-gnu",
}


def pe_mapper(raw: bytes):
    if raw[:2] != b"MZ":
        return None
    pe = struct.unpack_from("<I", raw, 0x3C)[0]
    if raw[pe : pe + 4] != b"PE\0\0":
        return None
    nsec = struct.unpack_from("<H", raw, pe + 6)[0]
    opt = struct.unpack_from("<H", raw, pe + 20)[0]
    magic = struct.unpack_from("<H", raw, pe + 24)[0]
    base = (
        struct.unpack_from("<Q", raw, pe + 24 + 24)[0]
        if magic == 0x20B
        else struct.unpack_from("<I", raw, pe + 24 + 28)[0]
    )
    secs = []
    for i in range(nsec):
        o = pe + 24 + opt + i * 40
        vsize, vaddr, rsize, roff = struct.unpack_from("<IIII", raw, o + 8)
        secs.append((vaddr, max(vsize, rsize), roff))

    def f(va):
        r = va - base
        for vaddr, size, roff in secs:
            if vaddr <= r < vaddr + size:
                return roff + (r - vaddr)
        return None

    return f


def elf_mapper(raw: bytes):
    if raw[:4] != b"\x7fELF":
        return None
    is64 = raw[4] == 2
    end = "<" if raw[5] == 1 else ">"
    if is64:
        phoff = struct.unpack_from(end + "Q", raw, 0x20)[0]
        phentsize, phnum = struct.unpack_from(end + "HH", raw, 0x36)
    else:
        phoff = struct.unpack_from(end + "I", raw, 0x1C)[0]
        phentsize, phnum = struct.unpack_from(end + "HH", raw, 0x2A)
    segs = []
    for i in range(phnum):
        o = phoff + i * phentsize
        ptype = struct.unpack_from(end + "I", raw, o)[0]
        if ptype != 1:
            continue
        if is64:
            off, vaddr = struct.unpack_from(end + "QQ", raw, o + 8)
            filesz = struct.unpack_from(end + "Q", raw, o + 32)[0]
        else:
            off, vaddr = struct.unpack_from(end + "II", raw, o + 4)
            filesz = struct.unpack_from(end + "I", raw, o + 16)[0]
        segs.append((vaddr, filesz, off))

    def f(va):
        for vaddr, size, off in segs:
            if vaddr <= va < vaddr + size:
                return off + (va - vaddr)
        return None

    return f


def macho_mapper(raw: bytes):
    from . import machostabs as ms

    try:
        macho_slices = ms.slices(raw)
        mo = ms.MachO(raw, macho_slices[0][1])
    except Exception:
        return None
    segs = [(s["vmaddr"], s["filesize"], s["fileoff"] + mo.base) for s in mo.segments if s["filesize"]]

    def f(va):
        for vmaddr, size, off in segs:
            if vmaddr <= va < vmaddr + size:
                return off + (va - vmaddr)
        return None

    return f


def mapper_for(raw: bytes):
    for m in (pe_mapper, elf_mapper, macho_mapper):
        f = m(raw)
        if f is not None:
            return f, m.__name__
    return None, None


def emit_asm(funcs: list[tuple[int, bytes]]) -> str:
    out = ["/* byte-exact reconstruction - generated, do not edit */", ".section .text"]
    for addr, data in funcs:
        out.append(f".globl F_{addr:08x}")
        out.append(f"F_{addr:08x}:")
        for i in range(0, len(data), 16):
            out.append(".byte " + ",".join(f"0x{b:02x}" for b in data[i : i + 16]))
    return "\n".join(out) + "\n"


def elf_symbol_bytes(obj: bytes, prefix: str = "F_") -> dict[str, bytes]:
    """Read symbols' bytes out of an ELF object."""
    is64 = obj[4] == 2
    end = "<" if obj[5] == 1 else ">"
    if is64:
        shoff = struct.unpack_from(end + "Q", obj, 0x28)[0]
        shentsize, shnum, shstrndx = struct.unpack_from(end + "HHH", obj, 0x3A)
    else:
        shoff = struct.unpack_from(end + "I", obj, 0x20)[0]
        shentsize, shnum, shstrndx = struct.unpack_from(end + "HHH", obj, 0x2E)
    del shstrndx
    secs = []
    for i in range(shnum):
        o = shoff + i * shentsize
        if is64:
            stype = struct.unpack_from(end + "I", obj, o + 4)[0]
            off, size = struct.unpack_from(end + "QQ", obj, o + 24)
            link = struct.unpack_from(end + "I", obj, o + 40)[0]
            entsize = struct.unpack_from(end + "Q", obj, o + 56)[0]
        else:
            stype = struct.unpack_from(end + "I", obj, o + 4)[0]
            off, size = struct.unpack_from(end + "II", obj, o + 16)
            link = struct.unpack_from(end + "I", obj, o + 24)[0]
            entsize = struct.unpack_from(end + "I", obj, o + 36)[0]
        secs.append((stype, off, size, link, entsize))

    out: dict[str, bytes] = {}
    for stype, off, size, link, entsize in secs:
        if stype != 2 or not entsize:
            continue
        _st, stroff, strsize, _l, _e = secs[link]
        strtab = obj[stroff : stroff + strsize]
        for i in range(size // entsize):
            so = off + i * entsize
            if is64:
                nameoff = struct.unpack_from(end + "I", obj, so)[0]
                shndx = struct.unpack_from(end + "H", obj, so + 6)[0]
                value, sz = struct.unpack_from(end + "QQ", obj, so + 8)
            else:
                nameoff, value, sz = struct.unpack_from(end + "III", obj, so)
                shndx = struct.unpack_from(end + "H", obj, so + 14)[0]
            e = strtab.find(b"\0", nameoff)
            name = strtab[nameoff:e].decode("latin1", "replace")
            if name.startswith(prefix) and 0 < shndx < len(secs):
                _t, soff, ssize, _lk, _es = secs[shndx]
                end_off = soff + value + sz if sz else soff + ssize
                out[name] = obj[soff + value : min(end_off, soff + ssize)]
    return out


def verify_batch(args) -> tuple[int, int, list[int]]:
    funcs, triple = args
    with tempfile.TemporaryDirectory() as td:
        tdp = pathlib.Path(td)
        s, o = tdp / "b.s", tdp / "b.o"
        s.write_text(emit_asm(funcs))
        subprocess.run(
            ["clang", f"--target={triple}", "-c", str(s), "-o", str(o)],
            capture_output=True,
            text=True,
        )
        if not o.exists():
            return 0, len(funcs), [a for a, _ in funcs]
        try:
            got = elf_symbol_bytes(o.read_bytes())
        except Exception:
            return 0, len(funcs), [a for a, _ in funcs]
        ok, bad = 0, []
        for addr, data in funcs:
            blob = got.get(f"F_{addr:08x}")
            if blob is not None and blob[: len(data)] == data:
                ok += 1
            else:
                bad.append(addr)
        return ok, len(funcs), bad


def _load_funcbytes(path: pathlib.Path) -> list[tuple[int, bytes]]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        d = json.loads(line)
        rows.append((d["a"], bytes.fromhex(d["b"])))
    return rows


def process(
    repo_path: str,
    outdir: pathlib.Path | str,
    store_path: pathlib.Path | str,
    *,
    raw_dir: pathlib.Path | str,
    funcbytes_dir: pathlib.Path | str | None = None,
    workers: int = 10,
    verify: bool = True,
) -> dict:
    """Emit GNU ``.byte`` sources for *repo_path*. *raw_dir* is required."""
    con = connect(store_path)
    row = con.execute(
        "SELECT id, arch, bits FROM binary WHERE repo_path=?",
        (repo_path,),
    ).fetchone()
    if row is None:
        return {"repo_path": repo_path, "error": "not in database"}
    triple = TARGET.get((row["arch"], row["bits"]))
    if triple is None:
        return {"repo_path": repo_path, "error": f"no target for {row['arch']}/{row['bits']}"}

    slug = slugify(repo_path)
    funcs: list[tuple[int, bytes]] = []
    skipped = 0
    kind = None

    raw_path = pathlib.Path(raw_dir) / slug
    if raw_path.exists():
        raw = raw_path.read_bytes()
        va2off, kind = mapper_for(raw)
        if va2off is not None:
            for r in con.execute(
                "SELECT addr, size FROM func WHERE binary_id=? AND n_instr>0 AND size>0",
                (row["id"],),
            ):
                off = va2off(r["addr"])
                if off is None or off + r["size"] > len(raw):
                    skipped += 1
                    continue
                funcs.append((r["addr"], raw[off : off + r["size"]]))

    fb_root = pathlib.Path(funcbytes_dir) if funcbytes_dir is not None else None
    fb_path = (fb_root / f"{slug}.jsonl") if fb_root is not None else None
    if funcs and skipped and fb_path is not None and fb_path.exists():
        have = {a for a, _ in funcs}
        for addr, data in _load_funcbytes(fb_path):
            if addr not in have:
                funcs.append((addr, data))
                skipped -= 1
        kind = f"{kind}+ghidra_memory"

    if not funcs:
        if fb_path is not None and fb_path.exists():
            kind = "ghidra_memory"
            funcs = _load_funcbytes(fb_path)
        else:
            return {"repo_path": repo_path, "error": "no raw image and no dumped function bytes"}
    if not funcs:
        return {"repo_path": repo_path, "error": f"no mappable functions ({kind})", "skipped": skipped}

    dest = pathlib.Path(outdir)
    dest.mkdir(parents=True, exist_ok=True)
    batches = [(funcs[i : i + BATCH], triple) for i in range(0, len(funcs), BATCH)]
    t0 = time.time()
    ok = tot = 0
    bad: list[int] = []
    if verify:
        with cf.ThreadPoolExecutor(max_workers=workers) as ex:
            for o, t, b in ex.map(verify_batch, batches):
                ok += o
                tot += t
                bad += b
    else:
        tot = len(funcs)

    srcdir = dest / slug
    srcdir.mkdir(parents=True, exist_ok=True)
    for i, (batch, _) in enumerate(batches):
        (srcdir / f"part{i:04d}.s").write_text(emit_asm(batch))

    el = time.time() - t0
    return {
        "repo_path": repo_path,
        "container": kind,
        "target": triple,
        "functions": len(funcs),
        "skipped_unmappable": skipped,
        "byte_exact": ok,
        "failed": len(bad),
        "rate": round(ok / max(tot, 1), 6),
        "seconds": round(el, 1),
        "ms_per_function": round(el / max(len(funcs), 1) * 1000, 3),
        "failed_sample": [f"0x{a:x}" for a in bad[:10]],
        "verified": verify,
        "excluded": repo_path in DRM_EXCLUDED,
    }


def write_coverage(outdir: pathlib.Path | str, results: list[dict]) -> pathlib.Path:
    dest = pathlib.Path(outdir)
    dest.mkdir(parents=True, exist_ok=True)
    path = dest / "_coverage.json"
    path.write_text(json.dumps(results, indent=1), encoding="utf-8")
    return path
