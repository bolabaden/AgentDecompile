"""Mach-O + STABS reader.

Ghidra's Mach-O loader consumes STABS well enough to name functions, but it does
not retain the two records this project cares most about:

* ``N_SO``  — the source file (``.cpp``) a compilation unit came from
* ``N_OSO`` — the object file (``.o``) the linker pulled it out of

Those give real compilation-unit boundaries, which is the strongest possible
blocking constraint for cross-build matching: two functions from different `.o`
files are almost never the same source function.

No third-party modules: everything is struct-unpacked by hand.
"""

from __future__ import annotations

import pathlib
import struct
import sys
from collections import defaultdict

MH_MAGIC = 0xFEEDFACE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM = 0xCEFAEDFE
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA

LC_SEGMENT = 0x01
LC_SYMTAB = 0x02
LC_SEGMENT_64 = 0x19

N_STAB = 0xE0
N_TYPE = 0x0E
N_EXT = 0x01
N_SECT = 0x0E

STAB_NAMES = {
    0x20: "N_GSYM", 0x22: "N_FNAME", 0x24: "N_FUN", 0x26: "N_STSYM",
    0x28: "N_LCSYM", 0x2A: "N_MAIN", 0x2E: "N_BNSYM", 0x30: "N_PC",
    0x32: "N_AST", 0x3C: "N_OPT", 0x40: "N_RSYM", 0x44: "N_SLINE",
    0x46: "N_DSLINE", 0x48: "N_BSLINE", 0x4E: "N_ENSYM", 0x50: "N_SSYM",
    0x60: "N_SO", 0x64: "N_SO", 0x66: "N_OSO", 0x80: "N_LSYM",
    0x82: "N_BINCL", 0x84: "N_SOL", 0x86: "N_PARAMS", 0x88: "N_VERSION",
    0x8A: "N_OLEVEL", 0xA0: "N_PSYM", 0xA2: "N_EINCL", 0xA4: "N_ENTRY",
    0xC0: "N_LBRAC", 0xC2: "N_EXCL", 0xE0: "N_RBRAC", 0xE2: "N_BCOMM",
    0xE4: "N_ECOMM", 0xE8: "N_ECOML", 0xFE: "N_LENG",
}

CPU_NAMES = {7: "i386", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "arm64",
             18: "ppc", 0x01000012: "ppc64"}


class MachO:
    def __init__(self, data: bytes, offset: int = 0):
        self.data = data
        self.base = offset
        magic = struct.unpack_from("<I", data, offset)[0]
        if magic == MH_MAGIC:
            self.bits, self.endian = 32, "<"
        elif magic == MH_CIGAM:
            self.bits, self.endian = 32, ">"
        elif magic == MH_MAGIC_64:
            self.bits, self.endian = 64, "<"
        elif magic == MH_CIGAM_64:
            self.bits, self.endian = 64, ">"
        else:
            raise ValueError(f"not a Mach-O at 0x{offset:x}: magic=0x{magic:08x}")
        hdr = struct.unpack_from(self.endian + "IiiIIII", data, offset)
        self.cputype, self.cpusubtype, self.filetype = hdr[1], hdr[2], hdr[3]
        self.ncmds, self.sizeofcmds, self.flags = hdr[4], hdr[5], hdr[6]
        self.hdr_size = 32 if self.bits == 64 else 28
        self.arch = CPU_NAMES.get(self.cputype, f"cpu{self.cputype}")
        self.segments: list[dict] = []
        self.symtab: dict | None = None
        self._parse_commands()

    def _parse_commands(self) -> None:
        off = self.base + self.hdr_size
        for _ in range(self.ncmds):
            cmd, cmdsize = struct.unpack_from(self.endian + "II", self.data, off)
            if cmd == LC_SYMTAB:
                symoff, nsyms, stroff, strsize = struct.unpack_from(
                    self.endian + "IIII", self.data, off + 8
                )
                self.symtab = {"symoff": symoff, "nsyms": nsyms,
                               "stroff": stroff, "strsize": strsize}
            elif cmd in (LC_SEGMENT, LC_SEGMENT_64):
                name = self.data[off + 8 : off + 24].split(b"\0")[0].decode("ascii", "replace")
                if cmd == LC_SEGMENT:
                    vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                        self.endian + "IIII", self.data, off + 24)
                else:
                    vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                        self.endian + "QQQQ", self.data, off + 24)
                self.segments.append({"name": name, "vmaddr": vmaddr, "vmsize": vmsize,
                                      "fileoff": fileoff, "filesize": filesize})
            off += cmdsize

    def _str(self, stroff: int, strx: int) -> str:
        if strx == 0:
            return ""
        start = self.base + stroff + strx
        end = self.data.find(b"\0", start)
        return self.data[start:end].decode("utf-8", "replace")

    def symbols(self):
        """Yield every nlist entry as a dict."""
        if not self.symtab:
            return
        st = self.symtab
        wide = self.bits == 64
        esize = 16 if wide else 12
        fmt = self.endian + ("IBBHQ" if wide else "IBBhI")
        base = self.base + st["symoff"]
        for i in range(st["nsyms"]):
            strx, ntype, nsect, ndesc, nvalue = struct.unpack_from(fmt, self.data,
                                                                   base + i * esize)
            yield {
                "index": i,
                "name": self._str(st["stroff"], strx),
                "type": ntype,
                "sect": nsect,
                "desc": ndesc & 0xFFFF,
                "value": nvalue,
                "is_stab": bool(ntype & N_STAB),
                "stab": STAB_NAMES.get(ntype) if ntype & N_STAB else None,
            }


def slices(data: bytes) -> list[tuple[str, int]]:
    """Return (arch, offset) for every Mach-O image in the file."""
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic in (FAT_MAGIC, FAT_CIGAM):
        endian = ">" if magic == FAT_MAGIC else "<"
        nfat = struct.unpack_from(endian + "I", data, 4)[0]
        out = []
        for i in range(nfat):
            cputype, _sub, offset, _size, _align = struct.unpack_from(
                endian + "IIIII", data, 8 + i * 20)
            out.append((CPU_NAMES.get(cputype, f"cpu{cputype}"), offset))
        return out
    return [("", 0)]


# ------------------------------------------------------------------ STABS model


def _split_stabs_decl(name: str) -> tuple[str, str]:
    """Split ``identifier:type`` without treating C++ ``::`` as a delimiter."""
    for index, char in enumerate(name):
        if char != ":":
            continue
        before = name[index - 1] if index else ""
        after = name[index + 1] if index + 1 < len(name) else ""
        if before != ":" and after != ":":
            return name[:index], name[index + 1 :]
    return name, ""


def _stabs_kind(name: str, stab_kind: str) -> tuple[str, str]:
    """Return (identifier, kind) from a STABS string.

    Colon suffix: t=typedef, T=struct/union/enum (=s/=u/=e), p/P=param,
    r=register, F/f=function. Anything else is a local.
    """
    ident, rest = _split_stabs_decl(name)
    if not rest:
        kind = {
            "N_PSYM": "param",
            "N_RSYM": "register",
            "N_FUN": "function",
        }.get(stab_kind, "local")
        return ident, kind
    tag = rest[0]
    if tag == "t":
        return ident, "typedef"
    if tag == "T":
        if "=s" in rest:
            return ident, "struct"
        if "=u" in rest:
            return ident, "union"
        if "=e" in rest:
            return ident, "enum"
        return ident, "struct"
    if tag in ("p", "P"):
        return ident, "param"
    if tag == "r" or stab_kind == "N_RSYM":
        return ident, "register"
    if tag in ("F", "f"):
        return ident, "function"
    if stab_kind == "N_PSYM":
        return ident, "param"
    return ident, "local"


def parse_stabs(mo: MachO) -> dict:
    """Group STABS records into compilation units with their functions."""
    units: list[dict] = []
    cur: dict | None = None
    pending_dir = None
    functions: list[dict] = []
    globals_: list[dict] = []
    statics: list[dict] = []
    types: list[dict] = []
    counts: dict[str, int] = defaultdict(int)
    open_fun: dict | None = None

    for sym in mo.symbols():
        if not sym["is_stab"]:
            continue
        kind = sym["stab"]
        counts[kind or f"0x{sym['type']:02x}"] += 1
        name = sym["name"]

        if kind == "N_SO":
            if name.endswith("/"):
                pending_dir = name          # directory record precedes the file
                continue
            if name == "":
                if cur:                      # empty N_SO terminates a unit
                    cur["end"] = sym["value"]
                    units.append(cur)
                    cur = None
                continue
            cur = {
                "source_dir": pending_dir,
                "source_file": name,
                "start": sym["value"],
                "end": None,
                "object_file": None,
                "functions": [],
                "statics": [],
            }
            pending_dir = None
        elif kind == "N_OSO":
            if cur is not None:
                cur["object_file"] = name
                cur["oso_mtime"] = sym["value"]
        elif kind == "N_FUN":
            if name:
                # `Foo::bar(int):F(0,1)` — the type follows a colon
                base, stabs_type = _split_stabs_decl(name)
                rec = {
                    "name": base,
                    "stabs_type": stabs_type or None,
                    "addr": sym["value"],
                    "size": None,
                    "source_file": cur["source_file"] if cur else None,
                    "object_file": cur["object_file"] if cur else None,
                }
                functions.append(rec)
                if cur:
                    cur["functions"].append(rec)
                open_fun = rec
            else:
                # anonymous N_FUN closes the previous one and carries its length
                if open_fun is not None and open_fun["size"] is None:
                    open_fun["size"] = sym["value"]
                open_fun = None
        elif kind in ("N_LSYM", "N_PSYM", "N_RSYM"):
            ident, tkind = _stabs_kind(name, kind)
            if ident:
                scoped = tkind in ("param", "local", "register")
                types.append({
                    "name": ident,
                    "kind": tkind,
                    "stab": name,
                    "func_addr": (open_fun["addr"] if scoped and open_fun else None),
                    "source_file": cur["source_file"] if cur else None,
                    "object_file": cur["object_file"] if cur else None,
                })
        elif kind in ("N_STSYM", "N_LCSYM"):
            ident, _ = _split_stabs_decl(name)
            rec = {"name": ident, "addr": sym["value"], "kind": kind,
                   "source_file": cur["source_file"] if cur else None}
            statics.append(rec)
            if cur:
                cur["statics"].append(rec)
            ident, tkind = _stabs_kind(name, kind)
            if ident and tkind in ("typedef", "struct", "union", "enum"):
                types.append({
                    "name": ident, "kind": tkind, "stab": name, "func_addr": None,
                    "source_file": cur["source_file"] if cur else None,
                    "object_file": cur["object_file"] if cur else None,
                })
        elif kind == "N_GSYM":
            ident, _ = _split_stabs_decl(name)
            globals_.append({"name": ident, "desc": sym["desc"]})
            ident, tkind = _stabs_kind(name, kind)
            if ident and tkind in ("typedef", "struct", "union", "enum"):
                types.append({
                    "name": ident, "kind": tkind, "stab": name, "func_addr": None,
                    "source_file": cur["source_file"] if cur else None,
                    "object_file": cur["object_file"] if cur else None,
                })

    if cur:
        units.append(cur)

    return {
        "record_counts": dict(counts),
        "units": units,
        "functions": functions,
        "statics": statics,
        "globals": globals_,
        "types": types,
    }


def analyze(path: pathlib.Path) -> dict:
    data = path.read_bytes()
    out = {"file": str(path), "size": len(data), "slices": []}
    for arch, off in slices(data):
        try:
            mo = MachO(data, off)
        except ValueError as exc:
            out["slices"].append({"arch": arch, "offset": off, "error": str(exc)})
            continue
        nstab = nsym = 0
        for s in mo.symbols():
            nsym += 1
            if s["is_stab"]:
                nstab += 1
        entry = {
            "arch": mo.arch, "bits": mo.bits, "offset": off,
            "filetype": mo.filetype, "n_symbols": nsym, "n_stabs": nstab,
            "segments": [s["name"] for s in mo.segments],
        }
        if nstab:
            entry["stabs"] = parse_stabs(mo)
        out["slices"].append(entry)
    return out


if __name__ == "__main__":
    for arg in sys.argv[1:]:
        res = analyze(pathlib.Path(arg))
        for sl in res["slices"]:
            print(f"{res['file']} [{sl.get('arch')}] symbols={sl.get('n_symbols')} "
                  f"stabs={sl.get('n_stabs')}")
            st = sl.get("stabs")
            if st:
                print("   record counts:", dict(sorted(st["record_counts"].items())))
                print(f"   compilation units: {len(st['units'])}")
                print(f"   functions        : {len(st['functions'])}")
                print(f"   statics          : {len(st['statics'])}")
                kinds = {}
                for t in st.get("types") or []:
                    kinds[t.get("kind") or "?"] = kinds.get(t.get("kind") or "?", 0) + 1
                print(f"   types            : {len(st.get('types') or [])}  {kinds}")
                for u in st["units"][:5]:
                    print(f"     {u['source_file']}  obj={u['object_file']} "
                          f"funcs={len(u['functions'])}")
