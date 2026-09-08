"""Wrap a slice of a raw binary image in a minimal COFF object.

The output layout was reverse-engineered from surviving objects rather than
written from the COFF spec. ``write_object`` takes required Path arguments;
there is no product-binary default.
"""

from __future__ import annotations

import pathlib
import re
import struct
import subprocess
import tempfile

MACHINE = {
    "coff-i386": 0x014C,
    "coff-x86-64": 0x8664,
}

TEXT_CHARACTERISTICS = 0x60500020

SYMBOL_SIZE = 18
FILE_HEADER_SIZE = 20
SECTION_HEADER_SIZE = 40

IMAGE_SYM_CLASS_EXTERNAL = 2
IMAGE_SYM_CLASS_STATIC = 3
IMAGE_SYM_DTYPE_FUNCTION = 0x20
IMAGE_REL_I386_REL32 = 0x14
RELOCATION_ENTRY_SIZE = 10


def find_call_targets(code: bytes, machine: int) -> dict[int, int]:
    """{byte offset of the displacement field: target offset (may be outside code)}.

    Only ``call rel32`` (E8) and ``jmp rel32`` (E9) whose target lands outside
    this function's own byte range get a relocation. Returns {} when objdump
    is unavailable or the machine is not i386.
    """
    if machine != MACHINE["coff-i386"]:
        return {}
    fmt = "coff-i386"
    try:
        with tempfile.NamedTemporaryFile(suffix=".o") as tf:
            tf.write(build_object(code, "_probe", machine))
            tf.flush()
            p = subprocess.run(
                ["objdump", "-b", fmt, "-d", tf.name],
                capture_output=True,
                text=True,
            )
    except OSError:
        return {}
    out: dict[int, int] = {}
    for line in p.stdout.splitlines():
        m = re.match(r"^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2} )+)\s*(call|jmp)\s", line)
        if not m:
            continue
        off = int(m.group(1), 16)
        raw = bytes.fromhex(m.group(2).replace(" ", ""))
        if not raw or raw[0] not in (0xE8, 0xE9) or len(raw) < 5:
            continue
        disp = int.from_bytes(raw[1:5], "little", signed=True)
        target = off + 5 + disp
        if target < 0 or target >= len(code):
            out[off + 1] = target
    return out


def symbol_name_field(name: str, strtab: bytearray) -> bytes:
    """8-byte name field: inline when it fits, else an offset into the string table."""
    raw = name.encode("ascii")
    if len(raw) <= 8:
        return raw.ljust(8, b"\0")
    offset = len(strtab)
    strtab.extend(raw + b"\0")
    return struct.pack("<II", 0, offset)


def build_object(
    code: bytes,
    symbol: str,
    machine: int,
    call_targets: dict[int, int] | None = None,
) -> bytes:
    """``call_targets`` is ``{displacement-field offset: target offset}``.

    None/empty reproduces the original zero-relocation layout.
    """
    size = len(code)
    data_off = FILE_HEADER_SIZE + SECTION_HEADER_SIZE

    call_targets = call_targets or {}
    targets = sorted(set(call_targets.values()))
    n_relocs = len(call_targets)
    reloc_off = data_off + size
    symtab_off = reloc_off + n_relocs * RELOCATION_ENTRY_SIZE
    n_symbols = 3 + len(targets)

    strtab = bytearray(b"\0\0\0\0")

    out = bytearray()
    out += struct.pack(
        "<HHIIIHH",
        machine,
        1,
        0,
        symtab_off,
        n_symbols,
        0,
        0,
    )
    out += b".text".ljust(8, b"\0")
    out += struct.pack(
        "<IIIIIIHHI",
        0,
        0,
        size,
        data_off,
        reloc_off if n_relocs else 0,
        0,
        n_relocs,
        0,
        TEXT_CHARACTERISTICS,
    )
    assert len(out) == data_off, (len(out), data_off)
    out += code
    assert len(out) == reloc_off, (len(out), reloc_off)

    target_index = {addr: 3 + i for i, addr in enumerate(targets)}
    for disp_off in sorted(call_targets):
        sym_idx = target_index[call_targets[disp_off]]
        out += struct.pack("<IIH", disp_off, sym_idx, IMAGE_REL_I386_REL32)
    assert len(out) == symtab_off, (len(out), symtab_off)

    out += b".text".ljust(8, b"\0")
    out += struct.pack("<IhHBB", 0, 1, 0, IMAGE_SYM_CLASS_STATIC, 1)
    out += struct.pack("<IHH", size, n_relocs, 0) + b"\0" * 10
    out += symbol_name_field(symbol, strtab)
    out += struct.pack(
        "<IhHBB", 0, 1, IMAGE_SYM_DTYPE_FUNCTION, IMAGE_SYM_CLASS_EXTERNAL, 0
    )
    for addr in targets:
        out += symbol_name_field(f"EXT_{addr & 0xffffffff:08x}", strtab)
        out += struct.pack(
            "<IhHBB", 0, 0, IMAGE_SYM_DTYPE_FUNCTION, IMAGE_SYM_CLASS_EXTERNAL, 0
        )

    struct.pack_into("<I", strtab, 0, len(strtab))
    out += strtab
    return bytes(out)


def write_object(
    *,
    binary: pathlib.Path | str,
    offset: int,
    size: int,
    name: str,
    output: pathlib.Path | str,
    symbol_prefix: str = "_",
    format: str = "coff-i386",
) -> pathlib.Path:
    """Slice *binary* and write a COFF object to *output*. All paths required."""
    if size <= 0:
        raise ValueError(f"mkobj: refusing zero/negative size {size}")
    if format not in MACHINE:
        raise ValueError(f"mkobj: unknown format {format!r}")

    raw = pathlib.Path(binary).read_bytes()
    end = offset + size
    if offset < 0 or end > len(raw):
        raise ValueError(f"mkobj: slice {offset}..{end} outside {binary} ({len(raw)} bytes)")

    code = raw[offset:end]
    machine = MACHINE[format]
    call_targets = find_call_targets(code, machine)
    if call_targets:
        code = bytearray(code)
        for disp_off in call_targets:
            code[disp_off : disp_off + 4] = b"\0\0\0\0"
        code = bytes(code)
    obj = build_object(code, symbol_prefix + name, machine, call_targets)
    dest = pathlib.Path(output)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(obj)
    return dest


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary", type=pathlib.Path, required=True)
    ap.add_argument("--offset", type=int, required=True)
    ap.add_argument("--size", type=int, required=True)
    ap.add_argument("--name", required=True)
    ap.add_argument("-o", "--output", type=pathlib.Path, required=True)
    ap.add_argument("--symbol-prefix", default="_")
    ap.add_argument("--format", choices=sorted(MACHINE), default="coff-i386")
    args = ap.parse_args(argv)
    try:
        write_object(
            binary=args.binary,
            offset=args.offset,
            size=args.size,
            name=args.name,
            output=args.output,
            symbol_prefix=args.symbol_prefix,
            format=args.format,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
