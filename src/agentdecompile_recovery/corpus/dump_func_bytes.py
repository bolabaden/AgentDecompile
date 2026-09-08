"""Dump each function's bytes from Ghidra memory. Destination is required."""

from __future__ import annotations

import json
from pathlib import Path


def dump(program, functions: list[tuple[int, int]], dest: Path) -> int:
    """Write ``{a, b}`` JSONL of (addr, hex bytes). *functions* is (addr, size)."""
    import jpype

    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    mem = program.getMemory()
    space = program.getAddressFactory().getDefaultAddressSpace()
    n = 0
    with dest.open("w", encoding="utf-8") as fh:
        for addr, size in functions:
            try:
                buf = jpype.JArray(jpype.JByte)(size)
                got = mem.getBytes(space.getAddress(addr), buf)
                if got != size:
                    continue
                fh.write(json.dumps({"a": addr, "b": bytes(memoryview(buf)[:size]).hex()}) + "\n")
                n += 1
            except Exception:
                continue
    return n
