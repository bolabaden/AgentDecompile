"""Recover on-disk FileBytes from a Ghidra program. Destination is required."""

from __future__ import annotations

from pathlib import Path


CHUNK = 1 << 20


def export(program, dest: Path) -> list[dict]:
    """Write every FileBytes blob of a program; returns per-blob metadata."""
    import jpype

    dest = Path(dest)
    mem = program.getMemory()
    all_fb = list(mem.getAllFileBytes())
    meta = []
    for idx, fb in enumerate(all_fb):
        size = int(fb.getSize())
        name = str(fb.getFilename())
        safe = name.replace("/", "_")
        out = dest if len(all_fb) == 1 else dest.with_name(f"{dest.name}.{idx}_{safe}")
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "wb") as fh:
            off = 0
            jbuf = jpype.JArray(jpype.JByte)(CHUNK)
            while off < size:
                n = min(CHUNK, size - off)
                got = fb.getOriginalBytes(off, jbuf, 0, n)
                if got <= 0:
                    break
                fh.write(bytes(memoryview(jbuf)[:got]))
                off += got
        meta.append(
            {
                "index": idx,
                "filename": name,
                "size": size,
                "written": out.stat().st_size,
                "out": str(out),
            }
        )
    return meta
