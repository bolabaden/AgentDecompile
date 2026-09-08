"""Rebuild a complete shipped binary from source and prove it is identical.

Emits an assembly source that reproduces the entire file image: identified
functions under their own symbols, everything else as labelled filler.
Store connection, raw image, and output directory are required.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import tempfile

from .canon import DRM_EXCLUDED
from .exact_universal import mapper_for
from .extract import slugify

TARGET = {32: "i386-linux-gnu", 64: "x86_64-linux-gnu"}


def build_source(name: str, raw: bytes, regions: list[tuple[int, int, str]]) -> str:
    """One .S that reproduces the whole file image byte-for-byte."""
    lines = [
        "/" + "*" * 74,
        f" * {name} — complete file image.",
        " *",
        f" * Total size: {len(raw):,} bytes.",
        " * Regions marked FUNCTION are identified functions with recovered names.",
        " * Regions marked FILLER are bytes not inside any identified function:",
        " * headers, data sections, resources, padding and unidentified code.",
        " * They are carried verbatim so the file reassembles exactly.",
        " */",
        '\t.section .image, "a"',
        "\t.globl _image_start",
        "_image_start:",
    ]
    for start, end, label in regions:
        chunk = raw[start:end]
        if not chunk:
            continue
        lines.append("")
        lines.append(f"/* {label}  [0x{start:x}..0x{end:x})  {len(chunk)} bytes */")
        sym = f"R_{start:08x}"
        lines.append(f"\t.globl {sym}")
        lines.append(f"{sym}:")
        for i in range(0, len(chunk), 32):
            lines.append("\t.byte " + ",".join(f"0x{b:02x}" for b in chunk[i : i + 32]))
    lines.append("")
    lines.append("\t.globl _image_end")
    lines.append("_image_end:")
    return "\n".join(lines) + "\n"


def regions_for(raw: bytes, funcs: list[tuple[int, int, str]]) -> list[tuple[int, int, str]]:
    """Split the file into function and filler regions, in file order."""
    out, cursor = [], 0
    for off, size, label in sorted(funcs):
        if off > cursor:
            out.append((cursor, off, "FILLER"))
        if off >= cursor:
            out.append((off, off + size, f"FUNCTION {label}"))
            cursor = off + size
    if cursor < len(raw):
        out.append((cursor, len(raw), "FILLER"))
    return out


def roundtrip(
    repo_path: str,
    con,
    *,
    raw_path: pathlib.Path | str,
    out_dir: pathlib.Path | str,
    assemble: bool = True,
) -> dict:
    """Write a whole-image .S for *repo_path* and optionally assemble it."""
    if repo_path in DRM_EXCLUDED:
        return {"binary": repo_path, "error": "excluded"}
    row = con.execute(
        "SELECT id, slug, bits, arch FROM binary WHERE repo_path=?",
        (repo_path,),
    ).fetchone()
    if row is None or row["arch"] != "x86":
        return {"binary": repo_path, "error": "not an x86 binary"}
    rawp = pathlib.Path(raw_path)
    if not rawp.exists():
        return {"binary": repo_path, "error": "raw image not exported"}
    raw = rawp.read_bytes()

    va2off, kind = mapper_for(raw)
    if va2off is None:
        return {"binary": repo_path, "error": "unrecognised container"}

    funcs = []
    for r in con.execute(
        """SELECT addr, size, canon_key FROM func
            WHERE binary_id=? AND n_instr>0 AND size>0""",
        (row["id"],),
    ):
        o = va2off(r["addr"])
        if o is None or o + r["size"] > len(raw):
            continue
        funcs.append((o, r["size"], r["canon_key"] or f"sub_{r['addr']:08x}"))

    regions = regions_for(raw, funcs)
    fn_bytes = sum(end - start for start, end, label in regions if label.startswith("FUNCTION"))
    fill_bytes = sum(end - start for start, end, label in regions if label == "FILLER")

    src = build_source(repo_path, raw, regions)
    dest = pathlib.Path(out_dir)
    dest.mkdir(parents=True, exist_ok=True)
    akey = slugify(repo_path)
    spath = dest / f"{akey}.image.S"
    spath.write_text(src, encoding="utf-8")

    rebuilt = b""
    if assemble:
        triple = TARGET.get(row["bits"], "i386-linux-gnu")
        with tempfile.TemporaryDirectory() as td:
            obj = pathlib.Path(td) / "img.o"
            binf = pathlib.Path(td) / "img.bin"
            r = subprocess.run(
                ["clang", f"--target={triple}", "-c", str(spath), "-o", str(obj)],
                capture_output=True,
                text=True,
            )
            if not obj.exists():
                return {
                    "binary": repo_path,
                    "error": "assemble failed",
                    "stderr": r.stderr[-300:],
                    "source": str(spath),
                }
            subprocess.run(
                ["objcopy", "-O", "binary", "--only-section=.image", str(obj), str(binf)],
                capture_output=True,
            )
            rebuilt = binf.read_bytes() if binf.exists() else b""

    same = rebuilt == raw if assemble else None
    return {
        "binary": repo_path,
        "container": kind,
        "size": len(raw),
        "rebuilt_size": len(rebuilt),
        "sha256_original": hashlib.sha256(raw).hexdigest(),
        "sha256_rebuilt": hashlib.sha256(rebuilt).hexdigest() if rebuilt else None,
        "identical": same,
        "functions": len(funcs),
        "bytes_in_functions": fn_bytes,
        "bytes_filler": fill_bytes,
        "pct_attributed": round(fn_bytes / max(len(raw), 1) * 100, 2),
        "source": str(spath),
        "assembled": assemble,
    }


def write_results(out_dir: pathlib.Path | str, results: list[dict]) -> pathlib.Path:
    dest = pathlib.Path(out_dir)
    dest.mkdir(parents=True, exist_ok=True)
    path = dest / "_roundtrip.json"
    path.write_text(json.dumps(results, indent=1), encoding="utf-8")
    return path
