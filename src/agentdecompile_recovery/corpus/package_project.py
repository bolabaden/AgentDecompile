"""Copy a generated workspace into an operator-supplied output directory.

Also emits a byte-exact reconstructed tree (assembler TUs + headers) when
given an identity store and function-byte dumps.
"""

from __future__ import annotations

import json
import re
import shutil
from collections import defaultdict
from pathlib import Path

from . import canon

TARGET_FLAGS = {
    ("x86", 32): "i386-linux-gnu",
    ("x86", 64): "x86_64-linux-gnu",
    ("ARM", 32): "arm-linux-gnueabi",
    ("AARCH64", 64): "aarch64-linux-gnu",
}
_SAFE = re.compile(r"[^A-Za-z0-9_./-]")


def safe_path(p: str) -> str:
    """Turn an original source path into a relative, filesystem-safe one."""
    p = p.replace("\\", "/").lstrip("/")
    for marker in ("depot/", "Dev/", "PC Source/", "Mac Source/"):
        i = p.find(marker)
        if i >= 0:
            p = p[i + len(marker):]
    return _SAFE.sub("_", p)


def load_bytes(funcbytes_path: Path) -> dict[int, bytes]:
    out: dict[int, bytes] = {}
    path = Path(funcbytes_path)
    if path.exists():
        for line in path.open():
            d = json.loads(line)
            out[d["a"]] = bytes.fromhex(d["b"])
    return out


def emit_tu(funcs: list[dict], title: str) -> str:
    lines = [
        f"/* {title}",
        " *",
        " * Byte-exact reconstruction: each function is its original machine code.",
        " */",
        "\t.section .text",
    ]
    for f in funcs:
        sym = f"F_{f['addr']:08x}"
        if f.get("canon_key"):
            lines.append(f"/* {f['canon_key']}"
                         + (f"  {f['signature']}" if f.get("signature") else "")
                         + " */")
        lines.append(f"\t.globl {sym}")
        lines.append(f"{sym}:")
        data = f["bytes"]
        for i in range(0, len(data), 16):
            lines.append("\t.byte " + ",".join(f"0x{b:02x}" for b in data[i:i + 16]))
        lines.append(f"\t.size {sym}, . - {sym}")
    return "\n".join(lines) + "\n"


def emit_header(slug: str, funcs: list[dict]) -> str:
    guard = "AD_" + _SAFE.sub("_", slug).upper() + "_H"
    lines = [
        f"/* {slug} — recovered symbol declarations. */",
        f"#ifndef {guard}",
        f"#define {guard}",
        "",
        "#ifdef __cplusplus",
        'extern "C" {',
        "#endif",
        "",
    ]
    for f in funcs:
        sym = f"F_{f['addr']:08x}"
        if f.get("canon_key"):
            lines.append(f"/* {f['canon_key']} */")
        lines.append(f"extern void {sym}(void);")
    lines += ["", "#ifdef __cplusplus", "}", "#endif", "", f"#endif /* {guard} */", ""]
    return "\n".join(lines)


def build_reconstructed(
    con,
    out_dir: Path,
    *,
    funcbytes_dir: Path,
    limit_per_tu: int = 300,
) -> dict:
    """Emit assembler TUs for every non-excluded binary under *out_dir*."""
    out = Path(out_dir)
    if out.exists():
        shutil.rmtree(out)
    (out / "include" / "corpus").mkdir(parents=True, exist_ok=True)
    bins = [dict(r) for r in con.execute(
        "SELECT id, repo_path, slug, game, platform, arch, bits, format FROM binary "
        "ORDER BY repo_path")]
    summary = []
    targets = []
    for b in bins:
        if b["repo_path"] in canon.DRM_EXCLUDED:
            continue
        triple = TARGET_FLAGS.get((b["arch"], b["bits"]))
        if triple is None:
            continue
        slug = b["slug"]
        akey = b["repo_path"].strip("/").replace("/", "__")
        raw_map = load_bytes(Path(funcbytes_dir) / f"{akey}.jsonl")
        if not raw_map:
            raw_map = load_bytes(Path(funcbytes_dir) / f"{slug}.jsonl")
        rows = con.execute(
            """SELECT f.addr, f.size, f.canon_key, f.signature, f.source_file,
                      i.logical_id
                 FROM func f
                 LEFT JOIN identity i ON i.binary_id=f.binary_id AND i.addr=f.addr
                WHERE f.binary_id=? AND f.n_instr>0 AND f.size>0
                ORDER BY f.addr""", (b["id"],)).fetchall()
        funcs = []
        seen: set[int] = set()
        for r in rows:
            data = raw_map.get(r["addr"])
            if data is None or r["addr"] in seen:
                continue
            seen.add(r["addr"])
            d = dict(r)
            d["bytes"] = data
            funcs.append(d)
        if not funcs:
            continue
        groups: dict[str, list[dict]] = defaultdict(list)
        for f in funcs:
            if f.get("source_file"):
                groups[safe_path(f["source_file"])].append(f)
            else:
                groups["_unattributed"].append(f)
        srcroot = out / "src" / slug
        sources = []
        for gname, gfuncs in sorted(groups.items()):
            if gname == "_unattributed":
                for i in range(0, len(gfuncs), limit_per_tu):
                    chunk = gfuncs[i:i + limit_per_tu]
                    p = srcroot / "_unattributed" / f"part{i//limit_per_tu:04d}.S"
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text(emit_tu(chunk, f"{slug} — unattributed functions"))
                    sources.append(p.relative_to(out).as_posix())
            else:
                p = srcroot / (gname + ".S")
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(emit_tu(gfuncs, f"{slug} — original source: {gname}"))
                sources.append(p.relative_to(out).as_posix())
        (out / "include" / "corpus" / f"{slug}.h").write_text(emit_header(slug, funcs))
        targets.append({"name": _SAFE.sub("_", slug), "triple": triple,
                        "sources": sources, "slug": slug})
        summary.append({
            "binary": b["repo_path"], "target": _SAFE.sub("_", slug),
            "arch": b["arch"], "bits": b["bits"], "triple": triple,
            "functions": len(funcs), "translation_units": len(sources),
        })
    (out / "build_manifest.json").write_text(json.dumps(summary, indent=1))
    return {"targets": len(targets), "functions": sum(s["functions"] for s in summary)}


def package_project(workspace: Path, out_dir: Path) -> dict:
    workspace = Path(workspace)
    out_dir = Path(out_dir)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    if workspace.is_dir():
        shutil.copytree(workspace, out_dir)
    else:
        out_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "workspace": str(workspace),
        "files": sorted(str(p.relative_to(out_dir)) for p in out_dir.rglob("*") if p.is_file()),
        "claimBoundary": "A packaged tree is readable layout, not byte-accuracy.",
    }
    (out_dir / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest
