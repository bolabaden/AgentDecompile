"""Merge per-binary readable trees into one operator-supplied directory."""

from __future__ import annotations

import shutil
from pathlib import Path

from .package_readable import package_readable, EH_FRAGMENT_RE
from .package_project import emit_tu, load_bytes, safe_path


def comment_block(text: str) -> str:
    """Embed decompiled C in a block comment, neutralising any ``*/`` inside."""
    return text.replace("*/", "*\\/")


def emit_function(f: dict, decomp: str | None, verified: bool) -> str:
    label = f"F_{f['addr']:08x}"
    head = [
        "/*",
        f" * {f.get('canon_key') or f.get('name') or label}",
        f" *   address : 0x{f['addr']:08x}   size: {f['size']} bytes",
    ]
    if decomp:
        head.append(" *   ghidra   : advisory decompilation (not byte-verified)")
        head.append(" */")
        head.append(comment_block(decomp))
        head.append("/* end advisory decompilation")
    if verified:
        head.append(" *   authority: verified-byte-exact")
    head.append(" */")
    return "\n".join(head) + "\n" + emit_tu([f], label)


def package_from_store(con, repo_path: str, out_dir: Path, *,
                       funcbytes_dir: Path | None = None) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    brow = con.execute("SELECT id, slug FROM binary WHERE repo_path=?", (repo_path,)).fetchone()
    if brow is None:
        raise ValueError(f"binary not in db: {repo_path}")
    raw_map = {}
    if funcbytes_dir is not None:
        raw_map = load_bytes(Path(funcbytes_dir) / f"{brow['slug']}.jsonl")
    n = 0
    for r in con.execute(
        "SELECT addr, name, canon_key, size, source_file FROM func "
        "WHERE binary_id=? AND n_instr>0", (brow["id"],)
    ):
        if EH_FRAGMENT_RE.match(r["name"] or ""):
            continue
        data = raw_map.get(r["addr"])
        if not data:
            continue
        rec = dict(r)
        rec["bytes"] = data
        rel = safe_path(r["source_file"] or f"_unattributed/{r['addr']:08x}")
        dest = out / (rel + ".S")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(emit_function(rec, None, False))
        n += 1
    return {"functions": n}


def package_unified(
    functions_by_binary: dict[str, list[dict]],
    out_dir: Path,
) -> dict:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = {}
    for binary_id, rows in functions_by_binary.items():
        dest = out_dir / binary_id
        if dest.exists():
            shutil.rmtree(dest)
        summary[binary_id] = package_readable(rows, dest, binary_id=binary_id)
    return summary
