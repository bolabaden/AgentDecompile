"""Emit a readable C tree grouped by source_file. Authority is per-function."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

from .source_claims import is_real_c, is_recovered_source

EH_FRAGMENT_RE = re.compile(r"^(Unwind[_@]|Catch[_@]|FrameHandler[_@])", re.I)
from .workspace import rel_source


def safe_relpath(source_file: str | None, fallback: str) -> str:
    """Turn a recovered source path into a safe project-relative .c path."""
    if not source_file:
        return f"_unattributed/{fallback}.cpp"
    s = source_file.replace("\\", "/").lstrip("/")
    s = re.sub(r"[^A-Za-z0-9_./-]", "_", s)
    parts = [p for p in s.split("/") if p not in ("", ".", "..")]
    if not parts:
        return f"_unattributed/{fallback}.cpp"
    if not parts[-1].endswith((".c", ".cpp", ".cc")):
        parts[-1] += ".cpp"
    if parts[-1].endswith(".c"):
        parts[-1] += "pp"
    return "/".join(parts)


def map_source_path(source_file: str) -> str:
    """Compatibility alias used by the recovered-tree packager."""
    return safe_relpath(source_file, "unattributed")


def function_block(rec: dict, body: str) -> str:
    """One function, with its provenance stated above it."""
    tier = rec["authority"]
    proof = ("recompiled and matched the shipped bytes"
             if tier == "verified-byte-exact"
             else "Ghidra decompilation -- readable, NOT byte-verified")
    head = [
        "/*",
        f" * {rec.get('canon_key') or rec.get('name')}",
        f" *   binary   : {rec.get('slug')}",
        f" *   address  : 0x{rec['addr']:08x}   size: {rec.get('size')} bytes",
        f" *   authority: {tier} -- {proof}",
        " */",
    ]
    return "\n".join(head) + "\n" + body.rstrip() + "\n"


def collect(con, repo_path: str) -> tuple[int, list[dict]]:
    row = con.execute("SELECT id, slug FROM binary WHERE repo_path=?",
                      (repo_path,)).fetchone()
    if row is None:
        raise ValueError(f"binary not in db: {repo_path}")
    binary_id, slug = int(row["id"]), row["slug"]
    verified_addr: set[int] = set()
    verified_name: set[str] = set()
    try:
        for r in con.execute(
            "SELECT addr, name FROM recovered_function"
            " WHERE binary_id=? AND real_c=1", (binary_id,),
        ):
            if r["addr"] is not None:
                verified_addr.add(int(r["addr"]))
            if r["name"]:
                verified_name.add(str(r["name"]))
    except Exception:
        pass
    out = []
    for r in con.execute(
        "SELECT addr, name, canon_key, signature, source_file, size"
        "  FROM func WHERE binary_id=? AND is_thunk=0 AND n_instr>=1"
        "  ORDER BY addr", (binary_id,),
    ):
        name = r["name"] or ""
        if EH_FRAGMENT_RE.match(name):
            continue
        out.append({
            "addr": int(r["addr"]), "name": name, "canon_key": r["canon_key"],
            "signature": r["signature"], "source_file": r["source_file"],
            "size": int(r["size"] or 0), "slug": slug,
            "authority": (
                "verified-byte-exact"
                if (int(r["addr"]) in verified_addr
                    or name in verified_name
                    or (r["canon_key"] or "") in verified_name)
                else "advisory-ghidra"),
        })
    return binary_id, out


def package_from_store(con, repo_path: str, out_dir: Path, *,
                       knowledge_c=None, limit: int | None = None) -> dict:
    """Readable C tree from the identity store. *out_dir* is required."""
    import collections
    _binary_id, funcs = collect(con, repo_path)
    if limit:
        funcs = funcs[:limit]
    slug = funcs[0]["slug"] if funcs else repo_path.strip("/").replace("/", "__")
    root = Path(out_dir)
    (root / "src").mkdir(parents=True, exist_ok=True)
    by_file: dict[str, list[str]] = collections.defaultdict(list)
    stats: collections.Counter = collections.Counter()
    manifest = []
    lookup = knowledge_c or (lambda *_a, **_k: None)
    for f in funcs:
        rec = lookup(Path(repo_path).name, f["addr"])
        if rec is None:
            stats["no_ghidra_c"] += 1
            continue
        _, base_c = rec
        if not is_real_c(base_c):
            stats["ghidra_shim"] += 1
            continue
        rel = safe_relpath(f["source_file"], f"{slug}_{f['addr'] >> 16:04x}")
        by_file[rel].append(function_block(f, base_c))
        stats[f["authority"]] += 1
        manifest.append({
            "address": f"0x{f['addr']:08x}", "name": f["canon_key"] or f["name"],
            "size": f["size"], "authority": f["authority"], "file": f"src/{rel}",
        })
    for rel, blocks in by_file.items():
        dest = root / "src" / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text("\n".join(blocks))
    (root / "MANIFEST.json").write_text(json.dumps({
        "binary": repo_path, "slug": slug, "functions": manifest,
        "functions_written": len(manifest),
    }, indent=1))
    return {"slug": slug, "written": len(manifest), "files": len(by_file), **stats}


def package_readable(functions: list[dict], out_dir: Path, *, binary_id: str) -> dict:
    out_dir = Path(out_dir)
    src_root = out_dir / "src"
    src_root.mkdir(parents=True, exist_ok=True)
    grouped: dict[str, list[dict]] = defaultdict(list)
    records = []
    for row in functions:
        body = row.get("source") or row.get("body") or ""
        rel = rel_source(row.get("source_file") or row.get("sourceFile") or "") or "_unattributed/unattributed.c"
        grouped[rel].append(row)
        records.append(
            {
                "id": row.get("id"),
                "name": row.get("name"),
                "source_file": rel,
                "authority": "advisory-ghidra" if is_recovered_source(body) else "not-source",
            }
        )
    for rel, rows in grouped.items():
        dest = src_root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        parts = []
        for row in rows:
            body = (row.get("source") or row.get("body") or "").rstrip()
            if body:
                parts.append(f"/* {row.get('name') or row.get('id')} */\n{body}\n")
        dest.write_text("\n".join(parts), encoding="utf-8")
    manifest = {"binaryId": binary_id, "functions": records}
    (out_dir / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return {"files": len(grouped), "functions": len(records)}
