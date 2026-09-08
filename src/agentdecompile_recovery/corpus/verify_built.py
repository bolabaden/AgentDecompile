"""Prove byte-exactness from the built libraries, not from a recorded claim.

Extracts every ``F_*`` symbol out of the compiled objects and compares its
bytes against the shipped binary. Project directory and store path are
required. Raw / funcbytes directories are optional Path arguments — there is
no workspace default.
"""

from __future__ import annotations

import json
import pathlib

from .exact_universal import elf_symbol_bytes, mapper_for
from .extract import slugify
from .store import connect


def truth_for(
    repo_path: str,
    con,
    *,
    raw_dir: pathlib.Path | str | None = None,
    funcbytes_dir: pathlib.Path | str | None = None,
) -> dict[int, bytes]:
    """addr -> original bytes from funcbytes jsonl or a mapped raw image."""
    akey = slugify(repo_path)
    out: dict[int, bytes] = {}
    if funcbytes_dir is not None:
        fb = pathlib.Path(funcbytes_dir) / f"{akey}.jsonl"
        if fb.exists():
            for line in fb.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                d = json.loads(line)
                out[d["a"]] = bytes.fromhex(d["b"])
            return out
    if raw_dir is None:
        return out
    rawp = pathlib.Path(raw_dir) / akey
    if not rawp.exists():
        return out
    raw = rawp.read_bytes()
    mapper, _kind = mapper_for(raw)
    if mapper is None:
        return out
    bid_row = con.execute("SELECT id FROM binary WHERE repo_path=?", (repo_path,)).fetchone()
    if bid_row is None:
        return out
    for addr, sz in con.execute(
        "SELECT addr, size FROM func WHERE binary_id=? AND n_instr>0 AND size>0",
        (bid_row["id"],),
    ):
        o = mapper(addr)
        if o is not None and o + sz <= len(raw):
            out[addr] = raw[o : o + sz]
    return out


def verify(
    project_dir: pathlib.Path | str,
    store_path: pathlib.Path | str,
    *,
    raw_dir: pathlib.Path | str | None = None,
    funcbytes_dir: pathlib.Path | str | None = None,
) -> dict:
    """Compare built objects under *project_dir* against the store's binaries."""
    proj = pathlib.Path(project_dir)
    man_path = proj / "build_manifest.json"
    if not man_path.is_file():
        return {"error": "no build_manifest.json", "project": str(proj), "verified": 0, "total": 0}
    man = json.loads(man_path.read_text(encoding="utf-8"))
    con = connect(store_path)
    tot_ok = tot = 0
    rows = []
    for entry in man:
        binary = entry.get("binary") or entry.get("repo_path") or ""
        target = entry.get("target") or ""
        objdir = proj / "build" / "CMakeFiles" / f"{target}.dir"
        if not objdir.exists():
            rows.append({"binary": binary, "error": "objects not built", "ok": 0, "bad": 0})
            continue
        truth = truth_for(binary, con, raw_dir=raw_dir, funcbytes_dir=funcbytes_dir)
        got: dict[str, bytes] = {}
        for obj in objdir.rglob("*.o"):
            try:
                got.update(elf_symbol_bytes(obj.read_bytes()))
            except Exception:
                pass
        ok = bad = 0
        for addr, data in truth.items():
            blob = got.get(f"F_{addr:08x}")
            if blob is not None and blob[: len(data)] == data:
                ok += 1
            elif blob is not None:
                bad += 1
        tot_ok += ok
        tot += ok + bad
        rows.append({"binary": binary, "ok": ok, "bad": bad})
    return {
        "project": str(proj),
        "verified": tot_ok,
        "total": tot,
        "rate": tot_ok / max(tot, 1),
        "binaries": rows,
    }
