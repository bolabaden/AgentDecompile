"""Build a source-tree skeleton from STABS paths, then fill compiling C.

Parameterized by donor binary. Output directory and fill source directory
are required — there is no product workspace default.
"""

from __future__ import annotations

import re
from pathlib import Path

from . import corpus_config
from .workspace import SAFE_SEG, SOURCE_SUFFIXES

DEFAULT_STRIP = ("/Users/", "/home/", "/usr/src/")


def rel_source(path: str, strip_prefixes: tuple[str, ...] | None = None) -> str | None:
    """Depot-relative posix path, or None if it cannot be a workspace file."""
    if not path:
        return None
    prefixes = strip_prefixes
    if prefixes is None:
        listed = corpus_config.load_maps().get("source_path_strip_prefixes")
        prefixes = tuple(listed) if isinstance(listed, list) and listed else DEFAULT_STRIP
    text = path.replace("\\", "/").strip()
    for prefix in prefixes:
        if text.startswith(prefix):
            text = text[len(prefix) :]
            break
    text = text.lstrip("/")
    if not text or ".." in text.split("/"):
        return None
    parts = text.split("/")
    if not all(SAFE_SEG.match(seg) for seg in parts):
        return None
    if not parts[-1].endswith(SOURCE_SUFFIXES):
        if "." not in parts[-1]:
            return None
    return text


def donor_files(con, slug: str) -> list[tuple[str, int]]:
    """(rel_path, function_count) for every source_file on the donor."""
    brow = con.execute("SELECT id FROM binary WHERE slug=?", (slug,)).fetchone()
    if not brow:
        raise SystemExit(f"no binary slug {slug!r}")
    counts: dict[str, int] = {}
    for row in con.execute(
        "SELECT source_file FROM func WHERE binary_id=? AND source_file IS NOT NULL",
        (int(brow["id"]),),
    ):
        rel = rel_source(row["source_file"])
        if rel:
            counts[rel] = counts.get(rel, 0) + 1
    return sorted(counts.items())


def write_skeleton(out: Path, files: list[tuple[str, int]]) -> int:
    """Create folders and a stub file per source path. Idempotent."""
    n = 0
    dest_root = Path(out)
    for rel, nfunc in files:
        dest = dest_root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists() and dest.stat().st_size > 0:
            continue
        dest.write_text(
            f"/* {rel}\n"
            f" * STABS-attributed compilation unit ({nfunc} functions on the donor).\n"
            f" * Bodies are filled by workspace_skeleton fill once a function compiles.\n"
            f" * This stub is layout only.\n"
            f" */\n",
            encoding="utf-8",
        )
        n += 1
    return n


def cu_unit_dir(out: Path, rel: str) -> Path:
    """Folder for one STABS compilation unit. Each function stays its own TU."""
    path = Path(rel)
    return Path(out) / path.parent / path.stem


def _note_stub(stub: Path, rel: str, fname: str) -> None:
    stub.parent.mkdir(parents=True, exist_ok=True)
    line = f" *   {fname}\n"
    if stub.exists():
        text = stub.read_text(encoding="utf-8")
        if fname in text:
            return
        if not text.endswith("\n"):
            text += "\n"
        stub.write_text(text + line, encoding="utf-8")
        return
    stub.write_text(
        f"/* {rel}\n"
        f" * STABS-attributed compilation unit.\n"
        f" * Function bodies live in {Path(rel).stem}/ as separate TUs.\n"
        f" * This stub is an index, not a compile input.\n"
        f"{line}"
        f" */\n",
        encoding="utf-8",
    )


def fill_from_ghidra(con, donor_slug: str, fill_program: str, out: Path, src_dir: Path) -> dict:
    """Place each compiling .c under the STABS CU folder that owns it.

    Concatenating standalone ghidra-bulk files into one CU cannot compile
    (duplicate headers and symbols). Each function stays a compile unit.
    """
    del donor_slug
    src_root = Path(src_dir)
    if not src_root.is_dir():
        raise SystemExit(f"no ghidra-bulk tree at {src_root}")

    fill_bin = con.execute(
        "SELECT id FROM binary WHERE slug=? OR repo_path=?",
        (fill_program, fill_program),
    ).fetchone()
    if not fill_bin:
        raise SystemExit(f"no binary matching {fill_program!r}")
    fid = int(fill_bin["id"])

    meta = {}
    for row in con.execute(
        """SELECT f.addr, i.logical_id,
                  COALESCE(lf.source_file, f.source_file) AS src
             FROM func f
             LEFT JOIN identity i
               ON i.binary_id=f.binary_id AND i.addr=f.addr
             LEFT JOIN logical_function lf ON lf.id=i.logical_id
            WHERE f.binary_id=?""",
        (fid,),
    ):
        meta[int(row["addr"])] = row

    placed = skipped_no_src = skipped_no_meta = 0
    addr_re = re.compile(r"address:\s*0x([0-9a-fA-F]+)")
    dest_root = Path(out)
    for cfile in src_root.glob("*.c"):
        if cfile.name.startswith("_"):
            continue
        head = cfile.read_text(errors="replace")[:500]
        match = addr_re.search(head)
        if not match:
            skipped_no_meta += 1
            continue
        addr = int(match.group(1), 16)
        row = meta.get(addr)
        if not row or not row["src"]:
            skipped_no_src += 1
            continue
        rel = rel_source(row["src"])
        if not rel:
            skipped_no_src += 1
            continue
        dest = cu_unit_dir(dest_root, rel) / cfile.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists() and dest.stat().st_size > 0:
            continue
        dest.write_text(cfile.read_text(errors="replace"), encoding="utf-8")
        _note_stub(dest_root / rel, rel, cfile.name)
        placed += 1
    return {"placed": placed, "skipped_no_source": skipped_no_src, "skipped_no_addr": skipped_no_meta}


def build_workspace(con, donor_slug: str, out: Path | str, *, fill_from: str | None = None, src_dir: Path | str | None = None) -> dict:
    files = donor_files(con, donor_slug)
    dest = Path(out)
    dest.mkdir(parents=True, exist_ok=True)
    created = write_skeleton(dest, files)
    stats = None
    if fill_from:
        if src_dir is None:
            raise ValueError("src_dir is required when fill_from is set")
        stats = fill_from_ghidra(con, donor_slug, fill_from, dest, Path(src_dir))
    return {
        "donor": donor_slug,
        "source_files": len(files),
        "attributed_functions": sum(n for _, n in files),
        "stubs_created": created,
        "out": str(dest),
        "fill": stats,
    }
