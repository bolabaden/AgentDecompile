"""Place a compiling body onto every binary that shares its logical_id.

Identity matching already ran. This copies source; it does not compile the
destination binaries.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from . import asm_seed

ADDR_RE = re.compile(r"address:\s*0x([0-9a-fA-F]+)", re.I)
SKIP_SLUG_SUFFIX = (".keep",)


def program_id(repo_path: str) -> str:
    return (repo_path or "").rstrip("/").split("/")[-1]


def safe_stem(name: str, entry_hex: str) -> str:
    base = re.sub(r"[^A-Za-z_0-9]+", "_", name or f"FUN_{entry_hex}").strip("_")
    return (base or f"FUN_{entry_hex}")[:80]


def parse_addr(text: str) -> int | None:
    match = ADDR_RE.search(text[:800] if text else "")
    return int(match.group(1), 16) if match else None


def rewrite_for_dest(text: str, dst_hex: str, dst_program: str, src_hex: str) -> str:
    _head, sep, rest = text.partition("*/")
    banner = (
        f"/*\n * cross-placed onto {dst_program}\n"
        f" * address: 0x{dst_hex}\n"
        f" * from 0x{src_hex} on the source program\n"
        f" * Identity logical_id bind; not a byte-verified rematch.\n */"
    )
    if sep:
        return banner + rest
    return banner + "\n" + text


def should_write(dest: Path, src_is_asm: bool) -> bool:
    if not dest.exists():
        return True
    dest_asm = asm_seed.is_compile_only_asm(dest)
    if dest_asm and not src_is_asm:
        return True
    return False


def place_one(
    src_path: Path,
    src_addr: int,
    index: dict[int, list[tuple[int, int, str, str]]],
    out_root: Path,
) -> int:
    targets = index.get(src_addr)
    if not targets:
        return 0
    text = src_path.read_text(errors="replace")
    src_is_asm = asm_seed.ASM_MARK in text[:800]
    src_hex = f"{src_addr:08x}"
    n = 0
    for _dst_bid, dst_addr, dst_prog, dst_name in targets:
        dst_hex = f"{dst_addr:08x}"
        dest_dir = out_root / dst_prog
        dest_dir.mkdir(parents=True, exist_ok=True)
        fname = f"{safe_stem(dst_name, dst_hex)}_{dst_hex}.c"
        dest = dest_dir / fname
        if not should_write(dest, src_is_asm):
            continue
        dest.write_text(rewrite_for_dest(text, dst_hex, dst_prog, src_hex))
        n += 1
    return n


def load_index(con, src_bid: int) -> dict[int, list[tuple[int, int, str, str]]]:
    out: dict[int, list[tuple[int, int, str, str]]] = {}
    rows = con.execute(
        """
        SELECT i1.addr AS src_addr, i2.binary_id AS dst_bid, i2.addr AS dst_addr,
               b.slug, b.repo_path, COALESCE(f.name, '') AS dst_name
          FROM identity i1
          JOIN identity i2 ON i2.logical_id = i1.logical_id
                          AND i2.binary_id <> i1.binary_id
          JOIN binary b ON b.id = i2.binary_id
          LEFT JOIN func f ON f.binary_id = i2.binary_id AND f.addr = i2.addr
         WHERE i1.binary_id = ?
        """,
        (src_bid,),
    )
    for row in rows:
        slug = str(row["slug"] or "")
        if any(slug.endswith(suf) for suf in SKIP_SLUG_SUFFIX):
            continue
        prog = program_id(str(row["repo_path"] or ""))
        if not prog:
            continue
        out.setdefault(int(row["src_addr"]), []).append(
            (int(row["dst_bid"]), int(row["dst_addr"]), prog, str(row["dst_name"] or ""))
        )
    return out


def resolve_source_dir(out_dir: Path, program: str) -> Path | None:
    """Prefer {out}/{program}/*.c, then Dump source layers."""
    candidates = [
        out_dir / program,
        out_dir / "dump-source" / "verified",
        out_dir / "dump-source" / "advisory" / "ghidra",
        out_dir / "dump-source" / "Port" / "CODE",
        out_dir / "dump-source",
    ]
    for cand in candidates:
        if cand.is_dir() and any(cand.glob("*.c")):
            return cand
    return None


def load_compile_ok_ids(out_dir: Path) -> set[str] | None:
    """Per-function ok ids from ghidra-bulk. None = missing/unreadable receipt."""
    path = Path(out_dir) / "compile-receipt.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    ok = data.get("ok")
    if not isinstance(ok, list):
        return None
    out: set[str] = set()
    for item in ok:
        token = str(item or "").strip().lower().removeprefix("0x")
        if token:
            out.add(token)
    return out


def _addr_token(addr: int) -> str:
    return f"{addr:x}"


def place_tree(
    src_dir: Path,
    src_bid: int,
    out_root: Path,
    con,
    *,
    compile_ok: set[str] | None = None,
) -> dict:
    if compile_ok is not None and not compile_ok:
        return {
            "placed": 0,
            "skipped_no_addr": 0,
            "src_linked": 0,
            "reason": "no compile receipt",
        }
    index = load_index(con, src_bid)
    placed = skipped = 0
    for cfile in src_dir.glob("*.c"):
        if cfile.name.startswith("_"):
            continue
        head = cfile.read_text(errors="replace")[:800]
        addr = parse_addr(head)
        if addr is None:
            skipped += 1
            continue
        if compile_ok is not None and _addr_token(addr) not in compile_ok:
            skipped += 1
            continue
        placed += place_one(cfile, addr, index, out_root)
    return {"placed": placed, "skipped_no_addr": skipped, "src_linked": len(index)}


def watch(src_dir: Path, src_bid: int, out_root: Path, con, interval: float) -> None:
    import time

    compile_ok = load_compile_ok_ids(out_root)
    if compile_ok is None or not compile_ok:
        print("cross-place watch: no compile receipt; copy 0", flush=True)
        return
    index = load_index(con, src_bid)
    seen: dict[str, float] = {}
    print(f"cross-place watch {src_dir} -> {len(index)} linked addrs", flush=True)
    while True:
        n = 0
        for cfile in src_dir.glob("*.c"):
            if cfile.name.startswith("_"):
                continue
            try:
                mtime = cfile.stat().st_mtime
            except OSError:
                continue
            if seen.get(cfile.name) == mtime:
                continue
            head = cfile.read_text(errors="replace")[:800]
            addr = parse_addr(head)
            seen[cfile.name] = mtime
            if addr is None:
                continue
            if _addr_token(addr) not in compile_ok:
                continue
            n += place_one(cfile, addr, index, out_root)
        if n:
            print(f"cross-placed {n} sibling files", flush=True)
        time.sleep(interval)


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys

    from .store import connect

    ap = argparse.ArgumentParser()
    ap.add_argument("--from", dest="program", required=True)
    ap.add_argument("--db", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path, required=True)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--watch", action="store_true")
    ap.add_argument("--interval", type=float, default=8.0)
    args = ap.parse_args(argv)
    con = connect(args.db)
    brow = con.execute("SELECT id FROM binary WHERE repo_path=?", (args.repo,)).fetchone()
    if not brow:
        raise SystemExit(f"not in database: {args.repo}")
    dump_tree = args.out_dir / "dump-source"
    src_dir = resolve_source_dir(args.out_dir, args.program)
    if src_dir is None:
        raise SystemExit(
            f"no recovered C under {args.out_dir / args.program} or {dump_tree}. "
            "Recover → Dump source writes C under dump-source, then run Cross-place."
        )
    compile_ok = load_compile_ok_ids(args.out_dir)
    if compile_ok is None or not compile_ok:
        print(f"cross-place {args.program}: {{'placed': 0, 'reason': 'no compile receipt'}}")
        return 0
    if args.watch:
        watch(src_dir, int(brow["id"]), args.out_dir, con, args.interval)
        return 0
    stats = place_tree(src_dir, int(brow["id"]), args.out_dir, con, compile_ok=compile_ok)
    print(f"cross-place {args.program}: {stats}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
