"""Check Ghidra-bulk-compiled functions for a free byte-exact match.

Library entry points take explicit paths. Offline callers pass ``program=None``
or omit a source tree and get a skip result — no live Ghidra required.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ADDR_RE = re.compile(r"address:\s*0x([0-9a-fA-F]+)")


def real_bytes(raw: bytes, va2off, addr: int, size: int) -> bytes | None:
    off = va2off(addr)
    if off is None or off + size > len(raw):
        return None
    return raw[off : off + size]


def parse_address_from_header(text: str) -> int | None:
    match = ADDR_RE.search(text[:400] if text else "")
    return int(match.group(1), 16) if match else None


def jobs_from_sources(
    src_dir: Path | str,
    meta: dict[int, dict],
    raw: bytes,
    va2off,
    *,
    limit: int | None = None,
) -> dict:
    """Build compile jobs from already-written C files. No Ghidra."""
    root = Path(src_dir)
    if not root.is_dir():
        return {"jobs": [], "skipped_no_meta": 0, "skipped_no_bytes": 0, "skipped": "no-source-dir"}
    files = sorted(root.glob("*.c"))
    if limit:
        files = files[:limit]
    jobs = []
    skipped_no_meta = skipped_no_bytes = 0
    for path in files:
        head = path.read_text(errors="replace")
        addr = parse_address_from_header(head)
        if addr is None:
            continue
        info = meta.get(addr)
        if not info:
            skipped_no_meta += 1
            continue
        target = real_bytes(raw, va2off, addr, int(info.get("size") or 0))
        if target is None:
            skipped_no_bytes += 1
            continue
        body_text = head
        if body_text.startswith("/*"):
            end = body_text.find("*/\n")
            if end != -1:
                body_text = body_text[end + 3 :]
        row = dict(info)
        row["addr"] = addr
        row["target_bytes"] = target
        jobs.append((path.stem, path.stem, "", body_text, row))
    return {"jobs": jobs, "skipped_no_meta": skipped_no_meta, "skipped_no_bytes": skipped_no_bytes}


def verify(
    *,
    store_path: Path | str | None = None,
    src_dir: Path | str | None = None,
    raw_path: Path | str | None = None,
    recovered_dir: Path | str | None = None,
    coverage_dir: Path | str | None = None,
    program: object | None = None,
    repo_path: str | None = None,
    va2off=None,
    compile_one=None,
) -> dict:
    """Verify compiled Ghidra C against raw bytes.

    Skips when no program and no ``src_dir``/``raw_path`` are available.
    """
    if program is None and (src_dir is None or raw_path is None):
        return {"skipped": "no-program", "written": 0, "jobs": 0}
    if src_dir is None or raw_path is None:
        return {"skipped": "no-program", "written": 0, "jobs": 0}

    raw = Path(raw_path).read_bytes()
    mapper = va2off or (lambda addr: None)
    meta: dict[int, dict] = {}
    if store_path is not None and repo_path is not None:
        from .store import connect

        con = connect(store_path)
        brow = con.execute("SELECT id FROM binary WHERE repo_path=?", (repo_path,)).fetchone()
        if brow is None:
            return {"skipped": "no-program", "written": 0, "jobs": 0, "reason": "binary not in store"}
        for row in con.execute(
            "SELECT addr, canon_key, size, calling_convention, stack_param_size FROM func WHERE binary_id=?",
            (int(brow["id"]),),
        ):
            meta[int(row["addr"])] = dict(row)

    collected = jobs_from_sources(src_dir, meta, raw, mapper)
    jobs = collected["jobs"]
    written = 0
    ledger_rows = []
    for entry_hex, _name, _header, body, fn in jobs:
        target = fn["target_bytes"]
        got = compile_one(body, fn) if compile_one else None
        matched = bool(got is not None and got[: len(target)] == target and len(got) >= len(target))
        if not matched:
            continue
        written += 1
        fname = fn.get("canon_key") or f"FUN_{entry_hex}"
        if recovered_dir is not None:
            dest = Path(recovered_dir) / f"{fname}.c"
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(
                f"/*\n * {fname}\n * address: 0x{fn['addr']:x}   size: {fn['size']} bytes\n"
                f" * VERIFIED BYTE-EXACT: Ghidra decompilation recompiled to identical bytes\n */\n"
                + body,
                encoding="utf-8",
            )
        ledger_rows.append(
            {
                "batch": "ghidra-bulk-zero-llm",
                "byteExact": True,
                "byteExactVerified": True,
                "convention": fn.get("calling_convention"),
                "error": "",
                "function": fname,
                "matched": True,
                "originalBytes": target.hex(),
                "size": fn["size"],
            }
        )
    if coverage_dir is not None and ledger_rows:
        path = Path(coverage_dir) / "ghidra_verify.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            for row in ledger_rows:
                fh.write(json.dumps(row, sort_keys=True) + "\n")
    return {
        "written": written,
        "jobs": len(jobs),
        "skipped_no_meta": collected["skipped_no_meta"],
        "skipped_no_bytes": collected["skipped_no_bytes"],
        "program": program is not None,
    }
