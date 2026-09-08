"""Build a read-only, address-level manifest from fresh Mach-O N_FUN records.

Only an exact N_FUN address intersection can become an application candidate.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from .naming import HUMAN, tier_of


def _candidate_key(row: dict) -> tuple:
    return (
        row.get("name"),
        row.get("source_file"),
        row.get("object_file"),
        row.get("stabs_type"),
    )


def build_records(
    stabs_functions: list[dict], database_functions: dict[int, dict]
) -> tuple[list[dict], dict]:
    """Return one manifest record per unique N_FUN address and its summary."""
    by_addr: dict[int, list[dict]] = defaultdict(list)
    for function in stabs_functions:
        by_addr[int(function["addr"])].append(function)

    records = []
    ambiguous = hits = misses = applicable = 0
    for addr in sorted(by_addr):
        candidates = list(dict.fromkeys(_candidate_key(row) for row in by_addr[addr]))
        current = database_functions.get(addr)
        record = {
            "addr": addr,
            "addr_hex": f"0x{addr:x}",
            "address_hit": current is not None,
            "n_fun_records": len(by_addr[addr]),
            "database_name": current.get("name") if current else None,
            "database_name_origin": current.get("name_origin") if current else None,
            "n_instr": current.get("n_instr") if current else None,
        }
        if current is None:
            misses += 1
        else:
            hits += 1
        if len(candidates) != 1:
            ambiguous += 1
            record["action"] = "ambiguous_n_fun"
            record["candidates"] = [
                {
                    "stabs_name": item[0],
                    "source_file": item[1],
                    "object_file": item[2],
                    "stabs_type": item[3],
                }
                for item in candidates
            ]
        else:
            name, source_file, object_file, stabs_type = candidates[0]
            record.update(
                stabs_name=name,
                source_file=source_file,
                object_file=object_file,
                stabs_type=stabs_type,
            )
            if current is None:
                record["action"] = "address_miss"
            else:
                applicable += 1
                proposed = {**current, "stabs_name": name}
                if tier_of(proposed) == HUMAN:
                    record["action"] = "keep_human_attach_metadata"
                elif (current.get("stabs_name") or "").strip() == (name or "").strip():
                    record["action"] = "already_attached"
                else:
                    record["action"] = "attach_stabs"
        records.append(record)

    summary = {
        "n_fun_records": len(stabs_functions),
        "n_fun_unique_addresses": len(by_addr),
        "duplicate_n_fun_records": len(stabs_functions) - len(by_addr),
        "func_address_hits": hits,
        "address_misses": misses,
        "ambiguous_addresses": ambiguous,
        "applicable_addresses": applicable,
        "rule": "Only exact, unambiguous N_FUN-to-func address intersections are applicable.",
        "database_mutated": False,
    }
    return records, summary


def write_manifest(records: list[dict[str, Any]], summary: dict[str, Any], dest_dir: Path, slug: str) -> tuple[Path, Path]:
    dest_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = dest_dir / f"{slug}.manifest.jsonl"
    summary_path = dest_dir / f"{slug}.summary.json"
    manifest_path.write_text("".join(json.dumps(item) + "\n" for item in records), encoding="utf-8")
    summary_path.write_text(json.dumps(summary, indent=1) + "\n", encoding="utf-8")
    return manifest_path, summary_path


def generate(
    con,
    repo_path: str,
    *,
    raw_dir: Path,
    out_dir: Path,
) -> tuple[Path, Path, dict]:
    """Build a dry-run manifest from fresh Mach-O N_FUN records."""
    from .machostabs import analyze as analyze_macho
    from .stabs_link import select_slices

    row = con.execute(
        "SELECT id, slug, repo_path, arch FROM binary WHERE repo_path=?",
        (repo_path,),
    ).fetchone()
    if row is None:
        raise KeyError(f"binary not found: {repo_path}")
    from .stabs_link import ensure_columns

    ensure_columns(con)
    raw = Path(raw_dir) / row["slug"]
    if not raw.is_file():
        raise FileNotFoundError(f"raw image not found: {raw}")
    result = analyze_macho(raw)
    stabs_functions: list[dict] = []
    for image_slice in select_slices(result, row["arch"]):
        stabs_functions.extend((image_slice.get("stabs") or {}).get("functions") or [])
    database_functions = {
        int(item["addr"]): dict(item)
        for item in con.execute(
            """SELECT addr, name, name_origin, n_instr, source_file, object_file,
                      stabs_name, stabs_type
                 FROM func WHERE binary_id=?""",
            (row["id"],),
        )
    }
    records, summary = build_records(stabs_functions, database_functions)
    summary.update(
        repo_path=repo_path,
        binary_id=row["id"],
        slug=row["slug"],
        architecture=row["arch"],
        raw_image=str(raw),
    )
    manifest_path, summary_path = write_manifest(records, summary, Path(out_dir), row["slug"])
    return manifest_path, summary_path, summary
