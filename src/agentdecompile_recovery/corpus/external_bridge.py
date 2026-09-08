"""Bridge the identity store into an external recovery work tree.

The donor wrote enrichment and reuse artefacts for a named recovery product.
This module does the same join with caller-supplied output and mapping:

1. ``enrichment/<program>.json`` — canonical name / signature / source file
   keyed by entry address.
2. ``reuse_candidates.jsonl`` — independently identified recoveries and their
   sibling-build addresses.
3. ``priority_targets.jsonl`` — unrecovered logical functions ranked by
   cross-build payoff.

Nothing here writes into the external recovery tree.
"""

from __future__ import annotations

import json
import pathlib
from collections import defaultdict

from . import canon
from .store import ensure_priority_index

OUTDIR: pathlib.Path | None = None
EXTERNAL_ROOT: pathlib.Path | None = None
PROGRAM_MAP: dict[str, str] = {}


def _out(out_dir: pathlib.Path | None = None) -> pathlib.Path:
    dest = pathlib.Path(out_dir) if out_dir is not None else OUTDIR
    if dest is None:
        raise ValueError("out_dir is required (or patch OUTDIR)")
    return pathlib.Path(dest)


def _rev_map() -> dict[str, str]:
    return {v: k for k, v in PROGRAM_MAP.items()}


def emit_enrichment(con, *, out_dir: pathlib.Path | None = None) -> dict:
    """Per-program map: entry address -> everything the store knows about it."""
    dest = _out(out_dir)
    (dest / "enrichment").mkdir(parents=True, exist_ok=True)
    stats = {}
    for program_name, repo_path in PROGRAM_MAP.items():
        if repo_path in canon.DRM_EXCLUDED:
            continue
        row = con.execute("SELECT id FROM binary WHERE repo_path=?", (repo_path,)).fetchone()
        if row is None:
            continue
        out = {}
        for r in con.execute(
            """SELECT f.addr, f.name, f.canon_key, f.canon_class, f.canon_method,
                      f.canon_arity, f.signature, f.plate, f.source_file, f.object_file,
                      f.calling_convention, f.param_count, f.n_instr, f.size,
                      l.best_signature, i.confidence, i.method, i.logical_id
                 FROM func f
                 LEFT JOIN identity i ON i.binary_id=f.binary_id AND i.addr=f.addr
                 LEFT JOIN logical_function l ON l.id=i.logical_id
                WHERE f.binary_id=?""",
            (row["id"],),
        ):
            if not r["canon_key"] and not r["source_file"]:
                continue
            if canon.is_default_name(r["name"] or "") and not r["canon_key"] \
               and not r["source_file"]:
                continue
            rec = {
                "address": f"{r['addr']:08x}",
                "canonical_name": r["canon_key"],
                "class": r["canon_class"],
                "method": r["canon_method"],
                "arity": r["canon_arity"],
                "source_file": r["source_file"],
                "object_file": r["object_file"],
                "signature": r["best_signature"] or r["signature"],
                "calling_convention": r["calling_convention"],
                "logical_id": r["logical_id"],
                "identity_confidence": r["confidence"],
                "identity_method": r["method"],
            }
            out[rec["address"]] = {k: v for k, v in rec.items() if v is not None}
        p = dest / "enrichment" / f"{program_name}.json"
        p.write_text(json.dumps(out, indent=1, sort_keys=True))
        stats[program_name] = len(out)
    return stats


def load_recovered(con) -> list[dict]:
    """Load only recoveries admitted by the authoritative coverage-gated ingest."""
    return [
        {
            "program": row["program"],
            "function": row["name"],
            "path": row["path"],
            "binary_id": row["binary_id"],
            "addr": row["addr"],
            "size": row["size"],
            "byte_exact": True,
            "is_asm_only": not bool(row["real_c"]),
            "logical_id": row["logical_id"],
        }
        for row in con.execute(
            """SELECT program, name, path, binary_id, addr, size, real_c, logical_id
                 FROM recovered_function
                ORDER BY program, name"""
        )
    ]


def emit_reuse_candidates(con, *, out_dir: pathlib.Path | None = None) -> dict:
    """Emit cross-build targets only for independently identified recoveries."""
    dest = _out(out_dir)
    recovered = load_recovered(con)
    rows = []
    stats = defaultdict(int)
    rev = _rev_map()

    logical_ids = sorted({
        int(rec["logical_id"]) for rec in recovered if rec["logical_id"] is not None
    })
    metadata = {}
    members: dict[int, list] = defaultdict(list)
    if logical_ids:
        marks = ",".join("?" for _ in logical_ids)
        metadata = {
            int(row["id"]): row
            for row in con.execute(
                f"""SELECT id, canon_key, best_signature, source_file
                       FROM logical_function WHERE id IN ({marks})""",
                logical_ids,
            )
        }
        for row in con.execute(
            f"""SELECT i.logical_id, i.binary_id, i.addr, i.confidence, i.method,
                       b.repo_path, f.name, f.n_instr, f.size
                  FROM identity i
                  JOIN binary b ON b.id=i.binary_id
                  JOIN func f ON f.binary_id=i.binary_id AND f.addr=i.addr
                 WHERE i.logical_id IN ({marks})""",
            logical_ids,
        ):
            members[int(row["logical_id"])].append(row)

    for rec in recovered:
        logical_id = rec["logical_id"]
        if logical_id is None:
            stats["recovered_without_identity"] += 1
            continue
        stats["recovered_with_identity"] += 1
        logical_id = int(logical_id)
        logical = metadata.get(logical_id)
        logical_members = members.get(logical_id, [])
        source_members = [m for m in logical_members if m["binary_id"] == rec["binary_id"]]
        if rec["addr"] is not None:
            source_members = [m for m in source_members if m["addr"] == rec["addr"]]
        source = source_members[0] if len(source_members) == 1 else None
        if source is None or logical is None:
            stats["recovered_identity_missing_source_binding"] += 1
            continue
        siblings = [m for m in logical_members if m["binary_id"] != rec["binary_id"]]
        if not siblings:
            continue
        for s in siblings:
            stats["reuse_targets"] += 1
            rows.append(
                {
                    "logical_id": logical_id,
                    "canonical_name": logical["canon_key"],
                    "signature": logical["best_signature"],
                    "source_file": logical["source_file"],
                    "recovered_from": {
                        "program": rec["program"],
                        "function": rec["function"],
                        "address": (f"{rec['addr']:08x}" if rec["addr"] is not None
                                    else None),
                        "size": rec["size"],
                        "byte_exact": rec["byte_exact"],
                        "asm_only": rec["is_asm_only"],
                        "source_path": rec["path"],
                    },
                    "reuse_target": {
                        "program": rev.get(s["repo_path"], s["repo_path"]),
                        "repo_path": s["repo_path"],
                        "address": f"{s['addr']:08x}",
                        "current_name": s["name"],
                        "size": s["size"],
                        "n_instr": s["n_instr"],
                    },
                    "identity_confidence": min(
                        source["confidence"] or 0.0, s["confidence"] or 0.0
                    ),
                    "identity_methods": [source["method"], s["method"]],
                    "same_size": bool(s["size"] and rec["size"] and s["size"] == rec["size"]),
                }
            )

    dest.mkdir(parents=True, exist_ok=True)
    p = dest / "reuse_candidates.jsonl"
    rows.sort(key=lambda r: (-r["identity_confidence"], not r["same_size"]))
    with open(p, "w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")

    summary = {
        "recovered_functions_scanned": len(recovered),
        "recovered_byte_exact": len(recovered),
        **dict(stats),
        "reuse_rows": len(rows),
        "high_confidence_rows": sum(1 for r in rows if r["identity_confidence"] >= 0.9),
        "same_size_rows": sum(1 for r in rows if r["same_size"]),
    }
    (dest / "identity_reuse_summary.json").write_text(json.dumps(summary, indent=1))
    return summary


def emit_priority_targets(con, limit: int = 4000, *, out_dir: pathlib.Path | None = None) -> dict:
    """Rank unrecovered functions by how much one recovery would pay off."""
    dest = _out(out_dir)
    ensure_priority_index(con)
    rev = _rev_map()

    rows = con.execute(
        """WITH eligible AS MATERIALIZED (
               SELECT logical_id,
                      COUNT(DISTINCT binary_id) AS builds,
                      MIN(confidence) AS min_conf
                 FROM identity
                GROUP BY logical_id
               HAVING COUNT(DISTINCT binary_id) >= 2
                  AND MIN(confidence) >= 0.9
           )
           SELECT l.id AS logical_id, l.canon_key, l.best_signature, l.source_file,
                  e.builds, e.min_conf,
                  MIN(f.size) AS min_size, MAX(f.size) AS max_size,
                  MIN(f.n_instr) AS min_instr
             FROM eligible e
             JOIN logical_function l ON l.id = e.logical_id
             JOIN identity i ON i.logical_id = e.logical_id
             JOIN func f INDEXED BY ix_func_priority_cover
               ON f.binary_id = i.binary_id AND f.addr = i.addr
            WHERE l.canon_key IS NOT NULL
              AND f.n_instr > 0
            GROUP BY l.id
           HAVING MIN(f.size) <= 400
            ORDER BY e.builds DESC, MIN(f.size) ASC
            LIMIT ?""",
        (limit,),
    ).fetchall()

    con.execute("DROP TABLE IF EXISTS temp.priority_candidate")
    con.execute("CREATE TEMP TABLE priority_candidate(logical_id INTEGER PRIMARY KEY)")
    con.executemany(
        "INSERT INTO priority_candidate(logical_id) VALUES (?)",
        ((r["logical_id"],) for r in rows),
    )
    members_by_logical = defaultdict(list)
    for member in con.execute(
        """SELECT i.logical_id, b.repo_path, i.addr, f.size, f.name
             FROM priority_candidate p
             JOIN identity i ON i.logical_id = p.logical_id
             JOIN binary b ON b.id = i.binary_id
             JOIN func f INDEXED BY ix_func_priority_cover
               ON f.binary_id = i.binary_id AND f.addr = i.addr
            ORDER BY i.logical_id, i.binary_id"""
    ):
        members_by_logical[member["logical_id"]].append(member)

    already: set[str] = set()
    try:
        already = {
            row["name"] for row in con.execute("SELECT name FROM recovered_function")
        }
    except Exception:
        already = set()
    out = []
    for r in rows:
        members = members_by_logical.get(r["logical_id"], [])
        if any(m["name"] in already for m in members):
            continue
        out.append(
            {
                "logical_id": r["logical_id"],
                "canonical_name": r["canon_key"],
                "signature": r["best_signature"],
                "source_file": r["source_file"],
                "builds": r["builds"],
                "min_confidence": round(r["min_conf"], 4),
                "size_range": [r["min_size"], r["max_size"]],
                "payoff": r["builds"],
                "targets": [
                    {
                        "program": rev.get(m["repo_path"], m["repo_path"]),
                        "repo_path": m["repo_path"],
                        "address": f"{m['addr']:08x}",
                        "size": m["size"],
                        "current_name": m["name"],
                    }
                    for m in members
                ],
            }
        )

    dest.mkdir(parents=True, exist_ok=True)
    p = dest / "priority_targets.jsonl"
    with open(p, "w") as fh:
        for r in out:
            fh.write(json.dumps(r) + "\n")
    summary = {
        "candidates": len(out),
        "total_reuse_if_all_recovered": sum(r["builds"] for r in out),
        "with_source_file": sum(1 for r in out if r.get("source_file")),
        "in_8plus_builds": sum(1 for r in out if r["builds"] >= 8),
    }
    (dest / "priority_summary.json").write_text(json.dumps(summary, indent=1))
    return summary
