"""Write feature-rich function snapshots for the corpus pipeline.

Ghidra-backed extract needs a live program. JSON snapshots do not: they accept
already-extracted rows (strings, consts, mnem, edges) and write ``{id}.functions.json``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .canon import canonicalize
from .corpus_config import load_maps
from .features import merge_tiers, tier1, tier2
from .io import write_json
from .store import j


def slugify(repo_path: str) -> str:
    return repo_path.strip("/").replace("/", "__").replace(" ", "_")


def resolve_source(repo_path: str, *, workspace: Path | str | None = None) -> str:
    """Map a canonical repo path to a local analysed copy when maps.json says so.

    ``maps.json`` may contain ``local_sources``: {repo_path: template}.
    Templates may include ``{w}`` for the workspace path. There is no built-in
    product map.
    """
    sources = dict(load_maps().get("local_sources") or {})
    tpl = sources.get(repo_path)
    if not tpl:
        return repo_path
    work = workspace or ""
    return str(tpl).format(w=work)


def snapshot_path(out_dir: Path, binary_id: str) -> Path:
    return Path(out_dir) / f"{binary_id}.functions.json"


def write_snapshot(out_dir: Path, binary_id: str, functions: list[dict[str, Any]]) -> Path:
    dest = snapshot_path(out_dir, binary_id)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(functions, indent=2) + "\n", encoding="utf-8")
    return dest


def enrich_canon(row: dict[str, Any]) -> dict[str, Any]:
    canon = canonicalize(
        row.get("name") or "",
        namespace=row.get("namespace") or "",
        plate=row.get("plate"),
        dm_name=row.get("dm_name"),
        dm_namespace=row.get("dm_namespace"),
        dm_params=row.get("dm_params"),
    )
    merged = dict(row)
    merged.update(canon)
    return merged


def functions_from_program(program, monitor=None) -> list[dict[str, Any]]:
    t1 = tier1(program)
    t2 = tier2(program, monitor)
    return [enrich_canon(row) for row in merge_tiers(t1, t2)]


def upsert_binary(con, *, repo_path: str, slug: str, program=None, meta: dict[str, Any] | None = None) -> int:
    """Insert or update a binary row. *meta* supplies game/platform/arch when known."""
    info = dict(meta or {})
    if program is not None:
        ld = program.getLanguage().getLanguageDescription()
        info.setdefault("language_id", str(ld.getLanguageID()))
        info.setdefault("arch", str(ld.getProcessor()))
        info.setdefault("bits", int(ld.getSize()))
        info.setdefault("format", str(program.getExecutableFormat()))
        info.setdefault("md5", str(program.getExecutableMD5()))
        info.setdefault("image_base", int(program.getImageBase().getOffset()))
    con.execute(
        """INSERT INTO binary(repo_path, slug, game, platform, variant, language_id,
                              arch, bits, format, md5, image_base, role)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(repo_path) DO UPDATE SET
             slug=excluded.slug, game=excluded.game, platform=excluded.platform,
             language_id=excluded.language_id, arch=excluded.arch, bits=excluded.bits,
             format=excluded.format, md5=excluded.md5, image_base=excluded.image_base,
             role=excluded.role""",
        (
            repo_path,
            slug,
            info.get("game"),
            info.get("platform"),
            info.get("variant"),
            info.get("language_id"),
            info.get("arch"),
            info.get("bits"),
            info.get("format"),
            info.get("md5"),
            info.get("image_base"),
            info.get("role"),
        ),
    )
    row = con.execute("SELECT id FROM binary WHERE repo_path=?", (repo_path,)).fetchone()
    con.commit()
    return int(row[0])


def persist_functions(con, binary_id: int, functions: list[dict[str, Any]]) -> int:
    payload = []
    edges = []
    for row in functions:
        addr = int(row.get("addr") or 0)
        payload.append(
            (
                binary_id,
                addr,
                row.get("name"),
                row.get("namespace"),
                row.get("source"),
                row.get("size"),
                row.get("ranges"),
                int(bool(row.get("is_thunk"))),
                row.get("thunked_to"),
                row.get("calling_convention"),
                row.get("return_type"),
                row.get("param_count"),
                j(row.get("param_types")),
                row.get("stack_frame_size"),
                row.get("stack_param_size"),
                row.get("stack_local_size"),
                row.get("plate"),
                row.get("signature"),
                row.get("n_instr"),
                row.get("n_blocks"),
                row.get("n_edges"),
                row.get("back_edges"),
                row.get("cyclomatic"),
                row.get("n_callees"),
                row.get("indirect_calls"),
                row.get("data_refs"),
                j(row.get("mnem") or row.get("mnemonic_counts")),
                j(row.get("strings")),
                j(row.get("consts")),
                j(row.get("ext_calls")),
                row.get("canon_class"),
                row.get("canon_method"),
                row.get("canon_key"),
                row.get("canon_arity"),
                row.get("name_origin"),
            )
        )
        for callee in row.get("callees") or row.get("callee_addrs") or []:
            edges.append((binary_id, addr, int(callee)))
    con.execute("DELETE FROM calledge WHERE binary_id=?", (binary_id,))
    con.execute("DELETE FROM func WHERE binary_id=?", (binary_id,))
    con.executemany(
        """INSERT INTO func(
               binary_id, addr, name, namespace, source, size, ranges, is_thunk, thunked_to,
               calling_convention, return_type, param_count, param_types,
               stack_frame_size, stack_param_size, stack_local_size, plate, signature,
               n_instr, n_blocks, n_edges, back_edges, cyclomatic, n_callees,
               indirect_calls, data_refs, mnem, strings, consts, ext_calls,
               canon_class, canon_method, canon_key, canon_arity, name_origin
           ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        payload,
    )
    if edges:
        con.executemany(
            "INSERT INTO calledge(binary_id, caller_addr, callee_addr) VALUES (?,?,?)",
            edges,
        )
    con.execute("UPDATE binary SET func_count=? WHERE id=?", (len(payload), binary_id))
    con.commit()
    return len(payload)


def write_extract_receipt(work_dir: Path, counts: dict[str, int]) -> Path:
    dest = Path(work_dir) / "extract.json"
    write_json(dest, {"functions": counts, "total": sum(counts.values())})
    return dest
