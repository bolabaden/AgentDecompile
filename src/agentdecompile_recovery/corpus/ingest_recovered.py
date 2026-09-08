"""Bind recovered C to the identity layer without inventing identities.

A recovered body inherits a logical id only when that source address or name
already has an independently established identity. Byte equality is a reuse
proposal, not identity evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sqlite3
from collections import defaultdict

from .source_claims import is_real_c

SHRINK_FLOOR = 0.7
HDR_SIZE = re.compile(r"size:\s*(\d+)\s*bytes", re.I)
HDR_CONV = re.compile(r"calling convention:\s*(\S+)", re.I)
HDR_CODE = re.compile(r"original machine code:\s*([0-9a-fA-F]+)")
HDR_EVID = re.compile(r"evidence:\s*(\S+)")
ADDR_IN_NAME = re.compile(r"(?:FUN|sub|LAB)_([0-9a-fA-F]{6,16})")
ADDR_SUFFIX = re.compile(r"_([0-9a-fA-F]{6,16})$")

RECOVERED_SCHEMA = """
CREATE TABLE IF NOT EXISTS recovered_function (
    program      TEXT NOT NULL,
    binary_id    INTEGER,
    addr         INTEGER,
    name         TEXT NOT NULL,
    size         INTEGER,
    convention   TEXT,
    machine_code TEXT,
    real_c       INTEGER NOT NULL,
    logical_id   INTEGER,
    path         TEXT NOT NULL,
    evidence     TEXT,
    PRIMARY KEY (program, name)
);
CREATE INDEX IF NOT EXISTS ix_recovered_logical ON recovered_function(logical_id);

CREATE TABLE IF NOT EXISTS reuse_candidate (
    src_program   TEXT NOT NULL,
    src_name      TEXT NOT NULL,
    dst_binary_id INTEGER NOT NULL,
    dst_addr      INTEGER NOT NULL,
    dst_name      TEXT,
    size          INTEGER NOT NULL,
    real_c        INTEGER NOT NULL,
    basis         TEXT NOT NULL,
    PRIMARY KEY (src_program, src_name, dst_binary_id, dst_addr)
);
CREATE INDEX IF NOT EXISTS ix_reuse_dst ON reuse_candidate(dst_binary_id, dst_addr);
"""


def ensure_recovered_schema(con: sqlite3.Connection) -> None:
    con.executescript(RECOVERED_SCHEMA)
    con.commit()


def load_coverage_index(coverage_dir: pathlib.Path) -> dict[tuple[str, str], dict]:
    """Return authoritative byte-exact rows keyed by program and function."""
    verified: dict[tuple[str, str], dict] = {}
    coverage_dir = pathlib.Path(coverage_dir)
    if not coverage_dir.is_dir():
        return verified
    for ledger in sorted(coverage_dir.glob("*.jsonl")):
        program = ledger.stem
        with ledger.open(errors="replace") as fh:
            for line in fh:
                try:
                    row = json.loads(line)
                except (ValueError, TypeError):
                    continue
                name = row.get("function")
                if name and row.get("byteExact") is True:
                    verified[(program, str(name))] = row
    return verified


def load_verified_coverage(coverage_dir: pathlib.Path) -> set[tuple[str, str]]:
    """Authoritative ``(program, function)`` rows with a byte-exact verdict."""
    return set(load_coverage_index(coverage_dir))


def parse_recovered(
    recovered_dir: pathlib.Path,
    coverage_dir: pathlib.Path,
) -> list[dict]:
    """Read only files backed by ``byteExact=true`` in the coverage ledger."""
    rows = []
    recovered_dir = pathlib.Path(recovered_dir)
    if not recovered_dir.is_dir():
        return rows
    verified = load_coverage_index(coverage_dir)
    for pdir in sorted(recovered_dir.iterdir()):
        if not pdir.is_dir():
            continue
        for f in sorted(pdir.glob("*.c")) + sorted(pdir.glob("*.cpp")):
            try:
                text = f.read_text(errors="replace")
            except OSError:
                continue
            head = text[:1200]
            size = HDR_SIZE.search(head)
            conv = HDR_CONV.search(head)
            code = HDR_CODE.search(head)
            evid = HDR_EVID.search(head)
            name = f.stem
            coverage = verified.get((pdir.name, name))
            if coverage is None:
                continue
            m = ADDR_IN_NAME.search(name) or ADDR_SUFFIX.search(name)
            machine_code = code.group(1).lower() if code else None
            if not machine_code:
                ledger_code = coverage.get("originalBytes")
                if isinstance(ledger_code, str) and re.fullmatch(
                    r"[0-9a-fA-F]+", ledger_code
                ):
                    machine_code = ledger_code.lower()
            rows.append({
                "program": pdir.name,
                "name": name,
                "addr": int(m.group(1), 16) if m else None,
                "size": int(size.group(1)) if size else None,
                "convention": conv.group(1) if conv else None,
                "machine_code": machine_code,
                "evidence": evid.group(1) if evid else None,
                "real_c": 1 if is_real_c(text) else 0,
                "path": str(f),
            })
    return rows


def _normalized_hex(value: str | int) -> str:
    return f"{int(str(value), 16):x}" if not isinstance(value, int) else f"{value:x}"


def load_seed_promotions(
    con,
    results_path: pathlib.Path,
    reuse_path: pathlib.Path,
) -> list[dict]:
    """Load seeds that proved identity and destination byte-exact compilation."""
    results_path = pathlib.Path(results_path)
    reuse_path = pathlib.Path(reuse_path)
    if not results_path.is_file() or not reuse_path.is_file():
        return []

    reuse_ids: dict[tuple[str, str, str], set[int]] = defaultdict(set)
    with reuse_path.open() as fh:
        for line in fh:
            if not line.strip():
                continue
            row = json.loads(line)
            source = row.get("recovered_from") or {}
            target = row.get("reuse_target") or {}
            if source.get("source_path") and target.get("repo_path") \
                    and target.get("address") is not None \
                    and row.get("logical_id") is not None:
                key = (
                    source["source_path"], target["repo_path"],
                    _normalized_hex(target["address"]),
                )
                reuse_ids[key].add(int(row["logical_id"]))

    binaries = {
        row["slug"]: (int(row["id"]), row["repo_path"])
        for row in con.execute("SELECT id, slug, repo_path FROM binary")
    }
    promotions = []
    with results_path.open() as fh:
        for line in fh:
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("static_status") != "identity_linked" \
                    or row.get("compile_status") != "byte_exact" \
                    or row.get("real_c") is not True:
                continue
            binary = binaries.get(row.get("dst_slug"))
            if binary is None:
                continue
            binary_id, repo_path = binary
            addr = int(row["dst_addr"], 16)
            key = (row["source_path"], repo_path, _normalized_hex(addr))
            logical_ids = set(int(x) for x in row.get("logical_ids") or [])
            if not logical_ids:
                logical_ids = reuse_ids.get(key, set())
            destination = con.execute(
                "SELECT logical_id FROM identity WHERE binary_id=? AND addr=?",
                (binary_id, addr),
            ).fetchone()
            if destination is None or logical_ids != {int(destination[0])}:
                continue
            seed_path = pathlib.Path(row["seed"])
            try:
                seed_text = seed_path.read_text(errors="replace")
            except OSError:
                continue
            if not is_real_c(seed_text):
                continue
            promotions.append({
                "program": row["dst_slug"].split("__", 1)[-1],
                "binary_id": binary_id,
                "addr": addr,
                "name": row.get("source_name") or row.get("dst_name"),
                "size": int(row["size"]),
                "convention": None,
                "machine_code": row["destination_bytes"].lower(),
                "real_c": 1,
                "logical_id": int(destination[0]),
                "path": str(seed_path),
                "evidence": f"seed-validation-byte-exact:{results_path}",
            })
    return promotions


def apply_seed_promotions(con, promotions: list[dict]) -> int:
    ensure_recovered_schema(con)
    con.executemany(
        "INSERT OR REPLACE INTO recovered_function"
        "(program, binary_id, addr, name, size, convention, machine_code,"
        " real_c, logical_id, path, evidence) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        [(r["program"], r["binary_id"], r["addr"], r["name"], r["size"],
          r["convention"], r["machine_code"], r["real_c"], r["logical_id"],
          r["path"], r["evidence"]) for r in promotions],
    )
    con.commit()
    return len(promotions)


def prune_unverified(con, verified_rows: list[dict]) -> tuple[int, int]:
    """Remove stale DB rows whose source lacks an authoritative verdict."""
    keep = {(r["program"], r["name"]) for r in verified_rows}
    stale = [
        (program, name)
        for program, name in con.execute(
            "SELECT program, name FROM recovered_function"
        )
        if (program, name) not in keep
    ]
    if stale:
        con.executemany(
            "DELETE FROM recovered_function WHERE program=? AND name=?", stale
        )
        con.executemany(
            "DELETE FROM reuse_candidate WHERE src_program=? AND src_name=?", stale
        )
    con.commit()
    return len(stale), len(keep)


def existing_logical_for_recovery(con, row: dict) -> int | None:
    """Return only an identity established independently of recovered bytes."""
    binary_id = row.get("binary_id")
    if binary_id is None:
        return None
    if row.get("addr") is not None:
        got = con.execute(
            "SELECT logical_id FROM identity WHERE binary_id=? AND addr=?",
            (binary_id, row["addr"]),
        ).fetchone()
        return int(got[0]) if got else None

    name = row.get("name") or ""
    keys = {name}
    if "_" in name:
        owner, _, method = name.rpartition("_")
        keys.add(f"{owner}::{method}")
    marks = ",".join("?" for _ in keys)
    matches = con.execute(
        f"""SELECT DISTINCT i.logical_id, f.addr
              FROM func f
              JOIN identity i ON i.binary_id=f.binary_id AND i.addr=f.addr
             WHERE f.binary_id=?
               AND (f.name IN ({marks}) OR f.canon_key IN ({marks}))""",
        (binary_id, *sorted(keys), *sorted(keys)),
    ).fetchall()
    return int(matches[0][0]) if len(matches) == 1 else None


def recovery_identity_indexes(con, rows: list[dict]) -> tuple[dict, dict]:
    """Resolve all recovered rows with two sequential queries."""
    address_identity = {
        (int(r["binary_id"]), int(r["addr"])): int(r["logical_id"])
        for r in con.execute("SELECT binary_id, addr, logical_id FROM identity")
    }
    names_by_binary: dict[int, dict[str, set[str]]] = defaultdict(dict)
    for row in rows:
        bid = row.get("binary_id")
        if bid is None or row.get("addr") is not None:
            continue
        name = row.get("name") or ""
        keys = {name}
        if "_" in name:
            owner, _, method = name.rpartition("_")
            keys.add(f"{owner}::{method}")
        names_by_binary[int(bid)][name] = keys

    matches: dict[tuple[int, str], set[tuple[int, int]]] = defaultdict(set)
    bids = sorted(names_by_binary)
    if bids:
        marks = ",".join("?" for _ in bids)
        for r in con.execute(
            f"""SELECT f.binary_id, f.addr, f.name, f.canon_key, i.logical_id
                  FROM identity i
                  JOIN func f ON f.binary_id=i.binary_id AND f.addr=i.addr
                 WHERE f.binary_id IN ({marks})""",
            bids,
        ):
            bid = int(r["binary_id"])
            observed = {r["name"] or "", r["canon_key"] or ""}
            for recovered_name, keys in names_by_binary[bid].items():
                if observed & keys:
                    matches[(bid, recovered_name)].add(
                        (int(r["logical_id"]), int(r["addr"]))
                    )
    named_identity = {
        key: next(iter(values))[0]
        for key, values in matches.items() if len(values) == 1
    }
    return address_identity, named_identity


def logical_from_indexes(row: dict, address_identity: dict,
                         named_identity: dict) -> int | None:
    bid = row.get("binary_id")
    if bid is None:
        return None
    if row.get("addr") is not None:
        return address_identity.get((int(bid), int(row["addr"])))
    return named_identity.get((int(bid), row.get("name") or ""))


def function_bytes_index(
    con,
    raw_dir: pathlib.Path,
    mapper_for,
) -> dict[str, list[tuple[int, int, str, int]]]:
    """sha1(bytes) -> [(binary_id, addr, name, size)] across every binary."""
    index: dict[str, list[tuple[int, int, str, int]]] = defaultdict(list)
    raw_dir = pathlib.Path(raw_dir)
    binaries = [dict(r) for r in con.execute(
        "SELECT id, repo_path, slug FROM binary ORDER BY id")]
    for b in binaries:
        raw = raw_dir / b["slug"]
        if not raw.exists():
            continue
        blob = raw.read_bytes()
        mapper, _kind = mapper_for(blob)
        if mapper is None:
            continue
        for addr, name, size in con.execute(
                "SELECT addr, name, size FROM func "
                "WHERE binary_id=? AND size>0 AND n_instr>0", (b["id"],)):
            off = mapper(addr)
            if off is None or off + size > len(blob):
                continue
            h = hashlib.sha1(blob[off:off + size]).hexdigest()
            index[h].append((b["id"], addr, name, size))
        del blob
    return index


def ingest(
    con,
    *,
    recovered_dir: pathlib.Path,
    coverage_dir: pathlib.Path,
    out_dir: pathlib.Path,
    program_to_repo: dict[str, str] | None = None,
    seed_results: pathlib.Path | None = None,
    reuse_candidates: pathlib.Path | None = None,
    raw_dir: pathlib.Path | None = None,
    mapper_for=None,
    force: bool = False,
) -> dict:
    """Parse recovered trees, bind existing identities, write reuse summary."""
    ensure_recovered_schema(con)
    rows = parse_recovered(recovered_dir, coverage_dir)
    if seed_results and reuse_candidates:
        rows = rows + load_seed_promotions(con, seed_results, reuse_candidates)
    have = con.execute(
        "SELECT COUNT(*) c, COALESCE(SUM(real_c),0) rc FROM recovered_function"
    ).fetchone()
    if have["c"] and len(rows) < have["c"] * SHRINK_FLOOR and not force:
        raise RuntimeError(
            f"refusing to rebuild: would go from {have['c']} rows to {len(rows)}"
        )
    con.execute("DELETE FROM identity WHERE method='identical-bytes'")
    con.execute("DELETE FROM logical_function WHERE canon_key LIKE 'recovered::%'")
    con.execute("DELETE FROM reuse_candidate")
    con.execute("DELETE FROM recovered_function")
    con.commit()

    repo_ids = {r["repo_path"]: r["id"] for r in
                con.execute("SELECT id, repo_path FROM binary")}
    mapping = program_to_repo or {}
    for r in rows:
        repo = mapping.get(r["program"])
        r["binary_id"] = repo_ids.get(repo) if repo else None

    address_identity, named_identity = recovery_identity_indexes(con, rows)
    index: dict = {}
    if raw_dir is not None and mapper_for is not None:
        index = function_bytes_index(con, raw_dir, mapper_for)

    reuse, bound = [], 0
    for r in rows:
        if r.get("machine_code") and index:
            h = hashlib.sha1(bytes.fromhex(r["machine_code"])).hexdigest()
            for bid, addr, name, size in index.get(h, []):
                if bid == r["binary_id"] and addr == r["addr"]:
                    continue
                reuse.append((r["program"], r["name"], bid, addr, name, size,
                              r["real_c"], "identical-bytes-uncompiled"))
        r["logical_id"] = logical_from_indexes(r, address_identity, named_identity)
        bound += r["logical_id"] is not None

    con.executemany(
        "INSERT OR REPLACE INTO recovered_function"
        "(program, binary_id, addr, name, size, convention, machine_code,"
        " real_c, logical_id, path, evidence) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        [(r["program"], r["binary_id"], r["addr"], r["name"], r["size"],
          r["convention"], r["machine_code"], r["real_c"], r.get("logical_id"),
          r["path"], r["evidence"]) for r in rows])
    con.executemany(
        "INSERT OR REPLACE INTO reuse_candidate"
        "(src_program, src_name, dst_binary_id, dst_addr, dst_name, size,"
        " real_c, basis) VALUES (?,?,?,?,?,?,?,?)", reuse)
    con.commit()
    summary = print_summary(con, pathlib.Path(out_dir))
    summary["linked"] = bound
    return summary


def print_summary(con, out_dir: pathlib.Path) -> dict:
    def one(sql):
        r = con.execute(sql).fetchone()
        return r[0] if r else 0

    total = one("SELECT COUNT(*) FROM recovered_function")
    real = one("SELECT COUNT(*) FROM recovered_function WHERE real_c=1")
    boundn = one("SELECT COUNT(*) FROM recovered_function WHERE logical_id IS NOT NULL")
    summary = {
        "recovered_functions_scanned": total,
        "recovered_real_c": real,
        "recovered_asm_shim": total - real,
        "recovered_bound_to_logical": boundn,
        "recovered_without_identity": total - boundn,
        "real_c_bound_to_logical": one(
            "SELECT COUNT(*) FROM recovered_function WHERE real_c=1 AND logical_id IS NOT NULL"
        ),
        "reuse_rows": one("SELECT COUNT(*) FROM reuse_candidate"),
        "reuse_rows_real_c": one("SELECT COUNT(*) FROM reuse_candidate WHERE real_c=1"),
        "reuse_target_binaries": one("SELECT COUNT(DISTINCT dst_binary_id) FROM reuse_candidate"),
        "identity_rule": (
            "recovered source inherits only a pre-existing identity at "
            "its own independently resolved source address or name"
        ),
    }
    dest = pathlib.Path(out_dir)
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "reuse_summary.json").write_text(json.dumps(summary, indent=1))
    return summary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", type=pathlib.Path, required=True)
    ap.add_argument("--recovered-dir", type=pathlib.Path, required=True)
    ap.add_argument("--coverage-dir", type=pathlib.Path, required=True)
    ap.add_argument("--out-dir", type=pathlib.Path, required=True)
    ap.add_argument("--seed-results", type=pathlib.Path)
    ap.add_argument("--reuse-candidates", type=pathlib.Path)
    ap.add_argument("--report", action="store_true")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args(argv)
    from .store import connect
    con = connect(args.db)
    ensure_recovered_schema(con)
    if args.report:
        print_summary(con, args.out_dir)
        return 0
    ingest(
        con,
        recovered_dir=args.recovered_dir,
        coverage_dir=args.coverage_dir,
        out_dir=args.out_dir,
        seed_results=args.seed_results,
        reuse_candidates=args.reuse_candidates,
        force=args.force,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
