"""Attach STABS source-file / object-file attribution to extracted functions.

Once those addresses are joined to the `func` table, compilation-unit membership
becomes a matching constraint, and source attribution can be carried onto builds
that never had it.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from .machostabs import analyze as analyze_macho
from .stabs_manifest import build_records

STABS_TYPE_DDL = """
CREATE TABLE IF NOT EXISTS stabs_type (
    id INTEGER PRIMARY KEY,
    binary_id INTEGER NOT NULL,
    source_file TEXT,
    object_file TEXT,
    name TEXT NOT NULL,
    kind TEXT,
    stab TEXT NOT NULL,
    func_addr INTEGER,
    UNIQUE(binary_id, source_file, name, kind, stab, func_addr)
)
"""

ADD_COLUMNS = [
    ("source_file", "TEXT"),
    ("object_file", "TEXT"),
    ("stabs_name", "TEXT"),
    ("stabs_type", "TEXT"),
]


def ensure_columns(con) -> None:
    have = {r[1] for r in con.execute("PRAGMA table_info(func)")}
    for name, typ in ADD_COLUMNS:
        if name not in have:
            con.execute(f"ALTER TABLE func ADD COLUMN {name} {typ}")
    con.execute("CREATE INDEX IF NOT EXISTS ix_func_srcfile ON func(binary_id, source_file)")
    con.commit()


def _normalise_arch(arch: str | None) -> str:
    value = (arch or "").strip().lower()
    aliases = {
        "x86": "i386",
        "x86_32": "i386",
        "amd64": "x86_64",
        "aarch64": "arm64",
        "powerpc": "ppc",
        "powerpc64": "ppc64",
    }
    return aliases.get(value, value)


def select_slices(result: dict, binary_arch: str | None) -> list[dict]:
    """Select only the Mach-O slice represented by a binary database row."""
    available = [sl for sl in result.get("slices") or [] if sl.get("stabs")]
    wanted = _normalise_arch(binary_arch)
    if wanted:
        selected = [sl for sl in available if _normalise_arch(sl.get("arch")) == wanted]
        if not selected and available:
            raise ValueError(
                f"no STABS slice for binary architecture {binary_arch!r}; "
                f"available: {[sl.get('arch') for sl in available]}"
            )
        return selected
    if len(available) > 1:
        raise ValueError(
            "binary architecture is missing for a multi-slice Mach-O; refusing "
            "to merge independent address spaces"
        )
    return available


def replace_stabs_types(con, binary_id: int, types: list[dict]) -> int:
    """Atomically refresh one binary's parsed types, including nullable rows."""
    con.execute(STABS_TYPE_DDL)
    con.execute("CREATE INDEX IF NOT EXISTS ix_stabs_type_bin ON stabs_type(binary_id, kind)")
    con.execute("CREATE INDEX IF NOT EXISTS ix_stabs_type_src ON stabs_type(binary_id, source_file)")
    con.commit()
    payload = list(dict.fromkeys(
        (
            binary_id,
            t.get("source_file"),
            t.get("object_file"),
            t["name"],
            t.get("kind"),
            t["stab"],
            t.get("func_addr"),
        )
        for t in types
        if t.get("name")
    ))
    with con:
        con.execute("DELETE FROM stabs_type WHERE binary_id=?", (binary_id,))
        con.executemany(
            """INSERT INTO stabs_type
               (binary_id, source_file, object_file, name, kind, stab, func_addr)
               VALUES (?,?,?,?,?,?,?)""",
            payload,
        )
    return len(payload)


def apply_manifest_records(con, binary_id: int, records: list[dict], *, commit: bool = True) -> int:
    """Attach only records admitted by the reviewed address-level manifest."""
    allowed = {"attach_stabs", "already_attached", "keep_human_attach_metadata"}
    payload = [
        (
            row.get("source_file"),
            row.get("object_file"),
            row.get("stabs_name"),
            row.get("stabs_type"),
            binary_id,
            row["addr"],
        )
        for row in records
        if row.get("action") in allowed
    ]
    con.executemany(
        """UPDATE func
              SET source_file = CASE WHEN source_file IS NULL THEN ? ELSE source_file END,
                  object_file = CASE WHEN source_file IS NULL THEN ? ELSE object_file END,
                  stabs_name = ?,
                  stabs_type = ?
            WHERE binary_id=? AND addr=?""",
        payload,
    )
    if commit:
        con.commit()
    return len(payload)


def manifest_donor_rows(con, repo_paths: set[str], manifest_dir: Path) -> list[dict]:
    """Load authoritative source/object pairs from reviewed manifest artifacts."""
    allowed = {"attach_stabs", "already_attached", "keep_human_attach_metadata"}
    donors = []
    for repo_path in sorted(repo_paths):
        binary = con.execute(
            "SELECT id, slug FROM binary WHERE repo_path=?", (repo_path,)
        ).fetchone()
        if binary is None:
            raise KeyError(repo_path)
        path = Path(manifest_dir) / f"{binary['slug']}.manifest.jsonl"
        if not path.is_file():
            raise RuntimeError(f"missing reviewed manifest {path}")
        for line in path.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            if row.get("action") not in allowed:
                continue
            donors.append({
                "binary_id": binary["id"],
                "addr": row["addr"],
                "source_file": row["source_file"],
                "object_file": row.get("object_file"),
            })
    return donors


def link(
    con,
    repo_paths: set[str] | None = None,
    *,
    raw_dir: Path,
    manifest_dir: Path,
    index: dict[str, dict] | None = None,
) -> dict:
    """Apply reviewed manifests for binaries whose raw images live in *raw_dir*."""
    ensure_columns(con)
    stats = {}
    entries = index or {}
    if not entries:
        for raw in Path(raw_dir).iterdir() if Path(raw_dir).is_dir() else []:
            if raw.is_file() and not raw.name.startswith("."):
                entries[raw.name] = {"repo_path": raw.name}
    for fname, meta in entries.items():
        repo_path = meta["repo_path"]
        if repo_paths is not None and repo_path not in repo_paths:
            continue
        raw = Path(raw_dir) / fname
        if not raw.is_file():
            continue
        data = analyze_macho(raw)
        row = con.execute(
            "SELECT id, image_base, arch FROM binary WHERE repo_path=?",
            (repo_path,),
        ).fetchone()
        if row is None:
            continue
        bid = row["id"]
        parsed_functions = []
        for sl in select_slices(data, row["arch"]):
            st = sl.get("stabs")
            if not st:
                continue
            parsed_functions.extend(st["functions"])
        current = {
            item["addr"]: dict(item)
            for item in con.execute(
                """SELECT addr, name, name_origin, n_instr, source_file, object_file,
                          stabs_name, stabs_type
                     FROM func WHERE binary_id=?""",
                (bid,),
            )
        }
        records, summary = build_records(parsed_functions, current)
        slug = fname
        binary = con.execute("SELECT slug FROM binary WHERE id=?", (bid,)).fetchone()
        if binary is not None:
            slug = binary["slug"]
        manifest_path = Path(manifest_dir) / f"{slug}.manifest.jsonl"
        if not manifest_path.is_file():
            raise RuntimeError(
                f"missing dry-run manifest {manifest_path}; generate and review it first"
            )
        reviewed = [json.loads(line) for line in manifest_path.read_text(encoding="utf-8").splitlines() if line]
        if reviewed != records:
            raise RuntimeError(
                f"stale dry-run manifest {manifest_path}; regenerate and review before applying"
            )
        linked = apply_manifest_records(con, bid, records)
        stats[repo_path] = {"linked": linked, **summary}
    return stats


def propagate_source_files(
    con,
    repo_paths: set[str] | None = None,
    donor_rows: list[dict] | None = None,
) -> int:
    """Carry source/object attribution across the logical identity layer."""
    if donor_rows is not None:
        con.execute("PRAGMA temp_store=MEMORY")
        con.execute(
            """CREATE TEMP TABLE IF NOT EXISTS stabs_donor_addr (
                   binary_id INTEGER NOT NULL,
                   addr INTEGER NOT NULL,
                   PRIMARY KEY(binary_id, addr)
               ) WITHOUT ROWID"""
        )
        con.execute("DELETE FROM stabs_donor_addr")
        con.executemany(
            "INSERT OR IGNORE INTO stabs_donor_addr(binary_id, addr) VALUES (?,?)",
            [(row["binary_id"], row["addr"]) for row in donor_rows],
        )
        con.commit()
        bound_donors = con.execute(
            """SELECT d.binary_id, d.addr, i.logical_id
                 FROM stabs_donor_addr d
                 JOIN identity i INDEXED BY ux_identity_bin_addr
                   ON i.binary_id=d.binary_id AND i.addr=d.addr"""
        ).fetchall()
        identity_by_addr = {
            (row["binary_id"], row["addr"]): row["logical_id"] for row in bound_donors
        }
        relevant_ids = sorted({row["logical_id"] for row in bound_donors})
        attribution = {}
        identities = []
        for start in range(0, len(relevant_ids), 500):
            chunk = relevant_ids[start : start + 500]
            marks = ",".join("?" for _ in chunk)
            attribution.update({
                row["id"]: (row["source_file"], row["object_file"])
                for row in con.execute(
                    f"""SELECT id, source_file, object_file FROM logical_function
                         WHERE id IN ({marks}) AND source_file IS NOT NULL""",
                    chunk,
                )
            })
            identities.extend(dict(row) for row in con.execute(
                f"""SELECT logical_id, binary_id, addr, confidence FROM identity
                     WHERE logical_id IN ({marks})""",
                chunk,
            ))
    else:
        identities = [dict(row) for row in con.execute(
            "SELECT logical_id, binary_id, addr, confidence FROM identity"
        )]
        identity_by_addr = {
            (row["binary_id"], row["addr"]): row["logical_id"] for row in identities
        }
        attribution = {
            row["id"]: (row["source_file"], row["object_file"])
            for row in con.execute(
                """SELECT id, source_file, object_file FROM logical_function
                    WHERE source_file IS NOT NULL"""
            )
        }

    donor: dict[int, tuple[tuple, str, str | None]] = {}
    has_source: set[tuple[int, int]] = set()
    sourced: Counter = Counter()
    if donor_rows is None:
        authoritative_binaries = [
            row["id"]
            for row in con.execute(
                "SELECT id, repo_path, platform, role FROM binary"
            )
            if (repo_paths is None or row["repo_path"] in repo_paths)
            and (
                (row["platform"] or "") == "mac"
                or (row["role"] or "") in ("donor", "anchor")
            )
        ]
        donor_rows = []
        for binary_id in authoritative_binaries:
            donor_rows.extend(dict(row) for row in con.execute(
                """SELECT binary_id, addr, source_file, object_file
                     FROM func INDEXED BY ix_func_bin
                    WHERE binary_id=? AND source_file IS NOT NULL""",
                (binary_id,),
            ))
    for row in donor_rows:
        key = (row["binary_id"], row["addr"])
        has_source.add(key)
        sourced[row["binary_id"]] += 1
        logical_id = identity_by_addr.get(key)
        if logical_id is None or logical_id in attribution:
            continue
        rank = (row["object_file"] is None, row["binary_id"], row["addr"])
        previous = donor.get(logical_id)
        if previous is None or rank < previous[0]:
            donor[logical_id] = (rank, row["source_file"], row["object_file"])

    logical_updates = [
        (source_file, object_file, logical_id)
        for logical_id, (_rank, source_file, object_file) in donor.items()
    ]
    attribution.update({
        logical_id: (source_file, object_file)
        for logical_id, (_rank, source_file, object_file) in donor.items()
    })
    function_updates = []
    for row in identities:
        key = (row["binary_id"], row["addr"])
        source = attribution.get(row["logical_id"])
        if source is None or key in has_source or (row["confidence"] or 0) < 0.9:
            continue
        function_updates.append((source[0], source[1], row["binary_id"], row["addr"]))
        has_source.add(key)

    con.execute("BEGIN IMMEDIATE")
    try:
        con.executemany(
            """UPDATE logical_function SET source_file=?, object_file=?
                WHERE id=? AND source_file IS NULL""",
            logical_updates,
        )
        before_function_updates = con.total_changes
        con.executemany(
            """UPDATE func SET source_file=?, object_file=?
                WHERE binary_id=? AND addr=? AND source_file IS NULL""",
            function_updates,
        )
        pushed = con.total_changes - before_function_updates
        con.commit()
    except Exception:
        con.rollback()
        raise
    return pushed
