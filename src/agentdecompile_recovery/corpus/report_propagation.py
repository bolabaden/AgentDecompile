"""How far named identities actually reach across builds.

Counts bound / reachable / named / sourced separately. Placeholder names are
not knowledge. Anchor and bridge targets are caller-supplied (role ``anchor``
or an explicit repo_path) — no product-path defaults.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from .naming import is_placeholder_name


def _ensure_logical_name(con) -> None:
    have = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type IN ('table','view')")}
    if "logical_name" in have:
        return
    con.execute(
        """CREATE TEMP TABLE logical_name (
               logical_id INTEGER PRIMARY KEY,
               best_name TEXT,
               tier_name TEXT,
               source_file TEXT
           )"""
    )
    rows = []
    for row in con.execute("SELECT id, best_name, source_file FROM logical_function"):
        name = row["best_name"]
        rows.append((row["id"], name, "placeholder" if is_placeholder_name(name) else "named", row["source_file"]))
    con.executemany("INSERT INTO logical_name(logical_id, best_name, tier_name, source_file) VALUES (?,?,?,?)", rows)


def _named_tier_sql() -> str:
    return "n.tier_name IS NOT NULL AND n.tier_name <> 'placeholder'"


def build_report(
    con,
    *,
    anchor_repo: str | None = None,
    bridge_game: str | None = None,
) -> dict:
    """Compute propagation reach. *anchor_repo* overrides role='anchor'."""
    _ensure_logical_name(con)
    t0 = time.time()
    bins = {
        r["repo_path"]: dict(r)
        for r in con.execute("SELECT id, repo_path, slug, role, game, func_count FROM binary")
    }
    # code_func_count is optional (added by fix_func_counts.apply).
    cols = {r[1] for r in con.execute("PRAGMA table_info(binary)")}
    if "code_func_count" in cols:
        for row in con.execute("SELECT repo_path, code_func_count FROM binary"):
            bins[row["repo_path"]]["code_func_count"] = row["code_func_count"]

    con.execute("DROP TABLE IF EXISTS temp.multi_build")
    con.execute(
        "CREATE TEMP TABLE multi_build AS "
        "SELECT logical_id FROM identity GROUP BY logical_id "
        "HAVING COUNT(DISTINCT binary_id) > 1"
    )
    con.execute("CREATE INDEX temp.ix_mb ON multi_build(logical_id)")

    named_sql = _named_tier_sql()
    agg = {
        r["binary_id"]: dict(r)
        for r in con.execute(
            f"""
        SELECT i.binary_id                                         AS binary_id,
               COUNT(DISTINCT i.addr)                              AS bound,
               COUNT(DISTINCT CASE WHEN m.logical_id IS NOT NULL
                                   THEN i.addr END)                AS reachable,
               COUNT(DISTINCT CASE WHEN {named_sql}
                                   THEN i.addr END)                AS named,
               COUNT(DISTINCT CASE WHEN {named_sql}
                                    AND n.source_file IS NOT NULL
                                    AND n.source_file <> ''
                                   THEN i.addr END)                AS sourced
        FROM identity i
        JOIN func f ON f.binary_id = i.binary_id AND f.addr = i.addr
                   AND f.n_instr > 0 AND f.size > 0
        LEFT JOIN logical_name n ON n.logical_id = i.logical_id
        LEFT JOIN multi_build m  ON m.logical_id = i.logical_id
        GROUP BY i.binary_id"""
        )
    }

    tier_rows = con.execute(
        f"""
        SELECT i.binary_id, n.tier_name, COUNT(DISTINCT i.addr) n
        FROM identity i
        JOIN func f ON f.binary_id = i.binary_id AND f.addr = i.addr
                   AND f.n_instr > 0 AND f.size > 0
        JOIN logical_name n ON n.logical_id = i.logical_id
        WHERE {named_sql}
        GROUP BY i.binary_id, n.tier_name"""
    ).fetchall()
    tiers_by_bin: dict[int, dict[str, int]] = {}
    for row in tier_rows:
        tiers_by_bin.setdefault(row["binary_id"], {})[row["tier_name"]] = row["n"]

    rows = []
    for repo, binary in sorted(bins.items()):
        a = agg.get(binary["id"], {})
        named = a.get("named") or 0
        total = binary.get("code_func_count") or binary.get("func_count") or 0
        rows.append(
            {
                "repo_path": repo,
                "slug": binary["slug"],
                "functions_with_code": total,
                "bound": a.get("bound") or 0,
                "reachable_multi_build": a.get("reachable") or 0,
                "named_real": named,
                "with_source_path": a.get("sourced") or 0,
                "name_tiers": tiers_by_bin.get(binary["id"], {}),
                "pct_named": round(named / total * 100, 2) if total else 0.0,
            }
        )

    if not anchor_repo:
        anchors = [p for p, b in bins.items() if (b.get("role") or "") == "anchor"]
        anchor_repo = anchors[0] if len(anchors) == 1 else None

    lane = {"anchor": anchor_repo}
    k1 = bins.get(anchor_repo) if anchor_repo else None
    if k1:
        r = con.execute(
            f"""
            SELECT COUNT(DISTINCT i.addr) bound,
                   COUNT(DISTINCT CASE WHEN {named_sql} THEN i.addr END) named,
                   COUNT(DISTINCT CASE WHEN m.logical_id IS NOT NULL
                         THEN i.addr END) reach,
                   COUNT(DISTINCT CASE WHEN m.logical_id IS NOT NULL
                         AND {named_sql} THEN i.addr END) carried
            FROM identity i
            LEFT JOIN logical_name n ON n.logical_id=i.logical_id
            LEFT JOIN multi_build m  ON m.logical_id=i.logical_id
            WHERE i.binary_id=?""",
            (k1["id"],),
        ).fetchone()
        lane["bound_in_anchor"] = r["bound"] or 0
        lane["named_real_in_anchor"] = r["named"] or 0
        lane["reach_another_build"] = r["reach"] or 0
        lane["carried_with_real_name"] = r["carried"] or 0
        lane["distinct_target_builds"] = con.execute(
            """
            SELECT COUNT(DISTINCT i2.binary_id) FROM identity i1
            JOIN multi_build m ON m.logical_id=i1.logical_id
            JOIN identity i2 ON i2.logical_id=i1.logical_id
            WHERE i1.binary_id=? AND i2.binary_id<>?""",
            (k1["id"], k1["id"]),
        ).fetchone()[0]

    if bridge_game:
        k2_ids = [b["id"] for p, b in bins.items() if (b.get("game") or "") == bridge_game]
    else:
        k2_ids = [b["id"] for p, b in bins.items() if (b.get("role") or "") == "donor" and p != anchor_repo]
    bridge = {"target_builds": len(k2_ids)}
    if k1 and k2_ids:
        ph = ",".join("?" * len(k2_ids))
        r = con.execute(
            f"""
            SELECT COUNT(DISTINCT i1.logical_id) shared,
                   COUNT(DISTINCT CASE WHEN {named_sql}
                         THEN i1.logical_id END) named
            FROM identity i1
            JOIN identity i2 ON i2.logical_id=i1.logical_id
            LEFT JOIN logical_name n ON n.logical_id=i1.logical_id
            WHERE i1.binary_id=? AND i2.binary_id IN ({ph})""",
            (k1["id"], *k2_ids),
        ).fetchone()
        bridge["logicals_shared"] = r["shared"] or 0
        bridge["of_which_named"] = r["named"] or 0

    return {
        "generated_at": time.time(),
        "seconds": round(time.time() - t0, 1),
        "per_binary": rows,
        "anchor_corpus": lane,
        "bridge": bridge,
    }


def write_report(payload: dict, out_dir: Path | str) -> dict:
    """Write markdown + JSON under *out_dir* (required)."""
    dest = Path(out_dir)
    dest.mkdir(parents=True, exist_ok=True)
    json_path = dest / "propagation_reach.json"
    md_path = dest / "propagation_reach.md"
    json_path.write_text(json.dumps(payload, indent=1), encoding="utf-8")
    lines = [
        "# How far named identities reach",
        "",
        f"Generated in {payload.get('seconds')}s.",
        "",
        "- **bound** — the function has a logical identity at all.",
        "- **reachable** — that identity spans more than one build.",
        "- **named** — the identity resolves to a real name, not a placeholder.",
        "- **sourced** — it also carries an original source path.",
        "",
        "| build | with code | bound | reachable | named | sourced | % named |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in payload.get("per_binary") or []:
        lines.append(
            f"| `{row['slug']}` | {row['functions_with_code']:,} | {row['bound']:,} | "
            f"{row['reachable_multi_build']:,} | {row['named_real']:,} | "
            f"{row['with_source_path']:,} | {row['pct_named']}% |"
        )
    lines += [
        "",
        "## Anchor corpus",
        "",
        "```json",
        json.dumps(payload.get("anchor_corpus") or {}, indent=1),
        "```",
        "",
        "## Bridge",
        "",
        "```json",
        json.dumps(payload.get("bridge") or {}, indent=1),
        "```",
    ]
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {"json": str(json_path), "markdown": str(md_path)}
