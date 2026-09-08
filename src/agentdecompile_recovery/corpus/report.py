"""Generate corpus coverage numbers from a store. Paths are caller-supplied."""

from __future__ import annotations


def table(rows, headers, aligns=None) -> str:
    aligns = aligns or ["---"] * len(headers)
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join(aligns) + "|"]
    for row in rows:
        out.append("| " + " | ".join(str(x) for x in row) + " |")
    return "\n".join(out)


def corpus_section(con) -> str:
    rows = []
    for r in con.execute(
        """SELECT b.*,
                  (SELECT COUNT(*) FROM func f WHERE f.binary_id=b.id) nf,
                  (SELECT COUNT(*) FROM func f WHERE f.binary_id=b.id
                     AND f.canon_key IS NOT NULL) named,
                  (SELECT COUNT(*) FROM func f WHERE f.binary_id=b.id
                     AND f.source_file IS NOT NULL) src,
                  (SELECT COUNT(*) FROM func f WHERE f.binary_id=b.id
                     AND (f.n_instr IS NULL OR f.n_instr=0)) noinstr
             FROM binary b ORDER BY b.game, b.repo_path"""
    ):
        rows.append(
            (
                r["slug"],
                r["game"] or "",
                r["platform"] or "",
                r["nf"],
                r["named"],
                r["src"],
                r["noinstr"],
            )
        )
    return table(rows, ["slug", "game", "platform", "funcs", "named", "sourced", "noinstr"])


def match_section(con, run: str | None = None) -> str:
    rows = []
    for r in con.execute(
        """SELECT status, COUNT(*) n FROM match
            WHERE (? IS NULL OR run=?)
            GROUP BY status ORDER BY status""",
        (run, run),
    ):
        rows.append((r["status"], r["n"]))
    return table(rows, ["status", "count"])


def identity_section(con) -> str:
    counts = con.execute(
        "SELECT method, COUNT(*) n, ROUND(AVG(confidence),3) c FROM identity"
        " GROUP BY method ORDER BY n DESC"
    ).fetchall()
    out = ["**Identity bindings by method**\n", table(
        [[f"`{r['method']}`", f"{r['n']:,}", r["c"]] for r in counts],
        ["method", "bindings", "mean confidence"],
        ["---", "---:", "---:"],
    )]
    spread = con.execute(
        """SELECT n, COUNT(*) c FROM (
             SELECT logical_id, COUNT(DISTINCT binary_id) n FROM identity GROUP BY logical_id)
            GROUP BY n ORDER BY n"""
    ).fetchall()
    out.append("\n**Builds per logical function**\n")
    out.append(table([[r["n"], f"{r['c']:,}"] for r in spread], ["builds", "logical functions"], ["---:", "---:"]))
    return "\n".join(out)


def source_section(con) -> str:
    rows = con.execute(
        """SELECT source_file, COUNT(*) n FROM logical_function
            WHERE source_file IS NOT NULL GROUP BY source_file ORDER BY n DESC LIMIT 25"""
    ).fetchall()
    total = con.execute(
        "SELECT COUNT(*) FROM logical_function WHERE source_file IS NOT NULL"
    ).fetchone()[0]
    units = con.execute(
        "SELECT COUNT(DISTINCT source_file) FROM logical_function WHERE source_file IS NOT NULL"
    ).fetchone()[0]
    head = f"{total:,} logical functions carry a source file across {units:,} compilation units.\n"
    return head + "\n" + table(
        [[f"`{r['source_file']}`", f"{r['n']:,}"] for r in rows],
        ["source file", "logical functions"],
        ["---", "---:"],
    )


def matches_detail_section(con) -> str:
    rows = []
    for r in con.execute(
        """SELECT sb.repo_path src, db_.repo_path dst, m.status, COUNT(*) n,
                  ROUND(AVG(m.score),3) avg_score
             FROM match m JOIN binary sb ON sb.id=m.src_binary
             JOIN binary db_ ON db_.id=m.dst_binary
            GROUP BY m.src_binary, m.dst_binary, m.status
            ORDER BY sb.repo_path, db_.repo_path, m.status"""
    ):
        rows.append(
            (
                f"`{r['src'].split('/')[-1]}`",
                f"`{r['dst'].split('/')[-1]}`",
                r["status"],
                f"{r['n']:,}",
                r["avg_score"],
            )
        )
    if not rows:
        return "_No propagation run recorded yet._"
    return table(
        rows,
        ["source", "target", "status", "count", "mean score"],
        ["---", "---", "---", "---:", "---:"],
    )


def unresolved_section(con) -> str:
    rows = con.execute(
        """SELECT b.repo_path, COUNT(*) n FROM match m
             JOIN binary b ON b.id=m.src_binary
            WHERE m.status IN ('review','unresolved') GROUP BY b.id ORDER BY n DESC"""
    ).fetchall()
    return table(
        [[f"`{r['repo_path']}`", f"{r['n']:,}"] for r in rows],
        ["source build", "matches left for human review"],
        ["---", "---:"],
    )


def write_fragments(con, out_dir, *, run: str = "v1") -> dict:
    from pathlib import Path

    dest = Path(out_dir)
    dest.mkdir(parents=True, exist_ok=True)
    parts = {
        "corpus": corpus_section(con),
        "identity": identity_section(con),
        "source": source_section(con),
        "matches": matches_detail_section(con),
        "unresolved": unresolved_section(con),
        "match_summary": match_section(con, run),
    }
    written = {}
    for name, body in parts.items():
        path = dest / f"_gen_{name}.md"
        path.write_text(body + "\n", encoding="utf-8")
        written[name] = str(path)
    return {"out_dir": str(dest), "fragments": written}
