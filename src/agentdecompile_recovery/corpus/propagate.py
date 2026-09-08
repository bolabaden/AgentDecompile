"""Directed matcher runs, identity binding, and named-conflict demotion."""

from __future__ import annotations

import json
from collections import Counter

from . import match


def bid(con, path: str) -> int:
    row = con.execute("SELECT id FROM binary WHERE repo_path=?", (path,)).fetchone()
    if row is None:
        raise KeyError(path)
    return row[0]


def run_pair(con, src_path: str, dst_path: str, note: str, run: str) -> dict:
    src_id, dst_id = bid(con, src_path), bid(con, dst_path)
    res = match.match_binaries(con, src_id, dst_id, rounds=4, use_name_features=True)
    sa, sb = res["src"], res["dst"]

    con.execute(
        "DELETE FROM match WHERE run=? AND src_binary=? AND dst_binary=?",
        (run, src_id, dst_id),
    )
    rows = []
    counts: Counter = Counter()
    for addr, result in res["results"].items():
        src_key = sa.funcs[addr]["canon_key"]
        dst_key = sb.funcs[result["dst"]]["canon_key"]
        canonical_name_conflict = bool(src_key and dst_key and src_key != dst_key)
        status = match.status_for(
            result["score"],
            result["margin"],
            res["pair_class"],
            result["evidence"].get("_content", 0),
            result["evidence"].get("compunit"),
            canonical_name_conflict,
        )
        counts[status] += 1
        rows.append(
            (
                run,
                src_id,
                addr,
                dst_id,
                result["dst"],
                result["score"],
                result["margin"],
                json.dumps(result["evidence"]),
                status,
            )
        )
    con.executemany(
        """INSERT INTO match(run, src_binary, src_addr, dst_binary, dst_addr,
                             score, margin, evidence, status)
           VALUES(?,?,?,?,?,?,?,?,?)""",
        rows,
    )
    con.commit()
    named_src = sum(1 for addr in res["results"] if sa.funcs[addr]["canon_key"])
    transferable = sum(
        1
        for addr, result in res["results"].items()
        if sa.funcs[addr]["canon_key"]
        and not sb.funcs[result["dst"]]["canon_key"]
        and match.status_for(
            result["score"],
            result["margin"],
            res["pair_class"],
            result["evidence"].get("_content", 0),
            result["evidence"].get("compunit"),
            False,
        )
        in ("auto", "verify")
    )
    return {
        "src": src_path,
        "dst": dst_path,
        "note": note,
        "counts": dict(counts),
        "named_src_candidates": named_src,
        "transferable": transferable,
        "src_funcs": len(sa.funcs),
        "dst_funcs": len(sb.funcs),
        "dst_already_named": sum(1 for f in sb.funcs.values() if f["canon_key"]),
    }


def bind_identities(con, run: str, *, commit: bool = True) -> int:
    """Attach matched target functions to the source's logical function."""
    con.execute("DELETE FROM identity WHERE method LIKE ?", (f"match:{run}:%",))
    owned = {
        (r[0], r[1])
        for r in con.execute(
            "SELECT binary_id, addr FROM identity WHERE method NOT LIKE 'match:%'"
        )
    }
    cur = con.execute(
        """SELECT m.dst_binary, m.dst_addr, m.score, m.status, m.evidence,
                  i.logical_id, m.src_binary, m.src_addr
             FROM match m
             JOIN identity i ON i.binary_id=m.src_binary AND i.addr=m.src_addr
            WHERE m.run=? AND m.status IN ('auto','verify')""",
        (run,),
    )
    best: dict[tuple[int, int], tuple] = {}
    for row in cur:
        key = (row["dst_binary"], row["dst_addr"])
        if key in owned:
            continue
        conf = (
            round(0.5 + 0.5 * row["score"], 4)
            if row["status"] == "auto"
            else round(0.35 + 0.45 * row["score"], 4)
        )
        cand = (
            row["logical_id"],
            row["dst_binary"],
            row["dst_addr"],
            conf,
            f"match:{run}:{row['status']}",
            row["evidence"],
        )
        prev = best.get(key)
        if prev is None or conf > prev[3]:
            best[key] = cand
    payload = list(best.values())
    con.executemany(
        "INSERT OR REPLACE INTO identity(logical_id,binary_id,addr,confidence,method,evidence)"
        " VALUES(?,?,?,?,?,?)",
        payload,
    )
    if commit:
        con.commit()
    return len(payload)


def dedupe_identity_addrs(con, *, commit: bool = True) -> int:
    rows = con.execute(
        """SELECT binary_id, addr, logical_id, confidence, method, rowid
             FROM identity
            WHERE (binary_id, addr) IN (
                SELECT binary_id, addr FROM identity
                 GROUP BY binary_id, addr HAVING COUNT(*) > 1
            )
            ORDER BY binary_id, addr, confidence DESC, rowid"""
    ).fetchall()
    seen: set[tuple[int, int]] = set()
    drop: list[int] = []
    for row in rows:
        key = (row["binary_id"], row["addr"])
        if key in seen:
            drop.append(row["rowid"])
        else:
            seen.add(key)
    if drop:
        con.executemany("DELETE FROM identity WHERE rowid=?", [(i,) for i in drop])
        if commit:
            con.commit()
    return len(drop)


def downgrade_named_conflicts(con, run: str | None = None, *, commit: bool = True) -> int:
    """Demote stored auto matches when independent canonical names disagree."""
    cur = con.execute(
        """UPDATE match
              SET status='verify'
            WHERE status='auto'
              AND (? IS NULL OR run=?)
              AND EXISTS (
                  SELECT 1
                    FROM func src
                    JOIN func dst
                      ON dst.binary_id=match.dst_binary
                     AND dst.addr=match.dst_addr
                   WHERE src.binary_id=match.src_binary
                     AND src.addr=match.src_addr
                     AND src.canon_key IS NOT NULL
                     AND src.canon_key<>''
                     AND dst.canon_key IS NOT NULL
                     AND dst.canon_key<>''
                     AND src.canon_key<>dst.canon_key
              )""",
        (run, run),
    )
    if commit:
        con.commit()
    return cur.rowcount


def reclassify_existing(con, run: str) -> tuple[int, int, int]:
    """Reclassify matches and rebuild derived identities in one transaction."""
    con.execute("BEGIN IMMEDIATE")
    try:
        changed = downgrade_named_conflicts(con, run, commit=False)
        bound = bind_identities(con, run, commit=False)
        dropped = dedupe_identity_addrs(con, commit=False)
        con.commit()
        return changed, bound, dropped
    except Exception:
        con.rollback()
        raise


def run_registry_pairs(con, pairs: list[tuple[str, str, str]], run: str = "v1") -> list[dict]:
    """Match each directed (src, dst, note) pair from a corpus registry."""
    summary = []
    for src, dst, note in pairs:
        summary.append(run_pair(con, src, dst, note, run))
    bind_identities(con, run)
    return summary
