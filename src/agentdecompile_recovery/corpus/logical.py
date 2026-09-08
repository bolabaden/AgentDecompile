"""Build the logical-function identity layer from name evidence."""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict

from . import canon, match

GENERIC = re.compile(
    r"^(map|set|list|vector|string|pair|iterator|allocator|_?init|_?fini|main|"
    r"entry|start|operator[^A-Za-z]|__.*)$"
)


def eligible(row) -> bool:
    key = row["canon_key"]
    if not key or canon.is_library(key):
        return False
    if canon.from_fid(row["plate"]):
        return False
    name = row["name"] if "name" in row.keys() else None
    if canon.is_eh_clone(name, row["plate"]):
        return False
    if not row["canon_class"] and GENERIC.match(row["canon_method"] or ""):
        return False
    return True


def build(con) -> dict[str, int]:
    con.execute("DELETE FROM identity")
    con.execute("DELETE FROM logical_function")
    con.commit()

    excluded = tuple(sorted(canon.DRM_EXCLUDED))
    if excluded:
        marks = ",".join("?" for _ in excluded)
        rows = con.execute(
            f"""SELECT f.binary_id, f.addr, f.canon_key, f.canon_class, f.canon_method,
                      f.canon_arity, f.name_origin, f.is_thunk, f.n_instr, f.n_blocks,
                      f.cyclomatic, f.n_callees, f.size, f.signature, f.plate,
                      f.strings, f.consts, f.param_count, f.name,
                      b.game, b.slug, b.role
                 FROM func f JOIN binary b ON b.id=f.binary_id
                WHERE f.canon_key IS NOT NULL
                  AND b.repo_path NOT IN ({marks})""",
            excluded,
        ).fetchall()
    else:
        rows = con.execute(
            """SELECT f.binary_id, f.addr, f.canon_key, f.canon_class, f.canon_method,
                      f.canon_arity, f.name_origin, f.is_thunk, f.n_instr, f.n_blocks,
                      f.cyclomatic, f.n_callees, f.size, f.signature, f.plate,
                      f.strings, f.consts, f.param_count, f.name,
                      b.game, b.slug, b.role
                 FROM func f JOIN binary b ON b.id=f.binary_id
                WHERE f.canon_key IS NOT NULL"""
        ).fetchall()

    groups: dict[str, list] = defaultdict(list)
    for row in rows:
        if eligible(row):
            groups[row["canon_key"]].append(row)

    n_logical = 0
    n_bound = 0
    counters: Counter = Counter()
    logicals = []
    identities = []

    for key, members in groups.items():
        arities = {m["canon_arity"] for m in members if m["canon_arity"] is not None}
        subgroups: dict[object, list] = defaultdict(list)
        if len(arities) > 1:
            for m in members:
                subgroups[m["canon_arity"]].append(m)
        else:
            subgroups[None] = members

        for arity, sub in subgroups.items():
            sub_by_bin: dict[int, list] = defaultdict(list)
            for m in sub:
                sub_by_bin[m["binary_id"]].append(m)

            if all(len(v) == 1 for v in sub_by_bin.values()):
                n_logical += 1
                _emit(logicals, identities, n_logical, key, arity, sub, 0.99, "name-unique", {})
                n_bound += len(sub)
                counters["name-unique"] += len(sub)
                continue

            for scored_members, note in resolve_ambiguous(sub_by_bin):
                n_logical += 1
                _emit_scored(logicals, identities, n_logical, key, arity, scored_members, note)
                n_bound += len(scored_members)
                for _m, _c, meth in scored_members:
                    counters[meth] += 1

    con.executemany(
        """INSERT INTO logical_function(id, canon_key, canon_class, canon_method, game,
                                        best_name, best_signature, source_file, object_file,
                                        n_members, notes)
           VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        logicals,
    )
    con.executemany(
        "INSERT OR REPLACE INTO identity(logical_id,binary_id,addr,confidence,method,evidence)"
        " VALUES(?,?,?,?,?,?)",
        identities,
    )
    con.commit()
    return {"logical": n_logical, "bound": n_bound, **dict(counters)}


def _feat(m):
    return (
        set(json.loads(m["strings"] or "[]")),
        set(json.loads(m["consts"] or "[]")),
    )


def _similar(a, b) -> float:
    sa, ca = _feat(a)
    sb, cb = _feat(b)
    parts = [
        0.30 * match.relsim(a["n_instr"], b["n_instr"]),
        0.25 * match.relsim(a["n_blocks"], b["n_blocks"]),
        0.15 * match.relsim(a["cyclomatic"], b["cyclomatic"]),
        0.10 * match.relsim(a["n_callees"], b["n_callees"]),
    ]
    score = sum(parts)
    weight = 0.80
    if sa or sb:
        score += 0.14 * match.jaccard(sa, sb)
        weight += 0.14
    if ca or cb:
        score += 0.06 * match.jaccard(ca, cb)
        weight += 0.06
    return score / weight


def resolve_ambiguous(sub_by_bin: dict[int, list]):
    """Split a same-name group using structure. Prefer donor/anchor roles."""

    def rank(bid):
        role = (sub_by_bin[bid][0]["role"] or "") if "role" in sub_by_bin[bid][0].keys() else ""
        pri = 0 if role in ("donor", "anchor") else 1
        return (len(sub_by_bin[bid]), pri)

    ref_bid = min(sub_by_bin, key=rank)
    slots = [[(m, 0.97, "name-reference")] for m in sorted(sub_by_bin[ref_bid], key=lambda m: -(m["n_instr"] or 0))]

    for bid, lst in sub_by_bin.items():
        if bid == ref_bid:
            continue
        pairs = []
        for mi, m in enumerate(lst):
            for si, slot in enumerate(slots):
                pairs.append((_similar(slot[0][0], m), si, mi))
        pairs.sort(reverse=True)
        used_slot, used_m = set(), set()
        best_for_m: dict[int, list[float]] = defaultdict(list)
        for s, si, mi in pairs:
            best_for_m[mi].append(s)
        for s, si, mi in pairs:
            if si in used_slot or mi in used_m:
                continue
            scores = sorted(best_for_m[mi], reverse=True)
            margin = scores[0] - scores[1] if len(scores) > 1 else 1.0
            used_slot.add(si)
            used_m.add(mi)
            if s >= 0.75 and margin >= 0.05:
                conf, meth = 0.95, "name-disambiguated"
            elif s >= 0.60:
                conf, meth = 0.80, "name-weak"
            else:
                conf, meth = 0.55, "name-ambiguous"
            slots[si].append((lst[mi], conf, meth))
        for mi, m in enumerate(lst):
            if mi not in used_m:
                slots.append([(m, 0.50, "name-unplaced")])

    for slot in slots:
        yield slot, {"slot_size": len(slot)}


def _emit_scored(logicals, identities, lid, key, arity, scored, note):
    members = [m for m, _c, _meth in scored]
    best = _best_signature(members)
    logicals.append(
        (
            lid,
            key,
            members[0]["canon_class"],
            members[0]["canon_method"],
            _game_of(members),
            best[0],
            best[1],
            None,
            None,
            len(members),
            json.dumps({"arity": arity, **note}),
        )
    )
    for m, conf, meth in scored:
        identities.append(
            (
                lid,
                m["binary_id"],
                m["addr"],
                conf,
                meth,
                json.dumps({"canon_key": key, "origin": m["name_origin"]}),
            )
        )


def _emit(logicals, identities, lid, key, arity, members, conf, method, note):
    best = _best_signature(members)
    logicals.append(
        (
            lid,
            key,
            members[0]["canon_class"],
            members[0]["canon_method"],
            _game_of(members),
            best[0],
            best[1],
            None,
            None,
            len(members),
            json.dumps({"arity": arity, "method": method, **note}),
        )
    )
    for m in members:
        identities.append(
            (
                lid,
                m["binary_id"],
                m["addr"],
                conf,
                method,
                json.dumps({"canon_key": key, "origin": m["name_origin"]}),
            )
        )


def _game_of(members) -> str | None:
    games = {m["game"] for m in members if m["game"]}
    if len(games) == 1:
        return games.pop()
    return "SHARED" if games else None


def _best_signature(members) -> tuple[str | None, str | None]:
    name = members[0]["canon_key"]
    sig = None
    for m in members:
        if m["name_origin"] == "mangled" and m["plate"]:
            return name, m["plate"].splitlines()[0]
    for m in members:
        if m["name_origin"] == "plate" and m["plate"]:
            sig = m["plate"].splitlines()[0]
            break
    if sig is None:
        for m in members:
            if m["signature"]:
                sig = m["signature"]
                break
    return name, sig
