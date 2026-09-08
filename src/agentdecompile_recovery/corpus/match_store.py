"""Store-backed identity matcher (kotorxid ``kx.match.Binary`` / ``match_binaries``)."""

from __future__ import annotations

import json
from collections import defaultdict

from . import canon
from .match_engine import (
    MAX_CONST_DF,
    MAX_STRING_DF,
    PAIR_POLICY,
    _basename,
    _passes,
    classify_pair,
    score_features,
    shape_key,
    status_for,
)


class Binary:
    """In-memory view of one binary's functions and call graph."""

    def __init__(self, con, binary_id: int):
        self.id = binary_id
        row = con.execute("SELECT * FROM binary WHERE id=?", (binary_id,)).fetchone()
        self.meta = dict(row)
        self.slug = row["slug"]
        self.funcs: dict[int, dict] = {}
        for rec in con.execute(
            """SELECT addr,name,namespace,canon_key,canon_arity,canon_method,canon_class,
                      name_origin,size,is_thunk,n_instr,n_blocks,n_edges,back_edges,
                      cyclomatic,n_callees,indirect_calls,data_refs,mnem,strings,consts,
                      ext_calls,plate,signature,source,param_count,source_file,object_file
                 FROM func WHERE binary_id=?""",
            (binary_id,),
        ):
            d = dict(rec)
            d["strings"] = json.loads(d["strings"] or "[]")
            d["consts"] = json.loads(d["consts"] or "[]")
            d["ext_calls"] = json.loads(d["ext_calls"] or "[]")
            d["mnem"] = json.loads(d["mnem"] or "{}")
            if canon.is_eh_clone(d["name"], d["plate"]):
                continue
            self.funcs[d["addr"]] = d

        self.decomp: dict[int, dict] = {}
        try:
            for rec in con.execute(
                """SELECT addr,n_tokens,n_lines,max_nest,n_calls,n_locals,n_deref,
                          n_index,n_field,ctrl,ops,skeleton_hash
                     FROM decomp WHERE binary_id=? AND ok=1""",
                (binary_id,),
            ):
                d = dict(rec)
                d["ctrl"] = json.loads(d["ctrl"] or "{}")
                d["ops"] = json.loads(d["ops"] or "{}")
                self.decomp[d["addr"]] = d
        except Exception:
            pass

        self.callees: dict[int, set[int]] = defaultdict(set)
        self.callers: dict[int, set[int]] = defaultdict(set)
        for a, b in con.execute(
            "SELECT caller_addr, callee_addr FROM calledge WHERE binary_id=?", (binary_id,)
        ):
            self.callees[a].add(b)
            self.callers[b].add(a)
        self._index()

    def _index(self) -> None:
        self.by_string: dict[str, list[int]] = defaultdict(list)
        self.by_const: dict[int, list[int]] = defaultdict(list)
        self.by_ext: dict[str, list[int]] = defaultdict(list)
        self.by_shape: dict[tuple, list[int]] = defaultdict(list)
        self.by_unit: dict[str, list[int]] = defaultdict(list)
        self.by_skeleton: dict[str, list[int]] = defaultdict(list)
        for addr, f in self.funcs.items():
            for s in f["strings"]:
                self.by_string[s].append(addr)
            for c in f["consts"]:
                self.by_const[c].append(addr)
            for e in f["ext_calls"]:
                self.by_ext[e].append(addr)
            self.by_shape[shape_key(f)].append(addr)
            unit = _basename(f.get("source_file"))
            if unit:
                self.by_unit[unit].append(addr)
        for addr, d in self.decomp.items():
            h = d.get("skeleton_hash")
            if h:
                self.by_skeleton[h].append(addr)

    def candidates_named(self) -> dict[str, list[int]]:
        out: dict[str, list[int]] = defaultdict(list)
        for addr, f in self.funcs.items():
            if f["canon_key"] and not canon.is_library(f["canon_key"]):
                out[f["canon_key"]].append(addr)
        return out


def candidate_pairs(sa: Binary, sb: Binary, src_addr: int, mapping: dict[int, int]) -> set[int]:
    f = sa.funcs[src_addr]
    from collections import Counter

    cands: Counter = Counter()
    for s in f["strings"]:
        hits = sb.by_string.get(s)
        if hits and len(hits) <= MAX_STRING_DF:
            for h in hits:
                cands[h] += 3
    for c in f["consts"]:
        hits = sb.by_const.get(c)
        if hits and len(hits) <= MAX_CONST_DF:
            for h in hits:
                cands[h] += 2
    for e in f["ext_calls"]:
        hits = sb.by_ext.get(e)
        if hits and len(hits) <= MAX_CONST_DF:
            for h in hits:
                cands[h] += 1
    for callee in sa.callees.get(src_addr, ()):
        mapped = mapping.get(callee)
        if mapped is not None:
            for h in sb.callers.get(mapped, ()):
                cands[h] += 2
    for caller in sa.callers.get(src_addr, ()):
        mapped = mapping.get(caller)
        if mapped is not None:
            for h in sb.callees.get(mapped, ()):
                cands[h] += 2
    unit = _basename(f.get("source_file"))
    if unit:
        for h in sb.by_unit.get(unit, ())[:400]:
            cands[h] += 2
    if not cands:
        for h in sb.by_shape.get(shape_key(f), ())[:200]:
            cands[h] += 1
    skel = (sa.decomp.get(src_addr) or {}).get("skeleton_hash")
    if skel:
        for h in sb.by_skeleton.get(skel, ())[:200]:
            cands[h] += 2
    return {c for c in cands if c in sb.funcs}


def _classify_store(sa: Binary, sb: Binary) -> str:
    return classify_pair(sa.meta, sb.meta)


def match_binaries(
    con,
    src_id: int,
    dst_id: int,
    rounds: int = 3,
    seed: dict[int, int] | None = None,
    restrict_src: set[int] | None = None,
    use_name_features: bool = True,
    quiet: bool = True,
) -> dict:
    sa, sb = Binary(con, src_id), Binary(con, dst_id)
    same_arch = (sa.meta["arch"], sa.meta["bits"]) == (sb.meta["arch"], sb.meta["bits"])
    pair_class = _classify_store(sa, sb)
    policy = PAIR_POLICY[pair_class]
    mapping: dict[int, int] = dict(seed or {})
    taken = set(mapping.values())
    results: dict[int, dict] = {}

    src_addrs = [
        a
        for a, f in sa.funcs.items()
        if not f["is_thunk"] and (f["n_instr"] or 0) >= 4 and (restrict_src is None or a in restrict_src)
    ]

    for rnd in range(rounds):
        new = 0
        scored: list[tuple[float, float, int, int, dict]] = []
        for a in src_addrs:
            if a in mapping:
                continue
            cands = candidate_pairs(sa, sb, a, mapping)
            cands -= taken
            if not cands:
                continue
            fa = sa.funcs[a]
            best = second = 0.0
            best_b = None
            best_ev: dict = {}
            for b in cands:
                fb = dict(sb.funcs[b])
                if use_name_features is False:
                    fa_score = {**fa, "canon_arity": None}
                    fb = {**fb, "canon_arity": None}
                else:
                    fa_score = fa
                if sa.decomp.get(a):
                    fa_score = {**fa_score, "decomp": sa.decomp[a]}
                if sb.decomp.get(b):
                    fb = {**fb, "decomp": sb.decomp[b]}
                int_map = {str(k): str(v) for k, v in mapping.items()} if mapping else None
                s, ev = score_features(fa_score, fb, same_arch=same_arch, mapping=int_map)
                ev = dict(ev)
                if s > best:
                    second, best, best_b, best_ev = best, s, b, ev
                elif s > second:
                    second = s
            if best_b is not None:
                margin = (best - second) if len(cands) > 1 else 0.0
                scored.append((best, margin, a, best_b, best_ev))

        scored.sort(key=lambda t: (-t[0], -t[1]))
        for best, margin, a, b, ev in scored:
            if a in mapping or b in taken:
                continue
            if _passes(policy["verify"], best, margin, ev.get("_content", 0)) and ev.get("compunit") != 0.0:
                mapping[a] = b
                taken.add(b)
                results[a] = {"dst": b, "score": best, "margin": margin, "evidence": ev, "round": rnd}
                new += 1
            else:
                prev = results.get(a)
                if prev is None or best > prev["score"]:
                    results[a] = {"dst": b, "score": best, "margin": margin, "evidence": ev, "round": rnd}
        if new == 0:
            break

    return {"mapping": mapping, "results": results, "src": sa, "dst": sb, "pair_class": pair_class}


__all__ = ["Binary", "candidate_pairs", "match_binaries", "status_for"]
