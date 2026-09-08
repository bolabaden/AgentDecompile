"""Multi-signal identity matcher ported from kotorxid `kx/match.py`.

Does not compare raw bytes or absolute addresses. Candidates are blocked by
shared strings, constants, imports, compilation unit, and decompiled shape.
Acceptance uses measured per-pair-class (score, margin, content-channel) triples.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from typing import Any, Iterable

MAX_STRING_DF = 12
MAX_CONST_DF = 12

WEIGHTS = {
    "strings": 3.0,
    "consts": 1.6,
    "ext": 1.2,
    "struct": 2.0,
    "mnem": 1.4,
    "neighbors": 2.4,
    "arity": 0.5,
    "compunit": 2.8,
    "decomp": 2.6,
}
CONTENT_CHANNELS = ("strings", "consts", "ext", "neighbors", "compunit", "decomp")
CONTENT_FLOOR = 0.5
CONTENT_FLOORS = {"decomp": 0.90}

PAIR_POLICY = {
    "same_platform": {"auto": (0.70, 0.06, 1), "verify": (0.62, 0.04, 1), "review": (0.55, 0.00, 0)},
    "cross_format": {"auto": (0.70, 0.12, 2), "verify": (0.70, 0.06, 1), "review": (0.60, 0.00, 0)},
    "cross_arch": {"auto": (0.70, 0.12, 2), "verify": (0.70, 0.08, 1), "review": (0.65, 0.00, 0)},
    "cross_game": {"auto": (0.75, 0.12, 2), "verify": (0.75, 0.08, 1), "review": (0.70, 0.00, 0)},
}


def jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 0.0
    union = len(a | b)
    return len(a & b) / union if union else 0.0


def relsim(x, y) -> float:
    x = x or 0
    y = y or 0
    if x == y:
        return 1.0
    m = max(abs(x), abs(y))
    if m == 0:
        return 1.0
    return max(0.0, 1.0 - abs(x - y) / m)


def cosine(a: dict, b: dict) -> float:
    if not a or not b:
        return 0.0
    keys = set(a) | set(b)
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    if not na or not nb:
        return 0.0
    return sum(a.get(k, 0) * b.get(k, 0) for k in keys) / (na * nb)


def shape_key(fn: dict[str, Any]) -> tuple:
    n_blocks = fn.get("n_blocks") or 0
    n_instr = fn.get("n_instr") or 0
    return (
        n_blocks,
        fn.get("cyclomatic") or 0,
        min(fn.get("n_callees") or 0, 12),
        0 if n_instr <= 0 else int(math.log(n_instr, 1.25)),
    )


def _basename(path: str | None) -> str | None:
    if not path:
        return None
    return path.replace("\\", "/").rsplit("/", 1)[-1].lower()


def classify_pair(left_meta: dict[str, Any], right_meta: dict[str, Any]) -> str:
    same_arch = (left_meta.get("arch"), left_meta.get("bits")) == (
        right_meta.get("arch"),
        right_meta.get("bits"),
    )
    if left_meta.get("game") and right_meta.get("game") and left_meta.get("game") != right_meta.get("game"):
        return "cross_game"
    if not same_arch:
        return "cross_arch"
    if left_meta.get("format") == right_meta.get("format"):
        return "same_platform"
    return "cross_format"


def _content_count(ev: dict[str, float]) -> int:
    return sum(
        1
        for key in CONTENT_CHANNELS
        if ev.get(key, 0.0) >= CONTENT_FLOORS.get(key, CONTENT_FLOOR)
    )


def _passes(tier: tuple, score: float, margin: float, content: int) -> bool:
    smin, mmin, cmin = tier
    return score >= smin and margin >= mmin and (content or 0) >= cmin


def status_for(
    score: float | str,
    margin: float | None = None,
    pair_class: str | float | None = None,
    content: int = 99,
    compunit: float | None = None,
    canonical_name_conflict: bool = False,
) -> str:
    """Classify a scored pair. Compunit 0.0 and independent name conflicts veto auto.

    Accepts both the store-style call ``status_for(score, margin, pair_class, …)``
    and the older list-style ``status_for(pair_class, score, margin, content)``.
    """
    if isinstance(score, str):
        pair_class, score, margin = score, margin, pair_class
    if pair_class is None:
        pair_class = "same_platform"
    if margin is None:
        margin = 0.0
    policy = PAIR_POLICY[str(pair_class)]
    veto = compunit == 0.0
    if not veto and not canonical_name_conflict and _passes(policy["auto"], score, margin, content):
        return "auto"
    if not veto and _passes(policy["verify"], score, margin, content):
        return "verify"
    if _passes(policy["review"], score, margin, content):
        return "review"
    return "unresolved"


DECOMP_SCALARS = ("n_tokens", "n_lines", "max_nest", "n_calls", "n_locals", "n_deref", "n_index", "n_field")


def decomp_similarity(a: dict, b: dict) -> float:
    if a.get("skeleton_hash") and a["skeleton_hash"] == b.get("skeleton_hash"):
        return 1.0
    ctrl = cosine(a.get("ctrl") or {}, b.get("ctrl") or {})
    ops = cosine(a.get("ops") or {}, b.get("ops") or {})
    scal = sum(relsim(a.get(k), b.get(k)) for k in DECOMP_SCALARS) / len(DECOMP_SCALARS)
    return 0.40 * ctrl + 0.30 * ops + 0.30 * scal


def score_features(
    fa: dict[str, Any],
    fb: dict[str, Any],
    *,
    same_arch: bool = True,
    mapping: dict[Any, Any] | None = None,
) -> tuple[float, dict[str, float]]:
    ev: dict[str, float] = {}
    a_str, b_str = set(fa.get("strings") or []), set(fb.get("strings") or [])
    if a_str or b_str:
        ev["strings"] = jaccard(a_str, b_str)
    a_c, b_c = set(fa.get("consts") or []), set(fb.get("consts") or [])
    if a_c or b_c:
        ev["consts"] = jaccard(a_c, b_c)
    a_e, b_e = set(fa.get("ext_calls") or []), set(fb.get("ext_calls") or [])
    if a_e or b_e:
        ev["ext"] = jaccard(a_e, b_e)

    if same_arch:
        ev["struct"] = (
            0.35 * relsim(fa.get("n_blocks"), fb.get("n_blocks"))
            + 0.25 * relsim(fa.get("cyclomatic"), fb.get("cyclomatic"))
            + 0.20 * relsim(fa.get("n_callees"), fb.get("n_callees"))
            + 0.20 * relsim(fa.get("n_instr"), fb.get("n_instr"))
        )
        ma, mb = fa.get("mnem") or {}, fb.get("mnem") or {}
        if ma and mb:
            ta = sum(ma.values()) or 1
            tb = sum(mb.values()) or 1
            ev["mnem"] = cosine({k: v / ta for k, v in ma.items()}, {k: v / tb for k, v in mb.items()})
    else:
        ev["struct"] = (
            0.45 * relsim(fa.get("n_blocks"), fb.get("n_blocks"))
            + 0.30 * relsim(fa.get("cyclomatic"), fb.get("cyclomatic"))
            + 0.25 * relsim(fa.get("n_callees"), fb.get("n_callees"))
        )

    if mapping:
        ca = set(fa.get("callee_addrs") or fa.get("callees") or [])
        cb = set(fb.get("callee_addrs") or fb.get("callees") or [])
        mapped = {mapping[x] for x in ca if x in mapping}
        if mapped or cb:
            ev["neighbors"] = jaccard(mapped, cb)

    da, db = fa.get("decomp"), fb.get("decomp")
    if da and db:
        ev["decomp"] = decomp_similarity(da, db)

    su_a, su_b = _basename(fa.get("source_file") or fa.get("sourceFile")), _basename(
        fb.get("source_file") or fb.get("sourceFile")
    )
    if su_a and su_b:
        ev["compunit"] = 1.0 if su_a == su_b else 0.0

    if fa.get("canon_arity") is not None and fb.get("canon_arity") is not None:
        ev["arity"] = 1.0 if fa["canon_arity"] == fb["canon_arity"] else 0.0

    num = sum(WEIGHTS[k] * v for k, v in ev.items())
    den = sum(WEIGHTS[k] for k in ev)
    ev["_content"] = float(_content_count(ev))
    return (num / den if den else 0.0), ev


def _fid(fn: dict[str, Any]) -> str:
    return str(fn.get("id") or fn.get("addr"))


def _callees_of(fn: dict[str, Any]) -> set[str]:
    return {str(x) for x in (fn.get("callee_addrs") or fn.get("callees") or [])}


def _callers_of(fn: dict[str, Any]) -> set[str]:
    return {str(x) for x in (fn.get("caller_addrs") or fn.get("callers") or [])}


class FeatureIndex:
    def __init__(self, functions: Iterable[dict[str, Any]]):
        self.funcs = {_fid(fn): fn for fn in functions}
        self.by_string: dict[str, list[str]] = defaultdict(list)
        self.by_const: dict[Any, list[str]] = defaultdict(list)
        self.by_ext: dict[str, list[str]] = defaultdict(list)
        self.by_shape: dict[tuple, list[str]] = defaultdict(list)
        self.by_unit: dict[str, list[str]] = defaultdict(list)
        self.by_skeleton: dict[str, list[str]] = defaultdict(list)
        self.callees: dict[str, set[str]] = defaultdict(set)
        self.callers: dict[str, set[str]] = defaultdict(set)
        for fid, fn in self.funcs.items():
            for s in fn.get("strings") or []:
                self.by_string[s].append(fid)
            for c in fn.get("consts") or []:
                self.by_const[c].append(fid)
            for e in fn.get("ext_calls") or []:
                self.by_ext[e].append(fid)
            self.by_shape[shape_key(fn)].append(fid)
            unit = _basename(fn.get("source_file") or fn.get("sourceFile"))
            if unit:
                self.by_unit[unit].append(fid)
            skel = (fn.get("decomp") or {}).get("skeleton_hash")
            if skel:
                self.by_skeleton[skel].append(fid)
            for callee in _callees_of(fn):
                self.callees[fid].add(callee)
                self.callers[callee].add(fid)
            for caller in _callers_of(fn):
                self.callers[fid].add(caller)
                self.callees[caller].add(fid)

    def candidates(self, src: dict[str, Any], mapping: dict[str, str] | None = None) -> set[str]:
        votes: Counter[str] = Counter()
        for s in src.get("strings") or []:
            hits = self.by_string.get(s) or []
            if len(hits) <= MAX_STRING_DF:
                votes.update({h: 3 for h in hits})
        for c in src.get("consts") or []:
            hits = self.by_const.get(c) or []
            if len(hits) <= MAX_CONST_DF:
                votes.update({h: 2 for h in hits})
        for e in src.get("ext_calls") or []:
            hits = self.by_ext.get(e) or []
            if len(hits) <= MAX_CONST_DF:
                votes.update({h: 1 for h in hits})
        if mapping:
            src_id = _fid(src)
            for callee in self.callees.get(src_id, ()):
                mapped = mapping.get(callee)
                if mapped is not None:
                    for hit in self.callers.get(mapped, ()):
                        votes[hit] += 2
            for caller in self.callers.get(src_id, ()):
                mapped = mapping.get(caller)
                if mapped is not None:
                    for hit in self.callees.get(mapped, ()):
                        votes[hit] += 2
        unit = _basename(src.get("source_file") or src.get("sourceFile"))
        if unit:
            for hit in self.by_unit.get(unit, ())[:400]:
                votes[hit] += 2
        skel = (src.get("decomp") or {}).get("skeleton_hash")
        if skel:
            for hit in self.by_skeleton.get(skel, ())[:200]:
                votes[hit] += 2
        if not votes:
            for hit in self.by_shape.get(shape_key(src), ())[:200]:
                votes[hit] += 1
        if not votes:
            return set(self.funcs)
        return {hit for hit in votes if hit in self.funcs}


def match_binaries(
    left: list[dict[str, Any]],
    right: list[dict[str, Any]],
    *,
    left_meta: dict[str, Any] | None = None,
    right_meta: dict[str, Any] | None = None,
    tier: str = "auto",
    rounds: int = 3,
) -> list[dict[str, Any]]:
    """Score blocked pairs across greedy rounds and keep those that clear policy."""
    pair_class = classify_pair(left_meta or {}, right_meta or {})
    same_arch = pair_class in ("same_platform", "cross_format") or (
        (left_meta or {}).get("arch") == (right_meta or {}).get("arch")
    )
    index = FeatureIndex(right)
    left_index = FeatureIndex(left)
    mapping: dict[str, str] = {}
    taken: set[str] = set()
    results: dict[str, dict[str, Any]] = {}
    src_ids = [
        fid
        for fid, fn in left_index.funcs.items()
        if not fn.get("is_thunk") and (fn.get("n_instr") or 4) >= 4
    ]

    for rnd in range(rounds):
        scored: list[tuple[float, float, str, str, dict[str, float]]] = []
        for sid in src_ids:
            if sid in mapping:
                continue
            fa = left_index.funcs[sid]
            cands = index.candidates(fa, mapping) - taken
            if not cands:
                continue
            best = second = 0.0
            best_b: str | None = None
            best_ev: dict[str, float] = {}
            for bid in cands:
                score, ev = score_features(fa, index.funcs[bid], same_arch=same_arch, mapping=mapping)
                if score > best:
                    second, best, best_b, best_ev = best, score, bid, ev
                elif score > second:
                    second = score
            if best_b is not None:
                margin = (best - second) if len(cands) > 1 else best
                scored.append((best, margin, sid, best_b, best_ev))

        scored.sort(key=lambda row: (-row[0], -row[1]))
        new = 0
        for best, margin, sid, bid, ev in scored:
            if sid in mapping or bid in taken:
                continue
            content = int(ev.get("_content") or 0)
            left_key = left_index.funcs[sid].get("canon_key")
            right_key = index.funcs[bid].get("canon_key")
            conflict = bool(left_key and right_key and left_key != right_key)
            status = status_for(
                best,
                margin,
                pair_class,
                content,
                compunit=ev.get("compunit"),
                canonical_name_conflict=conflict,
            )
            if status == "unresolved":
                prev = results.get(sid)
                if prev is None or best > prev["score"]:
                    results[sid] = {
                        "left_id": left_index.funcs[sid].get("id"),
                        "right_id": index.funcs[bid].get("id"),
                        "score": round(best, 4),
                        "margin": round(margin, 4),
                        "content": content,
                        "pair_class": pair_class,
                        "status": status,
                        "signals": {k: v for k, v in ev.items() if not k.startswith("_")},
                        "kind": "identity",
                    }
                continue
            if ev.get("compunit") != 0.0 and _passes(PAIR_POLICY[pair_class]["verify"], best, margin, content):
                mapping[sid] = bid
                taken.add(bid)
                new += 1
            results[sid] = {
                "left_id": left_index.funcs[sid].get("id"),
                "right_id": index.funcs[bid].get("id"),
                "score": round(best, 4),
                "margin": round(margin, 4),
                "content": content,
                "pair_class": pair_class,
                "status": status,
                "signals": {k: v for k, v in ev.items() if not k.startswith("_")},
                "kind": "identity",
            }
        if new == 0:
            break

    accepted = [row for row in results.values() if row["status"] != "unresolved"]
    if tier == "auto":
        accepted = [row for row in accepted if row["status"] == "auto"]
    return accepted
