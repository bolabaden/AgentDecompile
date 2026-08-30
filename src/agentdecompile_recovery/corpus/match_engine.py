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


def status_for(pair_class: str, score: float, margin: float, content: int) -> str | None:
    policy = PAIR_POLICY[pair_class]
    for name in ("auto", "verify", "review"):
        if _passes(policy[name], score, margin, content):
            return name
    return None


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


class FeatureIndex:
    def __init__(self, functions: Iterable[dict[str, Any]]):
        self.funcs = {str(fn.get("id") or fn.get("addr")): fn for fn in functions}
        self.by_string: dict[str, list[str]] = defaultdict(list)
        self.by_const: dict[Any, list[str]] = defaultdict(list)
        self.by_ext: dict[str, list[str]] = defaultdict(list)
        for fid, fn in self.funcs.items():
            for s in fn.get("strings") or []:
                self.by_string[s].append(fid)
            for c in fn.get("consts") or []:
                self.by_const[c].append(fid)
            for e in fn.get("ext_calls") or []:
                self.by_ext[e].append(fid)

    def candidates(self, src: dict[str, Any]) -> set[str]:
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
        if not votes:
            return set(self.funcs)
        return set(votes)


def match_binaries(
    left: list[dict[str, Any]],
    right: list[dict[str, Any]],
    *,
    left_meta: dict[str, Any] | None = None,
    right_meta: dict[str, Any] | None = None,
    tier: str = "auto",
) -> list[dict[str, Any]]:
    """Score blocked pairs and keep those that clear PAIR_POLICY[class][tier]."""
    pair_class = classify_pair(left_meta or {}, right_meta or {})
    same_arch = pair_class in ("same_platform", "cross_format") or (
        (left_meta or {}).get("arch") == (right_meta or {}).get("arch")
    )
    index = FeatureIndex(right)
    accepted: list[dict[str, Any]] = []
    for fa in left:
        cands = index.candidates(fa)
        scored: list[tuple[float, dict[str, float], dict[str, Any]]] = []
        for fid in cands:
            fb = index.funcs[fid]
            score, ev = score_features(fa, fb, same_arch=same_arch)
            scored.append((score, ev, fb))
        if not scored:
            continue
        scored.sort(key=lambda row: row[0], reverse=True)
        best, ev, fb = scored[0]
        runner = scored[1][0] if len(scored) > 1 else 0.0
        margin = best - runner
        content = int(ev.get("_content") or 0)
        status = status_for(pair_class, best, margin, content)
        if status is None:
            continue
        if tier == "auto" and status != "auto":
            continue
        accepted.append(
            {
                "left_id": fa.get("id"),
                "right_id": fb.get("id"),
                "score": round(best, 4),
                "margin": round(margin, 4),
                "content": content,
                "pair_class": pair_class,
                "status": status,
                "signals": {k: v for k, v in ev.items() if not k.startswith("_")},
                "kind": "identity",
            }
        )
    return accepted
