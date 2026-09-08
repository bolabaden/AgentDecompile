"""Measure the matcher against name-derived ground truth."""

from __future__ import annotations

from collections import Counter, defaultdict

from . import canon, logical, match


def ground_truth(con, src_id: int, dst_id: int, mode: str = "engine") -> dict[int, int]:
    """Unique-name correspondences between two binaries.

    mode="engine" uses independently named functions (not library / FID).
    mode="fid" uses Ghidra Function-ID library matches instead.
    """

    def load(bid):
        by_key = defaultdict(list)
        for r in con.execute(
            """SELECT addr, name, canon_key, canon_class, canon_method, is_thunk,
                      n_instr, plate
                 FROM func WHERE binary_id=? AND canon_key IS NOT NULL""",
            (bid,),
        ):
            if canon.is_eh_clone(r["name"], r["plate"]):
                continue
            is_fid = canon.from_fid(r["plate"])
            if mode == "fid":
                if not is_fid:
                    continue
            elif canon.is_library(r["canon_key"]) or is_fid:
                continue
            if not r["canon_class"] and logical.GENERIC.match(r["canon_method"] or ""):
                continue
            by_key[r["canon_key"]].append(r)
        return by_key

    left, right = load(src_id), load(dst_id)
    gt = {}
    for key, arows in left.items():
        brows = right.get(key)
        if not brows or len(arows) != 1 or len(brows) != 1:
            continue
        if arows[0]["is_thunk"] or brows[0]["is_thunk"]:
            continue
        if (arows[0]["n_instr"] or 0) < 4 or (brows[0]["n_instr"] or 0) < 4:
            continue
        gt[arows[0]["addr"]] = brows[0]["addr"]
    return gt


def bucket_of(f: dict) -> str:
    n = f["n_instr"] or 0
    if n < 15:
        return "tiny(<15)"
    if n < 40:
        return "small(15-39)"
    if n < 120:
        return "medium(40-119)"
    return "large(>=120)"


def evaluate(
    con,
    src_path: str,
    dst_path: str,
    rounds: int = 4,
    mode: str = "engine",
) -> dict:
    src = con.execute("SELECT * FROM binary WHERE repo_path=?", (src_path,)).fetchone()
    dst = con.execute("SELECT * FROM binary WHERE repo_path=?", (dst_path,)).fetchone()
    if src is None or dst is None:
        raise KeyError((src_path, dst_path))
    gt = ground_truth(con, src["id"], dst["id"], mode)
    if not gt:
        return {"src": src_path, "dst": dst_path, "gt": 0}

    res = match.match_binaries(con, src["id"], dst["id"], rounds=rounds, use_name_features=False)
    results = res["results"]
    sa = res["src"]
    stats = Counter()
    per_bucket: dict[str, Counter] = defaultdict(Counter)
    wrong_examples = []
    raw = []

    for addr, truth in gt.items():
        r = results.get(addr)
        bk = bucket_of(sa.funcs[addr])
        per_bucket[bk]["gt"] += 1
        stats["gt"] += 1
        if r is None:
            stats["no_candidate"] += 1
            per_bucket[bk]["no_candidate"] += 1
            continue
        st = match.status_for(
            r["score"],
            r["margin"],
            res["pair_class"],
            r["evidence"].get("_content", 0),
            r["evidence"].get("compunit"),
        )
        ok = r["dst"] == truth
        raw.append(
            (
                round(r["score"], 4),
                round(r["margin"], 4),
                r["evidence"].get("_content", 0),
                r["evidence"].get("compunit"),
                int(ok),
            )
        )
        stats[f"{st}_total"] += 1
        per_bucket[bk][f"{st}_total"] += 1
        if ok:
            stats[f"{st}_correct"] += 1
            per_bucket[bk][f"{st}_correct"] += 1
            stats["top1_correct"] += 1
            per_bucket[bk]["top1_correct"] += 1
        elif st in ("auto", "verify") and len(wrong_examples) < 25:
            wrong_examples.append(
                {
                    "src_addr": f"0x{addr:x}",
                    "src_name": sa.funcs[addr]["canon_key"],
                    "predicted": f"0x{r['dst']:x}",
                    "predicted_name": res["dst"].funcs[r["dst"]]["canon_key"],
                    "truth": f"0x{truth:x}",
                    "truth_name": res["dst"].funcs[truth]["canon_key"],
                    "score": round(r["score"], 4),
                    "margin": round(r["margin"], 4),
                    "evidence": {k: round(v, 3) for k, v in r["evidence"].items() if not str(k).startswith("_")},
                }
            )

    def prec(st):
        total = stats[f"{st}_total"]
        return (stats[f"{st}_correct"] / total) if total else None

    return {
        "src": src_path,
        "dst": dst_path,
        "src_slug": src["slug"],
        "dst_slug": dst["slug"],
        "pair_class": res["pair_class"],
        "gt_mode": mode,
        "same_arch": (src["arch"], src["bits"]) == (dst["arch"], dst["bits"]),
        "same_format": src["format"] == dst["format"],
        "gt_pairs": len(gt),
        "total_accepted": len(res["mapping"]),
        "top1_accuracy": stats["top1_correct"] / max(stats["gt"], 1),
        "precision": {st: prec(st) for st in ("auto", "verify", "review", "unresolved")},
        "volume": {st: stats[f"{st}_total"] for st in ("auto", "verify", "review", "unresolved")},
        "no_candidate": stats["no_candidate"],
        "by_size": {
            k: {
                "gt": v["gt"],
                "auto_prec": (v["auto_correct"] / v["auto_total"]) if v["auto_total"] else None,
                "auto_n": v["auto_total"],
                "top1": v["top1_correct"] / v["gt"] if v["gt"] else None,
            }
            for k, v in sorted(per_bucket.items())
        },
        "false_positive_examples": wrong_examples,
        "raw_decisions": raw,
    }


def evaluate_pairs(con, pairs: list[tuple[str, str]], *, mode: str = "engine") -> list[dict]:
    out = []
    for src, dst in pairs:
        try:
            out.append(evaluate(con, src, dst, mode=mode))
        except Exception as exc:
            out.append({"src": src, "dst": dst, "error": str(exc)})
    return out
