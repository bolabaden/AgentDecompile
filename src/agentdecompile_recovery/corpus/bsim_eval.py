"""Measure Ghidra BSim against the same name-derived ground truth.

Pairs, BSim URL, and output path are required. Offline callers get a skip
result when no program / client factory is available.
"""

from __future__ import annotations

import json
import random
import time
from pathlib import Path

from . import evaluate, ghidra_env as ge

THRESH = 0.5
SIGNIF = 0.0


def _client(bsim_url: str):
    if ge.start() is False:
        return None
    from ghidra.features.bsim.query import BSimClientFactory

    url = BSimClientFactory.buildURL(bsim_url)
    client = BSimClientFactory.buildClient(url, False)
    if not client.initialize():
        raise RuntimeError(f"BSim init failed: {client.getLastError()}")
    return client


def query_sample(
    src_repo: str,
    dst_md5: str,
    addrs: list[int],
    *,
    bsim_url: str,
    open_program=None,
    top_k: int = 5,
) -> dict[int, list]:
    """Return {src_addr: [(md5, name, addr, similarity, significance), ...]}."""
    opener = open_program or ge.open_program
    client = _client(bsim_url)
    if client is None:
        return {}
    from ghidra.features.bsim.gui.filters import Md5BSimFilterType
    from ghidra.features.bsim.query import GenSignatures
    from ghidra.features.bsim.query.protocol import BSimFilter, QueryNearest

    out: dict[int, list] = {}
    try:
        with opener(src_repo) as program:
            if program is None:
                return {}
            fm = program.getFunctionManager()
            space = program.getAddressFactory().getDefaultAddressSpace()
            wanted = []
            for addr in addrs:
                func = fm.getFunctionAt(space.getAddress(addr))
                if func is not None:
                    wanted.append((addr, func))

            filt = BSimFilter()
            filt.addAtom(Md5BSimFilterType(), dst_md5)
            batch = 50
            for i in range(0, len(wanted), batch):
                chunk = wanted[i : i + batch]
                gensig = GenSignatures(False)
                gensig.setVectorFactory(client.getLSHVectorFactory())
                gensig.openProgram(program, None, None, None, None, None)
                for _a, func in chunk:
                    gensig.scanFunction(func)
                query = QueryNearest()
                query.manage = gensig.getDescriptionManager()
                query.max = top_k
                query.thresh = THRESH
                query.signifthresh = SIGNIF
                query.bsimFilter = filt
                resp = query.execute(client)
                if resp is None:
                    continue
                for sim in resp.result:
                    base = sim.getBase()
                    src_addr = int(base.getAddress())
                    hits = []
                    for note in sim.iterator():
                        fd = note.getFunctionDescription()
                        exe = fd.getExecutableRecord()
                        hits.append(
                            (
                                str(exe.getMd5()),
                                str(fd.getFunctionName()),
                                int(fd.getAddress()),
                                float(note.getSimilarity()),
                                float(note.getSignificance()),
                            )
                        )
                    out[src_addr] = hits
                gensig.dispose()
    finally:
        client.close()
    return out


def evaluate_pairs(
    con,
    pairs: list[tuple[str, str]],
    *,
    bsim_url: str,
    out_path: Path | str,
    sample: int = 400,
    seed: int = 20260811,
    query=None,
) -> list[dict]:
    """Evaluate caller-supplied (src, dst) repo_path pairs. *out_path* is required."""
    if not pairs:
        raise ValueError("pairs is required")
    random.seed(seed)
    results = []
    querier = query
    for src, dst in pairs:
        srow = con.execute("SELECT * FROM binary WHERE repo_path=?", (src,)).fetchone()
        drow = con.execute("SELECT * FROM binary WHERE repo_path=?", (dst,)).fetchone()
        if not srow or not drow:
            results.append({"src": src, "dst": dst, "skipped": "not extracted"})
            continue
        gt = evaluate.ground_truth(con, srow["id"], drow["id"])
        if not gt:
            results.append({"src": src, "dst": dst, "skipped": "no ground truth"})
            continue
        addrs = sorted(gt)
        if len(addrs) > sample:
            addrs = random.sample(addrs, sample)
        t0 = time.time()
        if querier is None:
            try:
                hits = query_sample(src, drow["md5"], addrs, bsim_url=bsim_url)
            except Exception as exc:
                results.append({"src": src, "dst": dst, "error": str(exc)})
                continue
            if not hits and ge.start() is False:
                results.append({"src": src, "dst": dst, "skipped": "no-program", "sampled": len(addrs)})
                continue
        else:
            hits = querier(src, drow["md5"], addrs)
        top1 = topk = queried = 0
        sims_correct, sims_wrong = [], []
        for addr in addrs:
            h = hits.get(addr)
            if not h:
                continue
            queried += 1
            truth = gt[addr]
            if h[0][2] == truth:
                top1 += 1
                sims_correct.append(h[0][3])
            else:
                sims_wrong.append(h[0][3])
            if any(x[2] == truth for x in h):
                topk += 1
        rec = {
            "src": src,
            "dst": dst,
            "sampled": len(addrs),
            "returned_a_hit": queried,
            "top1_correct": top1,
            "topk_correct": topk,
            "top1_precision_of_returned": round(top1 / queried, 4) if queried else None,
            "top1_recall_of_sample": round(top1 / len(addrs), 4),
            "mean_similarity_correct": round(sum(sims_correct) / len(sims_correct), 4) if sims_correct else None,
            "mean_similarity_wrong": round(sum(sims_wrong) / len(sims_wrong), 4) if sims_wrong else None,
            "seconds": round(time.time() - t0, 1),
        }
        results.append(rec)

    dest = Path(out_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(results, indent=1), encoding="utf-8")
    return results
