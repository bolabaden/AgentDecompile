"""Measure the byte-exact yield of raw Ghidra C on an unbiased sample.

Sampling and reporting are offline. Evaluation of a single case is injected
by the caller so this module does not import live compiler/Ghidra helpers.
"""

from __future__ import annotations

import collections
import json
import random
import time
from pathlib import Path

from .realc import is_real_c

BANDS = [(1, 8), (9, 16), (17, 32), (33, 64), (65, 128), (129, 512), (513, 1 << 30)]


def band_of(size: int) -> str:
    for lo, hi in BANDS:
        if lo <= size <= hi:
            return f"{lo}-{hi}B" if hi < (1 << 30) else f"{lo}+B"
    return "?"


def sample_functions(con, repo_path: str, n: int, seed: int) -> list[dict]:
    """Unbiased sample: every real function, no name or recovery filter."""
    rows = con.execute(
        """
        SELECT f.addr, f.size, f.name, f.canon_key, b.slug
          FROM func f JOIN binary b ON b.id = f.binary_id
         WHERE b.repo_path = ?
           AND f.is_thunk = 0
           AND f.n_instr >= 1
           AND f.size > 0
        """,
        (repo_path,),
    ).fetchall()
    pool = [dict(r) for r in rows]
    random.Random(seed).shuffle(pool)
    return pool[:n]


def summarize_results(results: list[dict]) -> dict:
    outcomes = collections.Counter(r.get("outcome") for r in results)
    exact = sum(1 for r in results if r.get("byte_exact"))
    by_band: dict[str, list[int]] = collections.defaultdict(lambda: [0, 0])
    for row in results:
        band = row.get("band") or band_of(int(row.get("size") or 0))
        by_band[band][0] += 1
        by_band[band][1] += int(bool(row.get("byte_exact")))
    return {
        "n": len(results),
        "byte_exact": exact,
        "rate": (exact / len(results)) if results else 0.0,
        "outcomes": dict(outcomes),
        "by_band": {k: {"n": v[0], "exact": v[1]} for k, v in by_band.items()},
    }


def write_yield(results: list[dict], dest: Path | str) -> Path:
    path = Path(dest)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in results:
            fh.write(json.dumps(row, default=str) + "\n")
    return path


def measure(
    con,
    repo_path: str,
    dest: Path | str,
    *,
    sample: int = 200,
    seed: int = 1,
    evaluate_one=None,
) -> dict:
    """Sample functions and write JSONL to *dest* (required).

    When *evaluate_one* is omitted, each case is recorded as skipped (offline).
    """
    cases = sample_functions(con, repo_path, sample, seed)
    results = []
    t0 = time.time()
    for case in cases:
        if evaluate_one is None:
            row = {**case, "outcome": "skipped-offline", "byte_exact": False}
        else:
            try:
                row = evaluate_one(case)
            except Exception as exc:
                row = {**case, "outcome": f"error:{type(exc).__name__}", "byte_exact": False}
        if "byte_exact" not in row and row.get("source"):
            row["byte_exact"] = False
            if not is_real_c(str(row.get("source") or "")):
                row["outcome"] = row.get("outcome") or "ghidra_shim"
        row["band"] = band_of(int(case["size"]))
        results.append(row)
    written = write_yield(results, dest)
    summary = summarize_results(results)
    summary["out"] = str(written)
    summary["seconds"] = round(time.time() - t0, 1)
    summary["repo_path"] = repo_path
    return summary
