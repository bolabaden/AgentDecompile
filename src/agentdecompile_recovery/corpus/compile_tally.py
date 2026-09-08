"""Count why Ghidra C fails to compile, over a random sample.

Stops at the compile step — no permuter, no byte comparison. Store path,
repo path, and output path are required. There is no default binary.
"""

from __future__ import annotations

import collections
import json
import pathlib
import random
import re
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor

from . import permuter_harness as ph
from .store import connect

ERR_RE = re.compile(r"error (C\d+): ([^\n\r]*)")


def sample_random(con, repo: str, n: int, *, seed: int = 1234) -> list[dict]:
    b = con.execute("SELECT id FROM binary WHERE repo_path=?", (repo,)).fetchone()
    if not b:
        return []
    rows = [
        dict(r)
        for r in con.execute(
            """SELECT addr, size, name FROM func
                WHERE binary_id=? AND n_instr>0 AND size>0 AND is_thunk=0""",
            (b["id"],),
        )
    ]
    random.seed(seed)
    random.shuffle(rows)
    return [{**r, "repo_path": repo} for r in rows[:n]]


def try_one(
    case: dict,
    ctx: str,
    base_c: str,
    compiler: str,
    *,
    compiler_path: pathlib.Path | str | None = None,
) -> dict:
    name = ph.defined_name(base_c, case["name"])
    called = {f for f in ph.CALL_RE.findall(base_c) if f not in ph.C_KEYWORDS and f != name}
    drop = {name} | called
    kept = []
    for line in ctx.splitlines():
        t = line.strip()
        if re.match(r"typedef\s+[\w ]+\s+(?:code|unicode)\s*;", t):
            continue
        if t.startswith("extern ") and t.endswith(";"):
            sym = t[:-1].split()[-1].lstrip("*")
            if sym in drop:
                continue
        kept.append(line)
    protos = [f"undefined4 {fn}();" for fn in sorted(called)]
    src = "\n".join(kept) + "\n" + ph.func_typedefs(base_c) + "\n".join(protos) + "\n\n" + ph.fix_thiscall(base_c)
    exe = compiler_path or ph.COMPILERS.get(compiler)
    if exe is None:
        return {**case, "ok": False, "errors": ["NO_COMPILER"]}
    with tempfile.TemporaryDirectory() as td:
        c = pathlib.Path(td) / "t.c"
        c.write_text(src)
        obj = pathlib.Path(td) / "t.o"
        try:
            r = subprocess.run(
                [str(exe), str(c), str(obj), f"_{name}"],
                capture_output=True,
                text=True,
                timeout=240,
            )
        except (subprocess.TimeoutExpired, OSError):
            return {**case, "ok": False, "errors": ["TIMEOUT"]}
        if obj.exists():
            return {**case, "ok": True, "errors": []}
        errs = [f"{m.group(1)}: {m.group(2)[:70]}" for m in ERR_RE.finditer(r.stdout + r.stderr)]
        return {**case, "ok": False, "errors": errs[:3]}


def tally(
    store_path: pathlib.Path | str,
    repo_path: str,
    dest: pathlib.Path | str,
    *,
    n: int = 300,
    compiler: str = "vc8",
    jobs: int = 8,
    context: str | None = None,
    cfuncs: dict[str, str] | None = None,
    compiler_path: pathlib.Path | str | None = None,
) -> dict:
    """Sample *n* functions from *repo_path*, compile, write the tally to *dest*."""
    if not repo_path:
        raise ValueError("repo_path is required; there is no default binary")
    con = connect(store_path)
    cases = sample_random(con, repo_path, n)
    if cfuncs is None:
        try:
            cfuncs = ph.ghidra_c_for(repo_path)
        except Exception:
            cfuncs = {}
    if context is None:
        try:
            context = ph.repair_context(ph.context_for(repo_path), compiler)
        except Exception:
            context = ""
    work = [(c, cfuncs[c["name"]]) for c in cases if c["name"] in cfuncs]
    if work:
        with ThreadPoolExecutor(max_workers=jobs) as ex:
            res = list(
                ex.map(
                    lambda t: try_one(t[0], context or "", t[1], compiler, compiler_path=compiler_path),
                    work,
                )
            )
    else:
        res = []
    ok = sum(1 for r in res if r["ok"])
    tally_codes: collections.Counter = collections.Counter()
    msg: dict[str, str] = {}
    for r in res:
        if not r["ok"] and r["errors"]:
            code = r["errors"][0].split(":")[0]
            tally_codes[code] += 1
            msg.setdefault(code, r["errors"][0])
    out = pathlib.Path(dest)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(res, indent=1), encoding="utf-8")
    return {
        "out": str(out),
        "repo_path": repo_path,
        "sampled": len(cases),
        "with_ghidra_c": len(work),
        "compiles": ok,
        "results": len(res),
        "codes": tally_codes.most_common(15),
        "examples": msg,
    }
