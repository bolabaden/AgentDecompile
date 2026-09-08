"""Measure whether the pipeline can produce real C, with inline assembly banned.

Rebuilds a prompt project with an anti-inline-asm system prompt and grades
results with ``is_real_c``. Source and destination paths are required. There
is no product checkout default.
"""

from __future__ import annotations

import json
import pathlib
import re
import shutil

from .realc import is_real_c

SYSTEM_PROMPT = """You are decompiling a function from a 2004 Windows game \
compiled with Microsoft Visual C++. Your job is to recover the ORIGINAL C++ \
SOURCE CODE.

**The output must be real C/C++ source.** It must read like code a human wrote.

**Absolutely forbidden — these count as total failure:**
- `__asm`, `_emit`, `.byte`, or any inline assembly whatsoever
- `__declspec(naked)` or `__attribute__((naked))`
- Any technique that embeds machine code instead of expressing logic

Emitting the original bytes would trivially match the target, and it is worthless \
to us. We already have the bytes. We want the source.

**What we want instead:** ordinary control flow (`if`, `for`, `while`, `switch`), \
named local variables, struct field accesses, and real function calls.

**Success criteria, in order:**
1. The code is genuine C/C++ with no inline assembly.
2. It compiles.
3. Its compiled assembly matches the target as closely as possible.

Getting to zero differences matters, but NOT at the cost of rule 1. If you cannot \
reach zero differences with honest C, submit your closest honest attempt and say \
what did not match. A near-miss in real C is far more valuable than a perfect \
match made of `_emit` bytes.

**Tools**
- `compile_and_view_assembly` compiles your C and shows the diff against the \
target. Use it. Iterate on the specific mismatched instructions.

<decompilation_task>
{{promptContent}}
</decompilation_task>

Respond with only the C code in a single ```c block.
"""


def build_project(src: pathlib.Path | str, dest: pathlib.Path | str, n: int = 20) -> pathlib.Path:
    """Copy *src* to *dest*, keep *n* prompts, swap in the anti-asm system prompt."""
    src_p = pathlib.Path(src)
    dest_p = pathlib.Path(dest)
    if not src_p.is_dir():
        raise FileNotFoundError(f"source project required: {src_p}")
    if dest_p.exists():
        shutil.rmtree(dest_p)
    shutil.copytree(src_p, dest_p)
    for f in dest_p.glob("run*.json"):
        f.unlink()
    for f in dest_p.glob("*.log"):
        f.unlink()

    prompts_dir = dest_p / "prompts"
    if prompts_dir.is_dir():
        prompts = sorted(p for p in prompts_dir.iterdir() if p.is_dir())
        for p in prompts[n:]:
            shutil.rmtree(p)

    yaml_name = "atlas.yaml" if (dest_p / "atlas.yaml").exists() else "mizuchi.yaml"
    cfg_path = dest_p / yaml_name
    if cfg_path.exists():
        cfg = cfg_path.read_text(encoding="utf-8")
        cfg = cfg.replace(str(src_p), str(dest_p))
        new_sys = "    systemPrompt: " + json.dumps(SYSTEM_PROMPT) + "\n"
        cfg = re.sub(
            r"^    systemPrompt: .*?(?=^    [a-zA-Z]|\Z)",
            lambda _m: new_sys,
            cfg,
            flags=re.S | re.M,
        )
        if "decomp-permuter:" not in cfg:
            cfg = cfg.replace(
                "  objdiff:",
                """  decomp-permuter:
    enable: true
    maxIterations: 400
    timeoutMs: 180000
    compilerType: base
    flags:
      - '--show-errors'
      - '-j 4'
  objdiff:""",
            )
        cfg_path.write_text(cfg, encoding="utf-8")
    return dest_p


def grade(project_dir: pathlib.Path | str) -> dict:
    root = pathlib.Path(project_dir)
    files = sorted(root.glob("run-results-*.json")) or sorted(root.glob("partial-run-results-*.json"))
    if not files:
        return {"error": "no results yet"}
    d = json.loads(files[-1].read_text(encoding="utf-8"))
    rows = d.get("results", [])
    out = {
        "attempted": len(rows),
        "objdiff_success": 0,
        "real_c": 0,
        "inline_asm_cheat": 0,
        "failed": 0,
        "examples": [],
    }
    for r in rows:
        code = None
        for at in r.get("attempts", []):
            for pr in at.get("pluginResults", []):
                g = (pr.get("data") or {}).get("generatedCode")
                if g:
                    code = g
        ok = bool(r.get("success"))
        out["objdiff_success"] += ok
        if not code:
            out["failed"] += 1
            continue
        if not is_real_c(code):
            out["inline_asm_cheat"] += 1
        elif ok:
            out["real_c"] += 1
            if len(out["examples"]) < 3:
                out["examples"].append({"function": r.get("functionName"), "code": code[:1200]})
        else:
            out["failed"] += 1
    return out
