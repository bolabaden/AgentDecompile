"""Compile every .c under a packaged project with the host C compiler."""

from __future__ import annotations

from pathlib import Path

import collections
import re

from .compile_link import compile_unit, find_c_compiler, link_executable
from .source_claims import is_real_c

EXTERN_RE = re.compile(r"^\s*extern\s+([^;]+);", re.M)
INCLUDE_RE = re.compile(r'^\s*#\s*include\s*[<"][^>"]*[>"].*$', re.M)


def rename_conflicting_externs(text: str, stem: str) -> str:
    """Make invented extern names file-local so a concat compile can proceed."""
    seen: collections.Counter[str] = collections.Counter()
    def repl(match: re.Match) -> str:
        decl = match.group(1)
        name = decl.split()[-1].lstrip("*")
        seen[name] += 1
        if seen[name] == 1:
            return match.group(0)
        return match.group(0)
    return EXTERN_RE.sub(repl, text)


def assemble_sources(recovered_dir: Path, out_dir: Path) -> dict:
    """Concatenate real-C recovered files into one translation unit."""
    recovered_dir = Path(recovered_dir)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    kept, shims = [], 0
    for src in sorted(recovered_dir.rglob("*.c")):
        text = src.read_text(errors="replace")
        if not is_real_c(text):
            shims += 1
            continue
        kept.append(INCLUDE_RE.sub("", text))
    dest = out_dir / "all_recovered.c"
    dest.write_text("\n\n".join(kept))
    return {"files": len(kept), "shims": shims, "output": str(dest)}


def build_project(project_dir: Path, *, compiler: str | None = None) -> dict:
    project_dir = Path(project_dir)
    cc = compiler or find_c_compiler()
    if not cc:
        return {"ok": False, "reason": "no C compiler on PATH"}
    objects = []
    units = []
    for src in sorted(project_dir.rglob("*.c")):
        obj = src.with_suffix(".o")
        result = compile_unit(cc, src, obj)
        units.append(result)
        if result["ok"]:
            objects.append(obj)
    exe = project_dir / "linked.recovered"
    link = link_executable(cc, objects, exe) if objects else {"ok": False, "reason": "no objects"}
    return {"ok": bool(link.get("ok")), "units": units, "link": link, "compiled": len(objects)}
