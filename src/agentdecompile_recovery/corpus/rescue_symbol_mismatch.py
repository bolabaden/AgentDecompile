"""Recover functions that failed only because the C function had the wrong name.

Rename the defining function to the required symbol, recompile, and keep it
only if the emitted bytes match. Project dirs, compile script, and output path
are required.
"""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
from pathlib import Path

CORE_RE = re.compile(r"(F_[0-9a-fA-F]{8})")


def wanted_symbol(result: dict) -> str | None:
    fn = str(result.get("functionName") or "")
    return fn or None


def defining_name(code: str, symbol: str | None = None) -> str | None:
    """The identifier the generated code actually defines."""
    del symbol
    for match in re.finditer(r"([A-Za-z_][A-Za-z0-9_:]*)\s*\([^;{]*\)\s*\{", code):
        name = match.group(1)
        if name in ("if", "for", "while", "switch", "return", "sizeof", "else"):
            continue
        return name
    return None


def rename(code: str, old: str, new: str) -> str:
    return re.sub(rf"(?<![A-Za-z0-9_]){re.escape(old)}(?![A-Za-z0-9_])", new, code)


def symbol_bytes(obj: Path, symbol: str) -> bytes | None:
    """Raw .text bytes of *symbol* in a COFF object, via objdump."""
    listed = subprocess.run(["objdump", "-b", "coff-i386", "-t", str(obj)], capture_output=True, text=True)
    if symbol not in listed.stdout:
        return None
    dumped = subprocess.run(["objdump", "-b", "coff-i386", "-d", str(obj)], capture_output=True, text=True)
    out, started = [], False
    for line in dumped.stdout.splitlines():
        if re.match(rf"^[0-9a-f]+ <{re.escape(symbol)}>:", line):
            started = True
            continue
        if started:
            if re.match(r"^[0-9a-f]+ <", line):
                break
            match = re.match(r"^\s*[0-9a-f]+:\s*((?:[0-9a-f]{2} )+)", line)
            if match:
                out.append(bytes.fromhex(match.group(1).replace(" ", "")))
    return b"".join(out) if out else None


def try_compile(code: str, symbol: str, target_obj: Path, compile_script: Path) -> tuple[bool, str]:
    """Compile and compare against the target object. True only on 0 differences."""
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "rescue.c"
        obj = Path(td) / "rescue.obj"
        src.write_text(code, encoding="utf-8")
        result = subprocess.run(
            ["sh", str(compile_script), str(src), str(obj), symbol],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if not obj.exists():
            return False, f"compile failed: {result.stderr.strip()[:160]}"
        ours = symbol_bytes(obj, symbol)
        theirs = symbol_bytes(target_obj, symbol)
        if ours is None:
            return False, "symbol still absent after rename"
        if theirs is None:
            return False, "target object unreadable"
        return (ours == theirs), ("byte-exact" if ours == theirs else f"differs ({len(ours)} vs {len(theirs)} bytes)")


def collect_candidates(project_dirs: list[Path | str]) -> list[tuple]:
    seen: set[str] = set()
    cands = []
    for directory in project_dirs:
        root = Path(directory)
        man: dict = {}
        try:
            payload = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
            for fn in payload.get("functions") or []:
                man[fn.get("prompt")] = fn
        except Exception:
            continue
        for rp in root.glob("*run-results*.json"):
            try:
                data = json.loads(rp.read_text(encoding="utf-8"))
            except Exception:
                continue
            for item in data if isinstance(data, list) else data.get("results") or []:
                for attempt in item.get("attempts") or []:
                    prs = {pr.get("pluginId"): pr for pr in (attempt.get("pluginResults") or [])}
                    od, cr = prs.get("objdiff"), prs.get("claude-runner")
                    if not (od and od.get("status") == "failure" and od.get("error") == "Symbol not found"):
                        continue
                    code = (cr.get("data") or {}).get("generatedCode") if cr else None
                    sym = wanted_symbol(item)
                    if not code or not sym:
                        continue
                    core = CORE_RE.search(sym)
                    if not core:
                        continue
                    key = core.group(1)
                    if key in seen:
                        continue
                    entry = man.get(key)
                    tobj = root / "target" / f"{key}.o"
                    if not entry or not tobj.exists():
                        continue
                    seen.add(key)
                    cands.append((key, sym, code, entry, tobj))
    return cands


def rescue(
    project_dirs: list[Path | str],
    compile_script: Path | str,
    out_path: Path | str,
    *,
    dry_run: bool = False,
    limit: int = 0,
    compare=None,
) -> dict:
    """Rescue symbol-mismatch failures. *compile_script* and *out_path* are required."""
    cands = collect_candidates(project_dirs)
    if limit:
        cands = cands[:limit]
    rescued, failed = [], 0
    comparer = compare or (lambda code, sym, tobj: try_compile(code, sym, tobj, Path(compile_script)))
    for key, sym, code, entry, tobj in cands:
        defname = defining_name(code, sym)
        if not defname or defname == key:
            failed += 1
            continue
        fixed = rename(code, defname, key)
        if dry_run:
            rescued.append((key, entry, fixed, sym))
            continue
        try:
            ok, _why = comparer(fixed, sym, tobj)
        except subprocess.TimeoutExpired:
            ok = False
        if ok:
            rescued.append((key, entry, fixed, sym))
        else:
            failed += 1

    dest = Path(out_path)
    if rescued and not dry_run:
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open("w", encoding="utf-8") as fh:
            for key, entry, code, sym in rescued:
                fh.write(
                    json.dumps(
                        {
                            "prompt": key,
                            "canonical_name": entry.get("canonical_name"),
                            "address": entry.get("address"),
                            "size": entry.get("size"),
                            "symbol": sym,
                            "code": code,
                            "evidence": "rescued-symbol-mismatch; recompiled and byte-compared",
                        }
                    )
                    + "\n"
                )
    return {"candidates": len(cands), "rescued": len(rescued), "failed": failed, "out": str(dest), "dry_run": dry_run}
