"""Rebuild a program coverage ledger from Mizuchi-style run-results."""

from __future__ import annotations

import glob
import json
import os
import re
import subprocess
import sys
from pathlib import Path

OK = re.compile(r"^\s*OK\s+(\S+?):\s*(\d+)\s*bytes byte-identical(?:\s*\((\w+)\))?")
BAD = re.compile(r"^\s*X\s+(\S+?):\s*(.*)$")
UNAVAIL = re.compile(r"^\s*!?\s*(\S+?):\s*VERIFICATION UNAVAILABLE\s*-*\s*(.*)$")


def nearest_manifest(start_dir: Path, root_limit: Path) -> Path | None:
    d = start_dir.resolve()
    root_limit = root_limit.resolve()
    while True:
        mpath = d / "manifest.json"
        if mpath.is_file():
            return mpath
        if d == root_limit or d == d.parent:
            return None
        d = d.parent


def manifest_map(project_dir: Path, projects_root: Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    mpath = nearest_manifest(project_dir, projects_root)
    if mpath is None:
        return out
    try:
        data = json.loads(mpath.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return out
    for fn in data.get("functions") or []:
        sym = fn.get("objSymbol") or fn.get("symbol")
        if sym:
            out[sym] = fn
    return out


def find_result_dirs(root: Path) -> list[Path]:
    found: list[Path] = []
    for r, _dirs, files in os.walk(root):
        if any(
            f.startswith(("run-results-", "partial-run-results-")) and f.endswith(".json")
            for f in files
        ):
            found.append(Path(r))
    return sorted(found)


def rebuild(
    program: str,
    *,
    projects_dir: Path,
    coverage_dir: Path,
    gen_project_script: Path,
    patterns: list[str] | None = None,
    recovery_root: Path | None = None,
) -> dict:
    """Verify run-results and write ``coverage_dir/<program>.jsonl``."""
    projects = Path(projects_dir)
    cov = Path(coverage_dir)
    script = Path(gen_project_script)
    if not script.is_file():
        raise FileNotFoundError(f"gen-project script not found: {script}")
    root = recovery_root or projects.parent
    globs = patterns or [program.split(".")[0] + "*"]
    project_dirs = sorted(
        {
            Path(d)
            for pattern in globs
            for d in glob.glob(str(projects / pattern))
            if Path(d).is_dir()
        }
    )

    def belongs(d: Path) -> bool:
        for r, _dirs, files in os.walk(d):
            if "manifest.json" in files:
                try:
                    data = json.loads((Path(r) / "manifest.json").read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                named = data.get("program") or data.get("binary", "")
                if named:
                    return Path(str(named)).name == program
        return True

    results: list[dict] = []
    skipped: list[str] = []
    for d in project_dirs:
        if not belongs(d):
            skipped.append(str(d.relative_to(root)))
            continue
        for sub in find_result_dirs(d):
            files = sorted(sub.glob("run-results-*.json")) or sorted(sub.glob("partial-run-results-*.json"))
            if not files:
                continue
            latest = files[-1]
            symmap = manifest_map(sub, projects) or manifest_map(d, projects)
            try:
                proc = subprocess.run(
                    [sys.executable, str(script), program, "--verify", str(latest)],
                    capture_output=True,
                    text=True,
                    timeout=3600,
                )
            except subprocess.TimeoutExpired:
                results.append({"function": None, "error": "verify timeout", "batch": sub.name})
                continue
            try:
                doc = json.loads(latest.read_text(encoding="utf-8", errors="replace"))
            except (OSError, json.JSONDecodeError):
                doc = {}
            for res in doc.get("results") or []:
                name = res.get("promptPath") or res.get("functionName")
                if not name or res.get("success"):
                    continue
                err, reached_objdiff = "", False
                for att in reversed(res.get("attempts") or []):
                    for pr in att.get("pluginResults") or []:
                        if pr.get("pluginId") == "objdiff" and pr.get("status") in ("success", "failure"):
                            reached_objdiff = True
                        if pr.get("status") == "failure" and pr.get("error"):
                            err = str(pr["error"])[:200]
                            break
                    if err:
                        break
                low = err.lower()
                is_infra = (
                    "spend limit" in low
                    or "process exited" in low
                    or "returned an error result" in low
                )
                results.append(
                    {
                        "function": name,
                        "symbol": None,
                        "size": None,
                        "convention": None,
                        "matched": False,
                        "byteExact": False,
                        "byteExactVerified": reached_objdiff,
                        "infraError": is_infra,
                        "attempts": len(res.get("attempts") or []),
                        "error": err or "no objdiff match after all attempts",
                        "batch": sub.name,
                    }
                )
            for line in (proc.stdout or "").splitlines():
                m = OK.match(line)
                if m:
                    sym, size, byts = m.group(1), int(m.group(2)), m.group(3)
                    meta = symmap.get(sym, {})
                    results.append(
                        {
                            "function": meta.get("cName") or sym.strip("_@").split("@")[0],
                            "symbol": sym,
                            "size": size,
                            "convention": meta.get("convention") or meta.get("callingConvention"),
                            "matched": True,
                            "byteExact": True,
                            "byteExactVerified": True,
                            "originalBytes": byts,
                            "error": "",
                            "batch": sub.name,
                        }
                    )
                    continue
                m = UNAVAIL.match(line)
                if m:
                    sym = m.group(1)
                    meta = symmap.get(sym, {})
                    results.append(
                        {
                            "function": meta.get("cName") or sym.strip("_@").split("@")[0],
                            "symbol": sym,
                            "size": meta.get("size"),
                            "convention": meta.get("convention"),
                            "matched": True,
                            "byteExact": False,
                            "byteExactVerified": False,
                            "error": "VERIFICATION UNAVAILABLE: " + m.group(2),
                            "batch": sub.name,
                        }
                    )
                    continue
                m = BAD.match(line)
                if m and "byte-ident" in line:
                    sym = m.group(1)
                    meta = symmap.get(sym, {})
                    results.append(
                        {
                            "function": meta.get("cName") or sym.strip("_@").split("@")[0],
                            "symbol": sym,
                            "size": meta.get("size"),
                            "convention": meta.get("convention"),
                            "matched": True,
                            "byteExact": False,
                            "byteExactVerified": True,
                            "error": m.group(2)[:200],
                            "batch": sub.name,
                        }
                    )

    best: dict[str, dict] = {}
    for row in results:
        fn = row.get("function")
        if not fn:
            continue
        if (
            fn not in best
            or (row.get("byteExact") and not best[fn].get("byteExact"))
            or (row.get("symbol") and not best[fn].get("symbol"))
        ):
            best[fn] = row

    cov.mkdir(parents=True, exist_ok=True)
    out = cov / f"{program}.jsonl"
    with out.open("w", encoding="utf-8") as fh:
        for row in sorted(best.values(), key=lambda r: r["function"]):
            fh.write(json.dumps(row) + "\n")
    ok = sum(1 for r in best.values() if r.get("byteExact"))
    unver = sum(1 for r in best.values() if not r.get("byteExactVerified"))
    return {
        "ledger": str(out),
        "rows": len(best),
        "byte_exact": ok,
        "unverified": unver,
        "skipped_projects": skipped,
    }
