"""Build each generated export package, then prove its bytes.

Two questions, asked separately because they fail separately:

  N-1  Does the package compile at all?
  N    Do the compiled bytes equal the original function bytes?

Packages directory, report dest, store path, and raw directory are required.
A green result on ``KOTOR_BYTES`` packages proves the emitter, not recovered
source — ``real_c`` stays a separate column.
"""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import time

from .exact_universal import elf_symbol_bytes
from .store import connect
from .verify_built import truth_for

ERR_RE = re.compile(r"error:\s*(.+)")
ADDR_IN_SRC = re.compile(r"^\s*\*\s*address\s*:\s*0x([0-9a-fA-F]+)", re.M)
SYM_IN_SRC = re.compile(r"^(?:KOTOR_NAKED|ASM_NAKED|NAKED)\s+void\s+([A-Za-z_]\w*)\s*\(", re.M)
ITANIUM_SIMPLE = re.compile(r"^_Z(\d+)(.+)$")


def build_one(pkg: pathlib.Path, jobs: int, timeout: int) -> dict:
    t0 = time.time()
    res: dict = {"package": pkg.name, "compiled": False, "seconds": 0.0, "errors": [], "objects": 0}
    subprocess.run(["make", "clean"], cwd=pkg, capture_output=True, timeout=120)
    try:
        r = subprocess.run(
            ["make", f"-j{jobs}", "-k"],
            cwd=pkg,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        res["errors"] = [f"timed out after {timeout}s"]
        res["seconds"] = round(time.time() - t0, 1)
        return res

    out = (r.stdout or "") + (r.stderr or "")
    res["objects"] = len(list((pkg / "build").rglob("*.o")))
    errs = [m.group(1).strip() for m in ERR_RE.finditer(out)]
    seen, uniq = set(), []
    for e in errs:
        key = re.sub(r"'[^']*'", "'X'", e)
        if key not in seen:
            seen.add(key)
            uniq.append(e)
    res["errors"] = uniq[:10]
    res["error_total"] = len(errs)
    res["compiled"] = r.returncode == 0 and not errs
    res["seconds"] = round(time.time() - t0, 1)
    lib = list(pkg.glob("build/lib*.a"))
    res["archive"] = lib[0].name if lib else None
    return res


def demangle(name: str) -> str:
    m = ITANIUM_SIMPLE.match(name)
    if m:
        n = int(m.group(1))
        rest = m.group(2)
        if len(rest) >= n:
            return rest[:n]
    return name


def demangle_all(names: list[str]) -> dict[str, str]:
    """Batch-demangle, preferring c++filt when it is installed."""
    out = {n: demangle(n) for n in names}
    hard = [n for n in names if n.startswith("_Z") and out[n] == n]
    if not hard:
        return out
    try:
        r = subprocess.run(
            ["c++filt"],
            input="\n".join(hard),
            text=True,
            capture_output=True,
            timeout=60,
        )
        if r.returncode == 0:
            for src, got in zip(hard, r.stdout.splitlines()):
                got = got.split("(")[0].strip()
                if got:
                    out[src] = got
    except (OSError, subprocess.SubprocessError):
        pass
    return out


def _symbol_to_addr(pkg: pathlib.Path) -> dict[str, int]:
    """Map each emitted symbol to the address it was generated from."""
    out: dict[str, int] = {}
    src_root = pkg / "src"
    if not src_root.is_dir():
        return out
    for src in src_root.rglob("*.cpp"):
        try:
            text = src.read_text(errors="replace")
        except OSError:
            continue
        addrs = [int(m.group(1), 16) for m in ADDR_IN_SRC.finditer(text)]
        syms = [m.group(1) for m in SYM_IN_SRC.finditer(text)]
        for sym, addr in zip(syms, addrs):
            out[sym] = addr
    return out


def verify_bytes(
    pkg: pathlib.Path,
    slug: str,
    *,
    store_path: pathlib.Path | str,
    raw_dir: pathlib.Path | str,
    funcbytes_dir: pathlib.Path | str | None = None,
    repo_path: str | None = None,
) -> dict:
    """Compare every compiled function's bytes against the shipped image."""
    out: dict = {"checked": 0, "matched": 0, "mismatched": 0, "unmapped": 0, "note": None, "examples": []}
    objs = sorted((pkg / "build").rglob("*.o"))
    if not objs:
        out["note"] = "nothing compiled, so there are no bytes to check"
        return out

    con = connect(store_path)
    expected = truth_for(repo_path or slug, con, raw_dir=raw_dir, funcbytes_dir=funcbytes_dir)
    if not expected:
        out["note"] = f"no raw image or db rows for {slug}"
        return out
    sym_addr = _symbol_to_addr(pkg)

    for obj in objs:
        try:
            data = obj.read_bytes()
            syms = elf_symbol_bytes(data, prefix="")
        except Exception:
            continue
        plain = demangle_all(list(syms))
        for name, got in syms.items():
            addr = sym_addr.get(plain.get(name, name)) or sym_addr.get(name)
            if addr is None:
                continue
            want = expected.get(addr)
            if want is None:
                out["unmapped"] += 1
                continue
            out["checked"] += 1
            if got[: len(want)] == want:
                out["matched"] += 1
            else:
                out["mismatched"] += 1
                if len(out["examples"]) < 5:
                    out["examples"].append(
                        {
                            "symbol": name,
                            "addr": f"0x{addr:08x}",
                            "want": want[:16].hex(),
                            "got": got[:16].hex(),
                        }
                    )
    return out


def verify(
    packages_dir: pathlib.Path | str,
    dest: pathlib.Path | str,
    store_path: pathlib.Path | str,
    raw_dir: pathlib.Path | str,
    *,
    funcbytes_dir: pathlib.Path | str | None = None,
    limit: int | None = None,
    jobs: int = 8,
    timeout: int = 3600,
    build: bool = True,
) -> dict:
    """Build packages under *packages_dir* and write a report to *dest*."""
    root = pathlib.Path(packages_dir)
    pkgs = sorted(p for p in root.iterdir() if p.is_dir() and (p / "Makefile").exists())
    if limit:
        pkgs = pkgs[:limit]
    rows = []
    for pkg in pkgs:
        r = build_one(pkg, jobs, timeout) if build else {
            "package": pkg.name,
            "compiled": False,
            "seconds": 0.0,
            "errors": [],
            "objects": len(list((pkg / "build").rglob("*.o"))),
        }
        r["bytes"] = verify_bytes(
            pkg,
            pkg.name,
            store_path=store_path,
            raw_dir=raw_dir,
            funcbytes_dir=funcbytes_dir,
        )
        rows.append(r)
    ok = sum(1 for r in rows if r.get("compiled"))
    checked = sum(r["bytes"].get("checked", 0) for r in rows)
    matched = sum(r["bytes"].get("matched", 0) for r in rows)
    report = {
        "generated_at": time.time(),
        "packages": len(rows),
        "compiled": ok,
        "functions_checked": checked,
        "functions_matched": matched,
        "results": rows,
    }
    path = pathlib.Path(dest)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=1), encoding="utf-8")
    report["out"] = str(path)
    return report
