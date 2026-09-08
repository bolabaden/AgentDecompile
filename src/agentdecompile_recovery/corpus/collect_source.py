"""Collect verified byte-exact C from Mizuchi-style run-results into a tree.

All paths are caller-supplied; there is no product checkout default.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path


def load_ledgers(coverage_dir: Path) -> tuple[dict[tuple[str, str], dict], dict[tuple[str, str], dict]]:
    """Return (byte_exact, seen) keyed by (program, function_name)."""
    byte_exact: dict[tuple[str, str], dict] = {}
    seen: dict[tuple[str, str], dict] = {}
    root = Path(coverage_dir)
    if not root.is_dir():
        return byte_exact, seen
    for path in root.glob("*.jsonl"):
        program = path.stem
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            name = row.get("function")
            if not name:
                continue
            key = (program, name)
            seen[key] = row
            if row.get("byteExact"):
                byte_exact[key] = row
    return byte_exact, seen


def program_for_project(project_dir: Path) -> str:
    d = Path(project_dir)
    for _ in range(4):
        manifest = d / "manifest.json"
        if manifest.is_file():
            break
        parent = d.parent
        if parent == d or d.name == "mizuchi-projects":
            break
        d = parent
    manifest = d / "manifest.json"
    if manifest.is_file():
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
            for key in ("program", "binary", "programName"):
                if isinstance(data, dict) and data.get(key):
                    return str(data[key])
        except (OSError, json.JSONDecodeError):
            pass
    base = Path(project_dir).name
    return re.sub(r"[_-]?(b\d+|r\d+|t\d+|s\d+|rerun\d*|shard\d+).*$", "", base) or base


def iter_results(projects_dir: Path):
    root = Path(projects_dir)
    if not root.is_dir():
        return
    for path in root.rglob("run-results-*.json"):
        yield path
    for path in root.rglob("partial-run-results-*.json"):
        yield path


def extract_run_results(path: Path):
    try:
        doc = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return
    for res in doc.get("results") or []:
        if not res.get("success"):
            continue
        name = res.get("promptPath") or res.get("functionName")
        code = None
        attempts = res.get("attempts") or []
        for att in reversed(attempts):
            for pr in att.get("pluginResults") or []:
                if pr.get("pluginId") == "claude-runner":
                    code = ((pr.get("data") or {}).get("generatedCode")) or code
            if code:
                break
        if name and code:
            yield name, code, len(attempts)


def collect(
    *,
    projects_dir: Path,
    coverage_dir: Path,
    out_dir: Path,
    recovery_root: Path | None = None,
) -> dict:
    """Write one .c per recovered function under *out_dir*."""
    byte_exact, seen = load_ledgers(coverage_dir)
    collected: dict[tuple[str, str], tuple[str, int, str]] = {}
    root = recovery_root or Path(projects_dir).parent
    for path in iter_results(projects_dir):
        program = program_for_project(path.parent)
        for name, code, attempts in extract_run_results(path):
            key = (program, name)
            if key in collected and key in byte_exact:
                continue
            collected[key] = (code, attempts, str(path.relative_to(root)))

    counts: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    out = Path(out_dir)
    for (program, name), (code, attempts, src) in sorted(collected.items()):
        row = byte_exact.get((program, name))
        verified = row is not None
        sub = "" if verified else "unverified"
        dest_dir = out / program / sub
        dest_dir.mkdir(parents=True, exist_ok=True)
        meta = row or seen.get((program, name)) or {}
        header = [
            "/*",
            f" * {name}  --  recovered from {program}",
            f" * size: {meta.get('size', '?')} bytes"
            f"   calling convention: {meta.get('convention', '?')}",
            f" * attempts: {attempts}",
        ]
        if meta.get("address"):
            header.append(f" * address: {meta['address']}")
        if meta.get("originalBytes"):
            header.append(f" * original machine code: {meta['originalBytes']}")
        header.append(
            " * VERIFIED BYTE-EXACT: recompiled and compared against the original binary"
            if verified
            else " * NOT byte-exact-verified: satisfied objdiff only. Treat as unconfirmed."
        )
        header += [f" * evidence: {src}", " */", ""]
        (dest_dir / f"{name}.c").write_text("\n".join(header) + code.rstrip() + "\n", encoding="utf-8")
        counts[program][0 if verified else 1] += 1

    lines = [f"{'binary':34s} {'byte-exact':>11s} {'unverified':>11s}"]
    tot_v = tot_u = 0
    for program, (v, u) in sorted(counts.items()):
        lines.append(f"{program:34s} {v:11d} {u:11d}")
        tot_v += v
        tot_u += u
    lines.append(f"{'TOTAL':34s} {tot_v:11d} {tot_u:11d}")
    report = "\n".join(lines)
    out.mkdir(parents=True, exist_ok=True)
    (out / "INDEX.txt").write_text(report + "\n", encoding="utf-8")
    return {
        "out_dir": str(out),
        "index": str(out / "INDEX.txt"),
        "byte_exact": tot_v,
        "unverified": tot_u,
        "programs": dict(counts),
        "report": report,
    }
