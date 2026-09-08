"""Drive machostabs.analyze and write JSON + markdown under a caller out_dir."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path, PurePosixPath

from . import machostabs

MEANINGS = {
    "N_SO": "source file / compilation unit boundary",
    "N_OSO": "object file (.o) the unit was linked from",
    "N_FUN": "function: name, source-level type, address, length",
    "N_STSYM": "file-scope static in data",
    "N_LCSYM": "file-scope static in bss",
    "N_GSYM": "global symbol with source type",
    "N_SLINE": "line-number to address mapping",
    "N_PSYM": "parameter, with source type",
    "N_LSYM": "local variable / typedef, with source type",
    "N_LBRAC": "lexical scope open",
    "N_RBRAC": "lexical scope close",
    "N_BNSYM": "begin nsect symbol",
    "N_ENSYM": "end nsect symbol",
    "N_RSYM": "register variable",
    "N_SOL": "included source file",
    "N_OPT": "compiler options / producer",
    "N_ENTRY": "alternate entry point",
}


def summarize(res: dict) -> str:
    lines = [f"# STABS analysis: `{res['file']}`", ""]
    lines.append(f"File size: {res['size']:,} bytes")
    lines.append("")
    for sl in res.get("slices") or []:
        lines.append(f"## slice `{sl.get('arch')}` ({sl.get('bits')}-bit) at file offset 0x{sl.get('offset', 0):x}")
        if "error" in sl:
            lines.append(f"- error: {sl['error']}")
            continue
        lines.append(f"- symbol table entries: {sl.get('n_symbols', 0):,}")
        lines.append(f"- STABS entries: {sl.get('n_stabs', 0):,}")
        lines.append(f"- segments: {', '.join(sl.get('segments') or [])}")
        st = sl.get("stabs")
        if not st:
            lines.append("- **no STABS debug information present**")
            lines.append("")
            continue
        lines.append("")
        lines.append("### Record type census")
        lines.append("")
        lines.append("| record | count | meaning |")
        lines.append("|---|---:|---|")
        for key, value in sorted(st["record_counts"].items(), key=lambda kv: -kv[1]):
            lines.append(f"| `{key}` | {value:,} | {MEANINGS.get(key, '')} |")
        lines.append("")
        units = st["units"]
        with_obj = [u for u in units if u["object_file"]]
        lines.append("### Compilation units")
        lines.append("")
        lines.append(f"- compilation units: **{len(units):,}**")
        lines.append(f"- units with an `.o` mapping: **{len(with_obj):,}**")
        lines.append(f"- functions with a source file: **{sum(1 for f in st['functions'] if f['source_file']):,}**")
        lines.append(f"- functions total in STABS: **{len(st['functions']):,}**")
        lines.append(f"- file-scope statics: **{len(st['statics']):,}**")
        lines.append(f"- globals with source types: **{len(st['globals']):,}**")
        exts = Counter(PurePosixPath(u["source_file"]).suffix for u in units if u["source_file"])
        lines.append(f"- source extensions: {dict(exts)}")
        lines.append("")
        lines.append("### Largest compilation units")
        lines.append("")
        lines.append("| source file | object file | functions |")
        lines.append("|---|---|---:|")
        for unit in sorted(units, key=lambda u: -len(u["functions"]))[:30]:
            obj = (unit["object_file"] or "").split("/")[-1]
            lines.append(f"| `{unit['source_file']}` | `{obj}` | {len(unit['functions'])} |")
        lines.append("")
        lines.append("### Sample function records")
        lines.append("")
        lines.append("| address | name | STABS type | source file |")
        lines.append("|---|---|---|---|")
        for fn in st["functions"][:20]:
            t = (fn["stabs_type"] or "")[:40]
            lines.append(f"| 0x{fn['addr']:x} | `{fn['name'][:70]}` | `{t}` | `{fn['source_file']}` |")
        lines.append("")
    return "\n".join(lines)


def write_report(binary_path: Path | str, out_dir: Path | str, *, repo_path: str | None = None) -> dict:
    """Analyze *binary_path* and write JSON + markdown under *out_dir* (required)."""
    src = Path(binary_path)
    dest = Path(out_dir)
    dest.mkdir(parents=True, exist_ok=True)
    res = machostabs.analyze(src)
    json_path = dest / f"{src.name}.json"
    md_path = dest / f"stabs_{src.name}.md"
    json_path.write_text(json.dumps(res, indent=1), encoding="utf-8")
    md_path.write_text(summarize(res), encoding="utf-8")
    index = {
        src.name: {
            "repo_path": repo_path or str(src),
            "slices": [
                {
                    "arch": s.get("arch"),
                    "n_symbols": s.get("n_symbols"),
                    "n_stabs": s.get("n_stabs"),
                    "units": len(s.get("stabs", {}).get("units", [])) if s.get("stabs") else 0,
                    "functions": len(s.get("stabs", {}).get("functions", [])) if s.get("stabs") else 0,
                }
                for s in res.get("slices") or []
            ],
        }
    }
    (dest / "_index.json").write_text(json.dumps(index, indent=1), encoding="utf-8")
    return {"json": str(json_path), "markdown": str(md_path), "index": index}
