"""Batch Ghidra / agentdecompile-cli decompilation into advisory/ghidra layer."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from .source_cleanup import format_source_text
from .source_dump import borealis_brace_style, normalize_entry_hex, strip_claim_banners


SCHEMA = "agentdecompile.ghidra-advisory-batch.v1"


def write_advisory_from_facts(
    *,
    facts_path: Path,
    out_dir: Path,
    limit: int = 0,
    skip_entries: set[str] | None = None,
) -> dict[str, Any]:
    """Materialize advisory C files from a function-facts JSONL with decompiled text."""

    out_dir.mkdir(parents=True, exist_ok=True)
    skip = skip_entries or set()
    written: list[dict[str, Any]] = []
    seen = 0
    with facts_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            row = json.loads(line)
            decompiled = row.get("decompiled")
            if not decompiled:
                continue
            status = row.get("decompilationStatus")
            if status and status != "complete":
                continue
            entry_raw = row.get("entry") or row.get("entryOffset") or row.get("address")
            entry = normalize_entry_hex(entry_raw)
            if not entry:
                continue
            if entry in skip:
                continue
            seen += 1
            if limit and len(written) >= limit:
                break
            name = str(row.get("name") or f"FUN_{entry}")
            # Prefer a clean FUN_* basename even when facts carry dump-stem names.
            if name.startswith(f"{entry}_"):
                name = name[len(entry) + 1 :]
            styled = borealis_brace_style(strip_claim_banners(str(decompiled)))
            formatted, formatting = format_source_text(styled, ".c")
            header = "\n".join(
                [
                    f"/* {name} entry={entry}",
                    " * Authority: Ghidra / agentdecompile-cli advisory — NOT objdiff-matched.",
                    f" * Prototype: {row.get('prototype')}",
                    " * claimBoundary: readability only.",
                    " */",
                    "",
                ]
            )
            path = out_dir / f"{entry}_{name}.c"
            path.write_text(header + formatted, encoding="utf-8")
            meta = {
                "name": name,
                "entry": entry,
                "path": str(path),
                "prototype": row.get("prototype"),
                "formatting": formatting,
                "claimBoundary": "advisory decompilation only; compile and objdiff gates remain required",
            }
            (out_dir / f"{entry}_{name}.json").write_text(
                json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            written.append(meta)

    receipt = {
        "schema": SCHEMA,
        "status": "complete",
        "factsPath": str(facts_path),
        "outDir": str(out_dir),
        "scannedWithDecompiled": seen,
        "written": len(written),
        "functions": written,
        "claimBoundary": "advisory layer only; never promote these files to verified/ without objdiff 0",
    }
    (out_dir / "batch-receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return receipt


def try_agentdecompile_cli_decompile(
    *,
    server_url: str,
    program_path: str,
    addresses: list[str],
    out_dir: Path,
    timeout: int = 120,
) -> dict[str, Any]:
    """Best-effort batch via agentdecompile-cli tool-seq when a server is up."""

    out_dir.mkdir(parents=True, exist_ok=True)
    if shutil.which("uv") is None and shutil.which("agentdecompile-cli") is None:
        return {
            "schema": SCHEMA,
            "status": "skipped:no-cli",
            "claimBoundary": "advisory batch skipped; install agentdecompile-cli or provide facts JSONL",
        }

    seq: list[dict[str, Any]] = []
    for address in addresses:
        seq.append(
            {
                "name": "decompile-function",
                "arguments": {"programPath": program_path, "address": address},
            }
        )
    cmd = [
        "uv",
        "run",
        "agentdecompile-cli",
        "--server-url",
        server_url,
        "tool-seq",
        json.dumps(seq),
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "schema": SCHEMA,
            "status": "error",
            "error": str(exc),
            "claimBoundary": "advisory batch failed; fall back to headless facts export",
        }
    raw_path = out_dir / "cli-tool-seq.json"
    raw_path.write_text(proc.stdout or "", encoding="utf-8")
    (out_dir / "cli-tool-seq.stderr").write_text(proc.stderr or "", encoding="utf-8")
    return {
        "schema": SCHEMA,
        "status": "complete" if proc.returncode == 0 else "error",
        "returncode": proc.returncode,
        "raw": str(raw_path),
        "addressCount": len(addresses),
        "claimBoundary": "CLI decompile output is advisory until objdiff 0",
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Batch advisory Ghidra decompilation into advisory/ghidra.")
    parser.add_argument("--facts", type=Path, help="Function facts JSONL with decompiled text (headless path).")
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--skip-entries-file", type=Path, help="JSON list of hex entries already verified.")
    parser.add_argument("--server-url", help="agentdecompile MCP server URL for live decompile (CLI path).")
    parser.add_argument("--program-path", help="Program path/name in the open project (with --server-url).")
    parser.add_argument("--address", action="append", default=[], help="Address to decompile via CLI. Repeatable.")
    args = parser.parse_args(argv)

    if args.server_url:
        if not (args.program_path and args.address):
            parser.error("--server-url requires --program-path and at least one --address")
        receipt = try_agentdecompile_cli_decompile(
            server_url=args.server_url,
            program_path=args.program_path,
            addresses=list(args.address),
            out_dir=args.out_dir,
        )
        print(json.dumps(receipt, indent=2))
        return 0 if receipt.get("status") == "complete" else 1

    if not args.facts:
        parser.error("either --facts (headless) or --server-url (CLI) is required")
    skip: set[str] = set()
    if args.skip_entries_file and args.skip_entries_file.exists():
        data = json.loads(args.skip_entries_file.read_text(encoding="utf-8"))
        if isinstance(data, list):
            skip = {normalize_entry_hex(item) for item in data}
    receipt = write_advisory_from_facts(
        facts_path=args.facts,
        out_dir=args.out_dir,
        limit=args.limit,
        skip_entries=skip,
    )
    print(json.dumps({k: receipt[k] for k in ("status", "written", "outDir", "claimBoundary")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
