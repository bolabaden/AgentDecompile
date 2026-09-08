"""Revalidate recovered files against their recorded project context.

Only ``byte_exact`` rows may be written to coverage ledgers. The ledger
records whether a row is readable C, but ingestion still recomputes that
classification from the source body.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import tempfile
from collections import Counter

from .seed_validation import destination_bytes, select_object_symbol
from .source_claims import is_real_c

ADDRESS_IN_FILENAME = re.compile(r"_([0-9a-fA-F]{8})\.c$")
SIZE_IN_HEADER = re.compile(r"size:\s*(\d+)\s*bytes", re.I)


def address_named_function(source: str, address: str) -> str | None:
    """Return ``F_<address>`` or ``_F_<address>`` from a function definition."""
    match = re.search(rf"\b(_?F_{re.escape(address)})\s*\(", source, re.I)
    return match.group(1) if match else None


def split_payload(source: str) -> str:
    end = source.find("*/")
    return source[end + 2 :].lstrip() if end >= 0 else source


def compile_current_source(
    source: pathlib.Path,
    context: str,
    slug: str,
    overrides: dict[str, str],
    cache: dict,
    *,
    compiler: pathlib.Path,
    raw_dir: pathlib.Path,
    mapper_for,
    coff_functions,
) -> dict:
    text = source.read_text(errors="replace")
    address_match = ADDRESS_IN_FILENAME.search(source.name)
    size_match = SIZE_IN_HEADER.search(text)
    result = {
        "source_path": str(source),
        "program": source.parent.name,
        "function": source.stem,
        "real_c": is_real_c(text),
    }
    if not address_match or not size_match:
        return {**result, "status": "parse_failed", "detail": "missing address or size"}

    address = address_match.group(1).lower()
    size = int(size_match.group(1))
    payload = split_payload(text)
    defined_name = address_named_function(payload, address)
    result.update({"address": address, "size": size, "defined_name": defined_name})
    if defined_name is None:
        return {**result, "status": "parse_failed", "detail": "no address-named function"}

    target = destination_bytes(
        slug, address, size, cache, raw_dir=raw_dir, mapper_for=mapper_for,
    )
    result["original_bytes"] = target.hex()
    with tempfile.TemporaryDirectory(prefix="ad-legacy-source-") as temp_dir:
        temp = pathlib.Path(temp_dir)
        candidate = temp / "candidate.c"
        obj = temp / "candidate.o"
        candidate.write_text(context + "\n" + payload)
        env = os.environ.copy()
        env.update(overrides)
        try:
            run = subprocess.run(
                [str(compiler), str(candidate), str(obj), defined_name],
                capture_output=True,
                text=True,
                env=env,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            return {**result, "status": "timeout"}
        detail = ((run.stdout or "") + (run.stderr or ""))[-1200:]
        if not obj.is_file():
            return {**result, "status": "compile_failed", "detail": detail}
        try:
            symbol, compiled = select_object_symbol(
                coff_functions(obj.read_bytes(), prefix=""), defined_name
            )
        except Exception as exc:
            return {**result, "status": "object_unreadable", "detail": str(exc)}

    result.update({"object_symbol": symbol, "compiled_bytes": compiled.hex()})
    result["status"] = (
        "byte_exact" if len(compiled) == len(target) and compiled == target
        else "not_byte_exact"
    )
    return result


def coverage_row(result: dict) -> dict:
    if result.get("status") != "byte_exact":
        raise ValueError("coverage requires a byte-exact result")
    return {
        "function": result["function"],
        "symbol": result["object_symbol"],
        "size": result["size"],
        "convention": None,
        "matched": True,
        "byteExact": True,
        "byteExactVerified": True,
        "originalBytes": result["original_bytes"],
        "error": "",
        "batch": "legacy-current-source-revalidation",
        "realC": result["real_c"],
        "verification": "compiled-current-source-vs-exported-binary",
    }


def merge_coverage(path: pathlib.Path, additions: list[dict]) -> None:
    """Replace same-name rows and retain every unrelated ledger row."""
    existing = []
    if path.is_file():
        with path.open(errors="replace") as handle:
            existing = [json.loads(line) for line in handle if line.strip()]
    names = {row["function"] for row in additions}
    merged = [row for row in existing if row.get("function") not in names]
    merged.extend(sorted(additions, key=lambda row: row["function"]))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in merged))


def verify(
    *,
    recovered_dir: pathlib.Path,
    projects: dict[str, dict],
    projects_root: pathlib.Path,
    results_path: pathlib.Path,
    summary_path: pathlib.Path,
    compiler: pathlib.Path,
    raw_dir: pathlib.Path,
    mapper_for,
    coff_functions,
    coverage_dir: pathlib.Path | None = None,
    write_coverage: bool = False,
    evidence_name: str | None = None,
) -> dict:
    rows = []
    raw_cache: dict = {}
    recovered_dir = pathlib.Path(recovered_dir)
    projects_root = pathlib.Path(projects_root)
    for program, config in projects.items():
        project = projects_root / config["project"]
        context = (project / "ctx.h").read_text(errors="replace")
        accepted: set[str] = set()
        if evidence_name and (project / evidence_name).is_file():
            results = json.loads((project / evidence_name).read_text())
            accepted = {
                str(row.get("functionName") or "").lstrip("_")
                for row in results.get("results", []) if row.get("success") is True
            }
        for source in sorted((recovered_dir / program).glob("*.c")):
            text = source.read_text(errors="replace")
            if evidence_name and (evidence_name not in text or config["project"] not in text):
                continue
            row = compile_current_source(
                source, context, config["slug"], config.get("env") or {}, raw_cache,
                compiler=compiler, raw_dir=raw_dir, mapper_for=mapper_for,
                coff_functions=coff_functions,
            )
            address = row.get("address")
            row["project"] = config["project"]
            row["old_result_success"] = bool(address and f"F_{address}" in accepted)
            rows.append(row)

    results_path = pathlib.Path(results_path)
    results_path.parent.mkdir(parents=True, exist_ok=True)
    results_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows))
    status = Counter(row["status"] for row in rows)
    summary = {
        "total": len(rows),
        "real_c": sum(bool(row["real_c"]) for row in rows),
        "shim": sum(not row["real_c"] for row in rows),
        "status": dict(sorted(status.items())),
        "byte_exact_real_c": sum(
            row["real_c"] and row["status"] == "byte_exact" for row in rows
        ),
        "byte_exact_shim": sum(
            not row["real_c"] and row["status"] == "byte_exact" for row in rows
        ),
        "coverage_written": write_coverage,
    }
    pathlib.Path(summary_path).write_text(json.dumps(summary, indent=2) + "\n")

    if write_coverage and coverage_dir is not None:
        coverage_dir = pathlib.Path(coverage_dir)
        for program in projects:
            additions = [
                coverage_row(row) for row in rows
                if row["program"] == program and row["status"] == "byte_exact"
            ]
            if additions:
                merge_coverage(coverage_dir / f"{program}.jsonl", additions)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recovered-dir", type=pathlib.Path, required=True)
    parser.add_argument("--projects-root", type=pathlib.Path, required=True)
    parser.add_argument("--projects-json", type=pathlib.Path, required=True)
    parser.add_argument("--results", type=pathlib.Path, required=True)
    parser.add_argument("--summary", type=pathlib.Path, required=True)
    parser.add_argument("--compiler", type=pathlib.Path, required=True)
    parser.add_argument("--raw-dir", type=pathlib.Path, required=True)
    parser.add_argument("--coverage-dir", type=pathlib.Path)
    parser.add_argument("--write-coverage", action="store_true")
    args = parser.parse_args(argv)
    projects = json.loads(pathlib.Path(args.projects_json).read_text())
    verify(
        recovered_dir=args.recovered_dir,
        projects=projects,
        projects_root=args.projects_root,
        results_path=args.results,
        summary_path=args.summary,
        compiler=args.compiler,
        raw_dir=args.raw_dir,
        mapper_for=lambda _raw: (None, None),
        coff_functions=lambda *_a, **_k: {},
        coverage_dir=args.coverage_dir,
        write_coverage=args.write_coverage,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
