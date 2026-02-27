#!/usr/bin/env python3
"""
extract_java_tools.py

Recursively scans Java files looking for occurrences of `.name("...")` and captures
nearby `properties.put("...")`, `required.add("...")`, and `List.of(...)` usages.

Usage examples:
  # Basic scan from current directory
  python extract_java_tools.py

  # Specify a workspace root and a base subpath, output JSON to file
  python extract_java_tools.py --root /c/GitHub/agentdecompile \
      --base vendor/reverse-engineering-assistant/src/main/java/reva/tools \
      --output results.json --format json

  # Narrow the lookback window and include code snippets
  python extract_java_tools.py --window 120 --include-snippet --snippet-context 12

  # Filter only tools matching a regex, produce TSV
  python extract_java_tools.py --filter-tool '^myTool' --format tsv

  # Show help
  python extract_java_tools.py --help
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import re
import sys

from dataclasses import asdict, dataclass
from pathlib import Path
from textwrap import shorten
from typing import Iterable, List, Optional, Pattern

# ------- Helpers -------


def compile_or_exit(pattern: str, flags=0) -> Pattern:
    try:
        return re.compile(pattern, flags)
    except re.error as e:
        logging.error("Invalid regex pattern %r: %s", pattern, e)
        sys.exit(2)


def dedup_preserve(seq: Iterable[str]) -> List[str]:
    out: list[str] = []
    seen = set()
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


@dataclass
class MatchResult:
    tool_name: str
    file_path: str  # relative or absolute depending on args
    lineno: int  # 1-based line where .name(...) occurred
    properties: List[str]
    required: List[str]
    snippet: Optional[str] = None


# ------- Core parsing logic -------


def find_matches_in_lines(
    lines: List[str], name_re: Pattern, prop_re: Pattern, req_re: Pattern, listof_re: Pattern, window: int, include_listof_only_when_required: bool = True
) -> List[MatchResult]:
    """
    Scan the lines of a single file and return MatchResult entries for every .name(...) match.
    Uses a look-back window of `window` lines to collect properties/required/list.of entries.
    """
    results: list[MatchResult] = []
    total_lines = len(lines)
    for i, line in enumerate(lines):
        m = name_re.search(line)
        if not m:
            continue
        tool = m.group(1)
        start = max(0, i - window)
        chunk_lines = lines[start : i + 1]
        # find property keys
        prop_keys: List[str] = []
        for cl in chunk_lines:
            for pm in prop_re.finditer(cl):
                prop_keys.append(pm.group(1))
        prop_keys = dedup_preserve(prop_keys)

        # find required keys
        req_keys: List[str] = []
        for cl in chunk_lines:
            for rm in req_re.finditer(cl):
                req_keys.append(rm.group(1))
            # detect inline List.of("a","b")
            if "List.of(" in cl and (not include_listof_only_when_required or "required" in cl):
                # find values inside parentheses (not multi-line aware here)
                lom = listof_re.search(cl)
                if lom:
                    vals = re.findall(r'"([^"]+)"', lom.group(1))
                    req_keys.extend(vals)

        # also try to detect multi-line List.of across chunk by joining chunk to single string
        # pattern: required.*?List.of( ... ) up to the closing paren
        joined = "\n".join(chunk_lines)
        if "List.of" in joined:
            for lm in re.finditer(r"required[^;{)]{0,120}List\.of\((.*?)\)", joined, flags=re.S):
                inner = lm.group(1)
                vals = re.findall(r'"([^"]+)"', inner)
                req_keys.extend(vals)

        req_keys = dedup_preserve(req_keys)

        results.append(
            MatchResult(
                tool_name=tool,
                file_path="",  # caller will fill relative/absolute path
                lineno=i + 1,
                properties=prop_keys,
                required=req_keys,
                snippet=None,
            )
        )
    return results


def scan_files(
    root: Path,
    base: Optional[str],
    pattern: str,
    encoding: str,
    errors: str,
    name_pattern: str,
    prop_pattern: str,
    req_pattern: str,
    listof_pattern: str,
    window: int,
    include_listof_only_when_required: bool,
    include_snippet: bool,
    snippet_context: int,
    follow_symlinks: bool,
    max_files: Optional[int],
    filter_tool_re: Optional[Pattern],
    verbose: bool,
) -> List[MatchResult]:
    if base:
        base_path = (root / base).resolve()
    else:
        base_path = root.resolve()
    if not base_path.exists():
        raise FileNotFoundError(f"base path does not exist: {base_path!s}")

    name_re = compile_or_exit(name_pattern)
    prop_re = compile_or_exit(prop_pattern)
    req_re = compile_or_exit(req_pattern)
    listof_re = compile_or_exit(listof_pattern, flags=re.S)

    results: List[MatchResult] = []
    files_scanned = 0

    for p in base_path.rglob(pattern):
        if max_files is not None and files_scanned >= max_files:
            break
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding=encoding, errors=errors)
        except Exception as e:
            logging.warning("Failed to read %s: %s", p, e)
            continue
        files_scanned += 1
        lines = text.splitlines()
        matches = find_matches_in_lines(lines, name_re, prop_re, req_re, listof_re, window, include_listof_only_when_required)
        if not matches:
            continue
        rel_path = p.relative_to(root).as_posix() if root in p.parents or p == root else str(p.resolve())
        for m in matches:
            m.file_path = rel_path
            if filter_tool_re and not filter_tool_re.search(m.tool_name):
                continue
            if include_snippet:
                # build snippet around m.lineno (1-based)
                idx = m.lineno - 1
                sstart = max(0, idx - snippet_context)
                send = min(len(lines), idx + 1)
                snippet = "\n".join(lines[sstart:send])
                m.snippet = snippet
            results.append(m)
    if verbose:
        logging.info("Scanned %d files under %s", files_scanned, base_path)
    return results


# ------- Output formatting -------


def to_json(results: List[MatchResult], pretty: bool = True) -> str:
    arr = [asdict(r) for r in results]
    return json.dumps(arr, indent=2 if pretty else None, ensure_ascii=False)


def to_json_lines(results: List[MatchResult]) -> str:
    out_lines = []
    for r in results:
        out_lines.append(json.dumps(asdict(r), ensure_ascii=False))
    return "\n".join(out_lines)


def to_tsv(results: List[MatchResult]) -> str:
    header = ["tool_name", "file_path", "lineno", "required", "properties", "snippet"]
    rows = []
    for r in results:
        rows.append([r.tool_name, r.file_path, str(r.lineno), ",".join(r.required), ",".join(r.properties), (r.snippet or "").replace("\n", "\\n")])
    lines = ["\t".join(header)]
    lines.extend("\t".join(row) for row in rows)
    return "\n".join(lines)


def to_csv(results: List[MatchResult]) -> str:
    import io

    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["tool_name", "file_path", "lineno", "required", "properties", "snippet"])
    for r in results:
        writer.writerow([r.tool_name, r.file_path, r.lineno, ",".join(r.required), ",".join(r.properties), r.snippet or ""])
    return out.getvalue()


def to_table(results: List[MatchResult], max_tool_len: int = 30, max_path_len: int = 60) -> str:
    # build a small ASCII table
    rows = []
    for r in results:
        rows.append(
            [
                shorten(r.tool_name, width=max_tool_len, placeholder="..."),
                shorten(r.file_path, width=max_path_len, placeholder="..."),
                str(r.lineno),
                ",".join(r.required) or "-",
                ",".join(r.properties) or "-",
            ]
        )
    # format columns widths
    cols = list(zip(*([["tool_name", "path", "lineno", "required", "properties"]] + rows)))
    col_widths = [max(len(x) for x in c) for c in cols]
    lines = []
    # header
    header = ["tool_name", "path", "lineno", "required", "properties"]
    lines.append(" | ".join(h.ljust(w) for h, w in zip(header, col_widths)))
    lines.append("-+-".join("-" * w for w in col_widths))
    for row in rows:
        lines.append(" | ".join(c.ljust(w) for c, w in zip(row, col_widths)))
    # optionally include snippet after table for each match that has one
    for r in results:
        if r.snippet:
            lines.append("\n--- snippet: {}:{} ---".format(r.file_path, r.lineno))
            lines.append(r.snippet)
    return "\n".join(lines)


# ------- CLI -------


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Scan Java files for .name(...) uses and extract nearby properties/required keys.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--root", "-r", type=Path, default=Path("."), help="Workspace root directory")
    p.add_argument(
        "--base",
        "-b",
        type=str,
        default="vendor/reverse-engineering-assistant/src/main/java/reva/tools",
        help="Base subpath (relative to root) to search. If empty, root is used.",
    )
    p.add_argument("--pattern", type=str, default="**/*.java", help="glob pattern for files to scan (rglob style)")
    p.add_argument("--window", type=int, default=260, help="number of lines to look back from .name(...) match")
    p.add_argument("--encoding", type=str, default="utf-8", help="file encoding when reading")
    p.add_argument("--errors", type=str, default="ignore", choices=["strict", "ignore", "replace"], help="errors handler for file reading")
    p.add_argument("--name-pattern", type=str, default=r'\.name\("([^"]+)"\)', help="Regex to identify the tool name; must contain one capture group for the name")
    p.add_argument("--prop-pattern", type=str, default=r'properties\.put\("([^"]+)"', help="Regex to find properties; should capture the key")
    p.add_argument("--req-pattern", type=str, default=r'required\.add\("([^"]+)"\)', help="Regex to find required.add(...) occurrences; should capture the value")
    p.add_argument("--listof-pattern", type=str, default=r"List\.of\((.*?)\)", help="Regex to capture inner of List.of(...) (DOTALL enabled internally)")
    p.add_argument(
        "--include-listof-only-when-required", action="store_true", help="Only treat List.of(...) as 'required' when the same line contains 'required' (like snippets)"
    )
    p.add_argument("--include-snippet", action="store_true", help="Include code snippet near the match in output")
    p.add_argument("--snippet-context", type=int, default=20, help="Number of lines before the match to include in the snippet (lines after match excluded)")
    p.add_argument("--format", "-f", type=str, default="json", choices=["json", "jsonl", "tsv", "csv", "table"], help="Output format")
    p.add_argument("--output", "-o", type=Path, help="Write output to file (otherwise stdout)")
    p.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    p.add_argument("--max-files", type=int, default=None, help="Stop after scanning this many files (for quick runs)")
    p.add_argument("--filter-tool", type=str, default=None, help="Only include tools whose name matches this regex")
    p.add_argument("--follow-symlinks", action="store_true", help="Follow symlinks when scanning")
    p.add_argument("--dry-run", action="store_true", help="Do everything but don't write output (prints counts)")
    return p


def main(argv: Optional[List[str]] = None):
    args = build_arg_parser().parse_args(argv)

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING, format="%(levelname)s: %(message)s")

    try:
        filter_tool_re = compile_or_exit(args.filter_tool) if args.filter_tool else None
        results = scan_files(
            root=args.root,
            base=args.base if args.base else None,
            pattern=args.pattern,
            encoding=args.encoding,
            errors=args.errors,
            name_pattern=args.name_pattern,
            prop_pattern=args.prop_pattern,
            req_pattern=args.req_pattern,
            listof_pattern=args.listof_pattern,
            window=args.window,
            include_listof_only_when_required=args.include_listof_only_when_required,
            include_snippet=args.include_snippet,
            snippet_context=args.snippet_context,
            follow_symlinks=args.follow_symlinks,
            max_files=args.max_files,
            filter_tool_re=filter_tool_re,
            verbose=args.verbose,
        )
    except FileNotFoundError as e:
        logging.error(e)
        sys.exit(2)
    except Exception as e:
        logging.exception("Unexpected error during scan: %s", e)
        sys.exit(3)

    # Default sort by tool_name then path to make output stable
    results.sort(key=lambda r: (r.tool_name.lower(), r.file_path.lower(), r.lineno))

    if args.format == "json":
        out = to_json(results, pretty=True)
    elif args.format == "jsonl":
        out = to_json_lines(results)
    elif args.format == "tsv":
        out = to_tsv(results)
    elif args.format == "csv":
        out = to_csv(results)
    elif args.format == "table":
        out = to_table(results)
    else:
        out = to_json(results, pretty=True)

    if args.dry_run:
        print(f"Dry run: discovered {len(results)} matches (no output written).")
        return

    if args.output:
        try:
            args.output.write_text(out, encoding="utf-8")
            print(f"Wrote {len(results)} results to {args.output}")
        except Exception as e:
            logging.error("Failed to write output file %s: %s", args.output, e)
            sys.exit(4)
    else:
        print(out)


if __name__ == "__main__":
    main()
