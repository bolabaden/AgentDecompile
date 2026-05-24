#!/usr/bin/env python3
"""Validate ce-compound docs/solutions/ frontmatter for parser-safety issues.

Usage:
    python3 scripts/validate-frontmatter.py <doc-path>

Copied from compound-engineering ce-compound skill; see skill for full semantics.
"""
import os
import re
import sys


def usage_fail(msg: str) -> "NoReturn":
    sys.stderr.write(f"validate-frontmatter: {msg}\n")
    sys.exit(2)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        usage_fail(f"usage: {os.path.basename(argv[0])} <doc-path>")

    doc_path = argv[1]
    if not os.path.isfile(doc_path):
        usage_fail(f"file not found: {doc_path}")

    with open(doc_path) as f:
        text = f.read()

    issues: list[str] = []

    lines = text.split("\n")
    if not lines or lines[0].rstrip() != "---":
        sys.stderr.write(
            f"FAIL: {doc_path}\n"
            f"  file does not start with '---' frontmatter delimiter line\n"
        )
        return 1

    end_idx: int | None = None
    for i in range(1, len(lines)):
        if lines[i].rstrip() == "---":
            end_idx = i
            break

    if end_idx is None:
        sys.stderr.write(
            f"FAIL: {doc_path}\n"
            f"  frontmatter not closed (no '---' line after the opening delimiter)\n"
        )
        return 1

    fm_text = "\n".join(lines[1:end_idx])

    for lineno, line in enumerate(fm_text.split("\n"), start=2):
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        if ":" not in line:
            continue
        if line.startswith((" ", "\t")):
            continue
        if stripped.startswith("- "):
            continue

        key, _, val = line.partition(":")
        val_stripped = val.strip()
        if not val_stripped:
            continue
        if val_stripped[0] in '"\'[{|>':
            continue

        if re.search(r"\s#", val_stripped):
            issues.append(
                f"line {lineno}: '{key.strip()}' value contains ' #' — quote it."
            )
        if re.search(r":\s", val_stripped):
            issues.append(
                f"line {lineno}: '{key.strip()}' value contains ': ' — quote it."
            )

    if issues:
        sys.stderr.write(f"FAIL: {doc_path}\n")
        for issue in issues:
            sys.stderr.write(f"  {issue}\n")
        return 1

    print(f"OK: {doc_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
