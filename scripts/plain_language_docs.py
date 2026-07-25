#!/usr/bin/env python3
"""Apply safe plain-language substitutions to Markdown prose (skips code blocks)."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Order matters: longer phrases first.
REPLACEMENTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bIt is important to note that\b", re.I), "Note:"),
    (re.compile(r"\bPlease note that\b", re.I), "Note:"),
    (re.compile(r"\bin order to\b", re.I), "to"),
    (re.compile(r"\bleverage\b", re.I), "use"),
    (re.compile(r"\butilize\b", re.I), "use"),
    (re.compile(r"\butilization\b", re.I), "use"),
    (re.compile(r"\bseamless(?:ly)?\b", re.I), ""),
    (re.compile(r"\brobust(?:ly)?\b", re.I), "reliable"),
    (re.compile(r"\bpowerful\b", re.I), ""),
    (re.compile(r"\benterprise-grade\b", re.I), ""),
    (re.compile(r"\bcutting-edge\b", re.I), ""),
    (re.compile(r"\bnext-gen(?:eration)?\b", re.I), ""),
    (re.compile(r"\bintuitive(?:ly)?\b", re.I), "clear"),
    (re.compile(r"\bholistic(?:ally)?\b", re.I), ""),
    (re.compile(r"\bgranular(?:ity)?\b", re.I), "detailed"),
    (re.compile(r"\bcomprehensive(?:ly)?\b", re.I), "full"),
    (re.compile(r"\bstreamlined\b", re.I), "simpler"),
    (re.compile(r"\bstate-of-the-art\b", re.I), ""),
    (re.compile(r"\bThis document provides\b", re.I), "This doc covers"),
    (re.compile(r"\bThis document describes\b", re.I), "This doc describes"),
    (re.compile(r"\bThe purpose of this document is to\b", re.I), "This doc"),
    (re.compile(r"\b  +"), " "),
    (re.compile(r" \."), "."),
    (re.compile(r" ,"), ","),
]

SKIP_DIRS = {".git", "node_modules", ".venv", "target", "vendor"}


def _split_fenced(text: str) -> list[tuple[str, bool]]:
    """Return (segment, is_code) pairs."""
    parts: list[tuple[str, bool]] = []
    pattern = re.compile(r"^(```+|~~~+).*$", re.MULTILINE)
    pos = 0
    in_fence = False
    for match in pattern.finditer(text):
        chunk = text[pos : match.start()]
        if chunk:
            parts.append((chunk, in_fence))
        parts.append((match.group(0) + "\n", True))
        in_fence = not in_fence
        pos = match.end()
    tail = text[pos:]
    if tail:
        parts.append((tail, in_fence))
    return parts


def plainize_prose(segment: str) -> str:
    # Do not alter inline code spans.
    pieces: list[str] = []
    last = 0
    for match in re.finditer(r"`[^`]+`", segment):
        prose = segment[last : match.start()]
        for pattern, repl in REPLACEMENTS:
            prose = pattern.sub(repl, prose)
        pieces.append(prose)
        pieces.append(match.group(0))
        last = match.end()
    prose = segment[last:]
    for pattern, repl in REPLACEMENTS:
        prose = pattern.sub(repl, prose)
    pieces.append(prose)
    return "".join(pieces)


def process_markdown(text: str) -> str:
    out: list[str] = []
    for segment, is_code in _split_fenced(text):
        if is_code:
            out.append(segment)
        else:
            out.append(plainize_prose(segment))
    return "".join(out)


def iter_markdown_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*.md"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        files.append(path)
    return sorted(files)


def main() -> int:
    dry_run = "--dry-run" in sys.argv
    changed = 0
    for path in iter_markdown_files(ROOT):
        original = path.read_text(encoding="utf-8")
        updated = process_markdown(original)
        if updated != original:
            changed += 1
            if not dry_run:
                path.write_text(updated, encoding="utf-8")
            rel = path.relative_to(ROOT)
            print(f"{'would update' if dry_run else 'updated'}: {rel}")
    print(f"{'would change' if dry_run else 'changed'} {changed} file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
