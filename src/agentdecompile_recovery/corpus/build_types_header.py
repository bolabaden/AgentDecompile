"""Emit recovered game types as a compilable header.

Field names starting with a digit or that are C keywords are renamed. Size-check
assertions are dropped and counted. Enum constants are prefixed with the enum
name so they cannot rewrite later type identifiers.
"""

from __future__ import annotations

import re
from pathlib import Path

C_KEYWORDS = {
    "auto", "break", "case", "char", "const", "continue", "default", "do",
    "double", "else", "enum", "extern", "float", "for", "goto", "if", "int",
    "long", "register", "return", "short", "signed", "sizeof", "static",
    "struct", "switch", "typedef", "union", "unsigned", "void", "volatile",
    "while", "class", "new", "delete", "this", "operator", "template",
}

FIELD_RE = re.compile(r"(^\s+[A-Za-z_][\w \*]*?\s+\*?)([A-Za-z_0-9]+)(\s*(?:\[[^\]]*\])?\s*;)", re.M)
SIZECHECK_RE = re.compile(r"typedef\s+char\s+_sizecheck_\w+\[[^\]]*\];\s*")
DEFINE_RE = re.compile(r"^#define\s+(\w+)(\s)", re.M)


def sanitise(defn: str, type_name: str) -> tuple[str, bool, int]:
    """Return (compilable definition, had_sizecheck, n_constants_prefixed)."""

    def field(match: re.Match) -> str:
        name = match.group(2)
        if name[0].isdigit() or name in C_KEYWORDS:
            name = "f_" + name
        return match.group(1) + name + match.group(3)

    had = bool(SIZECHECK_RE.search(defn))
    defn = FIELD_RE.sub(field, defn)
    defn = SIZECHECK_RE.sub("", defn)
    n_const = 0
    if DEFINE_RE.search(defn):
        seen: set[str] = set()
        lines = []
        for line in defn.splitlines():
            match = DEFINE_RE.match(line)
            if not match:
                lines.append(line)
                continue
            n_const += 1
            nm = f"{type_name}_{match.group(1)}"
            if nm in seen:
                val = re.search(r"\((-?\d+)\)\s*\)\s*$", line)
                nm = f"{nm}_{val.group(1)}" if val else f"{nm}_dup"
            seen.add(nm)
            lines.append(f"#define {nm}{match.group(2)}{line[match.end():]}")
        defn = "\n".join(lines)
    return defn, had, n_const


def build_header(con, binary_id: int, out: Path | str, *, program: str = "") -> dict:
    """Write sanitised ghidra_type rows for *binary_id* to *out* (required)."""
    rows = con.execute(
        "SELECT name, kind, size, definition FROM ghidra_type"
        " WHERE binary_id=? AND definition IS NOT NULL AND definition<>''"
        " ORDER BY name",
        (int(binary_id),),
    ).fetchall()
    parts, n_sizecheck, n_const = [], 0, 0
    for row in rows:
        text, had, nc = sanitise(row["definition"], row["name"])
        n_sizecheck += had
        n_const += nc
        parts.append(text.rstrip() + "\n")

    dest = Path(out)
    dest.parent.mkdir(parents=True, exist_ok=True)
    label = program or f"binary {binary_id}"
    header = (
        "/* Recovered game types for " + label + ".\n"
        " * Field offsets and sizes are analysis of the shipped binary.\n"
        " * They are evidence about layout, NOT recovered source.\n"
        " * Enum constants are prefixed with their enum's name.\n"
        " */\n\n"
    )
    dest.write_text(header + "\n".join(parts), encoding="utf-8")
    return {
        "types": len(rows),
        "had_sizecheck": n_sizecheck,
        "enum_constants": n_const,
        "out": str(dest),
        "bytes": dest.stat().st_size,
    }
