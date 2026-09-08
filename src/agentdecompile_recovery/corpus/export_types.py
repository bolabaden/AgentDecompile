"""Export Ghidra struct/union/enum definitions so decompiled C can compile.

Emitted C is ``#pragma pack(1)`` with explicit padding at every gap. Nested
composites become byte arrays; pointers become ``void *``.
"""

from __future__ import annotations

import re
import sqlite3

from . import ghidra_env as ge

SCHEMA = """
CREATE TABLE IF NOT EXISTS ghidra_type (
    binary_id   INTEGER NOT NULL,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL,
    size        INTEGER,
    definition  TEXT NOT NULL,
    n_fields    INTEGER,
    PRIMARY KEY (binary_id, name, kind)
);
CREATE INDEX IF NOT EXISTS ix_ghidra_type_bin ON ghidra_type(binary_id);
"""

_PRIM = {
    "byte": "unsigned char",
    "sbyte": "signed char",
    "char": "char",
    "uchar": "unsigned char",
    "schar": "signed char",
    "word": "unsigned short",
    "sword": "short",
    "ushort": "unsigned short",
    "short": "short",
    "dword": "unsigned int",
    "sdword": "int",
    "uint": "unsigned int",
    "int": "int",
    "long": "long",
    "ulong": "unsigned long",
    "qword": "unsigned long long",
    "sqword": "long long",
    "longlong": "long long",
    "ulonglong": "unsigned long long",
    "float": "float",
    "double": "double",
    "longdouble": "long double",
    "bool": "unsigned char",
    "void": "void",
    "undefined": "unsigned char",
    "undefined1": "unsigned char",
    "undefined2": "unsigned short",
    "undefined4": "unsigned int",
    "undefined8": "unsigned long long",
    "pointer": "void *",
    "pointer32": "void *",
}

_IDENT_OK = re.compile(r"^[A-Za-z_]\w*$")


def c_ident(name: str) -> str:
    """Ghidra type names carry `::`, spaces, templates and punctuation."""
    text = re.sub(r"::", "__", str(name))
    text = re.sub(r"\W+", "_", text).strip("_")
    return text or "anon"


def render_field_type(dt, depth: int = 0) -> str:
    """Render a Ghidra DataType as a C type, conservatively."""
    from ghidra.program.model.data import Array, Enum, Pointer, Structure, TypeDef, Union  # type: ignore

    if dt is None:
        return ""
    if isinstance(dt, Pointer):
        return "void *"
    if isinstance(dt, TypeDef):
        return render_field_type(dt.getBaseDataType(), depth + 1)
    nm = str(dt.getName())
    low = nm.lower()
    if low in _PRIM:
        return _PRIM[low]
    if isinstance(dt, Enum):
        return "int" if dt.getLength() == 4 else "int"
    if isinstance(dt, (Structure, Union, Array)):
        return ""
    return ""


def emit_struct(dt) -> tuple[str, int] | None:
    """Emit one struct/union as packed C with explicit gap padding."""
    from ghidra.program.model.data import Union  # type: ignore

    name = c_ident(dt.getName())
    if not _IDENT_OK.match(name):
        return None
    length = int(dt.getLength() or 0)
    if length <= 0:
        return None

    lines = [f"typedef struct {name} {{"]
    n_fields = 0

    if isinstance(dt, Union):
        lines = [f"typedef struct {name} {{", f"  unsigned char _u[0x{length:x}];"]
    else:
        cursor = 0
        for comp in dt.getComponents():
            off = int(comp.getOffset())
            clen = int(comp.getLength() or 0)
            if off < cursor or clen <= 0:
                continue
            if off > cursor:
                lines.append(f"  unsigned char _pad{cursor:x}[0x{off - cursor:x}];")
            fname = comp.getFieldName()
            fname = c_ident(fname) if fname else f"field_{off:x}"
            ctype = render_field_type(comp.getDataType())
            if ctype and clen in (1, 2, 4, 8):
                lines.append(f"  {ctype} {fname};")
            else:
                lines.append(f"  unsigned char {fname}[0x{clen:x}];")
            n_fields += 1
            cursor = off + clen
        if cursor < length:
            lines.append(f"  unsigned char _pad{cursor:x}[0x{length - cursor:x}];")

    lines.append(f"}} {name};")
    lines.append(f"typedef char _sizecheck_{name}[(sizeof({name}) == 0x{length:x}) ? 1 : -1];")
    return "\n".join(lines), n_fields


def emit_enum(dt) -> tuple[str, int] | None:
    name = c_ident(dt.getName())
    if not _IDENT_OK.match(name):
        return None
    width = {1: "unsigned char", 2: "unsigned short", 4: "unsigned int", 8: "unsigned long long"}.get(
        int(dt.getLength() or 4), "unsigned int"
    )
    lines = [f"typedef {width} {name};"]
    n = 0
    for vname in dt.getNames():
        ident = c_ident(vname)
        if not _IDENT_OK.match(ident):
            continue
        lines.append(f"#define {ident} (({name})({dt.getValue(vname)}))")
        n += 1
    return "\n".join(lines), n


def definitions_for(con: sqlite3.Connection, binary_id: int, names: set[str]) -> tuple[str, set[str]]:
    """Return emitted C for whichever of *names* this binary has a layout for."""
    if not names:
        return "", set()
    qs = ",".join("?" * len(names))
    rows = con.execute(
        f"SELECT name, definition FROM ghidra_type WHERE binary_id=? AND name IN ({qs})",
        (binary_id, *sorted(names)),
    ).fetchall()
    out, got = [], set()
    for row in rows:
        nm = row["name"] if hasattr(row, "keys") else row[0]
        dfn = row["definition"] if hasattr(row, "keys") else row[1]
        out.append(dfn)
        got.add(nm)
    return ("\n".join(out) + "\n" if out else ""), got


def export(repo_path: str, con: sqlite3.Connection, *, open_program=None, start=None) -> dict:
    """Walk a live program's datatypes into ``ghidra_type``. Skips when no program."""
    opener = open_program or ge.open_program
    starter = start or ge.start
    if starter() is False:
        return {"struct": 0, "union": 0, "enum": 0, "skipped": 0, "reason": "no-program"}

    from ghidra.program.model.data import Enum, Structure, Union  # type: ignore

    row = con.execute("SELECT id FROM binary WHERE repo_path=?", (repo_path,)).fetchone()
    if row is None:
        raise SystemExit(f"binary not in db: {repo_path}")
    binary_id = int(row["id"] if hasattr(row, "keys") else row[0])

    stats = {"struct": 0, "union": 0, "enum": 0, "skipped": 0}
    rows = []
    with opener(repo_path) as program:
        if program is None:
            stats["reason"] = "no-program"
            return stats
        dtm = program.getDataTypeManager()
        for dt in dtm.getAllDataTypes():
            try:
                if isinstance(dt, (Structure, Union)):
                    got = emit_struct(dt)
                    kind = "union" if isinstance(dt, Union) else "struct"
                elif isinstance(dt, Enum):
                    got = emit_enum(dt)
                    kind = "enum"
                else:
                    continue
                if got is None:
                    stats["skipped"] += 1
                    continue
                text, nf = got
                rows.append((binary_id, c_ident(dt.getName()), kind, int(dt.getLength() or 0), text, nf))
                stats[kind] += 1
            except Exception:
                stats["skipped"] += 1

    con.executescript(SCHEMA)
    con.executemany(
        "INSERT OR REPLACE INTO ghidra_type (binary_id, name, kind, size, definition, n_fields) VALUES (?,?,?,?,?,?)",
        rows,
    )
    con.commit()
    return stats
