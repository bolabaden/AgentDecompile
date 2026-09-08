"""Package only functions whose source_claim is recovered."""

from __future__ import annotations

import re
from pathlib import Path

from .package_readable import map_source_path, package_readable
from .source_claims import is_real_c, is_recovered_source

_SAFE_NAME = re.compile(r"[^A-Za-z0-9_.+-]")


def _safe_seg(s: str) -> str:
    s = _SAFE_NAME.sub("_", s).strip("._")
    return s or "unnamed"


def names_agree(recovered: str, best: str | None) -> bool:
    if not best:
        return False
    if recovered == best:
        return True
    last = best.split("::")[-1]
    return recovered == last


def dest_for(src: str | None, program: str, name: str, addr: int | None,
             out_dir: Path) -> Path:
    if src:
        rel = map_source_path(src)
        stem = Path(rel)
        if stem.suffix:
            stem = stem.with_suffix("")
        dest_dir = Path(out_dir) / stem
    else:
        dest_dir = Path(out_dir) / "unsorted" / _safe_seg(program)
    dest_dir.mkdir(parents=True, exist_ok=True)
    base = dest_dir / f"{_safe_seg(name)}.c"
    if base.exists():
        extra = f"{addr:x}" if addr is not None else _safe_seg(program)
        base = dest_dir / f"{_safe_seg(name)}_{extra}.c"
    return base


def package_from_store(con, out_dir: Path) -> dict:
    """Write real-C recovered_function rows under *out_dir*."""
    written = 0
    try:
        rows = list(con.execute(
            "SELECT program, name, path, addr, binary_id FROM recovered_function WHERE real_c=1"
        ))
    except Exception:
        return {"files": 0}
    for row in rows:
        try:
            text = Path(row["path"]).read_text(errors="replace")
        except OSError:
            continue
        if not is_real_c(text):
            continue
        dest = dest_for(None, row["program"], row["name"], row["addr"], Path(out_dir))
        dest.write_text(text)
        written += 1
    return {"files": written}


def package_recovered(functions: list[dict], out_dir: Path, *, binary_id: str) -> dict:
    kept = [
        row
        for row in functions
        if row.get("source_claim") == "recovered"
        or is_recovered_source(row.get("source") or row.get("body") or "")
    ]
    return package_readable(kept, out_dir, binary_id=binary_id)
