"""Emit a Phasor-shaped hook pack from the identity store.

A VA is an instance. The pack's identity is the logical site plus the
signature family that hits the most registered builds. expected_bytes
are copied from a registered image when that window is unique. They
are never invented.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


FORMAT = "agentdecompile.hookpack/v1"


def _preferred_signature(best: str | None, member_sigs: list[str]) -> dict:
    members = [str(s).strip() for s in member_sigs if s and str(s).strip()]
    best_s = str(best or "").strip()
    if not members:
        return {"kind": "none", "value": ""}
    if best_s and all(sig == best_s for sig in members):
        return {"kind": "shared", "value": best_s, "hits": len(members), "of": len(members)}
    value, count = Counter(members).most_common(1)[0]
    return {
        "kind": "shared" if count == len(members) else "majority",
        "value": value,
        "hits": count,
        "of": len(members),
    }


def unique_window(image: bytes, offset: int, size: int, *, min_n: int = 8, max_n: int = 24) -> bytes | None:
    """Shortest unique slice at *offset*, or None if the window is not unique."""
    if offset < 0 or offset >= len(image):
        return None
    limit = min(len(image) - offset, max(int(size or 0), min_n), max_n)
    if limit < min_n:
        return None
    for n in range(min_n, limit + 1):
        window = image[offset : offset + n]
        if image.count(window) == 1:
            return window
    return None


def _raw_image(repo_path: str) -> bytes | None:
    from .ghidra_bulk import raw_image_path

    path = raw_image_path(repo_path or "")
    if not path.is_file():
        return None
    try:
        return path.read_bytes()
    except OSError:
        return None


def _file_offset(image: bytes, addr: int) -> int | None:
    from .genproject import pe_va_mapper

    mapper = pe_va_mapper(image)
    if mapper is None:
        return None
    return mapper(int(addr))


def export_hookpack(con, out: Path) -> dict:
    binaries = {int(r["id"]): dict(r) for r in con.execute("SELECT id, slug, game, platform, format, repo_path FROM binary")}
    raw_by_bid: dict[int, bytes | None] = {}
    logicals = list(con.execute(
        "SELECT id, best_name, best_signature, canon_class, canon_method, canon_key, n_members FROM logical_function"
    ))
    sites: dict[str, dict] = {}
    for lf in logicals:
        lid = int(lf["id"])
        members = list(con.execute(
            """SELECT i.binary_id, i.addr, i.confidence, i.method,
                      f.name, f.signature, f.source_file, f.object_file, f.size
                 FROM identity i
                 LEFT JOIN func f ON f.binary_id=i.binary_id AND f.addr=i.addr
                WHERE i.logical_id=?
                ORDER BY i.binary_id""",
            (lid,),
        ))
        member_sigs = [str(m["signature"]) for m in members if m["signature"]]
        instances = []
        windows: list[bytes] = []
        for m in members:
            bid = int(m["binary_id"])
            b = binaries.get(bid) or {}
            row = {
                "binary": b.get("slug") or str(bid),
                "addr": int(m["addr"] or 0),
                "name": m["name"] or "",
                "confidence": m["confidence"],
                "method": m["method"] or "",
                "source_file": m["source_file"] or "",
            }
            if bid not in raw_by_bid:
                raw_by_bid[bid] = _raw_image(str(b.get("repo_path") or ""))
            image = raw_by_bid.get(bid)
            if image:
                off = _file_offset(image, int(m["addr"] or 0))
                if off is not None:
                    window = unique_window(image, off, int(m["size"] or 0))
                    if window:
                        row["expected_bytes"] = window.hex().upper()
                        windows.append(window)
            instances.append(row)
        site_bytes = ""
        if windows:
            counts = Counter(w.hex().upper() for w in windows)
            hex_win, n = counts.most_common(1)[0]
            if n == len(windows):
                site_bytes = hex_win
        key = (lf["best_name"] or lf["canon_key"] or f"logical_{lid}").replace(" ", "_")
        sites[key] = {
            "logical_id": lid,
            "cls": lf["canon_class"] or "",
            "method": lf["canon_method"] or "",
            "signature": _preferred_signature(lf["best_signature"], member_sigs),
            "instances": instances,
        }
        if site_bytes:
            sites[key]["expected_bytes"] = site_bytes

    pack = {
        "format": FORMAT,
        "note": "VA is a cache. Resolve with signature; bind by logical_id.",
        "binaries": [
            {"slug": b["slug"], "game": b["game"], "platform": b["platform"], "format": b["format"]}
            for b in binaries.values()
        ],
        "sites": sites,
    }
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(pack, indent=2) + "\n", encoding="utf-8")
    return {"wrote": str(out), "sites": len(sites), "binaries": len(binaries)}
