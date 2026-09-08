"""Bounded function pickers. Never OFFSET. Never dump a whole `func` table."""

from __future__ import annotations

from agentdecompile_recovery.corpus.dashboard.panels.common import format_address, parse_address, query_db

CHOICE_LIMIT = 80


def _limit(raw) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return CHOICE_LIMIT
    return max(1, min(CHOICE_LIMIT, value))


def _binary(slug: str):
    rows, err = query_db(
        "SELECT id, slug, bits FROM binary WHERE slug=? LIMIT 1",
        (slug,),
    )
    if err:
        return None, err
    if not rows:
        return None, f"no build called {slug}"
    return {"id": rows[0][0], "slug": rows[0][1], "bits": rows[0][2] or 32}, None


def list_function_choices(slug: str, q: str = "", around=None, limit=CHOICE_LIMIT):
    """Return up to `limit` functions for a combobox.

    Address search is a point lookup. Name search is a bounded LIKE on the
    resolved name. With neither, the window sits around `around` or the start
    of the address order.
    """
    slug = (slug or "").strip()
    if not slug:
        return {"ok": False, "error": "pick a build first", "results": []}
    binary, err = _binary(slug)
    if err:
        return {"ok": False, "error": err, "results": []}
    bid, bits = binary["id"], binary["bits"]
    cap = _limit(limit)
    needle = (q or "").strip()
    around_addr = parse_address(around) if around not in (None, "") else None

    name_expr = (
        "COALESCE((SELECT ln.name FROM identity ni "
        "JOIN logical_name ln ON ln.logical_id=ni.logical_id "
        "WHERE ni.binary_id=f.binary_id AND ni.addr=f.addr "
        "ORDER BY ni.confidence DESC LIMIT 1), f.name, '')"
    )

    def pack(rows):
        out = []
        seen = set()
        for addr, name, size in rows:
            if addr in seen:
                continue
            seen.add(addr)
            out.append({
                "addr": format_address(addr, bits),
                "address": int(addr),
                "name": name or f"FUN_{format_address(addr, bits)[2:]}",
                "size": int(size or 0),
            })
        return out

    if needle:
        exact = parse_address(needle)
        looks_addr = needle.lower().startswith("0x") or needle.isdigit() or len(needle) in (8, 16)
        if exact is not None and looks_addr:
            rows, qerr = query_db(
                f"SELECT f.addr, {name_expr}, f.size FROM func f "
                "WHERE f.binary_id=? AND f.addr=? LIMIT 1",
                (bid, exact),
            )
            if qerr:
                return {"ok": False, "error": qerr, "results": []}
            return {"ok": True, "slug": slug, "results": pack(rows or [])}

        safe = needle.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        rows, qerr = query_db(
            f"SELECT f.addr, {name_expr}, f.size FROM func f "
            f"WHERE f.binary_id=? AND {name_expr} LIKE ? ESCAPE '\\' COLLATE NOCASE "
            "ORDER BY f.addr LIMIT ?",
            (bid, f"%{safe}%", cap + 1),
        )
        if qerr:
            return {"ok": False, "error": qerr, "results": []}
        more = len(rows or []) > cap
        return {
            "ok": True,
            "slug": slug,
            "results": pack((rows or [])[:cap]),
            "hasMore": more,
        }

    if around_addr is not None:
        before, berr = query_db(
            f"SELECT f.addr, {name_expr}, f.size FROM func f "
            "WHERE f.binary_id=? AND f.addr<? ORDER BY f.addr DESC LIMIT ?",
            (bid, around_addr, cap // 2),
        )
        after, aerr = query_db(
            f"SELECT f.addr, {name_expr}, f.size FROM func f "
            "WHERE f.binary_id=? AND f.addr>=? ORDER BY f.addr LIMIT ?",
            (bid, around_addr, cap - (cap // 2)),
        )
        if berr or aerr:
            return {"ok": False, "error": berr or aerr, "results": []}
        rows = list(reversed(before or [])) + list(after or [])
        return {"ok": True, "slug": slug, "results": pack(rows), "around": format_address(around_addr, bits)}

    rows, qerr = query_db(
        f"SELECT f.addr, {name_expr}, f.size FROM func f "
        "WHERE f.binary_id=? AND f.addr>? ORDER BY f.addr LIMIT ?",
        (bid, -1, cap + 1),
    )
    if qerr:
        return {"ok": False, "error": qerr, "results": []}
    more = len(rows or []) > cap
    return {"ok": True, "slug": slug, "results": pack((rows or [])[:cap]), "hasMore": more}


def neighbor_addrs(binary_id: int, addr: int) -> tuple[int | None, int | None]:
    """Previous and next function by address. Two point keyset reads."""
    prev_rows, _ = query_db(
        "SELECT addr FROM func WHERE binary_id=? AND addr<? ORDER BY addr DESC LIMIT 1",
        (binary_id, addr),
    )
    next_rows, _ = query_db(
        "SELECT addr FROM func WHERE binary_id=? AND addr>? ORDER BY addr LIMIT 1",
        (binary_id, addr),
    )
    prev_addr = int(prev_rows[0][0]) if prev_rows else None
    next_addr = int(next_rows[0][0]) if next_rows else None
    return prev_addr, next_addr
