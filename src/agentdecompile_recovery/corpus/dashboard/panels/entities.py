"""Drill-down views — the pages every count on the dashboard points at.

The complaint this file answers is quoted verbatim in
``docs/dashboard-design/09-linked-entities.md``:

    "clicking the '579336 functions' part should open a new page or expand an
    expander showing all the functions ..... all the functions should also be
    clickable to find their equivalent in the other binaries."

So a count is never a dead end here. `render_functions` is the set behind the
number, `render_function` is one element of that set, and the reason
`render_function` exists at all is the sibling table two thirds of the way down
it — the one click from "a function in this build" to "the same function in the
other twenty-three". Everything above that table is context for it.

Three constraints shape every query below, and all three were paid for once
already by this project:

1. **`func` is never bulk-read.** 579,336 rows of 40 columns on a spinning
   disk; a cold six-row point lookup measured 2.5 s. The list view reads one
   keyset window of 100 rows and nothing else, and the detail views read single
   addresses. There is no OFFSET anywhere in this file, and no `COUNT(*)` over
   a filtered `func` scan — totals come from `binary.func_count`, which the
   extractor already stored.

2. **`func_knowledge.decompiled` is fetched one row at a time, with an explicit
   column list.** One cold row costs ~667 ms because the text lives in overflow
   pages; `SELECT *` faults them in even when nothing displays them.

3. **A placeholder name never displaces a real one.** Display names come from
   `logical_name` (the winner of `kx/name_precedence.py`'s tier ladder), and
   this build's raw `func.name` is a labelled fallback for unbound addresses
   only — never a silent substitute.

Mounting (another author owns routing):

    render_functions(params)      ->  /functions?binary=<slug>&...
    render_function(slug, addr)   ->  /function/<slug>/<addr>
    render_logical(logical_id)    ->  /logical/<id>

Every function returns an HTML fragment and never raises; a view that cannot
answer says why, in place, the way `missing()` does everywhere else.
"""

from __future__ import annotations

from urllib.parse import urlencode

from agentdecompile_recovery.corpus.dashboard.app.models import BinaryRef, ConcreteFunctionRef
from agentdecompile_recovery.corpus.dashboard.app.routes import function_url, functions_url, logical_url

from agentdecompile_recovery.corpus.dashboard.panels.common import (
    KNOWLEDGE_DB,
    esc,
    fnum,
    format_address,
    missing,
    parse_address,
    query_db,
    table,
)

# kx/ lives beside scripts/; the dashboard may be launched from anywhere.
# Rule 1 of the controlling document is a *shared* helper, so that nine panels
# by different authors render a count the same way. It may not have landed in
# common.py yet — another author owns that file — so fall back locally rather
# than fail to import.
try:  # noqa: SIM105
    from agentdecompile_recovery.corpus.dashboard.panels.common import count_link  # type: ignore
except ImportError:
    def count_link(n, href, unit=None, title=None) -> str:
        """A count that is itself the control for the set it counts.

        Zero from a step nobody attempted is the one case that must not be a
        link, but the caller knows that and passes `href=None` for it.
        """
        body = fnum(n) + (f" {esc(unit)}" if unit else "")
        if not href:
            return f'<span title="{esc(title or "")}">{body}</span>'
        return f'<a href="{href}" title="{esc(title or "")}">{body}</a>'

try:
    # The placeholder test belongs to the precedence resolver. A local copy of
    # this regex is exactly how FUN_* names creep back onto the page.
    from agentdecompile_recovery.corpus.naming import is_placeholder_name as _is_placeholder

    _RESOLVER_ERR = ""
except Exception as exc:  # noqa: BLE001
    _RESOLVER_ERR = f"{type(exc).__name__}: {exc}"

    def _is_placeholder(name):  # conservative; the page says the fallback is on
        n = (name or "").strip()
        return not n or n.split("_")[0] in ("FUN", "SUB", "sub", "LAB", "loc", "Unwind",
                                            "switchD", "caseD", "DAT", "thunk")

try:
    # real_c is one test, in one place. `kx/realc.py` exists because local
    # copies of the shim regex drifted and reported 402,750 shims as real C.
    from agentdecompile_recovery.corpus.source_claims import is_real_c as _is_real_c

    _REALC_ERR = ""
except Exception as exc:  # noqa: BLE001
    _REALC_ERR = f"{type(exc).__name__}: {exc}"
    _is_real_c = None


TITLE = "Functions, one function, and one logical function"

FUNCTIONS_ROUTE = "/functions"
FUNCTION_ROUTE = "/function"
LOGICAL_ROUTE = "/logical"
GRAPH_ROUTE = "/graph"
REVIEW_ROUTE = "/review"

# Default keyset window. The reader can raise it; OFFSET is still forbidden.
PAGE = 100
PAGE_SIZE_CHOICES = (25, 50, 100, 250, 500, 1000)
ALL_CAP = 5000

# Cross-build member cap. `logical_function` maxes out at 14 members in this
# corpus and there are only 24 builds, so this bound is never actually reached
# — it exists so a corrupt identity row cannot turn one page into 10,000 seeks.
MAX_MEMBERS = 32

FG_ANNOT, FG_DIM, LINK = "#8b98ab", "#7d8aa0", "#6cc6ff"

# Size bands are page-local filters over `func.size`. The boundaries are chosen
# to separate the three things a reader actually asks for: thunk-sized stubs,
# ordinary methods, and the handful of monsters worth recovering by hand.
SIZE_BANDS = {
    "tiny": (0, 32, "under 32 bytes — thunks, stubs, single returns"),
    "small": (32, 128, "32 to 127 bytes"),
    "medium": (128, 512, "128 to 511 bytes"),
    "large": (512, 4096, "512 to 4,095 bytes"),
    "huge": (4096, None, "4,096 bytes and up"),
}

# Flag filters, in the order they are offered. Each is a link, because a filter
# and a count are the same object seen from two sides.
FLAGS = (
    ("bound", "bound to a logical function"),
    ("unbound", "bound to nothing — bridges no other build"),
    ("named", "carries a real name"),
    ("placeholder", "name is a FUN_/sub_/LAB_ placeholder"),
    ("has_source_file", "attributed to an original .cpp by STABS"),
    ("real_c", "has assembly-free source that matched the shipped bytes"),
)


# ---------------------------------------------------------------------------
# parameters
# ---------------------------------------------------------------------------

def _one(params, key, default=None):
    """Accept both `parse_qs` lists and plain dicts, so either mount works."""
    val = (params or {}).get(key, default)
    if isinstance(val, (list, tuple)):
        val = val[0] if val else default
    return val


def _page_size(params) -> tuple[int, bool]:
    """Return (window, asked_for_all). Unknown values fall back to PAGE."""
    raw = _one(params, "page_size")
    if raw is None:
        raw = _one(params, "pagesize")
    text = "" if raw is None else str(raw).strip().lower()
    if text in {"all", "*"}:
        return ALL_CAP, True
    if not text:
        return PAGE, False
    try:
        value = int(text, 10)
    except ValueError:
        return PAGE, False
    if value <= 0:
        return PAGE, False
    if value > ALL_CAP:
        return ALL_CAP, True
    return value, False


def _page_size_control(
    page_size: int,
    show_all: bool,
    *,
    field: str = "page_size",
    control_id: str = "page-size",
) -> str:
    options = []
    for choice in PAGE_SIZE_CHOICES:
        selected = " selected" if not show_all and choice == page_size else ""
        options.append(f'<option value="{choice}"{selected}>{choice}</option>')
    all_selected = " selected" if show_all else ""
    options.append(f'<option value="all"{all_selected}>All (up to {ALL_CAP:,})</option>')
    return (
        f'<label for="{esc(control_id)}">Rows per page</label>'
        f'<select id="{esc(control_id)}" name="{esc(field)}">{"".join(options)}</select>'
    )


def _carry_fields(params, extra=()) -> str:
    """Keep browse-page query state when a section form submits."""
    bits = []
    seen: set[str] = set()
    for key in ("binary", "slug", "q", "size_band", *extra):
        if key in seen:
            continue
        seen.add(key)
        val = _one(params, key)
        if val not in (None, ""):
            bits.append(f'<input type="hidden" name="{esc(key)}" value="{esc(val)}">')
    for key, _blurb in FLAGS:
        if key in seen:
            continue
        if _flag(params, key):
            bits.append(f'<input type="hidden" name="{esc(key)}" value="1">')
    return "".join(bits)


def _page_kwargs(active) -> dict:
    if not active or "page_size" not in active:
        return {}
    return {"page_size": active["page_size"]}


def _flag(params, key) -> bool:
    """Presence is the signal; `?bound` and `?bound=1` mean the same thing."""
    val = _one(params, key)
    if val is None:
        return False
    return str(val).strip().lower() not in ("0", "false", "no", "off")


def _addr(value):
    """Parse an address written as int, decimal, hex, or `0x`-prefixed hex.

    The ambiguity is real and has to be resolved by convention rather than by
    guessing: `/function/<slug>/<addr>` carries the zero-padded lowercase hex
    that `func_knowledge.entry_hex` uses, so a string of exactly 8 or 16 hex
    digits is hex, while a bare decimal from an internal link is decimal.
    """
    return parse_address(value)


def _hex(addr, bits) -> str:
    rendered = format_address(addr, bits)
    return rendered[2:] if rendered.startswith("0x") else rendered


def _mono(text) -> str:
    return (f'<span style="font-family:ui-monospace,Menlo,Consolas,monospace">'
            f'{esc(text)}</span>')


def _fit(text, n) -> str:
    text = "" if text is None else str(text)
    return text if len(text) <= n else text[: n - 1] + "…"


# ---------------------------------------------------------------------------
# links — generated in one place so re-pointing a route is a one-line change
# ---------------------------------------------------------------------------

def _functions_href(slug, after=None, **filters) -> str:
    params = {}
    for key, val in sorted(filters.items()):
        if val not in (None, False, ""):
            params[key] = "1" if val is True else str(val)
    if after is not None:
        # `0x`-prefixed on purpose: a bare 8-digit decimal cursor is
        # indistinguishable from an 8-digit hex address, and guessing wrong
        # sends the reader to a random point in the build.
        params["after"] = f"0x{int(after):x}"
    return functions_url(str(slug), **params)


def _corpus_functions_href(**filters) -> str:
    pairs = []
    for key, val in sorted(filters.items()):
        if val in (None, False, ""):
            continue
        pairs.append((key, "1" if val is True else str(val)))
    return functions_url(None, **dict(pairs))


def _function_href(slug, addr, bits) -> str:
    return function_url(str(slug), int(addr), bits=int(bits or 32))


def _logical_href(logical_id) -> str:
    value = int(logical_id)
    return logical_url(value) if value > 0 else "#"


def _review_href(after=None, **filters) -> str:
    params = {}
    for key, val in filters.items():
        if val not in (None, False, ""):
            params[key] = "1" if val is True else str(val)
    if after is not None:
        params["review_after"] = after
    if not params:
        return "/dashboard/functions#review"
    return f"/dashboard/functions?{urlencode(params)}#review"


def _graph_href(slug, addr) -> str:
    if isinstance(slug, int):
        return (f"{GRAPH_ROUTE}?{urlencode({'binary_id': slug, 'addr': f'0x{int(addr):x}', 'depth': 2})}"
                .replace("&", "&amp;"))
    return function_url(str(slug), int(addr))


def _crumb(parts) -> str:
    """A short breadcrumb where every segment but the last is a link."""
    cells = []
    for i, (label, href) in enumerate(parts):
        last = i == len(parts) - 1
        if href and not last:
            cells.append(f'<a href="{href}">{esc(label)}</a>')
        else:
            cells.append(f'<span style="color:#f2f6fb">{esc(label)}</span>')
    return (f'<p class="note" style="margin:0 0 10px">'
            f'{" / ".join(cells)}</p>')


# ---------------------------------------------------------------------------
# small shared reads — all indexed, all bounded
# ---------------------------------------------------------------------------

def _binaries():
    """id -> row dict. 24 rows; the whole table is cheaper than a join."""
    rows, err = query_db(
        "SELECT id, slug, repo_path, game, platform, arch, bits, func_count, named_count "
        "FROM binary ORDER BY id"
    )
    if err:
        return {}, err
    keys = ("id", "slug", "repo_path", "game", "platform", "arch", "bits",
            "func_count", "named_count")
    return {r[0]: dict(zip(keys, r)) for r in rows}, None


def _binary_by_slug(slug):
    binaries, err = _binaries()
    if err:
        return None, {}, err
    for row in binaries.values():
        if row["slug"] == slug:
            return row, binaries, None
    return None, binaries, f"no build with slug {slug!r} — check the `binary` table"


def _program_key(binary_row) -> str:
    """`func_knowledge.program` is the basename of `repo_path`, not the slug.

    This mismatch is load-bearing and has bitten before: keying on `slug` finds
    nothing and the C pane silently renders empty rather than saying why.
    """
    return str(binary_row.get("repo_path") or "").rsplit("/", 1)[-1]


def _names_for(logical_ids):
    """Resolved display names for a batch of logical ids. `logical_name` PK."""
    lids = sorted({int(x) for x in logical_ids if x is not None})
    if not lids:
        return {}
    marks = ",".join("?" * len(lids))
    rows, err = query_db(
        f"SELECT logical_id, name, tier, tier_name FROM logical_name "
        f"WHERE logical_id IN ({marks})",
        tuple(lids),
    )
    if err:
        return {}
    return {r[0]: {"name": r[1], "tier": r[2], "tier_name": r[3]} for r in rows}


def _display_name(logical_id, resolved, raw_name, addr, bits):
    """(text, tier_label, is_real) — the one place a name is chosen.

    Precedence is not a preference: a placeholder must never be shown when a
    real name exists for that logical id, because doing so hides the single
    fact this whole project produces.
    """
    if logical_id is not None and resolved and resolved.get("name"):
        nm = resolved["name"]
        if not _is_placeholder(nm):
            return nm, (resolved.get("tier_name") or "resolved"), True
        # The resolver ran and every fork offered a placeholder. Say so rather
        # than dressing FUN_* up as a name.
        return nm, "placeholder", False
    raw = raw_name or ""
    if raw and not _is_placeholder(raw):
        return raw, "build-local", True
    return raw or f"FUN_{_hex(addr, bits)}", "placeholder", False


# ---------------------------------------------------------------------------
# /functions — the set behind "579,336 functions"
# ---------------------------------------------------------------------------

def _filter_bar(slug, active, count_hint):
    """Every filter is a link, and the active ones are removable links."""
    chips = []
    base_href = _functions_href(slug, **_page_kwargs(active))
    plain = ('display:inline-block;border:1px solid #1e242e;border-radius:6px;'
             'padding:2px 9px;font-size:12px;text-decoration:none;')
    on = ('display:inline-block;border:1px solid #2a3342;border-radius:6px;'
          'padding:2px 9px;font-size:12px;text-decoration:none;'
          'background:#171e2a;color:#f2f6fb;')
    chips.append(f'<a href="{base_href}" style="{plain}color:{LINK}">all</a>')
    for key, blurb in FLAGS:
        live = bool(active.get(key))
        nxt = dict(active)
        nxt.pop(key, None) if live else nxt.update({key: True})
        href = _functions_href(slug, **nxt)
        style = on if live else f"{plain}color:{LINK}"
        chips.append(f'<a href="{href}" style="{style}" title="{esc(blurb)}">'
                     f'{esc(key)}{" ×" if live else ""}</a>')
    for band, (_lo, _hi, blurb) in SIZE_BANDS.items():
        live = active.get("size_band") == band
        nxt = dict(active)
        nxt.pop("size_band", None) if live else nxt.update({"size_band": band})
        href = _functions_href(slug, **nxt)
        style = on if live else f"{plain}color:{FG_ANNOT}"
        chips.append(f'<a href="{href}" style="{style}" title="{esc(blurb)}">'
                     f'{esc(band)}{" ×" if live else ""}</a>')
    return (f'<div style="display:flex;flex-wrap:wrap;gap:6px;margin:10px 0">'
            f'{"".join(chips)}</div>'
            f'<p class="note" style="margin:4px 0 0">{count_hint}</p>')


def _window_identity(binary_id, lo, hi):
    """logical bindings for one address window. `identity` PK range scan.

    One range query, not one lookup per row: the PK leads with `binary_id` and
    then `addr`, so the window is contiguous and costs a single seek.
    """
    rows, err = query_db(
        "SELECT addr, logical_id, confidence FROM identity "
        "WHERE binary_id=? AND addr BETWEEN ? AND ?",
        (binary_id, lo, hi),
    )
    if err:
        return {}
    best = {}
    for addr, lid, conf in rows:
        # A (binary, addr) may carry several bindings; the weakest must not
        # decide how the row looks.
        cur = best.get(addr)
        if cur is None or (conf or 0) > (cur[1] or 0):
            best[addr] = (lid, conf)
    return best


def _recovered_flags(binary_id):
    """addr -> real_c, from `recovered_function`. 734 rows corpus-wide.

    There is no index on (binary_id, addr) here, but the whole table is smaller
    than one page of `func`, so scanning it is cheaper than adding an index
    would be to maintain. Only read when a real_c/shim filter is active.
    """
    rows, err = query_db(
        "SELECT addr, real_c FROM recovered_function WHERE binary_id=?", (binary_id,)
    )
    if err:
        return {}
    return {r[0]: bool(r[1]) for r in rows if r[0] is not None}


def render_functions(params) -> str:
    """A paged, filterable list of one build's functions. Never raises.

    Params: `binary` (slug), `after` (keyset cursor), and the filter flags.
    Pagination is keyset only — `WHERE binary_id=? AND addr>? ORDER BY addr
    LIMIT n`. OFFSET is absent on purpose: it degrades linearly and this
    table has 579,336 rows on a spinning disk. The default window is PAGE;
    the reader can raise it, including All (capped at ALL_CAP).
    """
    try:
        params = params or {}
        slug = _one(params, "binary") or _one(params, "slug")
        page_size, show_all = _page_size(params)
        if not slug:
            active = {k: True for k, _b in FLAGS if _flag(params, k)}
            band = _one(params, "size_band")
            if band in SIZE_BANDS:
                active["size_band"] = band
            needle = (_one(params, "q") or "").strip()
            if needle:
                active["q"] = needle
            corpus_after = (_one(params, "after") or "").strip()
            if corpus_after:
                active["_cursor"] = corpus_after
            if page_size != PAGE or show_all:
                active["page_size"] = "all" if show_all else page_size
            if active:
                return _corpus_functions(active)
            binaries, berr = _binaries()
            if not berr and len(binaries) == 1:
                slug = next(iter(binaries.values()))["slug"]
            else:
                return _build_picker("pick a build — the function list is per binary")

        binary, _all_bins, err = _binary_by_slug(str(slug))
        if err:
            return missing(err) + _build_picker("builds that do exist:")

        bid, bits = binary["id"], binary["bits"]
        after = _addr(_one(params, "after"))
        cursor = -1 if after is None else int(after)

        active = {k: True for k, _b in FLAGS if _flag(params, k)}
        band = _one(params, "size_band")
        if band in SIZE_BANDS:
            active["size_band"] = band
        needle = (_one(params, "q") or "").strip()
        if needle:
            active["q"] = needle
        if page_size != PAGE or show_all:
            active["page_size"] = "all" if show_all else page_size

        # Filters belong in the set query. Applying them after LIMIT makes a
        # count link open a sample rather than the set it names.
        name_expr = (
            "COALESCE((SELECT ln.name FROM identity ni "
            "JOIN logical_name ln ON ln.logical_id=ni.logical_id "
            "WHERE ni.binary_id=f.binary_id AND ni.addr=f.addr "
            "ORDER BY ni.confidence DESC LIMIT 1), f.name, '')"
        )
        placeholder = (
            f"({name_expr}='' OR upper({name_expr}) LIKE 'FUN\\_%' ESCAPE '\\' "
            f"OR lower({name_expr}) LIKE 'sub\\_%' ESCAPE '\\' "
            f"OR upper({name_expr}) LIKE 'LAB\\_%' ESCAPE '\\')"
        )
        predicates = ["f.binary_id=?", "f.addr>?"]
        values = [bid, cursor]
        if active.get("bound"):
            predicates.append("EXISTS (SELECT 1 FROM identity i WHERE i.binary_id=f.binary_id AND i.addr=f.addr)")
        if active.get("unbound"):
            predicates.append("NOT EXISTS (SELECT 1 FROM identity i WHERE i.binary_id=f.binary_id AND i.addr=f.addr)")
        if active.get("named"):
            predicates.append("NOT " + placeholder)
        if active.get("placeholder"):
            predicates.append(placeholder)
        if active.get("has_source_file"):
            predicates.append("f.source_file IS NOT NULL AND f.source_file<>''")
        if active.get("real_c"):
            predicates.append(
                "EXISTS (SELECT 1 FROM recovered_function r WHERE r.binary_id=f.binary_id "
                "AND r.addr=f.addr AND r.real_c=1)"
            )
        if "size_band" in active:
            blo, bhi, _ = SIZE_BANDS[active["size_band"]]
            predicates.append("COALESCE(f.size,0)>=?")
            values.append(blo)
            if bhi is not None:
                predicates.append("COALESCE(f.size,0)<?")
                values.append(bhi)
        if needle:
            exact_addr = _addr(needle)
            if exact_addr is not None and (needle.lower().startswith("0x") or
                                           needle.isdigit() or len(needle) in (8, 16)):
                predicates.append("f.addr=?")
                values.append(exact_addr)
            else:
                predicates.append(f"{name_expr} LIKE ? ESCAPE '\\' COLLATE NOCASE")
                safe_needle = needle.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                values.append(f"%{safe_needle}%")
        values.append(page_size + 1)
        rows, err = query_db(
            "SELECT f.addr, f.name, f.size, f.source_file, f.is_thunk FROM func f WHERE "
            + " AND ".join(predicates) + " ORDER BY f.addr LIMIT ?",
            tuple(values),
        )
        if err:
            err_html = missing(f"function list unavailable: {err}")
            if _flag(params, "partial"):
                return f'<div id="function-results">{err_html}</div>'
            return _functions_head(binary, active, page_size, show_all) + f'<div id="function-results">{err_html}</div>'
        if not rows:
            empty = missing("No functions matched this search and filter set.")
            wrapped = f'<div id="function-results">{empty}</div>'
            if _flag(params, "partial"):
                return wrapped
            return _functions_head(binary, active, page_size, show_all) + wrapped

        has_more = len(rows) > page_size
        rows = rows[:page_size]

        lo, hi = rows[0][0], rows[-1][0]
        bindings = _window_identity(bid, lo, hi)
        resolved = _names_for(lid for lid, _c in bindings.values())
        out, kept = [], 0
        for addr, raw_name, size, source_file, is_thunk in rows:
            lid, conf = bindings.get(addr, (None, None))
            name, tier, is_real = _display_name(lid, resolved.get(lid), raw_name, addr, bits)

            kept += 1

            href = _function_href(binary["slug"], addr, bits)
            name_cell = (f'<a href="{href}">{esc(_fit(name, 58))}</a>'
                         if is_real else
                         f'<a href="{href}" style="color:{FG_DIM}">{esc(_fit(name, 58))}</a>')
            bound_cell = (
                f'<a href="{_logical_href(lid)}">#{int(lid)}</a>'
                f'<span style="color:{FG_ANNOT}"> &middot; {esc(f"{conf:.2f}" if conf is not None else "?")}</span>'
                if lid is not None else f'<span style="color:{FG_DIM}">&mdash;</span>'
            )
            out.append([
                f'<a href="{href}">{_mono(_hex(addr, bits))}</a>',
                name_cell,
                f'<span style="color:{FG_ANNOT};font-size:11px">{esc(tier)}</span>',
                fnum(size),
                bound_cell,
                (f'<span style="color:{FG_ANNOT}" title="{esc(source_file)}">'
                 f'{esc(_fit(str(source_file).rsplit("/", 1)[-1], 26))}</span>'
                 if source_file else f'<span style="color:{FG_DIM}">&mdash;</span>'),
                (f'<a href="{_graph_href(binary["slug"], addr)}" style="color:{LINK}" '
                 f'aria-label="Open call graph for {esc(name)} at {_hex(addr, bits)}">call graph</a>'
                 + (" &middot; " + f'<span style="color:{FG_ANNOT}">thunk</span>' if is_thunk else "")),
            ])

        body = table(
            ["address", "name", "name tier", "size", "logical", "source file", ""],
            out, numeric={3},
        ) if out else missing(
            "No functions matched this search and filter set."
        )

        # The cursor is the last address of the *unfiltered* window, so a page
        # that filters down to nothing still advances instead of dead-ending.
        nxt = _functions_href(binary["slug"], after=hi, **active)
        first = _functions_href(binary["slug"], **active)
        next_label = "all remaining" if show_all else f"next {page_size}"
        shown_note = (
            f'{fnum(kept)} matching rows shown'
            + (" — All is capped at "
               f"{fnum(ALL_CAP)}; refine the search for the rest" if show_all and has_more else "")
        )
        pager = (
            f'<p class="note" id="function-pager" style="margin:10px 0 0">'
            f'{esc(_hex(lo, bits))} – {esc(_hex(hi, bits))} &middot; '
            f'{shown_note}'
            + (f' &middot; <a href="{nxt}">{next_label} ›</a>' if has_more else "")
            + ("" if cursor < 0 else f' &middot; <a href="{first}">‹ first page</a>')
            + "</p>"
        )

        note = ('<p class="note" style="margin:6px 0 0">Filters run before pagination. '
                'Names use the resolved logical name when one exists. A dimmed name is a '
                'placeholder.</p>')
        results = f'<div id="function-results">{body}{pager}{note}{_resolver_warning()}</div>'
        if _flag(params, "partial"):
            return results
        return _functions_head(binary, active, page_size, show_all) + results
    except Exception as exc:  # noqa: BLE001 — a view degrades, it never raises
        return missing(f"function list failed: {type(exc).__name__}: {exc}")


def _functions_head(binary, active, page_size=PAGE, show_all=False):
    slug, bid = binary["slug"], binary["id"]
    total, named = binary.get("func_count"), binary.get("named_count")

    bound_rows, err = query_db(
        "SELECT COUNT(DISTINCT addr) FROM identity WHERE binary_id=?", (bid,)
    )
    bound = None if err or not bound_rows else bound_rows[0][0]

    keep = _page_kwargs(active)
    stats = [
        count_link(total, _functions_href(slug, **keep), "functions",
                   "from binary.func_count, written by the extractor"),
        count_link(named, _functions_href(slug, named=True, **keep), "named",
                   "from binary.named_count"),
        (count_link(bound, _functions_href(slug, bound=True, **keep), "bound to a logical function",
                    "COUNT(DISTINCT addr) over the identity primary key")
         if bound is not None else
         '<span style="color:#7d8aa0">binding count unavailable</span>'),
        (count_link((total or 0) - (bound or 0), _functions_href(slug, unbound=True, **keep), "unbound",
                    "these bridge no other build")
         if bound is not None and total is not None else ""),
    ]
    chips = " &middot; ".join(s for s in stats if s)

    filter_items = {k: v for k, v in active.items() if k not in {"page_size", "q"}}
    filters_on = ", ".join(
        f"{k}={v}" if v is not True else k for k, v in sorted(filter_items.items())
    ) or "none"
    query = esc(str(active.get("q") or ""))
    extras = "".join(
        f'<input type="hidden" name="{esc(key)}" value="1">'
        for key, val in filter_items.items() if val is True
    )
    if filter_items.get("size_band"):
        extras += f'<input type="hidden" name="size_band" value="{esc(filter_items["size_band"])}">'
    return (
        f'<div style="display:flex;flex-wrap:wrap;gap:10px;align-items:baseline">'
          f'<b style="font-size:15px;color:#f2f6fb">{esc(slug)}</b>'
          f'<span class="note">{esc(binary.get("game") or "?")}/'
          f'{esc(binary.get("platform") or "?")}/{esc(binary.get("arch") or "?")} &middot; '
          f'{esc(binary.get("bits") or "?")}-bit</span></div>'
        + f'<p class="note" style="margin:6px 0 0">{chips}</p>'
        + '<form class="search-form" id="function-search-form" role="search" method="get" '
          'action="/dashboard/functions" data-live-search="functions">'
          f'<input type="hidden" name="binary" value="{esc(slug)}">'
          + extras +
          '<label for="function-search">Find a function</label>'
          f'<input id="function-search" name="q" value="{query}" '
          'placeholder="Name or exact address" autocomplete="off">'
          + _page_size_control(page_size, show_all) +
          '<button type="submit">Search functions</button></form>'
        + _filter_bar(slug, active, f"active filters: <b>{esc(filters_on)}</b>")
    )


def _build_picker(headline) -> str:
    """Without a build there is no list, so offer the 24 that exist."""
    binaries, err = _binaries()
    if err:
        return missing(f"binary table unavailable: {err}")
    rows = []
    for row in binaries.values():
        rows.append([
            f'<a href="{_functions_href(row["slug"])}">{esc(row["slug"])}</a>',
            f'<span style="color:{FG_ANNOT}">{esc(row.get("game") or "?")}/'
            f'{esc(row.get("platform") or "?")}</span>',
            count_link(row.get("func_count"), _functions_href(row["slug"]), None,
                       "binary.func_count"),
            count_link(row.get("named_count"), _functions_href(row["slug"], named=True), None,
                       "binary.named_count"),
        ])
    return (f'<p class="note">{esc(headline)}</p>'
            + table(["build", "game/platform", "functions", "named"], rows, numeric={2, 3}))


def _corpus_filter_bar(active) -> str:
    """Corpus controls keep global filters global until a build is chosen."""
    chips = []
    plain = ('display:inline-block;border:1px solid #1e242e;border-radius:6px;'
             'padding:4px 10px;font-size:12px;text-decoration:none;')
    on = plain + 'background:#171e2a;color:#f2f6fb;'
    chips.append(f'<a href="{FUNCTIONS_ROUTE}" style="{plain}color:{LINK}">all builds</a>')
    for key, blurb in FLAGS:
        live = bool(active.get(key))
        nxt = dict(active)
        nxt.pop(key, None) if live else nxt.update({key: True})
        chips.append(f'<a href="{_corpus_functions_href(**nxt)}" '
                     f'style="{on if live else plain + "color:" + LINK}" '
                     f'title="{esc(blurb)}">{esc(key)}{" ×" if live else ""}</a>')
    return '<div style="display:flex;flex-wrap:wrap;gap:6px;margin:10px 0">' + "".join(chips) + '</div>'


def _corpus_functions(active) -> str:
    """A bounded corpus result set for global recovery filters and point search.

    `recovered_function` is intentionally tiny (hundreds of rows) and is the
    authoritative source for assembly-free recovery membership. Address search performs
    one `(binary_id, addr)` point seek per build. Other flags retain their
    visible state and lead into build-scoped indexed lists instead of implying
    that a page-local sample is the whole corpus.
    """
    binaries, err = _binaries()
    if err:
        return missing(f"binary table unavailable: {err}")
    cursor_token = str(active.get("_cursor") or "")
    visible_active = {k: v for k, v in active.items() if k != "_cursor"}
    filters_on = ", ".join(
        f"{k}={v}" if v is not True else k
        for k, v in sorted(visible_active.items())
        if k != "page_size"
    )
    head = (
        '<div style="display:flex;gap:10px;align-items:baseline;flex-wrap:wrap">'
          '<b style="font-size:15px;color:#f2f6fb">Functions across every build</b>'
          f'<span class="note">active filters: <b>{esc(filters_on)}</b></span></div>'
        + _corpus_filter_bar(visible_active)
        + '<form action="/dashboard/functions" method="get" role="search" '
          'style="display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin:8px 0 12px">'
          + "".join(
              f'<input type="hidden" name="{esc(key)}" value="{esc(val)}">'
              for key, val in visible_active.items() if key != "q"
          )
          +
          '<label for="corpus-function-q" class="note">Find an exact address</label>'
          f'<input id="corpus-function-q" name="q" value="{esc(visible_active.get("q") or "")}" '
          'placeholder="0x00401000" inputmode="text" '
          'style="background:#070a0f;color:#f2f6fb;border:1px solid #2a3342;border-radius:6px;padding:6px 9px">'
          '<button type="submit" style="background:#171e2a;color:#f2f6fb;border:1px solid #2a3342;'
          'border-radius:6px;padding:6px 10px">Find address</button></form>'
    )

    rows = []
    q = str(visible_active.get("q") or "").strip()
    query_addr = _addr(q) if q else None
    recovery_mode = bool(visible_active.get("real_c"))
    unsupported = [k for k in visible_active if k not in ("real_c", "q", "page_size")]
    page_size, show_all = _page_size(visible_active)

    if q and query_addr is None:
        return head + missing(
            "Corpus search is an exact indexed address lookup. Use 0x-prefixed hex, "
            "then narrow name and size filters inside a build."
        )
    if unsupported:
        chooser = []
        for b in binaries.values():
            chooser.append([
                f'<a href="{esc(_functions_href(b["slug"], **active))}">{esc(b["slug"])}</a>',
                f'{esc(b.get("game") or "?")}/{esc(b.get("platform") or "?")}',
                fnum(b.get("func_count")),
            ])
        return (head + '<p class="note">These filters depend on each build’s indexed address '
                'window. Choose a build; the filter state is preserved.</p>'
                + table(["build", "game/platform", "functions"], chooser, numeric={2}))

    if recovery_mode:
        sql = (
            "SELECT binary_id, addr, name, size, real_c, logical_id "
            "FROM recovered_function WHERE real_c=? AND addr IS NOT NULL"
        )
        args = [1]
        cursor_bid = cursor_addr = None
        if cursor_token:
            try:
                bid_text, addr_text = cursor_token.split(":", 1)
                cursor_bid, cursor_addr = int(bid_text), parse_address(addr_text)
            except (TypeError, ValueError):
                return head + missing("That corpus page cursor is invalid; start from the first page.")
            if cursor_addr is None:
                return head + missing("That corpus page cursor is invalid; start from the first page.")
            sql += " AND (binary_id>? OR (binary_id=? AND addr>?))"
            args.extend((cursor_bid, cursor_bid, cursor_addr))
        if query_addr is not None:
            sql += " AND addr=?"
            args.append(query_addr)
        sql += " ORDER BY binary_id, addr LIMIT ?"
        args.append(page_size + 1)
        found, ferr = query_db(sql, tuple(args))
        if ferr:
            return head + missing(f"recovered function list unavailable: {ferr}")
        more = len(found) > page_size
        for bid, addr, name, size, real_c, lid in found[:page_size]:
            b = binaries.get(bid)
            if not b or addr is None:
                continue
            href = _function_href(b["slug"], addr, b.get("bits") or 32)
            rows.append([
                f'<a href="{href}">{esc(b["slug"])}</a>',
                f'<a href="{href}">{_mono(_hex(addr, b.get("bits") or 32))}</a>',
                f'<a href="{href}">{esc(_fit(name or "unnamed", 58))}</a>',
                fnum(size),
                '<span class="tag ok">real C, byte matched</span>',
                f'<a href="{_logical_href(lid)}">#{int(lid)}</a>' if lid is not None else '—',
            ])
        shown = min(len(found), page_size)
        cap_note = (
            f" All is capped at {fnum(ALL_CAP)}." if show_all and more else ""
        )
        note = (f'<p class="note">Showing {fnum(shown)} authoritative '
                f'recovery rows across the corpus, ordered by build and address.{cap_note}</p>')
        if more and found[:page_size]:
            last_bid, last_addr = found[page_size - 1][0], found[page_size - 1][1]
            nxt = dict(visible_active)
            nxt["after"] = f"{int(last_bid)}:0x{int(last_addr):x}"
            next_label = "all remaining" if show_all else f"next {page_size}"
            note += f'<p><a href="{_corpus_functions_href(**nxt)}">{next_label} &rsaquo;</a></p>'
    elif query_addr is not None:
        for b in binaries.values():
            found, ferr = query_db(
                "SELECT name, size FROM func WHERE binary_id=? AND addr=?",
                (b["id"], query_addr),
            )
            if ferr or not found:
                continue
            name, size = found[0]
            href = _function_href(b["slug"], query_addr, b.get("bits") or 32)
            rows.append([
                f'<a href="{href}">{esc(b["slug"])}</a>',
                f'<a href="{href}">{_mono(_hex(query_addr, b.get("bits") or 32))}</a>',
                f'<a href="{href}">{esc(_fit(name or "unnamed", 58))}</a>',
                fnum(size), "—", "—",
            ])
        note = '<p class="note">Exact address search uses one indexed point lookup per build.</p>'
    else:
        return head + _build_picker("pick a build to browse its address-ordered function list")

    if not rows:
        return head + missing("no functions match these corpus filters.")
    return head + table(["build", "address", "name", "size", "recovery", "logical"], rows, numeric={3}) + note


# ---------------------------------------------------------------------------
# /function/<slug>/<addr> — one function, and the point of the page
# ---------------------------------------------------------------------------

def _entry_hex_forms(addr):
    """The candidate `func_knowledge.entry_hex` spellings for one address.

    The width is NOT a property of the build's word size, which is the obvious
    and wrong assumption: the ARM64 `.so` builds are 64-bit but their addresses
    are section offsets that fit in eight digits and Ghidra wrote `003d2a60`,
    while `nwmain.exe` and the iOS `.ipa` sit above 4 GB and got sixteen. So
    the natural width is tried first and the other second — a miss on the
    primary key costs one index seek and reads none of the text pages.
    """
    try:
        addr = int(addr)
    except (TypeError, ValueError):
        return []
    narrow, wide = f"{addr:08x}", f"{addr:016x}"
    return [wide, narrow] if addr > 0xFFFFFFFF else [narrow, wide]


def _knowledge_row(program, addr):
    """One `func_knowledge` row, explicit columns, full primary key.

    `SELECT *` here faults in the overflow pages holding `decompiled` and `asm`
    even when nothing renders them. Naming the columns is the difference
    between 0.6 ms and 667 ms on a cold cache, and this is the *one* place in
    the file allowed to ask for the text at all.
    """
    keys = ("name", "size", "calling_convention", "signature", "decompiled", "n_instructions")
    last_err = None
    for entry_hex in _entry_hex_forms(addr):
        rows, err = query_db(
            "SELECT name, size, calling_convention, signature, decompiled, n_instructions "
            "FROM func_knowledge WHERE program=? AND entry_hex=?",
            (program, entry_hex),
            db=KNOWLEDGE_DB,
        )
        if err:
            last_err = err
            continue
        if rows:
            return dict(zip(keys, rows[0])), entry_hex, None
    return None, None, last_err


def _members(logical_id, cap=MAX_MEMBERS):
    """Every build this logical function is bound into. `ix_identity_logical`."""
    rows, err = query_db(
        "SELECT binary_id, addr, confidence, method FROM identity "
        "WHERE logical_id=? ORDER BY binary_id LIMIT ?",
        (int(logical_id), cap),
    )
    return ([] if err else rows), err


def _func_points(pairs):
    """(binary_id, addr) -> name/size, in one statement.

    An OR-chain rather than a loop: SQLite answers it with MULTI-INDEX OR over
    the `(binary_id, addr)` unique index, so it is N point lookups in one round
    trip instead of N connections. Bounded by MAX_MEMBERS by construction.
    """
    pairs = list(pairs)[:MAX_MEMBERS]
    if not pairs:
        return {}
    where = " OR ".join("(binary_id=? AND addr=?)" for _ in pairs)
    args = tuple(v for pair in pairs for v in pair)
    rows, err = query_db(
        f"SELECT binary_id, addr, name, size, source_file FROM func WHERE {where}", args
    )
    if err:
        return {}
    return {(r[0], r[1]): {"name": r[2], "size": r[3], "source_file": r[4]} for r in rows}


_FUNC_DETAIL_COLS = (
    "name", "size", "calling_convention", "return_type", "param_count", "signature",
    "source_file", "object_file", "stabs_name", "name_origin", "is_thunk", "n_instr",
    "n_blocks", "cyclomatic", "n_callees",
)


def _func_table_cols() -> set[str]:
    rows, err = query_db("PRAGMA table_info(func)")
    if err or not rows:
        return set()
    return {r[1] for r in rows if len(r) > 1}


def _load_func(bid, addr) -> tuple[dict | None, str | None]:
    """One `func` row. Missing columns become None. `source` fills `source_file`."""
    cols = _func_table_cols()
    parts = []
    for name in _FUNC_DETAIL_COLS:
        if name == "source_file":
            if "source_file" in cols and "source" in cols:
                parts.append("COALESCE(source_file, source) AS source_file")
            elif "source_file" in cols:
                parts.append("source_file")
            elif "source" in cols:
                parts.append("source AS source_file")
            else:
                parts.append("NULL AS source_file")
        elif name in cols:
            parts.append(name)
        else:
            parts.append(f"NULL AS {name}")
    rows, err = query_db(
        f"SELECT {', '.join(parts)} FROM func WHERE binary_id=? AND addr=?",
        (bid, addr),
    )
    if err:
        return None, err
    if not rows:
        return None, None
    return dict(zip(_FUNC_DETAIL_COLS, rows[0])), None


def render_function(slug, addr) -> str:
    """One function in one build, and its counterparts in the others.

    The sibling table is why this page exists. Everything above it is the
    context needed to read it; if the function is bound to nothing, the page
    says exactly that rather than showing an empty table, because "bridges
    nothing" is the common and honest case in this corpus.
    """
    try:
        slug = str(slug)
        addr = _addr(addr)
        if addr is None:
            return missing("a function needs an address (hex or decimal)")

        binary, binaries, err = _binary_by_slug(slug)
        if err:
            return missing(err) + _build_picker("builds that do exist:")
        bid, bits = binary["id"], binary["bits"]
        hexed = _hex(addr, bits)

        row, err = _load_func(bid, addr)
        if err:
            return missing(f"function lookup failed: {err}")
        if not row:
            return (missing(f"no function at {hexed} in {slug} — the address is not in `func`. "
                              f"Addresses in this build start where the list does.")
                    + f'<p class="note"><a href="{_functions_href(slug)}">'
                      f'browse this build’s functions</a></p>')
        f = row

        ident, err = query_db(
            "SELECT logical_id, confidence, method FROM identity WHERE binary_id=? AND addr=?",
            (bid, addr),
        )
        lid, conf, method = (None, None, None)
        if not err and ident:
            lid, conf, method = sorted(ident, key=lambda r: -(r[1] or 0))[0]

        resolved = _names_for([lid]).get(lid) if lid is not None else None
        name, tier, is_real = _display_name(lid, resolved, f["name"], addr, bits)

        head = (
            f'<div style="display:flex;flex-wrap:wrap;gap:10px;align-items:baseline">'
              f'<b style="font-size:16px;color:{"#f2f6fb" if is_real else FG_DIM}">'
              f'{esc(name)}</b>'
              f'<span class="note">{_mono(hexed)} &middot; {fnum(f["size"])} bytes &middot; '
              f'name tier {esc(tier)}</span></div>'
        )
        if not is_real:
            head += ('<p class="note" style="margin:2px 0 0">This is a placeholder, not a '
                     'name — no fork of this function has yielded a real one yet.</p>')

        facts = [
            ("address", _mono(hexed) + f' <span style="color:{FG_ANNOT}">({fnum(addr)})</span>'),
            ("size", fnum(f["size"]) + " bytes"),
            ("calling convention", esc(f["calling_convention"] or "—")),
            ("signature", f'<code style="font-size:12px">{esc(_fit(f["signature"] or "—", 110))}</code>'),
            ("return / params", f'{esc(f["return_type"] or "?")} / {fnum(f["param_count"])}'),
            ("blocks / instr / cyclomatic",
             f'{fnum(f["n_blocks"])} / {fnum(f["n_instr"])} / {fnum(f["cyclomatic"])}'),
            ("source file (STABS)",
             (f'<span title="{esc(f["source_file"])}">{esc(f["source_file"])}</span>'
              if f["source_file"] else
              f'<span style="color:{FG_DIM}">none — this build carries no debug symbols '
              f'for it</span>')),
            ("object file", esc(f["object_file"] or "—")),
            ("name origin", esc(f["name_origin"] or "—")),
            ("this build’s raw name", _mono(f["name"] or "—")),
            ("call graph", '<a href="#graph">On this page</a>'),
        ]
        facts_html = (
            '<div class="fn-facts-table">'
            + table(["fact", "value"], [[esc(k), v] for k, v in facts])
            + "</div>"
        )

        # --- the point of the page ------------------------------------------
        siblings = _siblings_section(lid, conf, method, bid, addr, binaries)

        # --- the one expensive read -----------------------------------------
        program = _program_key(binary)
        know, key_used, kerr = _knowledge_row(program, addr)
        c_html = _c_section(know, kerr, program, key_used or hexed)

        return head + siblings + facts_html + c_html + _resolver_warning()
    except Exception as exc:  # noqa: BLE001
        return missing(f"function view failed: {type(exc).__name__}: {exc}")


def _siblings_section(lid, conf, method, bid, addr, binaries) -> str:
    """The cross-build counterparts, or the honest statement that there are none."""
    if lid is None:
        return (
            '<div style="border:1px solid #1e242e;border-radius:8px;padding:10px 12px;'
            'margin:12px 0;background:#151a22">'
            '<b style="color:#9aa7bb">Bound to no logical function, so it bridges nothing.</b>'
            '<p class="note" style="margin:6px 0 0">There is no <code>identity</code> row for '
            'this address, so it has no counterpart in any other build, and nothing learned '
            'about it here propagates anywhere. This is the common case, not an error: most '
            'addresses in most builds are still unbound, and hiding that would misreport '
            'coverage.</p></div>'
        )

    rows, err = _members(lid)
    if err:
        return missing(f"cross-build members unavailable: {err}")

    resolved = _names_for([lid]).get(lid) or {}
    points = _func_points((r[0], r[1]) for r in rows)

    out = []
    for m_bid, m_addr, m_conf, m_method in rows:
        b = binaries.get(m_bid) or {"slug": f"binary {m_bid}", "bits": 32}
        bits = b.get("bits") or 32
        meta = points.get((m_bid, m_addr), {})
        nm, tier, real = _display_name(lid, resolved, meta.get("name"), m_addr, bits)
        here = m_bid == bid and m_addr == addr
        href = _function_href(b["slug"], m_addr, bits)
        label = (f'<span style="color:#f2f6fb">{esc(b["slug"])} ← here</span>'
                 if here else f'<a href="{href}">{esc(b["slug"])}</a>')
        out.append([
            label,
            f'<span style="color:{FG_ANNOT}">{esc(b.get("game") or "?")}/'
            f'{esc(b.get("platform") or "?")}</span>',
            f'<a href="{href}">{_mono(_hex(m_addr, bits))}</a>',
            (f'<span style="color:{"#f2f6fb" if real else FG_DIM}">{esc(_fit(nm, 46))}</span>'),
            fnum(meta.get("size")),
            esc(f"{m_conf:.2f}" if m_conf is not None else "?"),
            f'<span style="color:{FG_ANNOT}">{esc(m_method or "?")}</span>',
            f'<a href="{_function_href(b["slug"], m_addr, bits)}" '
            f'aria-label="Open {esc(nm)} in {esc(b["slug"])}">open</a>',
        ])

    lead = (
        f'<p style="margin:14px 0 4px;font-size:14px">'
        f'<b>Also in {count_link(max(0, len(rows) - 1), _logical_href(lid), "other builds")}</b>'
        f' — logical <a href="{_logical_href(lid)}">#{int(lid)}</a>'
        f'{" &middot; " + esc(resolved.get("tier_name") or "") if resolved.get("tier_name") else ""}'
        f' &middot; confidence {esc(f"{conf:.2f}" if conf is not None else "?")}'
        f' &middot; {esc(method or "?")}</p>'
    )
    return lead + table(
        ["build", "game/platform", "address", "name there", "size", "conf", "method", ""],
        out, numeric={4, 5},
    )


def _c_section(know, kerr, program, hexed) -> str:
    head = (
        '<div id="source" class="fn-source">'
        '<div class="fn-source-head">'
        "<b>Decompiled C</b>"
        '<button type="button" class="copy-addr" data-copy-source="1">Copy C</button>'
        "</div>"
    )
    if kerr:
        return head + missing(f"knowledge database unavailable: {kerr}") + "</div>"
    if not know:
        return head + missing(
            f"no Ghidra knowledge row for {program} / {hexed} — this build's ingest either "
            f"has not run or did not reach this address."
        ) + "</div>"
    text = know.get("decompiled") or ""
    if not text.strip():
        return head + missing("the knowledge row exists but carries no decompiled body.") + "</div>"

    if _is_real_c is not None:
        real = _is_real_c(text)
        chip = ('<span class="tag">assembly-free pseudocode</span>' if real
                else '<span class="tag warn">pseudocode contains assembly</span>')
        verdict = (f'{chip} <span class="note">This checks only the text below. It does not '
                   f'prove that the code compiles or matches the shipped bytes.</span>')
    else:
        verdict = (f'<span class="note">real-C verdict unavailable: '
                   f'<code>kx/realc.py</code> would not import ({esc(_REALC_ERR)}).</span>')

    meta = (f'<p class="note" style="margin:0 0 6px">{verdict}</p>'
            f'<p class="note" style="margin:0 0 6px">'
            f'Ghidra name {_mono(know.get("name") or "?")} &middot; '
            f'{fnum(know.get("n_instructions"))} instructions &middot; '
            f'convention {esc(know.get("calling_convention") or "?")} &middot; '
            f'read as one row from <code>func_knowledge</code> '
            f'(<code>{esc(program)}</code>, <code>{esc(hexed)}</code>).</p>')
    body = f'<pre class="fn-c">{esc(text)}</pre>'
    return head + meta + body + "</div>"


# ---------------------------------------------------------------------------
# /logical/<id> — the identity group itself
# ---------------------------------------------------------------------------

def render_logical(logical_id) -> str:
    """One logical function: its resolved name, every member build, and any
    recovered source attached to it. Never raises."""
    try:
        try:
            lid = int(str(logical_id).strip())
        except (TypeError, ValueError):
            return missing("a logical function needs a numeric id")

        lf, err = query_db(
            "SELECT canon_key, canon_class, canon_method, game, best_name, best_signature, "
            "source_file, object_file, n_members FROM logical_function WHERE id=?",
            (lid,),
        )
        if err:
            return missing(f"logical_function unavailable: {err}")
        if not lf:
            return missing(f"no logical function #{lid} — ids are rowids and are not stable "
                           f"across a rebuild of the identity layer.")
        keys = ("canon_key", "canon_class", "canon_method", "game", "best_name",
                "best_signature", "source_file", "object_file", "n_members")
        g = dict(zip(keys, lf[0]))

        resolved = _names_for([lid]).get(lid) or {}
        name, tier, is_real = _display_name(lid, resolved, g.get("best_name"), 0, 32)
        cls = g.get("canon_class")
        title = f"{cls}::{name}" if cls and "::" not in (name or "") else name

        binaries, berr = _binaries()
        rows, merr = _members(lid)
        points = _func_points((r[0], r[1]) for r in rows)

        head = (
            f'<div style="display:flex;flex-wrap:wrap;gap:10px;align-items:baseline">'
              f'<b style="font-size:16px;color:{"#f2f6fb" if is_real else FG_DIM}">'
              f'{esc(title)}</b>'
              f'<span class="note">logical #{lid} &middot; name tier {esc(tier)} &middot; '
              f'{esc(g.get("game") or "?")}</span></div>'
        )
        if not is_real:
            head += ('<p class="note" style="margin:2px 0 0">Every fork of this function still '
                     'offers only a placeholder name.</p>')

        facts = [
            ("canonical key", _mono(g.get("canon_key") or "—")),
            ("class / method", esc(f'{g.get("canon_class") or "—"} :: {g.get("canon_method") or "—"}')),
            ("best signature",
             f'<code style="font-size:12px">{esc(_fit(g.get("best_signature") or "—", 110))}</code>'),
            ("source file (STABS)", esc(g.get("source_file") or "—")),
            ("object file", esc(g.get("object_file") or "—")),
            ("current members",
             count_link(len(rows), _logical_href(lid), "builds",
                        "live identity rows") if not merr else "unavailable"),
            ("name resolved from",
             esc(resolved.get("tier_name") or "—")
             + (f' <span style="color:{FG_ANNOT}">(tier {esc(resolved.get("tier"))})</span>'
                if resolved.get("tier") is not None else "")),
        ]
        facts_html = table(["fact", "value"], [[esc(k), v] for k, v in facts])

        if merr:
            members_html = missing(f"members unavailable: {merr}")
        elif not rows:
            members_html = missing(
                "this logical function has no identity rows, so it is bound into no build at "
                "all — it exists as a name without a body."
            )
        else:
            out = []
            for m_bid, m_addr, m_conf, m_method in rows:
                b = (binaries or {}).get(m_bid) or {"slug": f"binary {m_bid}", "bits": 32}
                bits = b.get("bits") or 32
                meta = points.get((m_bid, m_addr), {})
                href = _function_href(b["slug"], m_addr, bits)
                out.append([
                    f'<a href="{href}">{esc(b["slug"])}</a>',
                    f'<span style="color:{FG_ANNOT}">{esc(b.get("game") or "?")}/'
                    f'{esc(b.get("platform") or "?")}/{esc(b.get("arch") or "?")}</span>',
                    f'<a href="{href}">{_mono(_hex(m_addr, bits))}</a>',
                    fnum(meta.get("size")),
                    esc(f"{m_conf:.2f}" if m_conf is not None else "?"),
                    f'<span style="color:{FG_ANNOT}">{esc(m_method or "?")}</span>',
                    (f'<span style="color:{FG_ANNOT}" title="{esc(meta.get("source_file"))}">'
                     f'{esc(_fit(str(meta["source_file"]).rsplit("/", 1)[-1], 24))}</span>'
                     if meta.get("source_file") else f'<span style="color:{FG_DIM}">&mdash;</span>'),
                    f'<a href="{_graph_href(b["slug"], m_addr)}" '
                    f'aria-label="Open call graph for {esc(meta.get("name") or title)} in {esc(b["slug"])}">call graph</a>',
                ])
            members_html = (
                f'<p style="margin:14px 0 4px;font-size:14px"><b>Present in '
                f'{count_link(len(rows), _logical_href(lid), "builds")}</b>'
                f' — candidate and accepted bindings are listed with their confidence and '
                f'method. A recovered body must still compile and compare in each target build.</p>'
                + table(["build", "game/platform/arch", "address", "size", "conf", "method",
                         "source file", ""], out, numeric={3, 4})
            )

        return head + facts_html + members_html + _recovery_section(lid, rows, binaries) \
            + _resolver_warning()
    except Exception as exc:  # noqa: BLE001
        return missing(f"logical view failed: {type(exc).__name__}: {exc}")


def _recovery_section(lid, members, binaries) -> str:
    """Recovered source attached to this identity group.

    `recovered_function` is a real recovery (a body someone compiled);
    `reuse_candidate` is a proposal to apply one of those bodies to another
    build's address. They are different claims and are never merged, exactly as
    `real_c` and `byte_exact` are never summed.
    """
    head = '<p style="margin:16px 0 4px;font-size:14px"><b>Recovered source</b></p>'
    parts = []

    rec, err = query_db(
        "SELECT program, name, size, convention, real_c, path FROM recovered_function "
        "WHERE logical_id=? AND real_c=1",
        (int(lid),),
    )
    if err:
        parts.append(missing(f"recovered_function unavailable: {err}"))
    elif not rec:
        parts.append('<p class="note">No recovered body is attached to this logical function.</p>')
    else:
        rows = [[
            _mono(r[0]),
            esc(r[1]),
            fnum(r[2]),
            esc(r[3] or "?"),
            '<span class="tag ok">real C, byte matched</span>',
            f'<span style="color:{FG_ANNOT}" title="{esc(r[5])}">'
            f'{esc(_fit(str(r[5]).rsplit("/", 1)[-1], 34))}</span>',
        ] for r in rec]
        # "recovered as" is the artifact's own identifier on disk, not a
        # display name — `FUN_00621cb0.c` is the filename the recovery run
        # wrote, and renaming it here would break the link to the file.
        parts.append(
            '<p class="note" style="margin:0 0 4px">A body someone actually recovered and '
            'compiled. The identifier is the artifact&rsquo;s filename on disk, not this '
            'function&rsquo;s name — the resolved name is in the heading above.</p>'
            + table(["program", "recovered as", "size", "convention", "real C", "path"],
                    rows, numeric={2})
        )

    # reuse_candidate is keyed by destination, so ask it per member address.
    pairs = [(r[0], r[1]) for r in (members or [])][:MAX_MEMBERS]
    if pairs:
        where = " OR ".join("(dst_binary_id=? AND dst_addr=?)" for _ in pairs)
        args = tuple(v for pair in pairs for v in pair)
        cand, cerr = query_db(
            f"SELECT src_program, src_name, dst_binary_id, dst_addr, size, real_c, basis "
            f"FROM reuse_candidate INDEXED BY ix_reuse_dst WHERE real_c=1 AND ({where})", args
        )
        if cerr:
            parts.append(missing(f"reuse_candidate unavailable: {cerr}"))
        elif cand:
            rows = []
            for src_p, src_n, d_bid, d_addr, size, real_c, basis in cand:
                b = (binaries or {}).get(d_bid) or {"slug": f"binary {d_bid}", "bits": 32}
                bits = b.get("bits") or 32
                rows.append([
                    _mono(src_p) + f' <span style="color:{FG_ANNOT}">{esc(_fit(src_n, 34))}</span>',
                    f'<a href="{_function_href(b["slug"], d_addr, bits)}">{esc(b["slug"])} '
                    f'{_mono(_hex(d_addr, bits))}</a>',
                    fnum(size),
                    '<span class="tag ok">assembly-free source</span>',
                    f'<span style="color:{FG_ANNOT}">{esc(basis)}</span>',
                ])
            parts.append(
                '<p class="note" style="margin:10px 0 4px">Reuse candidates — a body '
                'recovered elsewhere <i>proposed</i> for one of these addresses. A proposal is '
                'not a recovery and the two are counted separately.</p>'
                + table(["recovered from", "proposed for", "size", "real C", "basis"],
                        rows, numeric={2})
            )

    return head + "".join(parts)


def _resolver_warning() -> str:
    if not _RESOLVER_ERR:
        return ""
    return (f'<p class="note" style="color:#fbbf24;margin:10px 0 0">'
            f'<b>Name tiers are approximate:</b> <code>kx/name_precedence.py</code> could not be '
            f'imported ({esc(_RESOLVER_ERR)}), so a fallback placeholder test is in use. Fix the '
            f'import before trusting a PLACEHOLDER label.</p>')


# ---------------------------------------------------------------------------
# review queue — match.status = 'review', ranked by score
# ---------------------------------------------------------------------------

# These rows are a human worklist, not names to apply. `output/ghidra_import/`
# only contains auto-tier matches; review-tier stays here until someone
# promotes or rejects them. The list is keyset-paged on (score DESC, id DESC)
# so a request never OFFSET-scans the match table.
REVIEW_STATUSES = ("auto", "verify", "review", "unresolved", "rejected")


def _parse_review_cursor(raw):
    """`score:id` from the previous page's last row. None = start of the list."""
    if not raw:
        return None
    text = str(raw).strip()
    if ":" not in text:
        return None
    score_s, id_s = text.rsplit(":", 1)
    try:
        return float(score_s), int(id_s)
    except (TypeError, ValueError):
        return None


def _review_cursor_of(score, match_id) -> str:
    return f"{float(score):.6f}:{int(match_id)}"


def render_review(params) -> str:
    """Paged review-tier matches, highest score first. Never raises. Never reads `func`."""
    try:
        params = params or {}
        cursor = _parse_review_cursor(_one(params, "review_after") or _one(params, "after"))
        page_size, show_all = _page_size({
            "page_size": _one(params, "review_page_size") or _one(params, "page_size"),
        })
        binaries, err = _binaries()
        if err:
            return missing(err)

        counts, err = query_db(
            "SELECT status, COUNT(*) FROM match GROUP BY status"
        )
        if err:
            return missing(f"match table unavailable: {err}")
        by_status = {str(s or ""): int(n or 0) for s, n in counts}
        review_n = by_status.get("review", 0)

        chips = []
        for st in REVIEW_STATUSES:
            n = by_status.get(st, 0)
            if st == "review":
                chips.append(f'<b>{esc(st)}</b> {fnum(n)}')
            else:
                chips.append(f'{esc(st)} {fnum(n)}')

        keep = {"page_size": "all"} if show_all else (
            {"page_size": page_size} if page_size != PAGE else {}
        )
        head = (
            '<p class="note">These are <b>review-tier</b> rows from the '
            '<code>match</code> table — ranked by score, with a margin, and '
            '<em>not</em> applied to Ghidra. Auto-tier names live in '
            '<a href="/artifact?p=output/ghidra_import">output/ghidra_import/</a>. '
            'Click a source or destination address to open that function.</p>'
            f'<p class="note">{" · ".join(chips)}</p>'
            + '<form class="search-form" method="get" action="/dashboard/functions#review">'
            + _carry_fields(params)
            + _page_size_control(page_size, show_all, control_id="review-page-size")
            + '<button type="submit">Update rows</button></form>'
        )
        if review_n == 0:
            return head + missing("no review-tier matches in the match table.")

        if cursor is None:
            sql = (
                "SELECT id, score, margin, src_binary, src_addr, dst_binary, dst_addr "
                "FROM match WHERE status='review' "
                "ORDER BY score DESC, id DESC LIMIT ?"
            )
            qparams = (page_size + 1,)
        else:
            cs, cid = cursor
            sql = (
                "SELECT id, score, margin, src_binary, src_addr, dst_binary, dst_addr "
                "FROM match WHERE status='review' AND "
                "(score < ? OR (score = ? AND id < ?)) "
                "ORDER BY score DESC, id DESC LIMIT ?"
            )
            qparams = (cs, cs, cid, page_size + 1)

        rows, err = query_db(sql, qparams)
        if err:
            return head + missing(f"review list unavailable: {err}")
        if not rows:
            return head + missing("no matches past this cursor — end of the queue.")

        more = len(rows) > page_size
        window = rows[:page_size]
        out = []
        for mid, score, margin, src_b, src_a, dst_b, dst_a in window:
            src = binaries.get(src_b) or {}
            dst = binaries.get(dst_b) or {}
            src_slug = src.get("slug") or f"binary:{src_b}"
            dst_slug = dst.get("slug") or f"binary:{dst_b}"
            src_bits = src.get("bits") or 32
            dst_bits = dst.get("bits") or 32
            src_hex = _hex(src_a, src_bits)
            dst_hex = _hex(dst_a, dst_bits)
            src_link = (
                f'<a href="{_function_href(src_slug, src_a, src_bits)}">'
                f'{esc(src_slug)} {_mono("0x" + src_hex)}</a>'
            )
            dst_link = (
                f'<a href="{_function_href(dst_slug, dst_a, dst_bits)}">'
                f'{esc(dst_slug)} {_mono("0x" + dst_hex)}</a>'
            )
            out.append([
                f'<span style="color:{FG_ANNOT}">#{int(mid)}</span>',
                f'{float(score):.3f}' if score is not None else "—",
                f'{float(margin):.3f}' if margin is not None else "—",
                src_link,
                dst_link,
            ])

        nxt = None
        if more:
            last = window[-1]
            nxt = _review_href(_review_cursor_of(last[1], last[0]), **keep)
        nav = []
        if cursor is not None:
            nav.append(f'<a href="{_review_href(**keep)}">‹ first page</a>')
        if nxt:
            next_label = "all remaining" if show_all else f"next {page_size}"
            nav.append(f'<a href="{nxt}">{next_label} ›</a>')
        nav_html = (
            f'<p class="note">{" · ".join(nav) if nav else "end of the queue."} '
            f'Keyset on <code>(score DESC, id DESC)</code> where '
            f'<code>status=review</code>. Showing {fnum(len(window))} rows from '
            f'{float(window[0][1]):.3f} down to {float(window[-1][1]):.3f}; '
            f'{fnum(review_n)} rows in the queue.</p>'
        )
        return (
            head
            + table(["match", "score", "margin", "source", "destination"], out,
                    numeric={0, 1, 2})
            + nav_html
        )
    except Exception as exc:  # noqa: BLE001
        return missing(f"review queue failed: {type(exc).__name__}: {exc}")


# ---------------------------------------------------------------------------
# landing-page view — a door, not a data dump
# ---------------------------------------------------------------------------

def render() -> str:
    """The builds, each count a link into its own function list."""
    try:
        return (
            '<p class="note">Every count below opens the set it counts. A function list is '
            'per build, paged by address, and every row reaches that function’s '
            'counterparts in the other builds.</p>'
            + _build_picker("browse a build:")
        )
    except Exception as exc:  # noqa: BLE001
        return missing(f"panel failed: {type(exc).__name__}: {exc}")
