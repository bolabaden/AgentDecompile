"""Inline-SVG chart primitives for the dashboard.

Rule C (docs/dashboard-design/10-relationship-layout.md) is the reason this file
exists: *visualization is the default representation*. Every number set on the
page gets a picture, and a table is only ever the expansion of a visual. Panels
call these helpers instead of emitting another 22-row table.

Two constraints shape every function here.

**Colour encodes verification state, only** (05-visual-system.md §2). Hue is the
page's scarcest resource and it is spent on how well-established a claim is —
never on category, platform, architecture or panel identity. That is why
`histogram` and `heatmap`, which plot magnitudes rather than evidence, use a
single neutral ramp: a bucket count is not a claim that passed a check, so it
gets no hue. Charts that *do* carry evidence take an explicit state per datum.

**Nothing external.** The server is stdlib Python on a machine that may be
offline, so there is no chart library, no CDN, no webfont and no raster image.
All geometry is computed here and emitted as inline SVG sized in relative units.

Every function is total: bad, empty or `None` input returns a placeholder, never
an exception. A panel that raises replaces data with an error box, which helps
nobody — so the failure mode is a quiet "no data" tile that still says what is
missing.

Accessibility floor (05-visual-system.md §6): every chart carries a `<title>`
and `role="img"`, and every state distinction is carried by a glyph or a hatch
pattern as well as by hue, because `proven`/`failed` is a green/red pair that
must survive greyscale.
"""

from __future__ import annotations

import itertools
import math

try:  # package import when loaded as scripts.panels.viz
    from .common import esc, fnum, fpct
except ImportError:  # direct import when the panels dir is on sys.path
    from common import esc, fnum, fpct  # type: ignore


# ---------------------------------------------------------------------------
# state palette
# ---------------------------------------------------------------------------

# (css-var stem, text/fill hex, border hex, background hex, glyph, label).
# Hex values duplicate 05-visual-system.md's tokens so a chart still renders in
# state colours if the stylesheet is served stale or stripped; the CSS variable
# wins whenever the page's :root is present, keeping one theme in one place.
_STATES: dict[str, tuple[str, str, str, str, str, str]] = {
    "proven":   ("proven",   "#5ee79b", "#46916a", "#0f2a1c", "●", "proven"),
    "partial":  ("partial",  "#fbbf24", "#9a8340", "#2b2411", "◐", "partial"),
    "unproven": ("unproven", "#9aa7bb", "#6a7688", "#1a212e", "○", "unproven"),
    "failed":   ("failed",   "#f87171", "#a45a5a", "#2c1618", "✕", "failed"),
    "excluded": ("excluded", "#7d8aa0", "#4a5768", "#0c0f14", "—", "excluded"),
    # `unknown` is not one of the five documented states. It borrows the neutral
    # unproven palette on purpose — an unrecognised state must never look like a
    # result — but keeps its own glyph so the page can be audited for callers
    # that are passing something the design does not define.
    "unknown":  ("unproven", "#9aa7bb", "#6a7688", "#1a212e", "?", "unknown"),
}

_NEUTRAL = "unproven"

# Ids must be unique per document: the page renders many charts into one HTML
# response, and a duplicated <pattern id> silently makes every later chart use
# the first chart's hatch.
_SEQ = itertools.count(1)


def _uid(prefix: str) -> str:
    return f"{prefix}{next(_SEQ)}"


def _state(name) -> str:
    key = str(name or "").strip().lower()
    return key if key in _STATES else _NEUTRAL


def _css(state: str, part: str) -> str:
    """CSS colour for a state, as `var(--token, #fallback)`."""
    stem, fg, bd, bg, _glyph, _label = _STATES[_state(state)]
    if part == "fg":
        return f"var(--st-{stem},{fg})"
    if part == "bd":
        return f"var(--st-{stem}-bd,{bd})"
    return f"var(--st-{stem}-bg,{bg})"


def _glyph(state: str) -> str:
    return _STATES[_state(state)][4]


def _label_of(state: str) -> str:
    return _STATES[_state(state)][5]


# Hatch geometry per state. This is the redundant, non-colour channel required
# by WCAG 1.4.1: printed greyscale or viewed by a red/green-blind reader, the
# fills still differ. Angles are chosen to be distinguishable at a 10px bar
# height, which is why partial/failed are 45/90 apart rather than adjacent.
_HATCH = {
    "proven":   "M0,4 l4,-4 M-1,1 l2,-2 M3,5 l2,-2",
    "partial":  "M0,0 l4,4 M-1,3 l2,2 M3,-1 l2,2",
    "unproven": "M2,2 l0.6,0",
    "failed":   "M0,0 l4,4 M0,4 l4,-4",
    "excluded": "M0,2 l4,0",
    "unknown":  "M2,0 l0,4",
}


def _defs(states, uid: str) -> tuple[str, dict[str, str]]:
    """Emit <pattern> defs for the states in use; return (svg, state->url)."""
    seen, out, urls = [], [], {}
    for st in states:
        st = _state(st)
        if st in seen:
            continue
        seen.append(st)
        pid = f"{uid}h{st}"
        urls[st] = f"url(#{pid})"
        out.append(
            f'<pattern id="{pid}" width="4" height="4" patternUnits="userSpaceOnUse">'
            f'<path d="{_HATCH.get(st, _HATCH["unproven"])}" '
            f'stroke="#000" stroke-opacity=".38" stroke-width="1" fill="none"/>'
            f"</pattern>"
        )
    return f"<defs>{''.join(out)}</defs>", urls


# ---------------------------------------------------------------------------
# scaffolding
# ---------------------------------------------------------------------------

_FG = "var(--fg-body,#d7dde7)"
_FG_MAX = "var(--fg-max,#f2f6fb)"
_FG_HEAD = "var(--fg-head,#9aa7bb)"
_FG_ANNOT = "var(--fg-annot,#8b98ab)"
_LINE = "var(--line,#1e242e)"
_LINE_STRONG = "var(--line-strong,#2a3342)"
_PANEL = "var(--bg-panel,#131924)"
_RAISED = "var(--bg-raised,#1a212e)"
_LINK = "var(--link,#6cc6ff)"
_MONO = "ui-monospace,SFMono-Regular,Menlo,Consolas,'DejaVu Sans Mono',monospace"
_UI = "ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,Arial,sans-serif"


def _svg(width: float, height: float, title: str, body: str,
         max_px: float | None = None, cls: str = "", description: str = "") -> str:
    """Wrap body in a responsive, titled SVG root.

    `width`/`height` are viewBox user units only. The element itself is sized in
    percent with `height:auto`, so a chart drawn at 640 units renders correctly
    inside a 320px column at 200% zoom — Rule "no page-level horizontal scroll".
    """
    # Never emit a zero/negative viewBox. Apart from being invalid geometry in
    # practice, browsers disagree about its intrinsic aspect ratio and can make
    # the surrounding layout jump when a fragment refreshes.
    width = max(1.0, _num(width))
    height = max(1.0, _num(height))
    uid = _uid("t")
    desc_id = f"{uid}d"
    cap = max(1.0, _num(max_px)) if max_px is not None else width
    desc = description or "Inline chart. Values are also stated in text within the graphic."
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" class="viz {cls}" role="img" '
        f'aria-labelledby="{uid} {desc_id}" focusable="false" '
        f'viewBox="0 0 {_n(width)} {_n(height)}" '
        f'preserveAspectRatio="xMidYMid meet" '
        f'style="display:block;width:100%;height:auto;aspect-ratio:{_n(width)} / {_n(height)};'
        f'max-width:{_n(cap)}px">'
        f'<title id="{uid}">{esc(title)}</title>'
        f'<desc id="{desc_id}">{esc(desc)}</desc>{body}</svg>'
    )


def _n(value) -> str:
    """Compact number for SVG geometry — trims 12.0 to 12, 12.3456 to 12.35."""
    try:
        f = float(value)
    except (TypeError, ValueError):
        return "0"
    if not math.isfinite(f):
        return "0"
    if abs(f - round(f)) < 1e-9:
        return str(int(round(f)))
    return f"{f:.2f}".rstrip("0").rstrip(".")


def _text(x, y, s, size=12, fill=_FG, anchor="start", mono=False, weight=400,
          extra: str = "") -> str:
    fam = _MONO if mono else _UI
    return (
        f'<text x="{_n(x)}" y="{_n(y)}" font-size="{_n(size)}" fill="{fill}" '
        f'text-anchor="{anchor}" font-family="{fam}" font-weight="{weight}"{extra}>'
        f"{esc(s)}</text>"
    )


def _clip(s, limit: int) -> str:
    s = "" if s is None else str(s)
    return s if len(s) <= limit else s[: max(1, limit - 1)] + "…"


def _num(value) -> float:
    try:
        f = float(value)
    except (TypeError, ValueError):
        return 0.0
    return f if math.isfinite(f) else 0.0


def placeholder(what: str = "no data", why: str = "") -> str:
    """The universal degrade target.

    05-visual-system.md §3.6: missing data is `unproven`, never amber, and it
    says what is absent rather than rendering an empty frame that reads as zero.
    """
    body = (
        f'<rect x=".5" y=".5" width="199" height="43" rx="6" fill="{_RAISED}" '
        f'stroke="{_LINE_STRONG}" stroke-dasharray="3 3"/>'
        + _text(12, 20, "○ " + _clip(what, 30), 12, _css("unproven", "fg"))
        + (_text(12, 34, _clip(why, 34), 11, _FG_ANNOT) if why else "")
    )
    return _svg(200, 44, f"{what}. {why}".strip(), body, max_px=200,
                cls="viz-empty", description="No chart data is available.")


def _rows(data) -> list[tuple[str, float, str]]:
    """Normalise `[(label, value, state)]`, tolerating 2-tuples and junk rows."""
    out: list[tuple[str, float, str]] = []
    for item in data or []:
        try:
            if isinstance(item, dict):
                label = item.get("label", item.get("name", ""))
                value = item.get("value", 0)
                state = item.get("state", _NEUTRAL)
            else:
                seq = list(item)
                label = seq[0] if seq else ""
                value = seq[1] if len(seq) > 1 else 0
                state = seq[2] if len(seq) > 2 else _NEUTRAL
        except TypeError:
            continue
        out.append((str(label), _num(value), _state(state)))
    return out


def _href(fn, label, value, state) -> str | None:
    """Call a caller-supplied href builder without caring about its arity."""
    if fn is None:
        return None
    for args in ((label, value, state), (label, value), (label,)):
        try:
            got = fn(*args)
        except TypeError:
            continue
        except Exception:  # noqa: BLE001 — a bad href must not kill the chart
            return None
        return str(got) if got else None
    return None


def _a(href: str | None, inner: str, tip: str = "") -> str:
    tip_el = f"<title>{esc(tip)}</title>" if tip else ""
    if not href:
        return f"<g>{tip_el}{inner}</g>"
    return f'<a href="{esc(href)}">{tip_el}{inner}</a>'


def _safe(fn):
    """Guarantee totality. A panel must never raise; see module docstring."""
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as exc:  # noqa: BLE001
            return placeholder("chart failed", f"{type(exc).__name__}: {exc}"[:60])
    wrapper.__name__ = getattr(fn, "__name__", "viz")
    wrapper.__doc__ = fn.__doc__
    return wrapper


# ---------------------------------------------------------------------------
# charts
# ---------------------------------------------------------------------------

@_safe
def donut(parts, total=None, size=120, title=None) -> str:
    """Part-of-whole ring: `[(label, value, state)]`.

    Used for real-C vs shim and bound vs unbound — the pairs where the whole is
    the honest denominator and the split is the finding. `total` overrides the
    sum when the denominator is larger than what is plotted (e.g. functions that
    were never attempted), so the ring shows the gap instead of hiding it.
    """
    rows = [r for r in _rows(parts) if r[1] > 0]
    if not rows:
        return placeholder("no parts to plot", "needs [(label, value, state)]")

    plotted = sum(r[1] for r in rows)
    whole = _num(total) if total not in (None, "") else plotted
    if whole < plotted:
        whole = plotted
    if whole <= 0:
        return placeholder("no parts to plot", "total is zero")

    size = max(72.0, min(320.0, _num(size) or 120))
    thick = max(10.0, size * 0.17)
    r = (size - thick) / 2.0
    cx = cy = size / 2.0
    circ = 2 * math.pi * r
    gap = min(2.0, circ * 0.004)

    defs, urls = _defs([r[2] for r in rows], _uid("d"))
    arcs, legend_rows, offset = [], [], 0.0

    # Unaccounted-for remainder: drawn as a dim track so a 3-of-9 ring cannot be
    # mistaken for a full one.
    track = (
        f'<circle cx="{_n(cx)}" cy="{_n(cy)}" r="{_n(r)}" fill="none" '
        f'stroke="{_LINE_STRONG}" stroke-width="{_n(thick)}" opacity=".55"/>'
    )

    for label, value, state in rows:
        seg = circ * value / whole
        draw = max(0.6, seg - gap) if seg > gap * 2 else seg
        common = (
            f'cx="{_n(cx)}" cy="{_n(cy)}" r="{_n(r)}" fill="none" '
            f'stroke-width="{_n(thick)}" '
            f'stroke-dasharray="{_n(draw)} {_n(circ - draw)}" '
            f'stroke-dashoffset="{_n(-offset)}" '
            f'transform="rotate(-90 {_n(cx)} {_n(cy)})"'
        )
        pct = fpct(value, whole)
        arcs.append(
            f"<g><title>{esc(f'{label}: {fnum(value)} of {fnum(whole)} ({pct})')}</title>"
            f'<circle {common} stroke="{_css(state, "fg")}"/>'
            f'<circle {common} stroke="{urls[_state(state)]}"/></g>'
        )
        offset += seg
        legend_rows.append(
            f'<li><span class="viz-sw" aria-hidden="true" '
            f'style="background:{_css(state, "fg")};border-color:{_css(state, "bd")}"></span>'
            f'<span class="viz-g" style="color:{_css(state, "fg")}">{esc(_glyph(state))}</span> '
            f"<span>{esc(_clip(label, 24))}</span> "
            f'<b style="font-family:{_MONO}">{esc(fnum(value))}</b> '
            f'<span class="annot">{esc(pct)}</span></li>'
        )

    head = fnum(rows[0][1]) if len(rows) == 1 else fnum(whole)
    centre = (
        _text(cx, cy + 2, head, size * 0.17, _FG_MAX, "middle", mono=True, weight=700)
        + _text(cx, cy + size * 0.17 + 4, "total" if len(rows) > 1 else _clip(rows[0][0], 12),
                size * 0.10, _FG_ANNOT, "middle")
    )
    cap = title or "Composition"
    svg = _svg(size, size, f"{cap}: {fnum(whole)} total across {len(rows)} parts",
               defs + track + "".join(arcs) + centre, max_px=size, cls="viz-donut")

    head_html = f'<figcaption class="h-sec">{esc(cap)}</figcaption>' if title else ""
    return (
        f'<figure class="viz-fig viz-fig-donut" style="display:flex;gap:12px;'
        f'align-items:center;flex-wrap:wrap;margin:0">'
        f'<div style="flex:0 0 auto;width:{_n(size)}px;max-width:40%">{svg}</div>'
        f'<div style="flex:1 1 12ch;min-width:12ch">{head_html}'
        f'<ul class="viz-legend">{"".join(legend_rows)}</ul></div></figure>'
    )


@_safe
def bars(rows, max_value=None, height=14, sort=True, href_fn=None) -> str:
    """Sorted horizontal bars: `[(label, value, state)]`.

    The workhorse. Any per-build comparison across the 22 forks is this chart —
    a 22-row table is a bar chart that was never drawn (Rule C). Sorting is the
    priority channel that 05-visual-system.md §2 substitutes for category hue,
    so it defaults on.
    """
    data = _rows(rows)
    if not data:
        return placeholder("no rows to compare", "needs [(label, value, state)]")
    if sort:
        data.sort(key=lambda r: r[1], reverse=True)

    bar_h = max(8.0, min(28.0, _num(height) or 14))
    step = bar_h + 8
    W = 640.0
    lab_w, val_w = 168.0, 84.0
    x0, track_w = lab_w + 12, W - lab_w - val_w - 24
    H = step * len(data) + 6

    peak = _num(max_value) if max_value not in (None, "") else max(r[1] for r in data)
    if peak <= 0:
        peak = 1.0

    defs, urls = _defs([r[2] for r in data], _uid("b"))
    out = [defs]
    for i, (label, value, state) in enumerate(data):
        y = i * step + 3
        # A measured zero draws nothing. Giving it the same 1-unit floor as a
        # small-but-real value would make "none" and "a few" pixel-identical,
        # which is the kind of quiet lie this dashboard exists to stop.
        w = max(1.0, track_w * min(1.0, value / peak)) if value > 0 else 0.0
        mid = y + bar_h / 2
        tip = f"{label}: {fnum(value)} ({_label_of(state)})"
        body = (
            f'<rect x="{_n(x0)}" y="{_n(y)}" width="{_n(track_w)}" height="{_n(bar_h)}" '
            f'rx="3" fill="{_PANEL}" stroke="{_LINE}"/>'
            + (f'<rect x="{_n(x0)}" y="{_n(y)}" width="{_n(w)}" height="{_n(bar_h)}" rx="3" '
               f'fill="{_css(state, "fg")}" fill-opacity=".85" stroke="{_css(state, "bd")}"/>'
               f'<rect x="{_n(x0)}" y="{_n(y)}" width="{_n(w)}" height="{_n(bar_h)}" rx="3" '
               f'fill="{urls[_state(state)]}"/>' if w else "")
            # Glyph rides the label, not the bar: a 1px bar has nowhere to put it.
            + _text(10, mid + 4, _glyph(state), 11, _css(state, "fg"))
            + _text(24, mid + 4, _clip(label, 22), 12,
                    _LINK if href_fn else _FG, mono=True)
            + _text(W - 8, mid + 4, fnum(value), 12, _FG_MAX, "end", mono=True, weight=600)
        )
        out.append(_a(_href(href_fn, label, value, state), body, tip))

    total = sum(r[1] for r in data)
    return _svg(W, H,
                f"{len(data)} rows compared, {fnum(total)} total, peak {fnum(peak)}",
                "".join(out), max_px=None, cls="viz-bars")


@_safe
def stacked_bar(segments, width=None, height=18) -> str:
    """One bar, many states: `[(label, value, state)]`.

    For a single build's step mix, where the question is the *proportion* of
    each state and the parts are known to sum to the whole.
    """
    data = [r for r in _rows(segments) if r[1] > 0]
    if not data:
        return placeholder("no segments", "needs [(label, value, state)]")
    total = sum(r[1] for r in data)
    if total <= 0:
        return placeholder("no segments", "all values are zero")

    W = _num(width) or 640.0
    W = max(160.0, min(1200.0, W))
    h = max(10.0, min(40.0, _num(height) or 18))
    H = h + 20

    defs, urls = _defs([r[2] for r in data], _uid("s"))
    out, x = [defs], 0.0
    for label, value, state in data:
        w = W * value / total
        pct = fpct(value, total)
        out.append(
            f"<g><title>{esc(f'{label}: {fnum(value)} ({pct})')}</title>"
            f'<rect x="{_n(x)}" y="0" width="{_n(max(0.7, w))}" height="{_n(h)}" '
            f'fill="{_css(state, "fg")}" fill-opacity=".85" stroke="{_css(state, "bd")}"/>'
            f'<rect x="{_n(x)}" y="0" width="{_n(max(0.7, w))}" height="{_n(h)}" '
            f'fill="{urls[_state(state)]}"/>'
        )
        # Only label a segment wide enough to hold the text; the <title> and the
        # caption below carry every segment regardless.
        if w > 46:
            out.append(_text(x + w / 2, h / 2 + 4,
                             f"{_glyph(state)} {fnum(value)}", 11,
                             "var(--bg-base,#0c0f14)", "middle", mono=True, weight=600))
        out.append("</g>")
        x += w

    caption = "  ".join(f"{_glyph(s)} {_clip(label, 14)} {fnum(v)}" for label, v, s in data)
    out.append(_text(0, h + 14, _clip(caption, 110), 11, _FG_ANNOT))
    return _svg(W, H, f"{len(data)} segments totalling {fnum(total)}",
                "".join(out), max_px=None, cls="viz-stack")


@_safe
def histogram(values, buckets=None, title=None) -> str:
    """Distribution of a plain list of numbers — size bands, confidence.

    Neutral fill throughout: a bucket count is a magnitude, not a verification
    claim, and 05-visual-system.md §2 forbids spending hue on anything else.
    """
    nums = []
    for v in values or []:
        try:
            f = float(v)
        except (TypeError, ValueError):
            continue
        if math.isfinite(f):
            nums.append(f)
    if not nums:
        return placeholder("no values to bin", "needs a list of numbers")

    lo, hi = min(nums), max(nums)
    if isinstance(buckets, (list, tuple)) and len(buckets) >= 2:
        edges = sorted(float(e) for e in buckets)
    else:
        try:
            nb = int(buckets) if buckets else 0
        except (TypeError, ValueError):
            nb = 0
        nb = nb if nb >= 2 else max(4, min(16, int(math.sqrt(len(nums))) + 1))
        if hi <= lo:  # every sample identical — one bin, stated honestly
            hi = lo + 1.0
        edges = [lo + (hi - lo) * i / nb for i in range(nb + 1)]

    nb = len(edges) - 1
    counts = [0] * nb
    for f in nums:
        idx = nb - 1
        for i in range(nb):
            if f < edges[i + 1] or i == nb - 1:
                idx = i
                break
        counts[idx] += 1
    peak = max(counts) or 1

    W, H = 640.0, 170.0
    base, top = H - 34, 14.0
    gap = 2.0
    bw = (W - gap * (nb - 1)) / nb

    defs, urls = _defs([_NEUTRAL], _uid("g"))
    out = [defs, f'<line x1="0" y1="{_n(base)}" x2="{_n(W)}" y2="{_n(base)}" '
                 f'stroke="{_LINE_STRONG}"/>']
    for i, c in enumerate(counts):
        x = i * (bw + gap)
        h = (base - top) * c / peak
        tip = (f"{_n(edges[i])} to {_n(edges[i + 1])}: "
               f"{fnum(c)} of {fnum(len(nums))} ({fpct(c, len(nums))})")
        out.append(
            f"<g><title>{esc(tip)}</title>"
            f'<rect x="{_n(x)}" y="{_n(base - h)}" width="{_n(bw)}" '
            f'height="{_n(max(1.0, h))}" fill="{_css(_NEUTRAL, "fg")}" fill-opacity=".7" '
            f'stroke="{_css(_NEUTRAL, "bd")}"/>'
            f'<rect x="{_n(x)}" y="{_n(base - h)}" width="{_n(bw)}" '
            f'height="{_n(max(1.0, h))}" fill="{urls[_NEUTRAL]}"/>'
        )
        if c and bw > 22:
            out.append(_text(x + bw / 2, base - h - 4, fnum(c), 11, _FG_HEAD,
                             "middle", mono=True))
        out.append("</g>")

    out.append(_text(0, base + 14, _n(edges[0]), 11, _FG_ANNOT, mono=True))
    out.append(_text(W, base + 14, _n(edges[-1]), 11, _FG_ANNOT, "end", mono=True))
    out.append(_text(W / 2, H - 4,
                     f"{fnum(len(nums))} samples · {nb} bins · peak {fnum(peak)}",
                     11, _FG_ANNOT, "middle"))
    if title:
        out.insert(1, _text(0, 10, title, 12, _FG_HEAD, weight=600))

    return _svg(W, H, f"{title or 'Distribution'}: {fnum(len(nums))} samples in {nb} bins",
                "".join(out), max_px=None, cls="viz-hist")


@_safe
def heatmap(matrix, row_labels, col_labels, href_fn=None) -> str:
    """Build x build density matrix. Cells are links.

    This is the project in one picture: how much of each fork is identified in
    every other fork. Density is drawn as a neutral luminance ramp rather than a
    colour scale — a match count is a magnitude, and hue on this page belongs to
    verification state alone (05-visual-system.md §2). The number is printed in
    the cell so the ramp never has to be decoded.
    """
    rows = list(matrix or [])
    rlab = [str(x) for x in (row_labels or [])]
    clab = [str(x) for x in (col_labels or [])]
    if not rows or not rlab or not clab:
        return placeholder("no matrix", "needs matrix + row and column labels")

    grid = []
    for r in range(len(rlab)):
        src = list(rows[r]) if r < len(rows) else []
        grid.append([_num(src[c]) if c < len(src) else 0.0 for c in range(len(clab))])

    # The diagonal is a build against itself and is structurally uninteresting;
    # including it in the scale would flatten every real cross-match to nothing.
    off = [grid[r][c] for r in range(len(rlab)) for c in range(len(clab))
           if not (r == c and rlab[r] == clab[c])]
    peak = max(off) if off and max(off) > 0 else 1.0

    cell = 34.0
    lab_w = 116.0
    head_h = 62.0
    W = lab_w + cell * len(clab)
    H = head_h + cell * len(rlab) + 26

    out = []
    for c, name in enumerate(clab):
        cx = lab_w + c * cell + cell / 2
        out.append(_text(cx, head_h - 8, _clip(name, 14), 10, _FG_HEAD, "start", mono=True,
                         extra=f' transform="rotate(-45 {_n(cx)} {_n(head_h - 8)})"'))

    for r, rname in enumerate(rlab):
        y = head_h + r * cell
        out.append(_text(lab_w - 8, y + cell / 2 + 4, _clip(rname, 16), 11, _FG_HEAD,
                         "end", mono=True))
        for c, cname in enumerate(clab):
            v = grid[r][c]
            x = lab_w + c * cell
            self_cell = r == c and rname == cname
            frac = 0.0 if self_cell else min(1.0, v / peak)
            if self_cell:
                fill, opacity, stroke = _RAISED, "1", _LINE_STRONG
            else:
                # One hue, varying opacity: magnitude without spending colour.
                fill, opacity, stroke = _css(_NEUTRAL, "fg"), _n(0.08 + 0.82 * frac), _LINE
            ink = "var(--bg-base,#0c0f14)" if frac > 0.55 else _FG
            label = "—" if self_cell else (fnum(v) if v else "·")
            body = (
                f'<rect x="{_n(x + 1)}" y="{_n(y + 1)}" width="{_n(cell - 2)}" '
                f'height="{_n(cell - 2)}" rx="2" fill="{fill}" fill-opacity="{opacity}" '
                f'stroke="{stroke}"/>'
                + _text(x + cell / 2, y + cell / 2 + 4, _clip(label, 6), 10,
                        _FG_ANNOT if self_cell else ink, "middle", mono=True)
            )
            tip = (f"{rname} × {cname}: same build"
                   if self_cell else f"{rname} × {cname}: {fnum(v)} matches")
            out.append(_a(None if self_cell else _href(href_fn, rname, v, cname), body, tip))

    # Scale key, so the ramp is legible without hovering a cell.
    ky = head_h + cell * len(rlab) + 16
    out.append(_text(lab_w - 8, ky, "density", 10, _FG_ANNOT, "end"))
    for i in range(6):
        out.append(
            f'<rect x="{_n(lab_w + i * 16)}" y="{_n(ky - 9)}" width="15" height="10" '
            f'fill="{_css(_NEUTRAL, "fg")}" fill-opacity="{_n(0.08 + 0.82 * i / 5)}" '
            f'stroke="{_LINE}"/>'
        )
    out.append(_text(lab_w + 6 * 16 + 6, ky, f"0 → {fnum(peak)}", 10, _FG_ANNOT,
                     mono=True))

    return _svg(W, H,
                f"Matrix density, {len(rlab)} by {len(clab)} categories, "
                f"peak {fnum(peak)}",
                "".join(out), max_px=None, cls="viz-heat",
                description=("Rows and columns identify categories. Each cell states its "
                             "value; darker cells represent larger values."))


@_safe
def rail(steps) -> str:
    """The ordered pipeline as one rail: `[(name, fraction, state, href)]`.

    Rule D puts this in the landing view, above the fold. Each step shows its
    own fill so a stalled stage is visible without opening anything, and the
    connectors make the ordering explicit rather than implied by reading order.
    """
    data = []
    for item in steps or []:
        try:
            seq = list(item)
        except TypeError:
            continue
        if not seq:
            continue
        name = str(seq[0])
        frac = max(0.0, min(1.0, _num(seq[1]) if len(seq) > 1 else 0.0))
        state = _state(seq[2] if len(seq) > 2 else _NEUTRAL)
        href = seq[3] if len(seq) > 3 else None
        data.append((name, frac, state, href))
    if not data:
        return placeholder("no pipeline steps", "needs [(name, fraction, state, href)]")

    n = len(data)
    sw = 96.0
    gapx = 10.0
    W = n * sw + (n - 1) * gapx
    H = 72.0
    track_y, track_h = 26.0, 16.0

    defs, urls = _defs([s[2] for s in data], _uid("r"))
    out = [defs]
    for i, (name, frac, state, href) in enumerate(data):
        x = i * (sw + gapx)
        if i:  # connector, drawn first so the step boxes sit on top of it
            out.append(
                f'<line x1="{_n(x - gapx)}" y1="{_n(track_y + track_h / 2)}" '
                f'x2="{_n(x)}" y2="{_n(track_y + track_h / 2)}" '
                f'stroke="{_LINE_STRONG}" stroke-width="2"/>'
            )
        fill_w = max(1.5, sw * frac) if frac > 0 else 0.0
        pct = f"{frac * 100:.0f}%"
        body = (
            _text(x, 14, f"{i + 1}. {_clip(name, 13)}", 11,
                  _LINK if href else _FG, weight=600)
            + f'<rect x="{_n(x)}" y="{_n(track_y)}" width="{_n(sw)}" '
              f'height="{_n(track_h)}" rx="4" fill="{_PANEL}" stroke="{_LINE}"/>'
            + (f'<rect x="{_n(x)}" y="{_n(track_y)}" width="{_n(fill_w)}" '
               f'height="{_n(track_h)}" rx="4" fill="{_css(state, "fg")}" '
               f'fill-opacity=".85" stroke="{_css(state, "bd")}"/>'
               f'<rect x="{_n(x)}" y="{_n(track_y)}" width="{_n(fill_w)}" '
               f'height="{_n(track_h)}" rx="4" fill="{urls[state]}"/>' if fill_w else "")
            + _text(x, track_y + track_h + 16, _glyph(state), 12, _css(state, "fg"))
            + _text(x + 14, track_y + track_h + 16, _label_of(state), 10, _css(state, "fg"))
            + _text(x + sw, track_y + track_h + 16, pct, 11, _FG_MAX, "end", mono=True,
                    weight=600)
        )
        out.append(_a(str(href) if href else None, body, f"{name}: {pct} · {_label_of(state)}"))

    done = sum(1 for s in data if s[1] >= 1.0)
    return _svg(W, H, f"Pipeline: {n} steps, {done} complete",
                "".join(out), max_px=None, cls="viz-rail")


@_safe
def sparkline(values, width=120, height=24) -> str:
    """Trend of a short series — log-derived job progress over time.

    Neutral by default for the same reason as `histogram`; the final point is
    emphasised because "where is it now" is the only question a sparkline in a
    summary row is asked.
    """
    nums = []
    for v in values or []:
        try:
            f = float(v)
        except (TypeError, ValueError):
            continue
        if math.isfinite(f):
            nums.append(f)
    if len(nums) < 2:
        return placeholder("no trend", "needs 2+ numeric samples")

    W = max(40.0, min(600.0, _num(width) or 120))
    H = max(12.0, min(120.0, _num(height) or 24))
    pad = 2.0
    lo, hi = min(nums), max(nums)
    span = (hi - lo) or 1.0
    stepx = (W - pad * 2) / (len(nums) - 1)

    pts = []
    for i, v in enumerate(nums):
        x = pad + i * stepx
        y = H - pad - (H - pad * 2) * (v - lo) / span
        pts.append((x, y))
    poly = " ".join(f"{_n(x)},{_n(y)}" for x, y in pts)
    area = f"{_n(pad)},{_n(H - pad)} {poly} {_n(W - pad)},{_n(H - pad)}"
    lx, ly = pts[-1]

    body = (
        f'<polygon points="{area}" fill="{_css(_NEUTRAL, "fg")}" fill-opacity=".14"/>'
        f'<polyline points="{poly}" fill="none" stroke="{_css(_NEUTRAL, "fg")}" '
        f'stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round"/>'
        f'<circle cx="{_n(lx)}" cy="{_n(ly)}" r="2.2" fill="{_FG_MAX}"/>'
    )
    return _svg(W, H,
                f"Trend over {fnum(len(nums))} samples, "
                f"{fnum(nums[0])} to {fnum(nums[-1])} (min {fnum(lo)}, max {fnum(hi)})",
                body, max_px=W, cls="viz-spark")


@_safe
def legend(states) -> str:
    """State key, stated once per page.

    Every chart above is coloured by the same five-plus-one vocabulary, so the
    meaning of hue is declared in one place instead of being re-guessed in each
    section. Glyph and word are always present; hue is the third channel, never
    the only one.
    """
    items, seen = [], []
    for s in states or []:
        if isinstance(s, (list, tuple)) and s:
            key, text = _state(s[0]), str(s[1]) if len(s) > 1 else None
        else:
            key, text = _state(s), None
        if key in seen:
            continue
        seen.append(key)
        items.append(
            f'<li><span class="pill is-{key}" '
            f'style="color:{_css(key, "fg")};border-color:{_css(key, "bd")};'
            f'background:{_css(key, "bg")}">'
            f'<span class="g" aria-hidden="true">{esc(_glyph(key))}</span> '
            f'{esc(text or _label_of(key))}</span></li>'
        )
    if not items:
        return placeholder("no states", "needs a list of state names")
    return (
        f'<ul class="viz-legend viz-legend-key" role="list" '
        f'style="display:flex;flex-wrap:wrap;gap:8px;list-style:none;margin:0;padding:0">'
        f'{"".join(items)}</ul>'
    )


# The minimum CSS these primitives need beyond the page's existing tokens. A
# panel can inline it once; it is kept here so the markup and its styling stay
# in the same file rather than drifting apart across two owners.
CSS = """
.viz{max-width:100%}
.viz-fig{margin:0}
.viz-legend{list-style:none;margin:0;padding:0;font-size:var(--fs-micro,12px)}
.viz-legend li{display:flex;align-items:center;gap:6px;padding:2px 0;
  color:var(--fg-annot,#8b98ab)}
.viz-legend b{color:var(--fg-max,#f2f6fb);font-weight:600}
.viz-sw{width:9px;height:9px;border-radius:2px;border:1px solid;flex:0 0 auto}
.viz-g{font-size:1.05em;line-height:1}
.viz a:focus-visible{outline:2px solid var(--focus,#6cc6ff);outline-offset:2px}
.viz a rect{transition:fill-opacity .12s ease}
.viz a:hover rect{fill-opacity:1}
@media (prefers-reduced-motion:reduce){.viz a rect{transition:none}}
@media (forced-colors:active){.viz rect,.viz circle,.viz polyline{forced-color-adjust:auto}}
"""
