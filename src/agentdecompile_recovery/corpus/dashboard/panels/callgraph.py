"""Execution flow — the caller/callee graph, with cross-build reach on every node.

This panel is the dashboard's foundation, not one more box of numbers. A
function is not a row in a table: it has callers above it, callees below it,
and it exists in up to 24 builds at once. Everything else the dashboard knows
about a function is a property of a node in this graph.

Three things this file refuses to do, and why:

1. **It never truncates silently.** A call graph that quietly drops half a
   function's callers is a lie about the program's control flow, and the lie is
   invisible — the picture still looks complete. Every level therefore states
   how many nodes it drew out of how many exist, and the selection rule
   (lowest address first) is deterministic and printed, so nobody has to guess
   whether the missing ones were the interesting ones.

2. **It never prints `FUN_xxxxxxxx` when a real name exists.** Names come from
   `logical_name`, which `kx/name_precedence.py` fills by running the ladder
   human > stabs > symbol > derived > placeholder across every fork. A node
   bound to a logical function shows the winning name and the tier that won;
   only an unbound node falls back to this build's raw `func.name`, and that
   fallback is labelled so it cannot be mistaken for a resolved name.

3. **It never scans `func`.** Every query here resolves through an index:
   `ix_edge_callee` / `ix_edge_caller` for the edges, the `identity` primary key
   and `ix_identity_logical` for the bindings, and `ix_func_bin_addr` for the
   fallback names. Node metadata is fetched in five batched statements no
   matter how many nodes are drawn, so cost is a function of the fan-out caps
   below and nothing else.

Node fill answers one narrow question: where the displayed name came from.
Binding reach and confidence are printed separately, and an arrow means only
that ``calledge`` records a call. None of those facts is labelled "proven".

Mounting (Implementer A owns routing):

    TITLE                       section heading
    render()                    picker + explainer, cheap, safe on the landing page
    render_fragment(params)     the graph itself; params come from the query string
                                (binary_id | slug, addr | addr_hex, depth, logical_id)

Links generated here point at ``GRAPH_ROUTE`` with a query string. Point that
route at ``render_fragment(parsed_query)`` and every link on the graph works
with JavaScript disabled.
"""

from __future__ import annotations

from contextlib import contextmanager
from urllib.parse import urlencode

from agentdecompile_recovery.corpus.dashboard.panels.common import esc, fnum, missing, query_db

try:
    from agentdecompile_recovery.corpus.dashboard.app.models import BinaryRef, ConcreteFunctionRef
    from agentdecompile_recovery.corpus.dashboard.app.routes import function_url as _canonical_function_url
    from agentdecompile_recovery.corpus.dashboard.app.routes import graph_url as _canonical_graph_url
except ImportError:  # compatibility with the standalone panel checkout
    BinaryRef = ConcreteFunctionRef = _canonical_function_url = _canonical_graph_url = None

# kx/ lives beside scripts/; the dashboard may be launched from anywhere.
try:
    # The placeholder test belongs to the precedence resolver. A local copy of
    # this regex is exactly how FUN_* names creep back onto the page after
    # someone "simplifies" it, so import the real one.
    from agentdecompile_recovery.corpus.naming import is_placeholder_name as _is_placeholder

    _RESOLVER_ERR = ""
except Exception as exc:  # noqa: BLE001
    _RESOLVER_ERR = f"{type(exc).__name__}: {exc}"

    def _is_placeholder(name):  # conservative fallback; the legend says it is in use
        n = (name or "").strip()
        return not n or n.split("_")[0] in ("FUN", "SUB", "sub", "LAB", "loc", "Unwind",
                                            "switchD", "caseD", "DAT", "thunk")


TITLE = "Execution flow — caller/callee graph"

# Route Implementer A mounts render_fragment on. Every link below is built from
# it, so re-pointing the graph is a one-line change.
GRAPH_ROUTE = "/graph"

# --- fan-out caps ---------------------------------------------------------
# A vtable dispatcher in this corpus has thousands of callers. Drawing them is
# neither possible nor useful; drawing 12 and admitting to the rest is both.
#
# The candidate limits are a latency budget, not a taste decision. `calledge`
# is stored roughly in caller order, so the callers of one address land on as
# many distinct pages as there are callers — each one a seek on this HDD.
# Fetching 201 candidates was measured at 1.3 s for a single cold query. Every
# limit below is therefore a bound on seeks, and the exact call-site total is
# recovered separately from an index-only COUNT, which costs nothing.
MAX_PER_LEVEL = 12       # nodes drawn on any one row
L2_PARENTS = 4           # depth-1 nodes whose own neighbours get expanded
L2_PER_PARENT = 3        # neighbours taken from each of those
CANDIDATE_LIMIT = 65     # rows read per depth-1 neighbour query
L2_CANDIDATE_LIMIT = 13  # …and per depth-2 one, which only needs three of them
# `func` is 600k rows of 40 columns; a point lookup is 0.4 ms warm and a real
# seek cold. It is consulted only for unbound nodes (a bound node already has a
# better name from the resolver) and only this many of them, nearest the focus
# first. The cap matters: in K1 GOG, 301 of 400 unbound functions do carry a
# real name there, so skipping the table entirely would throw away good names.
FUNC_NAME_CAP = 12

# --- geometry (plain arithmetic; no layout engine, no library) -------------
NODE_W, NODE_H = 158, 58
H_GAP, V_GAP = 16, 74
PAD, GUTTER = 18, 132
DENSITY = {
    "compact": (128, 48, 10, 56, 14, 100),
    "comfortable": (158, 58, 16, 74, 18, 132),
    "roomy": (196, 70, 22, 92, 22, 156),
}
DIRECTIONS = ("both", "callers", "callees")
LABEL_MODES = ("both", "name", "address")
EDGE_STYLES = ("curved", "straight")
INK_MODES = ("default", "contrast")

# --- name-provenance palette ----------------------------------------------
# text, border, fill, glyph. These are deliberately not verification states:
# a canonical name, an identity binding and a recorded call are separate facts.
NAME_STYLE = {
    "canonical-name": ("#5ee79b", "#46916a", "#0f2a1c", "●"),
    "build-local-name": ("#fbbf24", "#9a8340", "#2b2411", "◐"),
    "address-only": ("#9aa7bb", "#6a7688", "#1a212e", "○"),
}
FG_MAX, FG_ANNOT, FG_DIM = "#f2f6fb", "#8b98ab", "#7d8aa0"
LINE, LINE_STRONG, LINK = "#1e242e", "#2a3342", "#6cc6ff"

LEVEL_LABEL = {
    -2: ("callers of callers", "two hops up the call chain"),
    -1: ("callers", "call into this function"),
    0: ("this function", "the focus"),
    1: ("callees", "called by this function"),
    2: ("callees of callees", "two hops down"),
}


# ---------------------------------------------------------------------------
# parameter handling
# ---------------------------------------------------------------------------

def _one(params, key, default=None):
    """Accept both `parse_qs` lists and plain dicts, so either mount works."""
    val = (params or {}).get(key, default)
    if isinstance(val, (list, tuple)):
        val = val[0] if val else default
    return val


def _num(value):
    """Decimal, or hex when prefixed or when the digits demand it. None on junk."""
    if value is None:
        return None
    text = str(value).strip().lower().replace("_", "")
    if not text:
        return None
    try:
        if text.startswith("0x"):
            return int(text[2:], 16)
        if text.isdigit():
            return int(text, 10)
        return int(text, 16)
    except ValueError:
        return None


def _hex(addr, bits):
    width = 16 if (bits or 32) > 32 else 8
    try:
        return f"{int(addr):0{width}x}"
    except (TypeError, ValueError):
        return "?"


def _hex_short(addr, bits):
    """In-node form. A 64-bit build pads to 16 digits, and 16 digits plus the
    state glyph runs straight into the reach badge, so the node drops leading
    zeros. The padded form stays in the tooltip and in every link."""
    text = _hex(addr, bits).lstrip("0")
    return text.rjust(6, "0") if text else "0"


def _fit(text, nchars):
    text = "" if text is None else str(text)
    return text if len(text) <= nchars else text[: nchars - 1] + "…"


def _page_title(focus_label=None):
    suffix = f": {focus_label}" if focus_label else ""
    return f'<h1 class="h-sec">Call graph{esc(suffix)}</h1>'


def _wrap(text, width, max_lines):
    """SVG has no text flow, so wrap by hand. The full string stays in a
    <title>, and the same sentence is repeated as HTML below the graph, so a
    clipped gutter can never be the only place an elision was reported."""
    words, lines, cur = str(text).split(), [], ""
    for word in words:
        if cur and len(cur) + 1 + len(word) > width:
            lines.append(cur)
            cur = word
            if len(lines) == max_lines:
                break
        else:
            cur = f"{cur} {word}".strip()
    if cur and len(lines) < max_lines:
        lines.append(cur)
    if len(lines) == max_lines and sum(len(x) for x in lines) + len(lines) < len(text):
        lines[-1] = _fit(lines[-1] + " …", width)
    return [_fit(ln, width) for ln in lines]


def _graph_href(slug, addr, depth, bits=32, **display):
    # The function page and the graph are the same workspace. Node clicks stay
    # on that page. Addresses always carry their base.
    params = {"depth": int(depth)}
    if display.get("direction") not in (None, "", "both"):
        params["direction"] = display["direction"]
    if display.get("density") not in (None, "", "comfortable"):
        params["density"] = display["density"]
    if display.get("labels") not in (None, "", "both"):
        params["labels"] = display["labels"]
    if display.get("edges") not in (None, "", "curved"):
        params["edges"] = display["edges"]
    if display.get("ink") not in (None, "", "default"):
        params["ink"] = display["ink"]
    query = urlencode(params)
    if _canonical_function_url is not None:
        try:
            path = _canonical_function_url(str(slug), int(addr), bits=int(bits or 32))
            return f"{path}?{query}"
        except Exception:
            pass
    if _canonical_graph_url is not None:
        focus = ConcreteFunctionRef(BinaryRef(slug=str(slug)), int(addr))
        return _canonical_graph_url(focus, depth=int(depth))
    fallback = urlencode({"slug": str(slug), "addr": f"0x{int(addr):x}", **params})
    return f"{GRAPH_ROUTE}?{fallback}"


@contextmanager
def _density(name):
    """Temporarily resize nodes. Restored even if rendering fails."""
    global NODE_W, NODE_H, H_GAP, V_GAP, PAD, GUTTER
    prior = (NODE_W, NODE_H, H_GAP, V_GAP, PAD, GUTTER)
    NODE_W, NODE_H, H_GAP, V_GAP, PAD, GUTTER = DENSITY.get(name) or DENSITY["comfortable"]
    try:
        yield
    finally:
        NODE_W, NODE_H, H_GAP, V_GAP, PAD, GUTTER = prior


# ---------------------------------------------------------------------------
# data access — every statement below resolves through an index
# ---------------------------------------------------------------------------

def _binaries():
    """id -> (slug, game, platform, arch, bits). 24 rows, no index needed."""
    rows, err = query_db(
        "SELECT id, slug, game, platform, arch, bits FROM binary ORDER BY id"
    )
    if err:
        return {}, err
    return {r[0]: (r[1], r[2], r[3], r[4], r[5]) for r in rows}, None


def _neighbours(binary_id, addr, direction, limit=CANDIDATE_LIMIT):
    """Distinct callers or callees of one address.

    `INDEXED BY` is not decoration here. `calledge` has no ANALYZE statistics,
    and left to guess, SQLite answers the callers query with `ix_edge_caller`
    (matching on `binary_id` alone) and then filters ~50,000 rows per binary —
    measured at 36 seconds for one hub function. Naming the index turns the
    same query into a sub-millisecond range scan. Do not remove these hints
    until `ANALYZE` is part of the build and has been re-measured.

    `DISTINCT` is likewise absent on purpose: it makes the planner prefer the
    index that yields sorted output over the index that answers the WHERE.
    Deduplication happens in Python, over at most `limit` rows.

    Returns (addrs_sorted, distinct_seen, capped, call_sites). When the fetch
    hits `limit` the distinct count is only a lower bound, so the exact call
    site count is fetched too — that one is index-only and stays cheap even for
    the 8,418-caller hub in the K1 GOG build.
    """
    if direction == "callers":
        col, key, idx = "caller_addr", "callee_addr", "ix_edge_callee"
    else:
        col, key, idx = "callee_addr", "caller_addr", "ix_edge_caller"

    rows, err = query_db(
        f"SELECT {col} FROM calledge INDEXED BY {idx} WHERE binary_id=? AND {key}=? LIMIT ?",
        (binary_id, addr, limit),
    )
    if err:
        return [], 0, False, 0
    uniq = {r[0] for r in rows}
    capped = len(rows) >= limit
    sites = len(rows)
    if capped:
        counted, c_err = query_db(
            f"SELECT COUNT(*) FROM calledge INDEXED BY {idx} WHERE binary_id=? AND {key}=?",
            (binary_id, addr),
        )
        if not c_err and counted:
            sites = counted[0][0] or sites
    return sorted(uniq), len(uniq), capped, sites


def _resolve(binary_id, addrs, bits, focus_addr):
    """Batch every node's identity, reach and resolved name. Five statements.

    Cost is near-independent of node count because each statement is one `IN`
    list against an index — with one exception, `func`, whose rows are 40
    columns wide and cost a real seek each on a cold cache (2.5 s for six rows,
    measured). So `func` is consulted only where it is the *only* source of a
    name: a node with no identity binding, which the precedence resolver has
    therefore never seen. Bound nodes already have a better name than
    `func.name` by construction.
    """
    out = {a: {"addr": a, "logical_id": None, "conf": None, "method": None,
               "reach": 0, "name": None, "tier": None, "tier_name": None,
               "canon_class": None, "source_file": None, "local_name": None,
               "unchecked": False}
           for a in addrs}
    if not addrs:
        return out, 0

    marks = ",".join("?" * len(addrs))

    # 1. binding: identity PK is (binary_id, addr, logical_id) — prefix hit.
    ident, err = query_db(
        f"SELECT addr, logical_id, confidence, method FROM identity "
        f"WHERE binary_id=? AND addr IN ({marks})",
        (binary_id, *addrs),
    )
    if not err:
        for a, lid, conf, method in ident:
            node = out.get(a)
            # A (binary, addr) can carry more than one binding; keep the
            # strongest, because the weakest must not decide how a node looks.
            if node and (node["logical_id"] is None or (conf or 0) > (node["conf"] or 0)):
                node.update(logical_id=lid, conf=conf, method=method)

    lids = sorted({n["logical_id"] for n in out.values() if n["logical_id"] is not None})
    if lids:
        lmarks = ",".join("?" * len(lids))

        # 2. reach — the whole point of the overlay: how many of the 24 builds
        #    this node's logical function is bound into. ix_identity_logical.
        reach, err = query_db(
            f"SELECT logical_id, COUNT(DISTINCT binary_id) FROM identity "
            f"WHERE logical_id IN ({lmarks}) GROUP BY logical_id",
            tuple(lids),
        )
        reach_by_lid = {} if err else {r[0]: r[1] for r in reach}

        # 3. name — from the precedence resolver, never raw. PK lookup.
        names, err = query_db(
            f"SELECT logical_id, name, tier, tier_name FROM logical_name "
            f"WHERE logical_id IN ({lmarks})",
            tuple(lids),
        )
        name_by_lid = {} if err else {r[0]: (r[1], r[2], r[3]) for r in names}

        # 4. qualifier — `Shutdown` alone identifies nothing; the class does.
        quals, err = query_db(
            f"SELECT id, canon_class, source_file FROM logical_function "
            f"WHERE id IN ({lmarks})",
            tuple(lids),
        )
        qual_by_lid = {} if err else {r[0]: (r[1], r[2]) for r in quals}

        for node in out.values():
            lid = node["logical_id"]
            if lid is None:
                continue
            node["reach"] = reach_by_lid.get(lid, 0)
            nm, tier, tier_name = name_by_lid.get(lid, (None, None, None))
            node.update(name=nm, tier=tier, tier_name=tier_name)
            cls, src = qual_by_lid.get(lid, (None, None))
            node.update(canon_class=cls, source_file=src)

    # 5. this build's own name — the only naming evidence an unbound node has.
    #    The focus goes first because its identity decides whether the page can
    #    be drawn at all. ix_func_bin_addr.
    # `addrs` arrives in level order (focus, callers, callees, then depth 2), so
    # the budget is spent nearest the focus, where the user is actually looking.
    unbound = [a for a in addrs if out[a]["logical_id"] is None]
    unbound.sort(key=lambda a: a != focus_addr)
    looked_up, skipped = unbound[:FUNC_NAME_CAP], unbound[FUNC_NAME_CAP:]
    for a in skipped:
        out[a]["unchecked"] = True
    if looked_up:
        fmarks = ",".join("?" * len(looked_up))
        local, err = query_db(
            f"SELECT addr, name FROM func WHERE binary_id=? AND addr IN ({fmarks})",
            (binary_id, *looked_up),
        )
        if not err:
            for a, nm in local:
                if a in out:
                    out[a]["local_name"] = nm

    for node in out.values():
        _label(node, bits)
    return out, len(skipped)


def _label(node, bits):
    """Keep name provenance and identity evidence as independent facts."""
    resolved = node.get("name")
    if node["logical_id"] is not None and resolved and not _is_placeholder(resolved):
        cls = node.get("canon_class")
        node["label"] = f"{cls}::{resolved}" if cls and "::" not in resolved else resolved
        node["label_tier"] = node.get("tier_name") or "resolved"
        node["from_resolver"] = True
    elif node["logical_id"] is not None and resolved:
        # The resolver ran and every fork offered a placeholder. Say that,
        # rather than dressing FUN_* up as a name.
        node["label"] = resolved
        node["label_tier"] = "placeholder"
        node["from_resolver"] = True
    elif node.get("unchecked"):
        # Saying "placeholder" here would assert something never checked.
        node["label"] = f"FUN_{_hex(node['addr'], bits)}"
        node["label_tier"] = "unread"
        node["from_resolver"] = False
    else:
        raw = node.get("local_name")
        node["from_resolver"] = False
        if raw and not _is_placeholder(raw):
            node["label"] = raw
            node["label_tier"] = "build-local"
        else:
            node["label"] = raw or f"FUN_{_hex(node['addr'], bits)}"
            node["label_tier"] = "placeholder"

    if node["from_resolver"] and node["label_tier"] != "placeholder":
        node["name_state"] = "canonical-name"
        node["name_why"] = f"canonical {node['label_tier']}-tier name"
    elif node["label_tier"] == "build-local":
        node["name_state"] = "build-local-name"
        node["name_why"] = "name found only in this build"
    else:
        node["name_state"] = "address-only"
        node["name_why"] = ("name was not read within the render budget"
                            if node.get("unchecked") else "placeholder or address label")

    conf = node.get("conf")
    confidence = "unscored" if conf is None else f"confidence {float(conf):.2f}"
    if node["logical_id"] is None:
        node["binding_label"] = "no identity binding"
        node["binding_why"] = "this address is not attached to a logical function"
    elif node["reach"] < 2:
        node["binding_label"] = f"one-build identity · {confidence}"
        node["binding_why"] = ("the logical function reaches one build; recorded method "
                               f"{node.get('method') or '?'}")
    else:
        node["binding_label"] = f"cross-build identity ×{node['reach']} · {confidence}"
        node["binding_why"] = f"recorded method {node.get('method') or '?'}"


# ---------------------------------------------------------------------------
# graph construction
# ---------------------------------------------------------------------------

def _collect(binary_id, addr, depth, direction="both"):
    """Walk the edges outward and return (levels, edges, notes).

    `levels` maps level -> list of addresses, deduplicated globally so a
    mutually recursive pair is drawn once instead of twice. `notes` carries the
    honesty line for each level.
    """
    levels = {0: [addr]}
    edges = []          # (parent_addr, child_addr) — always in call direction
    notes = {}
    seen = {addr}
    self_call = False

    sides = []
    if direction in ("both", "callers"):
        sides.append(("callers", -1, "callers"))
    if direction in ("both", "callees"):
        sides.append(("callees", 1, "callees"))
    for side, level, other in sides:
        cand, total, capped, sites = _neighbours(binary_id, addr, side, CANDIDATE_LIMIT)
        if addr in cand:
            self_call = True
            cand = [a for a in cand if a != addr]
        fresh = [a for a in cand if a not in seen]
        drawn = fresh[:MAX_PER_LEVEL]
        seen.update(drawn)
        levels[level] = drawn
        notes[level] = _note(len(drawn), total, capped, len(cand) - len(fresh), other,
                             sites=sites)
        for a in drawn:
            edges.append((a, addr) if level == -1 else (addr, a))

    if depth >= 2:
        hop = []
        if direction in ("both", "callers"):
            hop.append(("callers", -2))
        if direction in ("both", "callees"):
            hop.append(("callees", 2))
        for side, level in hop:
            parents = levels.get(-1 if level == -2 else 1, [])[:L2_PARENTS]
            drawn, total, capped, dupes = [], 0, False, 0
            for parent in parents:
                cand, sub_total, sub_capped, _sites = _neighbours(
                    binary_id, parent, side, L2_CANDIDATE_LIMIT)
                total += sub_total
                capped = capped or sub_capped
                taken = 0
                for a in cand:
                    if a in seen:
                        dupes += 1
                        continue
                    if taken >= L2_PER_PARENT or len(drawn) >= MAX_PER_LEVEL:
                        break
                    drawn.append(a)
                    seen.add(a)
                    taken += 1
                    edges.append((a, parent) if level == -2 else (parent, a))
            levels[level] = drawn
            label = "callers of the callers" if level == -2 else "callees of the callees"
            notes[level] = _note(len(drawn), total, capped, dupes, label,
                                 parents=len(parents),
                                 of=len(levels.get(-1 if level == -2 else 1, [])))
    return levels, edges, notes, self_call


def _note(drawn, total, capped, dupes, what, parents=None, of=None, sites=None):
    """One honest sentence per level. Elision is stated, never implied.

    A graph that quietly drops nodes is worse than no graph: it still looks
    complete. So every row says what it left out, and when the scan itself was
    capped it says the count is a floor rather than pretending to a total.
    """
    if total == 0:
        return f"no {what}"
    if capped:
        text = (f"{fnum(drawn)} drawn; at least {fnum(total)} distinct {what}"
                + (f" across {fnum(sites)} call sites" if sites else "")
                + " — lowest addresses first")
    elif drawn >= total and not dupes:
        text = f"all {fnum(total)} {what}"
    else:
        text = f"{fnum(drawn)} of {fnum(total)} {what} — lowest addresses first"
    if dupes:
        text += f"; {fnum(dupes)} already drawn elsewhere (mutual recursion)"
    if parents is not None and of is not None and parents < of:
        text += f"; expanded from {fnum(parents)} of {fnum(of)} nodes above"
    return text


def _layout(levels, depth):
    """Place every node with arithmetic. Rows are centred; the widest row sets
    the canvas, and the wrapper scrolls rather than the page."""
    order = [-2, -1, 0, 1, 2] if depth >= 2 else [-1, 0, 1]
    order = [lv for lv in order if levels.get(lv) or lv == 0]
    widest = max(
        (len(levels.get(lv, [])) * NODE_W + max(0, len(levels.get(lv, [])) - 1) * H_GAP)
        for lv in order
    )
    band = max(widest, 420)
    width = GUTTER + band + PAD
    # V_GAP is row-top to row-top, so the last row still needs its own height.
    height = PAD * 2 + (len(order) - 1) * V_GAP + NODE_H

    pos = {}
    rows = []
    for i, lv in enumerate(order):
        addrs = levels.get(lv, [])
        y = PAD + i * V_GAP
        row_w = len(addrs) * NODE_W + max(0, len(addrs) - 1) * H_GAP
        x0 = GUTTER + max(0, (band - row_w) // 2)
        for j, a in enumerate(addrs):
            pos[a] = (x0 + j * (NODE_W + H_GAP), y, lv)
        rows.append((lv, y, addrs))
    return pos, rows, width, height


# ---------------------------------------------------------------------------
# SVG
# ---------------------------------------------------------------------------

def _node_svg(node, x, y, level, focus, bits, depth, slug, labels="both", display=None):
    text, border, fill, glyph = NAME_STYLE[node["name_state"]]
    stroke_w = 2 if focus else 1
    tier = node["label_tier"]
    # A placeholder must never look like a resolved name: dim, and the tier tag
    # says so in words as well.
    name_fill = FG_DIM if tier == "placeholder" else FG_MAX
    reach = node["reach"]
    badge = f"×{reach}" if reach else "—"
    tip = (f'{node["label"]}  ({tier})\n'
           f'addr {_hex(node["addr"], bits)}\n'
           f'{node["name_why"]}\n{node["binding_label"]}\n{node["binding_why"]}')
    if node["logical_id"] is not None:
        tip += (f'\nlogical #{node["logical_id"]}'
                f' · confidence {node["conf"] if node["conf"] is not None else "?"}'
                f' · {node["method"] or "?"}')
    if node.get("source_file"):
        tip += f'\n{node["source_file"]}'
    if node.get("local_name") and node["local_name"] != node["label"]:
        tip += f'\nthis build calls it {node["local_name"]}'

    href = _graph_href(slug, node["addr"], depth, bits, **(display or {}))
    role = LEVEL_LABEL.get(level, ("graph node", ""))[0]
    accessible = (f'{node["label"]}, address 0x{_hex(node["addr"], bits)}, {role}; '
                  f'{node["name_why"]}; {node["binding_label"]}; '
                  'open this function')
    title_y = y + 19
    addr_y = y + 35
    if labels == "address":
        title_y = y + 27
    primary = (
        esc(_hex_short(node["addr"], bits)) if labels == "address"
        else esc(_fit(node["label"], 21))
    )
    addr_line = ""
    if labels != "name" and labels != "address":
        addr_line = (
            f'<text x="{x + 9}" y="{addr_y}" font-size="10.5" fill="{text}" '
            f'font-family="ui-monospace,Menlo,Consolas,monospace">'
            f'{glyph} {esc(_hex_short(node["addr"], bits))}</text>'
        )
    elif labels == "name":
        addr_line = (
            f'<text x="{x + 9}" y="{addr_y}" font-size="10.5" fill="{text}" '
            f'font-family="ui-monospace,Menlo,Consolas,monospace">{glyph}</text>'
        )
    return (
        f'<a href="{esc(href)}" aria-label="{esc(accessible)}"><g>'
        f'<title>{esc(tip)}</title>'
        f'<rect x="{x}" y="{y}" width="{NODE_W}" height="{NODE_H}" rx="7" '
        f'fill="{fill}" stroke="{border}" stroke-width="{stroke_w}"/>'
        f'<text x="{x + 9}" y="{title_y}" font-size="11.5" font-weight="600" '
        f'fill="{name_fill}">{primary}</text>'
        f'{addr_line}'
        f'<text x="{x + 9}" y="{y + 49}" font-size="9" letter-spacing="0.08em" '
        f'fill="{FG_ANNOT}">{esc(tier.upper())}</text>'
        f'<rect x="{x + NODE_W - 46}" y="{y + NODE_H - 30}" width="37" height="17" rx="8" '
        f'fill="none" stroke="{border}"/>'
        f'<text x="{x + NODE_W - 27}" y="{y + NODE_H - 17}" font-size="10" '
        f'text-anchor="middle" fill="{text}" '
        f'font-family="ui-monospace,Menlo,Consolas,monospace">{esc(badge)}</text>'
        f'</g></a>'
    )


def _edge_svg(x1, y1, x2, y2, uid, strong, style="curved"):
    colour = LINE_STRONG if strong else LINE
    width = 2 if strong else 1.2
    if style == "straight":
        path = f"M{x1:.0f},{y1:.0f} L{x2:.0f},{y2:.0f}"
    else:
        dy = max(18, (y2 - y1) / 2)
        path = (
            f"M{x1:.0f},{y1:.0f} C{x1:.0f},{y1 + dy:.0f} "
            f"{x2:.0f},{y2 - dy:.0f} {x2:.0f},{y2:.0f}"
        )
    return (
        f'<path d="{path}" fill="none" stroke="{colour}" '
        f'stroke-width="{width}" marker-end="url(#kg-a-{uid})"/>'
    )


def _svg(levels, edges, notes, nodes, focus_addr, slug, bits, depth, uid, labels="both", display=None):
    pos, rows, width, height = _layout(levels, depth)

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'role="img" aria-labelledby="kg-title-{uid} kg-desc-{uid}" focusable="false" '
        f'preserveAspectRatio="xMidYMid meet" '
        f'style="display:block;width:100%;height:auto;min-width:{min(width, 620)}px">'
        f'<title id="kg-title-{uid}">Caller and callee graph centred on '
        f'{esc(nodes[focus_addr]["label"])}</title>'
        f'<desc id="kg-desc-{uid}">Callers are above the selected function and callees '
        f'are below it. Arrows point in call direction. A structured list follows the '
        f'graphic.</desc>',
        f'<defs><marker id="kg-a-{uid}" viewBox="0 0 8 8" refX="7.5" refY="4" '
        f'markerWidth="6" markerHeight="6" orient="auto">'
        f'<path d="M0,0 L8,4 L0,8 z" fill="{LINE_STRONG}"/></marker></defs>',
    ]

    for parent, child in edges:
        if parent not in pos or child not in pos:
            continue
        px, py, _ = pos[parent]
        cx, cy, _ = pos[child]
        parts.append(_edge_svg(
            px + NODE_W / 2, py + NODE_H, cx + NODE_W / 2, cy,
            uid, focus_addr in (parent, child),
            (display or {}).get("edges") or "curved",
        ))

    for lv, y, addrs in rows:
        label, _ = LEVEL_LABEL[lv]
        parts.append(
            f'<text x="{PAD}" y="{y + 18}" font-size="10" font-weight="600" '
            f'letter-spacing="0.1em" fill="#9aa7bb">{esc(label.upper())}</text>'
        )
        note = notes.get(lv, "")
        if note:
            for k, line in enumerate(_wrap(note, 23, 4)):
                parts.append(
                    f'<text x="{PAD}" y="{y + 33 + k * 11}" font-size="9.5" '
                    f'fill="{FG_ANNOT}">{esc(line)}<title>{esc(note)}</title></text>'
                )
        for a in addrs:
            x, ny, _ = pos[a]
            parts.append(_node_svg(
                nodes[a], x, ny, lv, a == focus_addr, bits, depth, slug, labels, display
            ))

    parts.append("</svg>")
    return "".join(parts)


def _list_fallback(levels, nodes, slug, bits, depth, display=None):
    """A compact semantic equivalent for readers that cannot use the SVG."""
    groups = []
    for level in sorted(levels):
        entries = []
        for addr in levels[level]:
            node = nodes.get(addr)
            if not node:
                continue
            role = LEVEL_LABEL.get(level, (f"level {level}", ""))[0]
            accessible = (f'{node["label"]}, address 0x{_hex(addr, bits)}, {role}; '
                          'open graph')
            entries.append(
                f'<li><a href="{esc(_graph_href(slug, addr, depth, bits, **(display or {})))}" '
                f'aria-label="{esc(accessible)}">'
                f'{esc(node["label"])}</a> &middot; '
                f'<code>0x{esc(_hex(addr, bits))}</code> &middot; '
                f'{esc(node["name_why"])} &middot; {esc(node["binding_label"])}</li>'
            )
        if entries:
            label = LEVEL_LABEL.get(level, (f"level {level}", ""))[0]
            groups.append(f'<section><h3>{esc(label)}</h3><ul>{"".join(entries)}</ul></section>')
    return (
        '<details class="graph-list"><summary>Read this graph as a list</summary>'
        f'{"".join(groups) or missing("no graph nodes to list")}</details>'
    )


# ---------------------------------------------------------------------------
# surrounding HTML
# ---------------------------------------------------------------------------

def _legend(nodes, notes, self_call, unread=0):
    counts = {key: 0 for key in NAME_STYLE}
    for node in nodes.values():
        counts[node["name_state"]] += 1
    keys = []
    for state, blurb in (
        ("canonical-name", "name selected by the cross-build precedence resolver"),
        ("build-local-name", "name read only from this build"),
        ("address-only", "placeholder, unread name, or address fallback"),
    ):
        text, border, fill, glyph = NAME_STYLE[state]
        keys.append(
            f'<span style="display:inline-flex;align-items:center;gap:6px;'
            f'border:1px solid {border};background:{fill};color:{text};'
            f'border-radius:999px;padding:2px 9px;font-size:12px;white-space:nowrap">'
            f'{glyph} {state.replace("-", " ")} &middot; {counts[state]}</span>'
            f'<span style="color:{FG_ANNOT};font-size:12px">{esc(blurb)}</span>'
        )
    grid = "".join(f"<div>{k}</div>" for k in keys)

    # The gutter clips; this does not. What the graph left out is stated in full
    # at least once, in text, on every render.
    elided = "".join(
        f'<li><b style="color:{FG_ANNOT}">{esc(LEVEL_LABEL[lv][0])}</b> &mdash; {esc(note)}</li>'
        for lv, note in sorted(notes.items())
        if lv != 0 and note
    )

    out = [
        f'<div class="graph-legend" style="display:grid;grid-template-columns:1fr;gap:6px;margin-top:12px">{grid}</div>',
        f'<p class="note" style="color:{FG_ANNOT};font-size:12px;margin:10px 0 2px">'
        f'<b>What this drawing leaves out</b> — fan-out is capped at {MAX_PER_LEVEL} nodes per '
        f'row so the picture stays readable, and a capped row is not a complete row:</p>'
        f'<ul style="margin:0;padding-left:18px;color:{FG_ANNOT};font-size:12px">{elided}</ul>',
        f'<p class="note" style="color:{FG_ANNOT};font-size:12px;margin:10px 0 0">'
        f'The badge on each node (<code>&times;N</code>) is its <b>cross-build reach</b>: how '
        f'many available builds contain the same logical function. <code>&mdash;</code> means '
        f'the address is bound to none, so nothing learned here transfers anywhere. '
        f'The small caps line is the <b>name tier</b> that won in '
        f'<code>kx/name_precedence.py</code>; <code>PLACEHOLDER</code> and '
        f'<code>BUILD-LOCAL</code> are dimmed because neither is a resolved cross-fork name. '
        f'Click any node to re-centre the graph on it.</p>',
        f'<p class="note" style="color:{FG_ANNOT};font-size:12px;margin:6px 0 0">'
        f'Identity is a separate fact. Each node tooltip and list row states its '
        f'cross-build reach, recorded confidence, and matching method. None of those '
        f'values changes the node fill.</p>',
        f'<p class="note" style="color:{FG_ANNOT};font-size:12px;margin:6px 0 0">'
        f'Edges point in the direction of the call. Rows are read top to bottom: '
        f'callers call the focus, the focus calls its callees. '
        f'An arrow means <code>calledge</code> records that call relation; its colour '
        f'and thickness only highlight the selected function. '
        f'Sources: <code>calledge</code> via <code>ix_edge_callee</code> / '
        f'<code>ix_edge_caller</code>, <code>identity</code> via its primary key and '
        f'<code>ix_identity_logical</code>, <code>logical_name</code> by primary key.</p>',
    ]
    if unread:
        out.append(
            f'<p class="note" style="color:{FG_ANNOT};font-size:12px;margin:6px 0 0">'
            f'{fnum(unread)} unbound node(s) are labelled <code>UNREAD</code>: reading a name '
            f'out of the 500 MB <code>func</code> table costs a disk seek each, and this render '
            f'stopped at {FUNC_NAME_CAP}. Those boxes show their address, not a claim about '
            f'their name. Click one to make it the focus and its name will be read.</p>'
        )
    if self_call:
        out.append(
            '<p class="note" style="color:#fbbf24;font-size:12px;margin:6px 0 0">'
            'This function calls itself. The self-edge is stated here rather than drawn, '
            'because a loop back into the same box reads as a layout bug.</p>'
        )
    if _RESOLVER_ERR:
        out.append(
            f'<p class="note" style="color:#fbbf24;font-size:12px;margin:6px 0 0">'
            f'<b>Name tiers are approximate:</b> <code>kx/name_precedence.py</code> could not '
            f'be imported ({esc(_RESOLVER_ERR)}), so a fallback placeholder test is in use. '
            f'Fix the import before trusting a PLACEHOLDER label.</p>'
        )
    return "".join(out)


def _siblings(focus, binary_id, binaries, depth):
    """The same logical function in every other build, as links into its graph.

    This is the cross-match made navigable: one click moves from this build's
    control flow to the same function's control flow in another fork.
    """
    lid = focus.get("logical_id")
    if lid is None:
        return (
            f'<p class="note" style="color:{FG_ANNOT};font-size:12px;margin:8px 0 0">'
            f'<b style="color:{NAME_STYLE["address-only"][0]}">No cross-build identity.</b> '
            f'This address is '
            f'bound to no logical function, so there is no counterpart in any other build to '
            f'compare against, and nothing learned about it here propagates.</p>'
        )
    rows, err = query_db(
        "SELECT binary_id, addr, confidence FROM identity WHERE logical_id=? ORDER BY binary_id",
        (lid,),
    )
    if err:
        return missing(f"cross-build members unavailable: {err}")
    chips = []
    for bid, addr, conf in rows:
        slug, game, platform, _arch, bits = binaries.get(bid, (f"binary {bid}", "", "", "", 32))
        here = bid == binary_id
        colour = FG_MAX if here else LINK
        border = LINE_STRONG if here else LINE
        body = (f'{esc(game or "?")} {esc(platform or "?")} &middot; '
                f'<span style="font-family:ui-monospace,Menlo,Consolas,monospace">'
                f'{esc(_hex(addr, bits))}</span>')
        tip = f'{slug}  conf {conf if conf is not None else "?"}'
        inner = (f'<span title="{esc(tip)}" style="display:inline-block;border:1px solid {border};'
                 f'border-radius:6px;padding:2px 8px;font-size:12px;color:{colour}">'
                 f'{body}{" &larr; here" if here else ""}</span>')
        chips.append(inner if here
                     else f'<a href="{esc(_graph_href(slug, addr, depth))}" '
                          f'style="text-decoration:none">{inner}</a>')
    return (
        f'<p class="note" style="color:{FG_ANNOT};font-size:12px;margin:10px 0 4px">'
        f'Same logical function (<code>#{lid}</code>) in <b>{fnum(len(rows))}</b> available builds — '
        f'follow any chip to that build&rsquo;s flow for the same code:</p>'
        f'<div style="display:flex;flex-wrap:wrap;gap:6px">{"".join(chips)}</div>'
    )


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------

def _display_toolbar(slug, addr, bits, depth, direction, density, labels, edges, ink):
    def opts(field, title, choices, current):
        items = []
        for value, label in choices:
            sel = " selected" if value == current else ""
            items.append(f'<option value="{esc(value)}"{sel}>{esc(label)}</option>')
        return (
            f'<label>{esc(title)}'
            f'<select name="{esc(field)}">{"".join(items)}</select></label>'
        )
    action = _graph_href(slug, addr, depth, bits)
    action = action.split("?", 1)[0]
    return (
        f'<form class="graph-display" method="get" action="{esc(action)}" '
        'aria-label="Change the graph">'
        + opts("depth", "Hops", (("1", "1 hop"), ("2", "2 hops")), str(depth))
        + opts("direction", "Show", (("both", "Callers and callees"), ("callers", "Callers"),
                                     ("callees", "Callees")), direction)
        + opts("density", "Size", (("compact", "Compact"), ("comfortable", "Comfortable"),
                                   ("roomy", "Roomy")), density)
        + opts("labels", "Labels", (("both", "Name and address"), ("name", "Name"),
                                    ("address", "Address")), labels)
        + opts("edges", "Edges", (("curved", "Curved"), ("straight", "Straight")), edges)
        + opts("ink", "Ink", (("default", "Default"), ("contrast", "High contrast")), ink)
        + '<button type="submit">Update graph</button>'
        + '<div class="graph-zoom" hidden>'
        '<button type="button" data-zoom="out" aria-label="Zoom out">−</button>'
        '<button type="button" data-zoom="reset">Reset view</button>'
        '<button type="button" data-zoom="in" aria-label="Zoom in">+</button>'
        '<button type="button" data-zoom="fit">Fit</button>'
        '<button type="button" data-zoom="wide">Wide</button>'
        '<button type="button" data-zoom="legend">Legend</button>'
        "</div></form>"
    )


def render_graph(binary_id, addr, depth=2, *, direction="both", density="comfortable",
                 labels="both", edges="curved", ink="default", heading=True):
    """Inline SVG caller/callee graph centred on one function. Never raises."""
    try:
        binary_id, addr = int(binary_id), int(addr)
        depth = 2 if int(depth) >= 2 else 1
        direction = direction if direction in DIRECTIONS else "both"
        density = density if density in DENSITY else "comfortable"
        labels = labels if labels in LABEL_MODES else "both"
        edges = edges if edges in EDGE_STYLES else "curved"
        ink = ink if ink in INK_MODES else "default"
    except (TypeError, ValueError):
        return _page_title() + missing("graph needs a numeric binary_id and addr")

    try:
        binaries, err = _binaries()
        if err:
            return missing(f"binary table unavailable: {err}")
        if binary_id not in binaries:
            title = _page_title() if heading else ""
            return title + missing(f"no build with binary_id {binary_id}") + _search_form(binaries)
        slug, game, platform, arch, bits = binaries[binary_id]
        edge_style = edges
        display = {
            "direction": direction, "density": density, "labels": labels,
            "edges": edge_style, "ink": ink,
        }

        levels, graph_edges, notes, self_call = _collect(binary_id, addr, depth, direction)
        every = [a for group in levels.values() for a in group]
        nodes, unread = _resolve(binary_id, every, bits, addr)
        focus = nodes[addr]

        if focus["local_name"] is None and focus["logical_id"] is None:
            title = _page_title() if heading else ""
            return title + missing(
                f"no function at {_hex(addr, bits)} in {slug} — the address is not in `func` "
                f"and carries no identity binding"
            ) + _search_form(binaries, slug, f"0x{addr:x}")

        uid = f"{binary_id}-{addr}"
        title = _page_title(focus["label"]) if heading else ""
        head = (
            f'{title}'
            f'<div class="fn-kicker">'
            f'<b>{esc(focus["label"])}</b>'
            f'<span class="note">'
            f'{esc(slug)} · {esc(game or "?")}/{esc(platform or "?")}/{esc(arch or "?")} '
            f'· <code>{esc(_hex(addr, bits))}</code> · {esc(focus["label_tier"])}</span></div>'
            f'<p class="note">{esc(focus["name_why"])}; {esc(focus["binding_label"])}.</p>'
            + _display_toolbar(slug, addr, bits, depth, direction, density, labels, edge_style, ink)
        )
        with _density(density):
            svg = _svg(levels, graph_edges, notes, nodes, addr, slug, bits, depth, uid, labels, display)
        wrap = (
            f'<div class="graph-stage" data-graph-stage data-ink="{esc(ink)}">'
            f'{svg}</div>'
            f'{_list_fallback(levels, nodes, slug, bits, depth, display)}'
        )
        return head + _siblings(focus, binary_id, binaries, depth) + wrap + _legend(
            nodes, notes, self_call, unread)
    except Exception as exc:  # noqa: BLE001 — a panel degrades, it never raises
        title = _page_title() if heading else ""
        return title + missing(f"call graph failed: {type(exc).__name__}: {exc}")


def render_picker():
    """Entry points into the graph: logical functions with the widest reach and
    a real name, because those are the ones where the flow is worth following
    and the boxes carry names instead of addresses."""
    try:
        binaries, err = _binaries()
        if err:
            return missing(f"binary table unavailable: {err}")

        selector = _search_form(binaries)

        # 69k narrow rows, no text columns — a ~20 ms scan, and there is no
        # index on n_members to hit instead. `func` is never touched.
        cands, err = query_db(
            "SELECT logical_id, name, tier_name, n_members FROM logical_name "
            "WHERE tier <= 2 ORDER BY n_members DESC, logical_id LIMIT 14"
        )
        if err:
            return missing(f"logical_name unavailable: {err}")
        if not cands:
            return selector + missing(
                "no named logical functions yet — run kx/name_precedence.py --apply to fill "
                "logical_name, then this picker has somewhere to point"
            )

        lids = [c[0] for c in cands]
        marks = ",".join("?" * len(lids))
        members, err = query_db(
            f"SELECT logical_id, binary_id, addr, confidence FROM identity "
            f"WHERE logical_id IN ({marks})",
            tuple(lids),
        )
        if err:
            return missing(f"identity unavailable: {err}")
        quals, _ = query_db(
            f"SELECT id, canon_class FROM logical_function WHERE id IN ({marks})", tuple(lids)
        )
        cls_by_lid = {r[0]: r[1] for r in quals}

        by_lid = {}
        for lid, bid, addr, conf in members:
            by_lid.setdefault(lid, []).append((bid, addr, conf))

        rows = []
        for lid, name, tier_name, _n in cands:
            picks = by_lid.get(lid) or []
            if not picks:
                continue
            # Prefer the strongest binding, then a stable build id. Architecture
            # and platform are categories, not quality signals.
            def _rank(item):
                return (-(item[2] or 0), item[0])

            bid, addr, conf = sorted(picks, key=_rank)[0]
            slug, game, platform, _arch, bits = binaries.get(bid, (f"binary {bid}", "", "", "", 32))
            cls = cls_by_lid.get(lid)
            label = f"{cls}::{name}" if cls and "::" not in (name or "") else (name or "?")
            reach = len({p[0] for p in picks})
            rows.append(
                f'<tr><td><a href="{esc(_graph_href(slug, addr, 2))}">{esc(label)}</a></td>'
                f'<td style="color:{FG_ANNOT}">{esc(tier_name or "?")}</td>'
                f'<td class="num" style="color:{NAME_STYLE["canonical-name"][0]}">'
                f'&times;{reach}</td>'
                f'<td style="color:{FG_ANNOT}">{esc(game or "?")}/{esc(platform or "?")}</td>'
                f'<td style="font-family:ui-monospace,Menlo,Consolas,monospace;'
                f'color:{FG_ANNOT}" title="{esc(slug)}">{esc(_hex(addr, bits))}</td></tr>'
            )

        if not rows:
            return missing("named logical functions exist but none has an identity binding yet")

        return (selector
            +
            f'<div class="tablewrap"><table><thead><tr>'
            f'<th>start here</th><th>name tier</th><th class="num">builds</th>'
            f'<th>opens in</th><th>address</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table></div>'
            f'<p class="note" style="color:{FG_ANNOT};font-size:12px;margin:8px 0 0">'
            f'Ranked by reach among functions with high-confidence names. Each link opens '
            f'the strongest available binding, independent of architecture or platform.</p>'
        )
    except Exception as exc:  # noqa: BLE001
        return missing(f"picker failed: {type(exc).__name__}: {exc}")


def _function_options(slug, address=""):
    """Bounded <option> list for the function combobox."""
    from agentdecompile_recovery.corpus.dashboard.function_choices import list_function_choices

    payload = list_function_choices(slug, around=address or None)
    results = payload.get("results") or []
    current = (address or "").strip().lower()
    options = []
    seen = False
    for row in results:
        addr = str(row.get("addr") or "")
        name = str(row.get("name") or addr)
        chosen = addr.lower() == current or addr.lower().endswith(current.removeprefix("0x"))
        if chosen:
            seen = True
        sel = " selected" if chosen else ""
        options.append(
            f'<option value="{esc(addr)}"{sel}>{esc(name)} — {esc(addr)}</option>'
        )
    if current and not seen:
        options.insert(0, f'<option value="{esc(address)}" selected>{esc(address)}</option>')
    if not options:
        options.append('<option value="" disabled>No functions in this window</option>')
    return "".join(options)


def _search_form(binaries, selected=None, address="", compact=False, display=None):
    """Build selector plus a function combobox. The list is a page, not the build."""
    options = []
    first_slug = None
    for bid, (slug, game, platform, arch, bits) in sorted(
            binaries.items(), key=lambda item: (str(item[1][0]).lower(), item[0])):
        if first_slug is None:
            first_slug = slug
        chosen = ' selected' if selected is not None and str(selected) == str(slug) else ''
        context = "/".join(str(x or "?") for x in (game, platform, arch))
        options.append(
            f'<option value="{esc(slug)}"{chosen}>{esc(slug)} — {esc(context)}, '
            f'{esc(bits or "?")}-bit</option>'
        )
    if not options:
        return missing("no builds are available for graph lookup")
    slug = selected or first_slug
    fn_opts = _function_options(str(slug), address)
    keep = display or {}
    hidden = []
    for key in ("depth", "direction", "density", "labels", "edges", "ink"):
        val = keep.get(key)
        if val not in (None, ""):
            hidden.append(f'<input type="hidden" name="{esc(key)}" value="{esc(val)}">')
    if not any('name="depth"' in item for item in hidden):
        hidden.append('<input type="hidden" name="depth" value="2">')
    list_size = 6 if compact else 8
    form = (
        '<form action="/dashboard/function-open" method="get" class="graph-search" '
        'role="search" aria-label="Open a function" '
        'data-fn-combo="1">'
        '<label>Build'
        f'<select name="slug" id="graph-build" required>{"".join(options)}</select></label>'
        '<label>Function'
        '<input id="fn-combo-filter" type="search" autocomplete="off" '
        'placeholder="Type a name or address" aria-controls="fn-combo-list"></label>'
        '<label class="sr-only" for="fn-combo-list">Matching functions</label>'
        f'<select id="fn-combo-list" name="addr" required size="{list_size}">{fn_opts}</select>'
        + "".join(hidden)
        + '<button type="submit">Open function</button>'
        '<span class="note">The list is one page of matches. Type to load more. '
        'It does not dump the whole build.</span></form>'
    )
    if not compact:
        return form
    return (
        '<details class="fn-picker">'
        '<summary>Change function</summary>'
        f"{form}</details>"
    )


def render():
    """Landing-page view: the explainer and the picker. Deliberately no graph.

    Drawing a graph here would cost edge queries on every 5 s poll and would
    answer no question the landing page is asking. The graph is one click away
    by design, per docs/dashboard-design/00-CONTINUATION-PROMPT.md.
    """
    try:
        explain = (
            f'<p class="note">A function is not a row in a table. It has <b>callers</b> above it, '
            f'<b>callees</b> below it, and it can exist in multiple builds at once. This view '
            f'draws that flow for one function and marks, on every node, how many builds share '
            f'it — so a name or a recovered body earned in one fork visibly reaches the rest.</p>'
            f'<p class="note" style="color:{FG_ANNOT};font-size:12px">'
            f'The graph is not rendered here. It costs edge queries against a 500 MB database on '
            f'a spinning disk and answers none of the questions this page exists to answer, so it '
            f'is one deliberate click away. Fan-out is capped at {MAX_PER_LEVEL} nodes per row and '
            f'depth 2; every row prints how many nodes it drew out of how many exist.</p>'
        )
        return explain + render_picker()
    except Exception as exc:  # noqa: BLE001
        return missing(f"panel failed: {type(exc).__name__}: {exc}")


def render_fragment(params):
    """Render a graph from query-string parameters. Never raises.

    Accepted: `binary_id` (or `slug`), `addr` (decimal, or hex with `0x`) or
    `addr_hex`, `depth` (1 or 2), or `logical_id` on its own to land on that
    logical function's strongest binding.
    """
    try:
        params = params or {}
        depth = _num(_one(params, "depth", 2)) or 2
        direction = str(_one(params, "direction", "both") or "both")
        density = str(_one(params, "density", "comfortable") or "comfortable")
        labels = str(_one(params, "labels", "both") or "both")
        edges = str(_one(params, "edges", "curved") or "curved")
        ink = str(_one(params, "ink", "default") or "default")
        heading = str(_one(params, "heading", "1") or "1") not in ("0", "false", "no")

        raw_binary_id = _one(params, "binary_id")
        raw_addr = _one(params, "addr")
        binary_id = _num(raw_binary_id)
        slug = _one(params, "slug")
        if slug:
            rows, err = query_db("SELECT id FROM binary WHERE slug=?", (str(slug),))
            if not err and rows:
                binary_id = rows[0][0]
            elif not err:
                return (_page_title()
                        + missing(f"no build called {slug}") + render_picker())

        addr = _num(raw_addr)
        if addr is None:
            hexed = _one(params, "addr_hex")
            addr = _num(f"0x{hexed}") if hexed else None

        if raw_binary_id not in (None, "") and binary_id is None:
            return (_page_title()
                    + missing("build id is not a valid number") + render_picker())
        if raw_addr not in (None, "") and addr is None:
            return (_page_title()
                    + missing("address is not valid; use decimal or 0x-prefixed hexadecimal")
                    + render_picker())

        if binary_id is None or addr is None:
            lid = _num(_one(params, "logical_id"))
            if lid is not None:
                rows, err = query_db(
                    "SELECT binary_id, addr FROM identity WHERE logical_id=? "
                    "ORDER BY confidence DESC, binary_id LIMIT 1",
                    (lid,),
                )
                if not err and rows:
                    binary_id, addr = rows[0][0], rows[0][1]

        if binary_id is None or addr is None:
            return (_page_title() + missing(
                "no function selected — a graph needs slug and addr (or logical_id). "
                "Pick a starting point:") + render_picker())

        return render_graph(
            binary_id, addr, depth,
            direction=direction, density=density, labels=labels,
            edges=edges, ink=ink, heading=heading,
        )
    except Exception as exc:  # noqa: BLE001
        return _page_title() + missing(f"call graph failed: {type(exc).__name__}: {exc}")
