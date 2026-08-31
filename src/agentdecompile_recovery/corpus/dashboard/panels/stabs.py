"""Original source names: STABS records, shipped symbol tables, and how far a
recovered `.cpp` path travels.

The naming problem in this project is not "invent a plausible name". It is
"find the name the BioWare programmer typed". Two shipped artifacts still carry
that information, and neither is a Windows build:

* the Mac builds were linked with STABS debug records left in the binary, which
  name the original compilation unit (`N_SO`/`N_OSO`) and every function in it
  (`N_FUN`), plus file statics (`N_STSYM`) and globals (`N_GSYM`);
* the Android builds ship a full C++ symbol table, so class and method names
  survive even though no source path does.

Because all 24 binaries are forks of one codebase, a path recovered from the Mac
build attaches to the same function in the Windows build through the cross-build
identity layer. That transfer is the single biggest source of real names here,
so this panel reports the recovery *and* its reach, and it reports the fraction
of the corpus still carrying no original path at all — the honest denominator.

Every number is read on request from `extract/stabs/` and the corpus store.
"""

from __future__ import annotations

import re
import sys
import time
from pathlib import Path
from urllib.parse import quote

if __package__ in (None, ""):
    # Keeps the module importable from a bare checkout, the way the loader does.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agentdecompile_recovery.corpus.dashboard.panels.common import (  # noqa: E402
    DRM_EXCLUDED,
    ago,
    esc,
    fnum,
    fpct,
    load_json,
    missing,
    panel,
    query_db,
    rel,
    table,
    tag,
)
from agentdecompile_recovery.corpus.dashboard.panels.viz import bars, donut, heatmap  # noqa: E402

try:  # count_link is landing in common.py from another author.
    from agentdecompile_recovery.corpus.dashboard.panels.common import count_link
except ImportError:  # the panel still renders, with plain links
    count_link = None


def _details(inner: str, summary: str = "raw numbers") -> str:
    """Collapsed-by-default expansion of a chart (10-relationship-layout.md
    Rule C). Visible on click, not open by default."""
    return f'<details><summary>{esc(summary)}</summary>{inner}</details>'


def _bin_href(slug) -> str:
    return "/binary/" + quote(str(slug or ""), safe="")


def _fn_href(slug, extra: str = "") -> str:
    return "/functions?binary=" + quote(str(slug or ""), safe="") + extra


def _clink(n, href: str, unit: str | None = None, title: str | None = None) -> str:
    """A count is the control that opens the set it counts."""
    if count_link is not None:
        try:
            return count_link(n, href, unit=unit, title=title)
        except Exception:  # noqa: BLE001 - a helper must never cost the panel
            pass
    if n is None:
        return "-"
    tip = f' title="{esc(title)}"' if title else ""
    return f'<a href="{esc(href)}"{tip}>{fnum(n)}</a>'


def _file_link(path: Path, label: str | None = None) -> str:
    return (f'<a href="/artifact?p={esc(rel(path))}">'
            f'{esc(label or rel(path))}</a>')


def _slugs() -> dict[str, str]:
    """repo_path and file name -> slug, so any label here can reach its build."""
    rows, err = query_db("SELECT repo_path, slug FROM binary")
    if err:
        return {}
    out = {}
    for repo, slug in rows:
        out[str(repo)] = str(slug)
        out[str(repo).rsplit("/", 1)[-1]] = str(slug)
    return out

TITLE = "Original source names — STABS, symbols and provenance"

from agentdecompile_recovery.corpus.dashboard.common import as_root, DB_PATH
STABS_DIR = as_root() / "extract" / "stabs"
STABS_INDEX = STABS_DIR / "_index.json"
PROVENANCE_SUMMARY = as_root() / "output" / "names" / "function_provenance_by_binary.json"

# What each STABS record type is worth to this project, so the page explains
# itself without the reader opening kx/machostabs.py.
STAB_GLOSS = {
    "N_SO": "compilation-unit boundary (the original .cpp path)",
    "N_OSO": "the .o that unit was linked from",
    "N_FUN": "function name, address and byte length",
    "N_STSYM": "file-scope static",
    "N_GSYM": "global",
    "N_BNSYM": "function start marker",
    "N_ENSYM": "function end marker",
    "N_SOL": "included source file for a line range",
    "N_OPT": "compiler options stamp (all a stripped build keeps)",
}

# The record_counts object sits in the first few hundred bytes of each parsed
# dump. The two Mac dumps are ~12 MB of per-function detail; parsing either one
# on a request path would blow the render budget for a header-sized fact.
HEAD_BYTES = 96 << 10
RECORD_BLOCK = re.compile(r'"record_counts"\s*:\s*\{([^}]*)\}')
RECORD_PAIR = re.compile(r'"(\w+)"\s*:\s*(\d+)')

# Ghidra's placeholder names. A function whose name still matches one of these
# was never named by anyone, in any build.
PLACEHOLDER_SQL = (
    "name LIKE 'FUN\\_%' ESCAPE '\\' "
    "OR name LIKE 'thunk\\_FUN\\_%' ESCAPE '\\' "
    "OR name LIKE 'sub\\_%' ESCAPE '\\' "
    "OR name LIKE 'LAB\\_%' ESCAPE '\\'"
)

HAS_SRC = "source_file IS NOT NULL AND source_file <> ''"


def _stat(path: Path):
    try:
        st = path.stat()
        return st.st_size, st.st_mtime
    except OSError:
        return None, None


def _human_bytes(n) -> str:
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "-"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:,.0f} {unit}" if unit == "B" else f"{n:,.1f} {unit}"
        n /= 1024
    return f"{n:,.1f} GB"


def _record_counts(path: Path) -> dict[str, int]:
    """Merge every `record_counts` block in a dump's header window."""
    counts: dict[str, int] = {}
    try:
        with path.open("rb") as fh:
            head = fh.read(HEAD_BYTES).decode("utf-8", "replace")
    except OSError:
        return counts
    for block in RECORD_BLOCK.findall(head):
        for name, value in RECORD_PAIR.findall(block):
            try:
                counts[name] = counts.get(name, 0) + int(value)
            except ValueError:
                continue
    return counts


def _index_slices(data) -> list[tuple[str, str, dict]]:
    """(label, repo_path, slice) triples, tolerant of index shape drift."""
    if isinstance(data, dict):
        items = list(data.items())
    elif isinstance(data, list):
        items = [(str(d.get("slug") or d.get("binary") or i), d)
                 for i, d in enumerate(data) if isinstance(d, dict)]
    else:
        return []
    out: list[tuple[str, str, dict]] = []
    for key, entry in items:
        if not isinstance(entry, dict):
            continue
        repo = str(entry.get("repo_path") or entry.get("path") or "")
        slices = entry.get("slices")
        if not isinstance(slices, list) or not slices:
            slices = [entry]  # a flat, sliceless shape still carries the counts
        for sl in slices:
            if isinstance(sl, dict):
                out.append((str(key), repo, sl))
    return out


def _render_index() -> str:
    heading = "STABS mining index (extract/stabs/_index.json)"
    data, err = load_json(STABS_INDEX)
    if err or data is None:
        return panel(missing(err or f"{rel(STABS_INDEX)} is empty"), heading)

    slices = _index_slices(data)
    if not slices:
        return panel(missing(f"{rel(STABS_INDEX)} has no recognisable entries"),
                     heading)

    slugs = _slugs()
    rows, tot_sym, tot_stabs, tot_units, tot_funcs = [], 0, 0, 0, 0
    chart_rows = []
    for label, repo, sl in slices:
        n_sym = sl.get("n_symbols")
        n_stabs = sl.get("n_stabs")
        units = sl.get("units")
        funcs = sl.get("functions")
        units = len(units) if isinstance(units, list) else units
        funcs = len(funcs) if isinstance(funcs, list) else funcs
        for total_name, value in (("sym", n_sym), ("stabs", n_stabs),
                                  ("units", units), ("funcs", funcs)):
            if isinstance(value, int):
                if total_name == "sym":
                    tot_sym += value
                elif total_name == "stabs":
                    tot_stabs += value
                elif total_name == "units":
                    tot_units += value
                else:
                    tot_funcs += value
        carries = isinstance(units, int) and units > 0
        name = repo or label
        slug = slugs.get(str(repo)) or slugs.get(str(label))
        rows.append([
            f'<a href="{esc(_bin_href(slug))}">{esc(name)}</a>' if slug else esc(name),
            esc(sl.get("arch") or "?"),
            fnum(n_sym), fnum(n_stabs), fnum(units),
            # N_FUN records, which live only in the dump — no function-list
            # filter describes them, so the count opens the dump itself.
            _clink(funcs, f"/artifact?p={rel(STABS_DIR / f'{label}.json')}",
                   title="the parsed dump these records came from"),
            tag("units + paths", "ok") if carries else tag("stripped", "dead"),
        ])
        chart_rows.append((name, funcs if isinstance(funcs, int) else 0,
                           "proven" if carries else "unproven"))
    rows.append(["<b>all slices</b>", "", f"<b>{fnum(tot_sym)}</b>",
                 f"<b>{fnum(tot_stabs)}</b>", f"<b>{fnum(tot_units)}</b>",
                 f"<b>{fnum(tot_funcs)}</b>", ""])

    body = (
        '<p class="sub">One row per Mach-O slice. <b>Units</b> are original '
        'compilation units named by <code>N_SO</code>/<code>N_OSO</code> — each '
        'one is a real <code>.cpp</code> path and the <code>.o</code> it linked '
        'from. <b>Functions</b> are <code>N_FUN</code> records with a name, an '
        'address and a byte length.</p>'
        + bars(chart_rows, href_fn=None)
        + _details(table(["Binary", "Arch", "Symbols", "STABS records",
                          "Compilation units", "Functions", "Debug info"],
                        rows, numeric={2, 3, 4, 5}))
    )
    return panel(body, heading)


def _render_record_types() -> str:
    heading = "Which record types each dump actually contains"
    if not STABS_DIR.is_dir():
        return panel(missing(f"{rel(STABS_DIR)} missing"), heading)

    dumps = sorted(p for p in STABS_DIR.glob("*.json") if p.name != "_index.json")
    if not dumps:
        return panel(missing(f"no per-binary dumps under {rel(STABS_DIR)}"),
                     heading)

    per_file = {p: _record_counts(p) for p in dumps}
    totals: dict[str, int] = {}
    for counts in per_file.values():
        for name, value in counts.items():
            totals[name] = totals.get(name, 0) + value
    if not totals:
        return panel(missing("no record_counts block found in any dump header"),
                     heading)

    cols = [name for name, _ in sorted(totals.items(),
                                       key=lambda kv: -kv[1])][:10]
    rows = []
    for path, counts in per_file.items():
        rows.append([_file_link(path, path.name)]
                    + [fnum(counts[c]) if c in counts else "-" for c in cols])
    rows.append([f"<b>{len(per_file)} dumps</b>"]
                + [f"<b>{fnum(totals.get(c))}</b>" for c in cols])

    gloss = "".join(
        f'<div><code>{esc(c)}</code></div><div>{esc(STAB_GLOSS.get(c, "-"))}</div>'
        for c in cols)
    # Dump x record-type is a real matrix (which dump carries which STABS
    # record kind, and how much of it), so it gets the same primitive the
    # controlling doc reserves for build x build density.
    matrix = [[per_file[p].get(c, 0) for c in cols] for p in per_file]
    chart = heatmap(matrix, [p.name for p in per_file], cols, href_fn=None)
    body = (
        '<p class="sub">Read from the header of each dump, not from the index — '
        'this is what the parser found in the binary itself.</p>'
        + chart
        + _details(table(["Dump"] + cols, rows, numeric=set(range(1, len(cols) + 1))))
        + f'<div class="kv" style="margin-top:10px">{gloss}</div>'
        + '<p class="sub" style="margin-top:8px">No <code>N_SLINE</code>, '
        '<code>N_PSYM</code> or <code>N_LSYM</code> appears above, so these '
        'builds carry function-level debug info only: names, addresses, sizes, '
        'source files and object files — no line numbers, no parameter names, '
        'no local variables.</p>'
    )
    return panel(body, heading)


def _render_files() -> str:
    heading = "What is on disk under extract/stabs/"
    if not STABS_DIR.is_dir():
        return panel(missing(f"{rel(STABS_DIR)} missing"), heading)
    entries = sorted(p for p in STABS_DIR.iterdir() if p.is_file())
    if not entries:
        return panel(missing(f"{rel(STABS_DIR)} is empty"), heading)
    rows = []
    total = 0
    for p in entries:
        size, mtime = _stat(p)
        total += size or 0
        rows.append([_file_link(p, p.name), _human_bytes(size), esc(ago(mtime))])
    rows.append([f"<b>{len(entries)} files</b>",
                 f"<b>{_human_bytes(total)}</b>", ""])
    return panel(table(["File", "Size", "Modified"], rows, numeric={1, 2}),
                 heading)


def _render_provenance() -> str:
    """Per-binary: what shipped with names, and where paths have reached."""
    heading = "Name provenance per binary (stored extraction facts)"
    bins, err = query_db(
        "SELECT id, repo_path, slug, platform, game, arch, func_count, named_count "
        "FROM binary ORDER BY platform, slug")
    if err:
        return panel(missing(err), heading)
    if not bins:
        return panel(missing("table `binary` has no rows"), heading)

    snapshot, snapshot_err = load_json(PROVENANCE_SUMMARY)
    by_slug = snapshot.get("by_slug", snapshot) if isinstance(snapshot, dict) else {}
    if not isinstance(by_slug, dict):
        by_slug = {}

    rows, agg = [], {}
    chart_rows = []
    for _bid, repo, slug, platform, game, arch, func_count, named_count in bins:
        # Function and naming totals are extraction-time facts stored on the
        # 24-row binary table. Source-path counts are accepted only from an
        # offline summary; deriving them here would visit the entire func corpus.
        total = int(func_count) if func_count is not None else None
        placeholder = (max(0, total - int(named_count))
                       if total is not None and named_count is not None else None)
        saved = by_slug.get(str(slug), {})
        with_src = (saved.get("with_source_file")
                    if isinstance(saved, dict) else None)
        try:
            with_src = int(with_src) if with_src is not None else None
        except (TypeError, ValueError):
            with_src = None
        drm = str(repo) in DRM_EXCLUDED
        rows.append([
            f'<a href="{esc(_bin_href(slug))}">{esc(repo or slug)}</a>'
            + (" " + tag("DRM, excluded", "warn") if drm else ""),
            esc(platform or "?"),
            esc(game or "?"),
            esc(arch or "?"),
            _clink(total, _fn_href(slug), title="every function in this build"),
            _clink(placeholder, _fn_href(slug, "&placeholder=1"),
                   title="functions nobody has ever named"),
            fpct(placeholder, total),
            _clink(with_src, _fn_href(slug, "&has_source_file=1"),
                   title="functions attributed to an original .cpp"),
            fpct(with_src, total),
        ])
        if not drm and total is not None and placeholder is not None:
            slot = agg.setdefault(platform or "?", [0, 0, 0, 0, 0])
            slot[0] += 1
            slot[1] += total
            slot[2] += placeholder
            if with_src is not None:
                slot[3] += with_src
                slot[4] += 1
                chart_rows.append((slug or repo, with_src,
                                   "proven" if with_src else "unproven"))

    if not rows:
        return panel(missing("no per-binary counts could be read"), heading)

    plat_rows = [
        [esc(plat), fnum(s[0]), fnum(s[1]), fnum(s[2]), fpct(s[2], s[1]),
         fnum(s[3]) if s[4] == s[0] else "-",
         fpct(s[3], s[1]) if s[4] == s[0] else "-"]
        for plat, s in sorted(agg.items(), key=lambda kv: -kv[1][3])
    ]
    tot = [sum(s[i] for s in agg.values()) for i in range(4)]
    all_source_known = sum(s[4] for s in agg.values()) == tot[0]
    plat_rows.append([
        "<b>all (DRM pair excluded)</b>", f"<b>{fnum(tot[0])}</b>",
        f"<b>{fnum(tot[1])}</b>", f"<b>{fnum(tot[2])}</b>",
        f"<b>{fpct(tot[2], tot[1])}</b>",
        f"<b>{fnum(tot[3]) if all_source_known else '-'}</b>",
        f"<b>{fpct(tot[3], tot[1]) if all_source_known else '-'}</b>",
    ])

    plat_chart = (bars(
        [(plat, s[3], "proven" if s[3] else "unproven") for plat, s in agg.items()]
    ) if chart_rows else missing(
        f"Per-binary source-path counts need the offline summary {rel(PROVENANCE_SUMMARY)}; "
        "the dashboard will not scan the function corpus to invent them."))
    bin_chart = (bars(chart_rows, href_fn=lambda slug, *_: _bin_href(slug))
                 if chart_rows else "")

    body = (
        '<p class="sub">Rolled up by platform first. <b>FUN_ placeholders</b> '
        'counts functions whose name is still <code>FUN_xxxxxxxx</code>, '
        '<code>sub_</code> or <code>LAB_</code> — nobody, in any build, has ever '
        'named them. <b>With a .cpp path</b> counts functions carrying a '
        '<code>source_file</code>, which only STABS mining can originate.</p>'
        + '<p class="sub" style="margin-top:8px">Functions with a real .cpp path, '
          "by platform:</p>"
        + plat_chart
        + _details(table(["Platform", "Builds", "Functions", "FUN_ placeholders", "%",
                          "With a .cpp path", "%"], plat_rows,
                        numeric={1, 2, 3, 4, 5, 6}))
        + '<p class="sub" style="margin:14px 0 0">Per binary. Windows rows with '
        'a non-zero path count did not ship one byte of debug info — every one '
        'of those paths arrived from a Mac build through the cross-build '
        'identity layer.</p>'
        + bin_chart
        + _details(table(["Binary", "Platform", "Game", "Arch", "Functions",
                          "FUN_ placeholders", "%", "With a .cpp path", "%"],
                        rows, numeric={4, 5, 6, 7, 8}))
    )
    return panel(body, heading)


def _render_logical() -> str:
    """The honest headline: how much of the corpus has a real original path."""
    heading = "Logical functions carrying a real original source path"
    totals, err = query_db(
        "SELECT COUNT(*), "
        f"SUM({HAS_SRC}), "
        "SUM(object_file IS NOT NULL AND object_file <> ''), "
        "COUNT(DISTINCT CASE WHEN source_file <> '' THEN source_file END), "
        "COUNT(DISTINCT CASE WHEN object_file <> '' THEN object_file END) "
        "FROM logical_function")
    if err:
        return panel(missing(err), heading)
    if not totals or not totals[0][0]:
        return panel(missing("table `logical_function` is empty"), heading)

    total, with_src, with_obj, n_files, n_objs = (v or 0 for v in totals[0])

    per_game, gerr = query_db(
        "SELECT game, COUNT(*), "
        f"SUM({HAS_SRC}) "
        "FROM logical_function GROUP BY game ORDER BY 2 DESC")
    game_rows = []
    kotor_total = kotor_named = 0
    for game, n, named in per_game or []:
        named = named or 0
        game_rows.append([esc(game or "?"), fnum(n), fnum(named),
                          fpct(named, n)])
        # "OTHER" is Neverwinter Nights / Jade Empire / Dragon Age — different
        # games in the same engine family, which no KotOR .cpp path can name.
        if str(game or "").startswith(("K1", "K2", "SHARED")):
            kotor_total += n or 0
            kotor_named += named
    if kotor_total:
        game_rows.append([
            "<b>KotOR only (K1/K2/SHARED)</b>", f"<b>{fnum(kotor_total)}</b>",
            f"<b>{fnum(kotor_named)}</b>", f"<b>{fpct(kotor_named, kotor_total)}</b>",
        ])

    game_chart = bars(
        [(game, named, "proven" if named else "unproven")
         for game, n, named in (per_game or [])],
    )

    body = (
        f'<p class="sub">{fnum(with_src)} of {fnum(total)} logical functions '
        f'({fpct(with_src, total)}) carry an original <code>.cpp</code> path. '
        f'The rest are still unattributed.</p>'
        + donut(
            [("with a .cpp path", with_src, "proven"),
             ("unattributed", max(0, total - with_src), "unproven")],
            total=total, title="Original-path attribution",
        )
        + '<div class="kv">'
        + f'<div>logical functions</div><div>{fnum(total)}</div>'
        + f'<div>with a source path</div><div>{fnum(with_src)} ({fpct(with_src, total)})</div>'
        + f'<div>with an object file</div><div>{fnum(with_obj)} ({fpct(with_obj, total)})</div>'
        + f'<div>distinct .cpp files named</div><div>{fnum(n_files)}</div>'
        + f'<div>distinct .o files named</div><div>{fnum(n_objs)}</div>'
        + '</div>'
        + (game_chart + _details(table(["Game", "Logical functions", "With a source path", "%"],
                                       game_rows, numeric={1, 2, 3}))
           if game_rows else missing(gerr or "no per-game breakdown"))
    )
    return panel(body, heading)


def _render_reach() -> str:
    """The transfer itself: paths mined from Mac, landing in every platform."""
    heading = "How far a recovered path travels (table `identity`)"
    reach, err = query_db(
        "SELECT b.platform, COUNT(DISTINCT i.logical_id) "
        "FROM logical_function lf "
        "JOIN identity i ON i.logical_id = lf.id "
        "JOIN binary b ON b.id = i.binary_id "
        "WHERE lf.source_file IS NOT NULL AND lf.source_file <> '' "
        "GROUP BY b.platform")
    if err:
        return panel(missing(err), heading)
    present, perr = query_db(
        "SELECT b.platform, COUNT(DISTINCT i.logical_id) "
        "FROM identity i JOIN binary b ON b.id = i.binary_id "
        "GROUP BY b.platform")
    if perr:
        return panel(missing(perr), heading)
    if not reach:
        return panel(missing("no source-attributed identities recorded yet"),
                     heading)

    seen = dict(present or [])
    rows = []
    reach_chart_rows = []
    for platform, named in sorted(reach, key=lambda r: -r[1]):
        total = seen.get(platform, 0)
        rows.append([esc(platform or "?"), fnum(total), fnum(named),
                     fpct(named, total)])
        reach_chart_rows.append((platform or "?", named, "proven" if named else "unproven"))

    methods, merr = query_db(
        "SELECT method, COUNT(*) FROM identity GROUP BY method "
        "ORDER BY 2 DESC LIMIT 12")
    method_rows = [[esc(m or "?"), fnum(n)] for m, n in methods or []]
    method_chart = bars([(m or "?", n, "unproven") for m, n in (methods or [])])

    body = (
        '<p class="sub">Each row: logical functions bound to at least one '
        'function in that platform, and how many of them carry a <code>.cpp</code> '
        'path. Only the Mac builds shipped those paths; every other row is '
        'transferred identity.</p>'
        + bars(reach_chart_rows, sort=False)
        + _details(table(["Platform", "Logical functions present", "…with a .cpp path",
                          "%"], rows, numeric={1, 2, 3}))
        + (('<p class="sub" style="margin:14px 0 0">How each binding was made '
            '(<code>identity.method</code>).</p>'
            + method_chart
            + _details(table(["Binding method", "Rows"], method_rows, numeric={1})))
           if method_rows else missing(merr or "no binding methods recorded"))
    )
    return panel(body, heading)


def _render_top_sources() -> str:
    heading = "Biggest original source files by logical functions attributed"
    rows, err = query_db(
        "SELECT source_file, COUNT(*) c FROM logical_function "
        f"WHERE {HAS_SRC} GROUP BY source_file ORDER BY c DESC LIMIT 25")
    if err:
        return panel(missing(err), heading)
    if not rows:
        return panel(missing("no logical function carries a source path yet"),
                     heading)
    out = []
    chart_rows = []
    for path, count in rows:
        text = str(path)
        head, _, name = text.rpartition("/")
        label = (f'<code>{esc(name or text)}</code>'
                 f'<div class="sub">{esc(head)}</div>' if head
                 else f'<code>{esc(text)}</code>')
        out.append([label, fnum(count)])
        chart_rows.append((name or text, count, "proven"))
    chart = bars(chart_rows)
    return panel(
        '<p class="sub">Top 25 by <code>GROUP BY source_file</code> over '
        '<code>logical_function</code>. These are the real paths from the '
        'BioWare/Aspyr build tree, exactly as the linker recorded them.</p>'
        + chart
        + _details(table(["Original source file", "Logical functions"], out,
                        numeric={1})),
        heading)


def _render_symbol_tables() -> str:
    """Say plainly what the DB does and does not store, instead of assuming."""
    heading = "Symbol storage in the corpus store"
    names, err = query_db(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    if err:
        return panel(missing(err), heading)
    if not names:
        return panel(missing("no tables found"), heading)
    tables = [str(n[0]) for n in names]
    symbolish = [t for t in tables
                 if any(k in t.lower() for k in ("symbol", "stab", "name", "sym"))]

    rows = []
    for t in tables:
        counts, cerr = query_db(f'SELECT COUNT(*) FROM "{t}"') if t in (
            "binary", "logical_function", "identity", "match", "eval",
            "decomp") else ([], None)
        # `func` and `calledge` are the huge tables; a COUNT(*) on them would
        # cost minutes on this disk, so their size is reported as unmeasured.
        n = fnum(counts[0][0]) if counts else ("not counted (too large to scan)"
                                               if not cerr else esc(cerr))
        rows.append([f"<code>{esc(t)}</code>", n])

    note = (
        '<p class="sub">A dedicated symbol table '
        + ("exists: " + ", ".join(f"<code>{esc(t)}</code>" for t in symbolish)
           if symbolish else
           "does not exist. Symbol-derived names live as columns on "
           "<code>func</code> (<code>name</code>, <code>source</code>, "
           "<code>source_file</code>, <code>object_file</code>) and are promoted "
           "to <code>logical_function</code>")
        + '.</p>'
    )
    return panel(note + table(["Table", "Rows"], rows, numeric={1}), heading)


def render() -> str:
    started = time.time()
    try:
        lead = (
            '<p class="sub" style="margin-bottom:14px">'
            + tag("real names, not invented ones", "ok")
            + ' Two shipped artifacts still carry what the original programmers '
            'typed. The <b>Mac</b> builds were linked with <b>STABS</b> debug '
            'records left in place, naming every compilation unit '
            '(<code>N_SO</code>, <code>N_OSO</code>) and every function in it '
            '(<code>N_FUN</code>), plus file statics (<code>N_STSYM</code>) and '
            'globals (<code>N_GSYM</code>) — real build-tree paths such as '
            '<code>/AspyrBuild/depot/KOTOR/PC Source/Dev/game/servercore/'
            'nwscreature.cpp</code>. The <b>Android</b> builds ship a full C++ '
            'symbol table with Itanium-mangled names, so classes and methods '
            'survive but source paths do not. <b>No Windows build has '
            'either.</b> Since all these binaries are forks of one codebase, a '
            'path mined from the Mac build attaches to the matching function in '
            'the Windows build through the cross-build identity layer — which is '
            'why the Windows rows below have paths at all, and why this is the '
            'largest source of real names in the project.</p>'
        )
        parts = [
            _render_index(),
            _render_record_types(),
            _render_files(),
            _render_logical(),
            _render_reach(),
            _render_provenance(),
            _render_top_sources(),
            _render_symbol_tables(),
        ]
        foot = (f'<p class="sub" style="margin-top:10px">Panel built in '
                f'{time.time() - started:.2f}s, entirely from '
                f'<code>{esc(rel(STABS_DIR))}</code> and '
                f'<code>{esc(str(DB_PATH) if DB_PATH else "AGENT_DECOMPILE_CORPUS_DB unset")}</code>.</p>')
        return lead + "".join(p for p in parts if p) + foot
    except Exception as exc:  # noqa: BLE001
        return missing(f"stabs panel failed to render: {exc}")
