"""Per-binary inventory panel.

Shows every row of the `binary` table with the fact that makes this corpus
worth building: the binaries are not 24 unrelated programs. They are versions,
forks and ports of the same two games — KotOR 1 and KotOR 2 — shipped on
Windows, Mac, Linux, Xbox, Android and iOS, plus a handful of non-KotOR
BioWare binaries kept as engine reference. Each fork was reverse engineered by
different people to a different depth (the named_count column is that history
made visible), so a symbol recovered in one fork is a symbol the other 23 can
inherit. That inheritance is the entire reason for cross-matching, and it is
why the panel groups rather than merely lists.

The panel also carries the two denominators. Three binaries cannot contribute
matchable functions — two are DRM ciphertext, one is a byte-identical copy —
so a total that includes them makes complete coverage read as a shortfall.
Both numbers are shown side by side so the gap is never mistaken for failure.

Every number is read live from db/kotorxid.sqlite and from MizuchiRE's
inventory.json. The `binary` table is 24 rows; the `func` table is never
touched here.
"""

from __future__ import annotations

import os
from urllib.parse import quote

from agentdecompile_recovery.corpus.dashboard.panels.common import (
    DRM_EXCLUDED,
    as_external,
    esc,
    fnum,
    fpct,
    kv,
    load_json,
    missing,
    panel,
    query_db,
    table,
    tag,
)
from agentdecompile_recovery.corpus.dashboard.panels.viz import bars, donut

try:  # count_link is landing in common.py from another author.
    from agentdecompile_recovery.corpus.dashboard.panels.common import count_link
except ImportError:  # the panel still renders, with plain links
    count_link = None


def _details(inner: str, summary: str = "raw numbers") -> str:
    """The chart is the finding; the table is what a reader asks for next.

    Rule C (10-relationship-layout.md): a table is only ever the *expansion* of
    a visual, so it starts collapsed rather than competing with the chart for
    the reader's first look.
    """
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

TITLE = "The 24 binaries — versions and forks of one game"

# MizuchiRE writes this after each import pass. It is a second, independent
# census of the same Ghidra projects, so it is the only cheap way to notice
# that one of the two sources has gone stale.
INVENTORY = as_external() / "reports" / "inventory.json"

# Recovery targets the x86 family first: that is where the decompiler, the
# MSVC 7.1 toolchain and the byte-exact ladder all work.
X86_ARCHES = {"x86", "x86_64", "x64", "i386", "i686", "amd64"}

# A source disagreement below this is import-order noise, not staleness.
INVENTORY_TOLERANCE = 0.01

GAME_LABEL = {"K1": "KotOR 1", "K2": "KotOR 2 (TSL)", "OTHER": "reference"}
GAME_ORDER = {"K1": 0, "K2": 1, "OTHER": 2}

FORMAT_SHORT = {
    "Portable Executable (PE)": "PE",
    "Executable and Linking Format (ELF)": "ELF",
    "Mac OS X Mach-O": "Mach-O",
    "Xbox Executable Format (XBE)": "XBE",
}

COLUMNS = ("repo_path", "slug", "game", "platform", "arch", "bits", "format",
           "md5", "func_count", "named_count")


def _load_rows():
    """Return (rows, error). 24 rows, so a full select costs nothing."""
    sql = f"SELECT {', '.join(COLUMNS)} FROM binary"
    raw, err = query_db(sql)
    if err:
        return [], err
    rows = [dict(zip(COLUMNS, r)) for r in raw]
    for r in rows:
        r["is_x86"] = str(r.get("arch") or "").strip().lower() in X86_ARCHES
    rows.sort(key=lambda r: (GAME_ORDER.get(r["game"], 9),
                             str(r.get("platform") or ""),
                             str(r.get("repo_path") or "")))
    return rows, None


def _duplicates(rows) -> dict[str, str]:
    """Map duplicate repo_path -> the copy it duplicates, keyed on md5.

    Derived from the md5 column rather than a hardcoded filename, so a second
    saved copy anywhere in the corpus is caught the same way. A ".keep" sidecar
    is always the copy, never the file the repo works from.
    """
    by_md5: dict[str, list[dict]] = {}
    for r in rows:
        md5 = str(r.get("md5") or "").strip().lower()
        if md5:
            by_md5.setdefault(md5, []).append(r)
    dups: dict[str, str] = {}
    for group in by_md5.values():
        if len(group) < 2:
            continue
        ordered = sorted(group, key=lambda r: (r["repo_path"].endswith(".keep"),
                                               len(r["repo_path"]),
                                               r["repo_path"]))
        for r in ordered[1:]:
            dups[r["repo_path"]] = ordered[0]["repo_path"]
    return dups


def _fmt_cell(value) -> str:
    text = str(value or "")
    short = FORMAT_SHORT.get(text)
    if not short:
        return esc(text) or "-"
    return f'<span title="{esc(text)}">{esc(short)}</span>'


def _status_cell(row, dups) -> str:
    path = row["repo_path"]
    if path in DRM_EXCLUDED:
        return tag("DRM ciphertext", "warn") + ' <span class="sub">.text encrypted</span>'
    if path in dups:
        other = os.path.basename(dups[path])
        return tag("duplicate", "warn") + f' <span class="sub">same md5 as {esc(other)}</span>'
    if row["is_x86"]:
        return tag("recovery priority", "prio")
    return tag("port / reference")


def _funcs_bars(rows, dups) -> str:
    """One bar per binary, sorted by function count — Rule C's per-build chart.

    State carries only the "counts in no denominator" fact (excluded), never
    architecture or platform — those stay category, per 05-visual-system.md §2.
    href_fn opens the same /binary/<slug> route the table row's link uses, so
    the chart and the table underneath it agree on where a click goes.
    """
    data = []
    for r in rows:
        state = "excluded" if (r["repo_path"] in DRM_EXCLUDED or r["repo_path"] in dups) else "unproven"
        data.append((r.get("slug") or r["repo_path"], r.get("func_count") or 0, state))
    return bars(data, href_fn=lambda slug, *_: _bin_href(slug))


def _funcs_donut(total_funcs, live_funcs) -> str:
    """The two denominators from the module docstring, drawn instead of stated.

    `live_funcs` (matchable) and the DRM/duplicate remainder are never summed
    into one figure elsewhere on the page; this ring is the same split, just
    visual instead of prose.
    """
    excluded = max(0, total_funcs - live_funcs)
    return donut(
        [("matchable (real code)", live_funcs, "proven"),
         ("DRM ciphertext / duplicate", excluded, "excluded")],
        total=total_funcs, title="Functions: matchable vs excluded",
    )


def _binary_table(rows, dups) -> str:
    body = []
    for r in rows:
        arch = str(r.get("arch") or "?")
        bits = r.get("bits")
        arch_txt = f"{arch} / {bits}-bit" if bits else arch
        slug = r.get("slug")
        body.append([
            f'<a href="{esc(_bin_href(slug))}"><code>{esc(r["repo_path"])}</code></a>',
            esc(GAME_LABEL.get(r["game"], r["game"] or "?")),
            esc(r.get("platform") or "?"),
            esc(arch_txt),
            _fmt_cell(r.get("format")),
            _clink(r.get("func_count"), _fn_href(slug),
                   title="every function in this build"),
            _clink(r.get("named_count"), _fn_href(slug, "&named=1"),
                   title="functions that carry a real name"),
            _status_cell(r, dups),
        ])
    return table(
        ["Binary", "Game", "Platform", "Arch", "Format", "Functions", "Named", "Status"],
        body,
        numeric={5, 6},
    )


def _totals_block(rows, dups) -> str:
    excluded = {r["repo_path"] for r in rows
                if r["repo_path"] in DRM_EXCLUDED or r["repo_path"] in dups}
    total_funcs = sum(int(r.get("func_count") or 0) for r in rows)
    live_funcs = sum(int(r.get("func_count") or 0) for r in rows
                     if r["repo_path"] not in excluded)
    total_named = sum(int(r.get("named_count") or 0) for r in rows
                      if r["repo_path"] not in excluded)
    x86_live = [r for r in rows if r["is_x86"] and r["repo_path"] not in DRM_EXCLUDED]
    games = {}
    for r in rows:
        games.setdefault(r["game"], set()).add(r.get("platform"))
    game_txt = ", ".join(
        f'{GAME_LABEL.get(g, g or "?")}: {len([r for r in rows if r["game"] == g])} '
        f'builds on {len(p)} platform{"" if len(p) == 1 else "s"}'
        for g, p in sorted(games.items(), key=lambda item: GAME_ORDER.get(item[0], 9))
    )
    # Corpus-wide totals open the function browser at its build picker: there is
    # no single build to filter by, and the reader still gets a way in.
    return _funcs_donut(total_funcs, live_funcs) + kv([
        ("Binaries in the corpus", fnum(len(rows))),
        ("Forks per game", esc(game_txt)),
        ("x86 / x64 recovery priority", fnum(len(x86_live))),
        ("Functions, all binaries", _clink(total_funcs, "/functions")),
        ("Functions, excluding the unmatchable",
         f'<b>{_clink(live_funcs, "/functions")}</b>'),
        ("Difference the exclusions make", fnum(total_funcs - live_funcs)),
        ("Full coverage scored against the raw total", fpct(live_funcs, total_funcs)),
        ("Functions already named across the matchable set",
         _clink(total_named, "/functions")),
    ])


def _exclusions_block(rows, dups) -> str:
    by_path = {r["repo_path"]: r for r in rows}
    body = []
    def _cell(path: str, r):
        link = f'<a href="{esc(_bin_href(r["slug"]))}">' if r else ""
        name = f'<code>{esc(path)}</code>'
        return (f"{link}{name}</a>" if r else name)

    for path in DRM_EXCLUDED:
        r = by_path.get(path)
        body.append([
            _cell(path, r),
            _clink(r.get("func_count"), _fn_href(r["slug"])) if r else "-",
            "Packed .text measures entropy 8.000 — DRM ciphertext, not code. "
            "Nothing in it can match, so it is skipped on purpose.",
        ])
    for path, canonical in sorted(dups.items()):
        r = by_path.get(path)
        other = by_path.get(canonical)
        canon_cell = (f'<a href="{esc(_bin_href(other["slug"]))}">'
                      f'<code>{esc(canonical)}</code></a>' if other
                      else f'<code>{esc(canonical)}</code>')
        body.append([
            _cell(path, r),
            _clink(r.get("func_count"), _fn_href(r["slug"])) if r else "-",
            f"Byte-identical to {canon_cell} (same md5). "
            "Counting both would double every function it holds.",
        ])
    if not body:
        return missing("no exclusions found in the binary table")
    note = ('<p class="sub">These rows are removed from every denominator by '
            'design. Their absence is a decision, not a gap.</p>')
    return note + table(["Excluded binary", "Functions", "Why"], body, numeric={1})


def _inventory_block(rows) -> str:
    data, err = load_json(INVENTORY)
    if err:
        return missing(f"MizuchiRE cross-check {err}")
    if not isinstance(data, list):
        return missing("inventory.json did not contain a list of programs")

    inv = {}
    for entry in data:
        if isinstance(entry, dict) and entry.get("name"):
            inv[str(entry["name"])] = entry

    flagged, checked = [], 0
    for r in rows:
        name = os.path.basename(r["repo_path"])
        entry = inv.get(name)
        if entry is None:
            continue
        checked += 1
        db_n = int(r.get("func_count") or 0)
        try:
            inv_n = int(entry.get("functions") or 0)
        except (TypeError, ValueError):
            continue
        denom = db_n or inv_n
        if not denom:
            continue
        drift = abs(db_n - inv_n) / denom
        if drift > INVENTORY_TOLERANCE:
            flagged.append([
                f'<a href="{esc(_bin_href(r.get("slug")))}">'
                f'<code>{esc(name)}</code></a>',
                _clink(db_n, _fn_href(r.get("slug"))),
                fnum(inv_n),
                f'<span class="bad">{drift * 100:.2f}%</span>',
            ])

    db_names = {os.path.basename(r["repo_path"]) for r in rows}
    only_inv = sorted(set(inv) - db_names)
    only_db = sorted(db_names - set(inv))

    parts = [f'<p class="sub">{checked} of {len(rows)} binaries cross-checked against '
             f'{esc(INVENTORY.name)} ({len(inv)} programs listed). '
             f'Tolerance {INVENTORY_TOLERANCE * 100:.0f}%.</p>']
    if flagged:
        parts.append(table(["Binary", "Database func_count", "inventory.json functions",
                            "Disagreement"], flagged, numeric={1, 2, 3}))
        parts.append('<p class="miss">A disagreement means one source is stale. '
                     'Re-run the import that feeds the smaller count before trusting '
                     'either number.</p>')
    else:
        parts.append('<p class="sub good">Both sources agree on every binary.</p>')
    if only_inv:
        parts.append(f'<p class="miss">In inventory.json but not in the database: '
                     f'{esc(", ".join(only_inv))}</p>')
    if only_db:
        parts.append(f'<p class="miss">In the database but not in inventory.json: '
                     f'{esc(", ".join(only_db))}</p>')
    return "".join(parts)


def render() -> str:
    try:
        rows, err = _load_rows()
        if err:
            return panel(missing(err))
        if not rows:
            return panel(missing("the binary table is empty"))

        dups = _duplicates(rows)
        x86 = [r for r in rows if r["is_x86"]]
        # The DRM rows stay in the table for provenance, so the heading counts
        # the ones recovery can actually work on.
        x86_live = [r for r in x86 if r["repo_path"] not in DRM_EXCLUDED]
        other = [r for r in rows if not r["is_x86"]]

        intro = (
            '<p class="sub">One codebase, 24 shipped builds. Every KotOR row below is '
            'the same game rebuilt for another platform or another storefront, so a '
            'function named in one build is a function the others can inherit. The '
            'reference binaries share BioWare engine code without sharing the game. '
            'The Named column shows how unevenly the forks were reverse engineered — '
            'that unevenness is what cross-matching converts into coverage.</p>'
        )

        blocks = [
            panel(intro + _totals_block(rows, dups)),
            panel('<h3 style="margin-top:0">Functions per binary, sorted</h3>'
                  '<p class="sub">Every row in the table below, as one chart. '
                  '"excluded" bars are the DRM ciphertext pair and the duplicate '
                  'copy — they render for provenance and count in no denominator.'
                  '</p>' + _funcs_bars(rows, dups)),
            panel(f'<h3 style="margin-top:0">x86 and x64 — recovery priority '
                  f'({len(x86_live)} of {len(x86)} rows)</h3>'
                  '<p class="sub">The decompiler, the MSVC 7.1 toolchain and the '
                  'byte-exact ladder all target this family first. Rows tagged below '
                  'stay listed for provenance and count in no denominator.</p>'
                  + _details(_binary_table(x86, dups))),
        ]
        if other:
            blocks.append(panel(
                f'<h3 style="margin-top:0">ARM and AArch64 — mobile ports '
                f'({len(other)} binaries)</h3>'
                '<p class="sub">Different instruction set, same source tree. These '
                'carry symbol names the desktop builds stripped.</p>'
                + _details(_binary_table(other, dups))))
        # Exclusions are 1-3 rows naming specific files, not a comparable set —
        # a bar chart of "two DRM binaries and one duplicate" says nothing a
        # bar can't already say better as a labelled row, so this stays a table.
        blocks.append(panel('<h3 style="margin-top:0">Excluded on purpose</h3>'
                            + _exclusions_block(rows, dups)))
        blocks.append(panel('<h3 style="margin-top:0">Cross-check against MizuchiRE</h3>'
                            + _inventory_block(rows)))
        return "".join(blocks)
    except Exception as exc:  # noqa: BLE001 - a panel must degrade, never crash
        return panel(missing(f"binary inventory unavailable: {exc}"))
