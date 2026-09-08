"""MizuchiRE per-function Ghidra knowledge, merged into kotorxid.

The 24 binaries are 24 forks of the same game, and each one carries different
reverse-engineering work: hand-named functions in one, STABS debug paths in
another, a full C++ symbol table in a third. Knowledge that exists in only one
fork is worth more than knowledge repeated in all of them, so the merge has to
preserve what each binary knows individually — hence the "named" column here,
which is what separates a symbol-rich build from a stripped one.

Why the per-function export replaced the whole-program dump: the older
CppExporter run emitted one C file per program, and on `k2_win_CD_1.0` most of
its entries were `Unwind_*` exception funclets rather than functions. Real
coverage was under half the program. MizuchiRE's per-function export writes one
JSON per function — decompiled C, an asm listing, every instruction with its
bytes and relocations, calling convention, signature, fileOffset — and covers
essentially every function the database knows about. Both numbers on this page
are measured from the two artifacts, not quoted.

The cost of that completeness is shape: ~500,000 tiny JSON files across 22
programs on a shared spinning disk. `kx/ingest_ghidra_knowledge.py` pays the
seek cost once per binary into `db/ghidra_knowledge.sqlite`; this panel reports
that cache, never the file tree.
"""

from __future__ import annotations

import os
import re
import threading
import time
from pathlib import Path
from urllib.parse import quote

from agentdecompile_recovery.corpus.dashboard.panels.common import (
    DRM_EXCLUDED,
    GHIDRA_SERVER_HOST,
    GHIDRA_SERVER_PORT,
    KNOWLEDGE_DB,
    as_external,
    as_root,
    ago,
    esc,
    fnum,
    fpct,
    kv,
    missing,
    panel,
    query_db,
    table,
    tag,
    tcp_up,
)
from agentdecompile_recovery.corpus.dashboard.panels.viz import bars, donut, stacked_bar

TITLE = "Ghidra knowledge merge"

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


def _slugs() -> dict[str, str]:
    """Program name and repo_path -> slug. MizuchiRE keys its work on the file name."""
    rows, err = query_db("SELECT repo_path, slug FROM binary")
    if err:
        return {}
    out = {}
    for repo, slug in rows:
        out[str(repo)] = str(slug)
        out[Path(str(repo)).name] = str(slug)
    return out

# The batch scripts that need the Ghidra server. Both resume by skipping work
# they believe already exists, so a dead server makes them exit 0 with nothing
# done — the only trace is in these per-job logs.
BATCH_LOG_DIRS = (as_root() / "logs" / "bsim", as_root() / "logs" / "cexport")
SERVER_FAIL_RE = re.compile(
    r"Connection to server failed|Unavailable \(BSimLaunchable\)"
    r"|No signature files found|Invalid Ghidra URL")
MAX_LOG_BYTES = 1 << 20

# The comparison that motivated the whole merge lives on this one program: it is
# the binary the old whole-program dump was built for, so it is the only place
# the two exports can be measured against each other.
def _coverage_program(status_rows=None) -> str:
    name = (
        os.environ.get("KNOWLEDGE_COVERAGE_PROGRAM")
        or os.environ.get("CORPUS_PROGRAM")
        or ""
    ).strip()
    if name:
        return name
    if status_rows:
        return str(status_rows[0][0] or "")
    return ""
MAX_DUMP_BYTES = 128 << 20
FUN_RE = re.compile(rb"\bFUN_[0-9a-fA-F]{6,}")
UNWIND_RE = re.compile(rb"\bUnwind_[0-9A-Za-z_]+")

# Ghidra's own placeholder names. Anything else is work a human (or a symbol
# table) put into that specific fork.
AUTO_NAME_SQL = ("name IS NOT NULL AND name NOT LIKE 'FUN!_%' ESCAPE '!' "
                 "AND name NOT LIKE 'Unwind!_%' ESCAPE '!' "
                 "AND name NOT LIKE 'thunk!_FUN!_%' ESCAPE '!'")


# --------------------------------------------------------------------------
# deep aggregate — the only query here that has to touch the 2.7 GB table
# --------------------------------------------------------------------------

# decompiled/asm/n_instructions/n_refs sit at the end of each record, behind the
# overflow pages that hold the C text, so summing them is a full 2.7 GB read:
# ~65 s cold, ~1.5 s once the page cache holds it. That cannot run inside a page
# request, so it runs on a background thread and the page shows its age. The
# result is keyed on the cache file's (mtime, size): the ingest rewrites the
# file whenever it adds a program, so a matching key means the numbers still
# describe exactly this file and cannot be stale.
_DEEP_LOCK = threading.Lock()
_DEEP: dict = {"key": None, "rows": {}, "ts": 0.0, "seconds": 0.0,
               "error": None, "running": False}

DEEP_SQL = """
SELECT program,
       COUNT(*)                    AS n,
       SUM(decompiled IS NOT NULL) AS n_decomp,
       SUM(asm IS NOT NULL)        AS n_asm,
       SUM(n_instructions)         AS instrs,
       SUM(n_refs)                 AS refs
FROM func_knowledge
GROUP BY program
"""


def _db_key(path: Path):
    try:
        st = path.stat()
    except OSError:
        return None
    return (int(st.st_mtime), st.st_size)


def _deep_worker(key) -> None:
    t0 = time.time()
    rows, err = query_db(DEEP_SQL, db=KNOWLEDGE_DB)
    elapsed = time.time() - t0
    with _DEEP_LOCK:
        _DEEP["running"] = False
        _DEEP["error"] = err
        if not err:
            _DEEP.update(key=key, ts=time.time(), seconds=elapsed,
                         rows={r[0]: r[1:] for r in rows})


def _deep_snapshot() -> dict:
    """Last full-scan aggregate, starting one if the cache file has changed."""
    key = _db_key(KNOWLEDGE_DB)
    with _DEEP_LOCK:
        snap = dict(_DEEP)
        stale = key is not None and key != _DEEP["key"]
        if stale and not _DEEP["running"]:
            _DEEP["running"] = True
            snap["running"] = True
            threading.Thread(target=_deep_worker, args=(key,), daemon=True,
                             name="knowledge-deep-scan").start()
    snap["fresh"] = key is not None and key == snap["key"]
    return snap


# --------------------------------------------------------------------------
# whole-program CppExporter dump — the artifact the per-function export replaced
# --------------------------------------------------------------------------

# 15 MB, read once per mtime. Distinct symbol names are counted rather than
# definitions because the dump repeats a name at every call site.
_DUMP_CACHE: dict = {}


def _dump_path(program: str) -> Path:
    return as_external() / "binaries" / program / "ghidra_knowledge" / f"{program}.c"


def _dump_counts(program: str):
    """Return (n_fun, n_unwind, size, error) for the whole-program C dump."""
    path = _dump_path(program)
    try:
        st = path.stat()
    except OSError:
        return None, None, None, f"whole-program dump missing ({path.name})"
    key = (str(path), int(st.st_mtime), st.st_size)
    hit = _DUMP_CACHE.get(key)
    if hit:
        return (*hit, None)
    if st.st_size > MAX_DUMP_BYTES:
        return None, None, st.st_size, f"{path.name} too large to scan live"
    try:
        blob = path.read_bytes()
    except OSError as exc:
        return None, None, st.st_size, f"could not read {path.name}: {exc}"
    counts = (len(set(FUN_RE.findall(blob))), len(set(UNWIND_RE.findall(blob))),
              st.st_size)
    _DUMP_CACHE.clear()
    _DUMP_CACHE[key] = counts
    return (*counts, None)


# --------------------------------------------------------------------------
# sections
# --------------------------------------------------------------------------


def _server_section() -> str:
    up = tcp_up(GHIDRA_SERVER_HOST, GHIDRA_SERVER_PORT)
    head = (f'<div class="ptitle"><b>Ghidra server {esc(GHIDRA_SERVER_HOST)}:'
            f'{GHIDRA_SERVER_PORT}</b>'
            f'{tag("reachable", "ok") if up else tag("unreachable", "dead")}</div>')

    scanned, failed, victims = 0, 0, []
    for d in BATCH_LOG_DIRS:
        if not d.is_dir():
            continue
        for log in sorted(d.glob("*.log")):
            scanned += 1
            try:
                with log.open("rb") as fh:
                    text = fh.read(MAX_LOG_BYTES).decode("utf-8", "replace")
            except OSError:
                continue
            if SERVER_FAIL_RE.search(text):
                failed += 1
                victims.append(f"{d.name}/{log.stem}")

    if not scanned:
        body = missing("no batch job logs under logs/bsim or logs/cexport yet")
    else:
        body = kv([
            ("Batch job logs on disk", fnum(scanned)),
            ("Logs recording a server failure",
             f'<span class="{"bad" if failed else "good"}">{fnum(failed)}</span>'),
            ("Share of jobs that lost the server", fpct(failed, scanned)),
        ])
        if victims:
            body += ('<div class="log" style="max-height:150px">'
                     + esc("\n".join(victims)) + "</div>")

    note = ('<p class="sub" style="margin-top:10px">Both batch scripts resume by '
            'skipping work they think is already done. A dead server makes them '
            'exit clean with nothing produced and no error raised. Every job '
            'listed here finished that way. Check this box before trusting a '
            'bsim or C-export run.</p>')
    return panel(head + body + note)


def _scale_section(status_rows, status_err) -> str:
    if status_err:
        return panel(missing(status_err))
    if not status_rows:
        return panel(missing("ingest_status is empty — run "
                             "kx/ingest_ghidra_knowledge.py"))
    done = sum(r[1] or 0 for r in status_rows)
    total = sum(r[2] or 0 for r in status_rows)
    seconds = sum(r[3] or 0.0 for r in status_rows)
    complete = sum(1 for r in status_rows if r[4])
    size = (
        KNOWLEDGE_DB.stat().st_size
        if KNOWLEDGE_DB is not None and KNOWLEDGE_DB.exists()
        else 0
    )
    head = ('<div class="ptitle"><b>Cached knowledge</b>'
            + tag(f"{complete}/{len(status_rows)} programs complete",
                  "ok" if complete == len(status_rows) else "warn") + "</div>")
    body = donut(
        [("cached", done, "proven"), ("offered but not yet cached", max(0, total - done), "unproven")],
        total=total, title="Functions ingested vs offered",
    ) + kv([
        ("Functions cached", fnum(done)),
        ("Functions offered by the export", fnum(total)),
        ("Ingested", fpct(done, total)),
        ("Total ingest wall time", f"{seconds / 60:.0f} min"),
        ("Mean read rate", f"{done / seconds:,.0f} files/s" if seconds else "-"),
        ("db/ghidra_knowledge.sqlite", f"{size / (1 << 30):.2f} GB"),
    ])
    note = (f'<p class="sub" style="margin-top:10px">{fnum(done)} per-function '
            f'JSON files, one per function, read once in a sequential walk. '
            f'Downstream tools now do one indexed lookup instead of one disk '
            f'seek per function.</p>')
    return panel(head + body + note)


def _coverage_section(status_rows) -> str:
    """Whole-program dump vs per-function export, both measured live."""
    program = _coverage_program(status_rows)
    if not program:
        return missing("set CORPUS_PROGRAM or KNOWLEDGE_COVERAGE_PROGRAM")
    n_fun, n_unwind, size, err = _dump_counts(program)
    per_func = next((r[1] for r in status_rows if r[0] == program), None)

    # The denominator is what the project database says the binary contains, so
    # neither export gets to define its own coverage.
    bins, _ = query_db("SELECT id, repo_path FROM binary")
    bid = next((b[0] for b in bins
                if Path(str(b[1])).name == program), None)
    real = None
    if bid is not None:
        rows, _ = query_db("SELECT COUNT(*) FROM func WHERE binary_id=?", (bid,))
        real = rows[0][0] if rows else None

    slug = _slugs().get(program)
    label = (f'<a href="{esc(_bin_href(slug))}">{esc(program)}</a>'
             if slug else esc(program))
    head = (f'<div class="ptitle"><b>Coverage: {label}</b>'
            + tag("why the export changed", "warn") + "</div>")
    if err:
        return panel(head + missing(err))

    entries = (n_fun or 0) + (n_unwind or 0)

    def _cov_state(part) -> str:
        try:
            frac = float(part or 0) / float(real) if real else 0.0
        except (TypeError, ValueError, ZeroDivisionError):
            frac = 0.0
        return "proven" if frac >= 0.9 else ("partial" if frac >= 0.5 else "failed")

    chart = bars(
        [("whole-program dump", n_fun or 0, _cov_state(n_fun)),
         ("per-function export", per_func or 0, _cov_state(per_func))],
        sort=False,
    )
    body = chart + _details(table(
        ["Export", "Entries", "Real functions", "Coverage"],
        [
            [f"whole-program CppExporter dump ({size / (1 << 20):.0f} MB .c)",
             fnum(entries), fnum(n_fun), fpct(n_fun, real)],
            ["per-function ghidra_knowledge export",
             fnum(per_func), fnum(per_func), fpct(per_func, real)],
        ],
        numeric={1, 2, 3},
    ))
    body += kv([
        ("Functions in the corpus store",
         _clink(real, _fn_href(slug)) if slug else fnum(real)),
        ("Dump entries that are Unwind_* funclets, not functions",
         f"{fnum(n_unwind)} ({fpct(n_unwind, entries)})"),
    ])
    body += ('<p class="sub" style="margin-top:10px">The dump names every '
             'exception funclet as if it were a function. Strip those and most '
             'of the program was never covered at all.</p>')
    return panel(head + body)


def _programs_section(status_rows, status_err) -> str:
    if status_err:
        return panel(missing(status_err))
    if not status_rows:
        return panel(missing("no ingested programs yet"))

    # Covering index (program, name), so this stays sub-second even cold and the
    # table has live rows while the deep scan is still running.
    live, live_err = query_db(
        f"SELECT program, COUNT(*), SUM(CASE WHEN {AUTO_NAME_SQL} THEN 1 ELSE 0 END) "
        "FROM func_knowledge GROUP BY program", db=KNOWLEDGE_DB)
    counts = {r[0]: (r[1], r[2]) for r in live}

    snap = _deep_snapshot()
    deep = snap.get("rows") or {}

    slugs = _slugs()
    rows = []
    chart_rows = []
    for prog, done, total, seconds, complete in status_rows:
        n_rows, named = counts.get(prog, (None, None))
        d = deep.get(prog)
        slug = slugs.get(str(prog))
        rows.append([
            f'<a href="{esc(_bin_href(slug))}">{esc(prog)}</a>' if slug else esc(prog),
            tag("done", "ok") if complete else tag("partial", "warn"),
            _clink(done, _fn_href(slug)) if slug else fnum(done),
            fnum(total),
            f"{(seconds or 0):.0f}s",
            f"{done / seconds:,.0f}/s" if seconds else "-",
            fnum(n_rows),
            _clink(named, _fn_href(slug, "&named=1")) if slug else fnum(named),
            fpct(named, n_rows),
            fnum(d[1]) if d else "-",
            fnum(d[2]) if d else "-",
            fnum(d[3]) if d else "-",
            fnum(d[4]) if d else "-",
        ])
        chart_rows.append((slug or prog, done or 0, "proven" if complete else "partial"))

    # Cached functions per program, sorted — the same "cached" column as the
    # table, drawn first so the 22-program comparison isn't only readable a
    # row at a time.
    chart = bars(chart_rows, href_fn=lambda slug, *_: _bin_href(slug))

    head = ('<div class="ptitle"><b>Per-program knowledge</b>'
            + tag(f"{len(status_rows)} programs") + "</div>")
    body = chart + _details(table(
        ["Program", "Status", "Cached", "Offered", "Ingest", "Rate", "Rows",
         "Named", "Named %", "Decompiled", "Asm", "Instructions", "Refs"],
        rows, numeric=set(range(2, 13))))

    if snap.get("error"):
        note = missing(f"deep columns unavailable: {snap['error']}")
    elif snap.get("fresh"):
        note = (f'<p class="sub">Decompiled / asm / instruction / ref totals '
                f'measured {esc(ago(snap["ts"]))} in a single full pass over the '
                f'2.7 GB table ({snap["seconds"]:.0f}s). They are re-measured '
                f'only when the cache file changes.</p>')
    elif snap.get("running"):
        note = ('<p class="sub">Decompiled / asm / instruction / ref totals are '
                'being measured now — one full pass over the 2.7 GB table, which '
                'takes about a minute on this disk. Everything else on this row '
                'is live.</p>')
    else:
        note = missing("deep totals not measured yet")
    if live_err:
        note += missing(live_err)

    named_note = ('<p class="sub">Named = a function this fork carries a real '
                  'name for. It varies by an order of magnitude between builds, '
                  'which is the reason all 24 are merged instead of one.</p>')
    return panel(head + body + note + named_note)


def _gaps_section(status_rows) -> str:
    """Binaries the project tracks that have no per-function export."""
    ingested = {r[0]: r[1] for r in status_rows}
    bins, err = query_db("SELECT repo_path FROM binary ORDER BY repo_path")
    if err:
        return panel(missing(err))
    if not bins:
        return panel(missing("corpus store has no binary rows"))

    root = as_external() / "binaries"
    try:
        dirs = {d.name for d in root.iterdir() if d.is_dir()}
    except OSError as exc:
        return panel(missing(f"cannot list {root}: {exc}"))

    slugs = _slugs()
    rows, gaps = [], 0
    state_counts = {"cached": 0, "exported, not ingested": 0, "no export": 0,
                    "not in MizuchiRE": 0}
    for (repo_path,) in bins:
        name = Path(str(repo_path)).name
        drm = str(repo_path) in DRM_EXCLUDED
        has_dir = name in dirs
        exported = has_dir and (root / name / "ghidra_knowledge" / "functions"
                                / "index.json").exists()
        cached = ingested.get(name)
        if cached:
            state = tag("cached", "ok")
            state_counts["cached"] += 1
        elif exported:
            state = tag("exported, not ingested", "warn")
            state_counts["exported, not ingested"] += 1
        elif has_dir:
            state = tag("no export", "dead")
            state_counts["no export"] += 1
        else:
            state = tag("not in MizuchiRE", "dead")
            state_counts["not in MizuchiRE"] += 1
        if not cached and not drm:
            gaps += 1
        slug = slugs.get(str(repo_path))
        rows.append([
            f'<a href="{esc(_bin_href(slug))}">{esc(repo_path)}</a>'
            if slug else esc(repo_path),
            state,
            tag("DRM ciphertext", "warn") if drm else "",
            _clink(cached, _fn_href(slug)) if (cached and slug) else "-",
        ])

    # All 24 binaries, broken into the same four knowledge states the table
    # rows carry as tags — the whole is the corpus, so this is one bar, not a
    # per-build comparison.
    chart = stacked_bar([
        ("cached", state_counts["cached"], "proven"),
        ("exported, not ingested", state_counts["exported, not ingested"], "partial"),
        ("no export", state_counts["no export"], "failed"),
        ("not in MizuchiRE", state_counts["not in MizuchiRE"], "unproven"),
    ])

    stray = sorted(dirs - {Path(str(b[0])).name for b in bins})
    head = ('<div class="ptitle"><b>Knowledge gaps across the 24 binaries</b>'
            + tag(f"{gaps} unexplained gap{'s' if gaps != 1 else ''}",
                  "ok" if not gaps else "dead") + "</div>")
    body = chart + _details(table(["Binary", "Knowledge", "Note", "Functions cached"],
                                  rows, numeric={3}))
    if stray:
        body += ('<p class="sub" style="margin-top:8px">MizuchiRE directories '
                 'the project database does not track: ' + esc(", ".join(stray))
                 + "</p>")
    return panel(head + body)


# --------------------------------------------------------------------------


def _render() -> str:
    status_rows, status_err = query_db(
        "SELECT program, functions_done, functions_total, seconds, complete "
        "FROM ingest_status ORDER BY program", db=KNOWLEDGE_DB)

    intro = ('<p class="sub">Every binary is a different fork of the same game '
             'and every fork was reverse-engineered differently. MizuchiRE '
             'exported what Ghidra knows about each function — C, asm, '
             'instructions with bytes and relocations, calling convention, '
             'signature, file offset. This page tracks that knowledge landing '
             'in db/ghidra_knowledge.sqlite.</p>')

    top = ('<div class="grid3">' + _server_section()
           + _scale_section(status_rows, status_err)
           + _coverage_section(status_rows) + "</div>")
    return (intro + top + _programs_section(status_rows, status_err)
            + _gaps_section(status_rows))


def render() -> str:
    try:
        return _render()
    except Exception as exc:  # noqa: BLE001 - a panel must never break the page
        return panel(missing(f"knowledge panel failed: {type(exc).__name__}: {exc}"))
