"""Corpus dashboard pages — honest headline, drill-downs, no completion claims.

Served from the AgentDecompile MCP HTTP app (default 8080). This module does
not bind ports. Real C and byte-accuracy stay separate columns.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path
from urllib.parse import quote, urlencode

from agentdecompile_recovery.corpus.dashboard.common import (
    DB_PATH,
    DRM_EXCLUDED,
    GHIDRA_SERVER_HOST,
    GHIDRA_SERVER_PORT,
    ROOT,
    ago,
    as_root,
    live_root,
    esc,
    fnum,
    load_json,
    format_address,
    parse_address,
    query_db,
    rel,
    table as render_table,
    tcp_up,
    table_exists,
)
from agentdecompile_recovery.corpus.dashboard.panels import viz

try:
    from agentdecompile_recovery.corpus.dashboard.common import count_link
except ImportError:
    count_link = None

from agentdecompile_recovery.corpus.io import read_json

WORKSPACE_NAME = (
    os.environ.get("BINARY_ANALYSIS_WORKSPACE_NAME")
    or os.environ.get("AGENT_DECOMPILE_WORKSPACE_NAME")
    or "AgentDecompile corpus"
).strip()
STATIC_ROOT = Path(__file__).resolve().parent / "static"

MAX_ARTIFACT_BYTES = 512 << 10
ARTIFACT_SNIFF_BYTES = 8 << 10
MAX_DIR_ENTRIES = 500
ARTIFACT_ROOT_NAMES = ("output", "reports", "logs", "docs", "data", ".mission")
ARTIFACT_TEXT_SUFFIXES = {
    ".txt", ".log", ".json", ".jsonl", ".md", ".csv", ".tsv", ".yaml", ".yml",
    ".html", ".xml", ".map", ".diff", ".patch",
}
ARTIFACT_DENIED_WORDS = {
    "key", "secret", "token", "credential", "password", "cookie", "session",
    "private", "id_rsa", "id_ed25519", ".env", "clipboard",
}
BINARY_SUFFIXES = {
    ".sqlite", ".db", ".mv", ".a", ".o", ".obj", ".so", ".dll", ".exe", ".xbe",
    ".bin", ".png", ".jpg", ".jpeg", ".gif", ".zip", ".gz", ".xz", ".7z",
    ".ipa", ".apk", ".jar", ".class", ".wal", ".shm", ".pyc",
}

PROBE_TTL = 10.0
STARTED_AT = datetime.now()

COVERAGE = as_root() / "output" / "exact_universal" / "_coverage.json"
QUEUE_SUMMARY = as_root() / "output" / "work_queue" / "logical_queue_summary.json"
CLAIM = (
    "This is a live view. It is not completion. Real C and "
    "byte-accuracy are separate. A green label is not a match."
)

# --------------------------------------------------------------------------
# panel loading
# --------------------------------------------------------------------------


def _load(name: str):
    """Import one panel module. A broken panel costs its own section, not the page."""
    try:
        module = __import__(f"agentdecompile_recovery.corpus.dashboard.panels.{name}", fromlist=["render"])
        if not hasattr(module, "render"):
            return None, f"{name}.py has no render()"
        return module, None
    except Exception:  # noqa: BLE001
        return None, traceback.format_exc(limit=3)


# Implementer B owns callgraph.py. Mount it the same way as everything else so
# the page is complete whether that file is finished, broken, or absent.
callgraph, CALLGRAPH_ERR = _load("callgraph")


def _load_any(name: str):
    """Import a panel module without demanding a `render()`.

    The entity pages expose `render_functions` / `render_function` /
    `render_logical` instead, so `_load`'s contract does not fit them.
    """
    try:
        return __import__(f"agentdecompile_recovery.corpus.dashboard.panels.{name}", fromlist=["*"]), None
    except Exception:  # noqa: BLE001
        return None, traceback.format_exc(limit=3)


# entities.py is written by another implementer and may not exist yet. The
# import is retried on request rather than only at boot, so the drill-down
# starts answering the moment that file lands — no restart of this server.
_LATE_LOCK = threading.Lock()
_LATE: dict[str, dict] = {}
LATE_RETRY = 5.0


def _late_module(name: str):
    """Return (module, error_text) for a module another author is still writing."""
    now = time.time()
    with _LATE_LOCK:
        slot = _LATE.setdefault(name, {"mod": None, "err": None, "at": 0.0})
        if slot["mod"] is not None:
            return slot["mod"], None
        if now - slot["at"] < LATE_RETRY:
            return None, slot["err"]
        slot["at"] = now
    mod, err = _load_any(name)
    with _LATE_LOCK:
        _LATE[name] = {"mod": mod, "err": err, "at": now}
    return mod, err


class Section:
    """One mounted panel.

    `lazy` sections are not rendered on the landing page at all — their body is
    fetched when the reader expands them. That is what keeps a 30-second panel
    from deciding how fast the page paints, and it is the same rule the design
    notes give for collapsed content: a section nobody opened costs nothing.
    """

    def __init__(self, sid, title, why, module=None, error=None,
                 lazy=False, open_default=False, ttl=15.0, heavy=False):
        self.id = sid
        self.title = title
        self.why = why
        self.module = module
        self.error = error
        self.lazy = lazy
        self.open_default = open_default
        self.ttl = ttl
        # `heavy` sections are on the landing page but refresh on a worker: they
        # read enough of a busy disk to have taken twelve seconds, and no page
        # load should ever wait that long for a section that is already on screen.
        self.heavy = heavy


def _sections() -> list[Section]:
    # (id, title, why, lazy, open_default, ttl, heavy)
    #
    # Rule A (10-relationship-layout.md): the page's top level is subjects, not
    # producing scripts. Every section below this point is producer-named — it
    # is the thing Rule A deletes from the landing view — so all nine are now
    # `lazy`, folded under one closed "more about the corpus" wrapper rather
    # than opened on load. The corpus-wide facts a reader actually wants first
    # (the pipeline, the per-build comparison) are drawn straight from
    # steps.collect() / the binary table as SVG, above this list, in
    # render_pipeline_rail() / render_binary_bars().
    specs = [
        ("steps", "Where the work stands",
         "Every step from reading the binaries to proving the build, each state "
         "read from a file on disk. The pipeline rail above is the same data, "
         "drawn as a picture instead of eight open panels.", True, False, 30.0, True),
        # Heavy, not because it computes much, but because it stats every
        # evidence path a directive claims. Measured: one landing request in
        # sixty took 14.7 s while the recovery jobs held the disk, and this was
        # the last section still rendering in the request thread.
        ("directives", "Mission contract",
         "One consolidated goal, its acceptance criteria, and live evidence "
         "checked against the filesystem.", False, False, 10.0, True),
        ("binaries", "The binaries",
         "The 24 builds this project reads, and which of them are in scope.",
         True, False, 30.0, False),
        ("crossmatch", "Cross-match between builds",
         "Which functions in one build are the same function in another, and how "
         "far that has been carried.", True, False, 45.0, True),
        ("recovery", "Source recovery",
         "Ghidra C, mutated and recompiled, until the bytes match without any "
         "assembly in the body.", True, False, 30.0, True),
        ("roundtrip", "Rebuild proof",
         "Reassembling each image from its own byte dump, and the export packages "
         "that come out of it.", True, False, 60.0, True),
        ("knowledge", "Ghidra knowledge merge",
         "Per-function Ghidra data from every fork, ingested once into an indexed "
         "store.", True, False, 300.0, True),
        ("stabs", "Original source names",
         "STABS records and symbol tables, and the .cpp paths they recover.",
         True, False, 120.0, True),
        ("processes", "Live jobs and logs",
         "What is running now, and the last lines each job wrote.", True, False,
         8.0, True),
    ]
    out = []
    for sid, title, why, lazy, open_default, ttl, heavy in specs:
        module, error = _load(sid)
        out.append(Section(sid, title, why, module, error, lazy, open_default,
                           ttl, heavy))
    return out


SECTIONS = _sections()
SECTION_BY_ID = {s.id: s for s in SECTIONS}


# --------------------------------------------------------------------------
# render cache
# --------------------------------------------------------------------------


class Cached:
    __slots__ = ("html", "etag", "at", "duration", "failed")

    def __init__(self, html, etag, at, duration, failed):
        self.html, self.etag = html, etag
        self.at, self.duration, self.failed = at, duration, failed


_CACHE: dict[str, Cached] = {}
_CACHE_LOCK = threading.Lock()
_RENDER_LOCKS: dict[str, threading.Lock] = {}


def _etag(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", "replace")).hexdigest()[:12]


def _lock_for(key: str) -> threading.Lock:
    with _CACHE_LOCK:
        return _RENDER_LOCKS.setdefault(key, threading.Lock())


def render_cached(key: str, fn, ttl: float) -> Cached:
    """Render at most once per `ttl`, once at a time, and never raise.

    Single-flight matters more than the cache here: several browser tabs and the
    poll timer all ask for the same panel, and without the lock a 30-second read
    would be started three times over on one disk.
    """
    now = time.time()
    hit = _CACHE.get(key)
    if hit and (now - hit.at) < ttl:
        return hit
    lock = _lock_for(key)
    if not lock.acquire(blocking=False):
        # Someone else is already reading this. Serving the older copy is the
        # honest option; the section prints its own age.
        if hit:
            return hit
        lock.acquire()
    try:
        hit = _CACHE.get(key)
        if hit and (time.time() - hit.at) < ttl:
            return hit
        started = time.time()
        try:
            html = fn()
            failed = False
        except Exception:  # noqa: BLE001 - a panel must never blank the page
            html = ('<p class="miss">this panel raised while rendering</p>'
                    f"<pre class=\"log\">{esc(traceback.format_exc(limit=4))}</pre>")
            failed = True
        entry = Cached(html, _etag(html), time.time(), time.time() - started, failed)
        _CACHE[key] = entry
        return entry
    finally:
        lock.release()


_INFLIGHT: dict[str, float] = {}


def render_async(key: str, fn, ttl: float):
    """Start the render on a worker and answer immediately.

    Some panels read a 2.6 GB store on a disk the recovery jobs are also using,
    and have taken minutes when that disk is busy. A request thread must never
    wait on that: it returns whatever is known, says the read is still running
    and how long it has been going, and the client asks again.
    """
    now = time.time()
    hit = _CACHE.get(key)
    if hit and (now - hit.at) < ttl:
        return hit, 0.0
    with _CACHE_LOCK:
        started = _INFLIGHT.get(key)
        if started is None:
            started = now
            _INFLIGHT[key] = started
            threading.Thread(target=_render_worker, args=(key, fn),
                             daemon=True).start()
    return hit, max(0.0, now - started)


def _render_worker(key: str, fn) -> None:
    started = time.time()
    try:
        html = fn()
        failed = False
    except Exception:  # noqa: BLE001
        html = ('<p class="miss">this panel raised while rendering</p>'
                f'<pre class="log">{esc(traceback.format_exc(limit=4))}</pre>')
        failed = True
    _CACHE[key] = Cached(html, _etag(html), time.time(), time.time() - started, failed)
    with _CACHE_LOCK:
        _INFLIGHT.pop(key, None)


def section_body(section: Section) -> Cached:
    if section.module is None:
        html = ('<p class="miss">panel not loaded</p>'
                f'<pre class="log">{esc(section.error or "unknown import error")}</pre>')
        return Cached(html, _etag(html), time.time(), 0.0, True)
    return render_cached(f"panel:{section.id}", section.module.render, section.ttl)


def section_body_async(section: Section) -> tuple[str, bool]:
    """(html, still_reading) for a panel that must not block a request thread."""
    if section.module is None:
        return ('<p class="miss">panel not loaded</p>'
                f'<pre class="log">{esc(section.error or "unknown import error")}</pre>',
                False)
    entry, pending = render_async(f"panel:{section.id}", section.module.render,
                                  section.ttl)
    if entry is None:
        return (f'<p class="annot">reading {esc(section.id)} &mdash; '
                f"{pending:.0f}s so far. This panel reads a large store on a "
                "shared disk; the page will fill it in.</p>", True)
    age = (f'<p class="annot">rendered {esc(ago(entry.at))} in '
           f"{entry.duration:.2f}s"
           + (f" &middot; re-reading now, {pending:.0f}s so far" if pending else "")
           + "</p>")
    return entry.html + age, bool(pending)


# --------------------------------------------------------------------------
# cheap probes
# --------------------------------------------------------------------------


_PROBES: dict[str, tuple[float, dict]] = {}
_PROBE_INFLIGHT: dict[str, float] = {}
_PROBE_LOCK = threading.Lock()


def _probe_worker(key: str, fn) -> None:
    try:
        value = fn()
    except Exception as exc:  # noqa: BLE001
        value = {"state": "unmeasured", "text": f"{type(exc).__name__}: {exc}"}
    _PROBES[key] = (time.time(), value)
    with _PROBE_LOCK:
        _PROBE_INFLIGHT.pop(key, None)


def _probe(key: str, fn) -> dict:
    """Serve the last health check and refresh it on a worker.

    These look cheap — one TCP connect, one `stat`, one `COUNT(*)` over a
    24-row table — and they are, until the recovery jobs have the spinning
    disk. Measured: a probe refresh took 5.9 s at load average 68, and every
    reader waited on it because it ran in the request thread. Same rule the
    panels already follow: answer with what is known, refresh behind the page.
    """
    hit = _PROBES.get(key)
    if hit and (time.time() - hit[0]) < PROBE_TTL:
        return hit[1]
    with _PROBE_LOCK:
        if key not in _PROBE_INFLIGHT:
            _PROBE_INFLIGHT[key] = time.time()
            threading.Thread(target=_probe_worker, args=(key, fn),
                             daemon=True).start()
    if hit:
        return hit[1]
    return {"state": "unmeasured", "text": f"{key} — measuring"}


def _probe_ghidra():
    up = tcp_up(GHIDRA_SERVER_HOST, GHIDRA_SERVER_PORT)
    return {"state": "done" if up else "failed",
            "text": f"ghidra {GHIDRA_SERVER_HOST}:{GHIDRA_SERVER_PORT} "
                    f"{'reachable' if up else 'refused'}"}


def _probe_db():
    try:
        if DB_PATH is None:
            raise OSError("AGENT_DECOMPILE_CORPUS_DB is unset")
        stat = DB_PATH.stat()
    except OSError as exc:
        return {"state": "failed", "text": f"corpus store unreadable: {exc}"}
    rows, err = query_db("SELECT COUNT(*) FROM binary")
    if err:
        return {"state": "failed", "text": f"corpus store: {err}"}
    return {"state": "done",
            "text": f"db {stat.st_size / (1 << 20):,.0f} MB, written {ago(stat.st_mtime)}, "
                    f"{fnum(rows[0][0])} binaries"}


def _probe_disk():
    try:
        st = os.statvfs(as_root())
    except OSError as exc:
        return {"state": "unmeasured", "text": f"disk unknown: {exc}"}
    free = st.f_bavail * st.f_frsize
    total = st.f_blocks * st.f_frsize
    pct = (free / total * 100) if total else 0
    state = "done" if pct >= 10 else ("partial" if pct >= 3 else "failed")
    return {"state": state, "text": f"disk {free / (1 << 30):,.0f} GB free ({pct:.0f}%)"}


# --------------------------------------------------------------------------
# the honest headline
# --------------------------------------------------------------------------


def headline_numbers() -> dict:
    """Read source recovery in one unit: unique logical functions.

    Recovery rows are artifacts. Concrete addresses and logical identities are
    different entities, so neither row count may be divided by a concrete
    function total. Unplaced source stays visible as a separate quality signal.
    """
    out = {"real_c": None, "placed_concrete": None, "unplaced_real_c": None,
           "queued": None,
           "errors": []}

    row, err = query_db(
        "SELECT COUNT(DISTINCT CASE WHEN real_c=1 THEN logical_id END), "
        "COUNT(DISTINCT CASE WHEN real_c=1 AND binary_id IS NOT NULL AND addr IS NOT NULL "
        "THEN printf('%d:%lld', binary_id, addr) END), "
        "SUM(real_c=1 AND logical_id IS NULL) FROM recovered_function",
        ignore_missing=True,
    )
    if err:
        out["errors"].append(err)
    elif row:
        out["real_c"], out["placed_concrete"], out["unplaced_real_c"] = row[0]

    queue, q_err = load_json(QUEUE_SUMMARY)
    if q_err:
        out["errors"].append(q_err)
    elif isinstance(queue, dict):
        out["queued"] = queue.get("logical_functions_queued")
    return out


def headline_numbers_for_slugs(slugs: set[str]) -> dict:
    """Tab-scoped headline: recovered logical functions for selected builds only."""
    if not slugs:
        return headline_numbers()
    out = {"real_c": None, "placed_concrete": None, "unplaced_real_c": None,
           "queued": None, "errors": []}
    placeholders = ",".join("?" * len(slugs))
    row, err = query_db(
        "SELECT COUNT(DISTINCT CASE WHEN r.real_c=1 THEN r.logical_id END), "
        "COUNT(DISTINCT CASE WHEN r.real_c=1 AND r.binary_id IS NOT NULL AND r.addr IS NOT NULL "
        "THEN printf('%d:%lld', r.binary_id, r.addr) END), "
        "SUM(r.real_c=1 AND r.logical_id IS NULL) "
        "FROM recovered_function r JOIN binary b ON b.id=r.binary_id "
        f"WHERE b.slug IN ({placeholders})",
        tuple(sorted(slugs)),
        ignore_missing=True,
    )
    if err:
        out["errors"].append(err)
    elif row:
        out["real_c"], out["placed_concrete"], out["unplaced_real_c"] = row[0]
    return out


def render_session_hero(slugs: set[str]) -> str:
    """Compact recovery headline for the workbench overview island."""
    n = headline_numbers_for_slugs(slugs)
    real_c = n.get("real_c")
    if real_c is None:
        return ""
    report_href = "/report?embed=1"
    return (
        '<section class="hero hero-compact">'
        '<div class="hero-main">'
        '<h2 class="eyebrow">Verified readable C in this tab</h2>'
        f'<p class="hero-n is-partial">'
        f'<span class="num">{_hero_count(real_c, report_href, "logical functions with assembly-free source in tab builds")}</span>'
        f' <span class="of">logical functions</span></p>'
        f'<p class="hero-meta">{fnum(n.get("placed_concrete"))} concrete instances · '
        f'{fnum(n.get("unplaced_real_c"))} without logical identity</p>'
        '</div></section>'
    )


def _pct(part, whole) -> str:
    """Percent with enough digits to stay a number instead of becoming '0.00%'.

    The headline sits near 0.1%, where two decimal places round away most of the
    signal and every further recovery would look like no movement at all.
    """
    try:
        part, whole = float(part), float(whole)
    except (TypeError, ValueError):
        return "-"
    if whole <= 0:
        return "-"
    value = part / whole * 100
    if value == 0:
        return "0%"
    digits = 2 if value >= 1 else (4 if value >= 0.01 else 6)
    return f"{value:.{digits}f}%"


def _src_chip(path: Path, note: str = "") -> str:
    """One evidence chip: basename on screen, full path in the title.

    05-visual-system §3.4's rule, and it is also what keeps the hero's source
    row to one line instead of two — three full repo paths wrapped, and the
    wrap cost more of the landing budget than the paths were worth.
    """
    label = esc(path.name)
    full = esc(rel(path))
    try:
        stamp = ago(path.stat().st_mtime)
    except OSError:
        return f'<span class="src broken" title="{full}">{label} &middot; missing</span>'
    # `note` is markup, not text: a chip that states a count has to carry that
    # count as a link like every other count on the page (Rule 1). Callers pass
    # already-escaped HTML.
    extra = f'<span class="age">{note}</span>' if note else ""
    href = "/dashboard/evidence/database" if path == DB_PATH else f"/dashboard/artifact?p={full}"
    return (f'<a class="src" href="{href}" title="{full}">{label}</a>'
            f'<span class="age">{esc(stamp)}</span>{extra}')


def render_database_evidence() -> tuple[str, int]:
    """Safe metadata view for the database that backs dashboard metrics."""
    rows, err = query_db(
        "SELECT name, type FROM sqlite_master WHERE type IN ('table','index') "
        "AND name NOT LIKE 'sqlite_%' ORDER BY type, name"
    )
    trail = [("overview", "/dashboard"), ("database evidence", None)]
    if err:
        return _drill("Database evidence", trail, missing_html(err)), 503
    try:
        if DB_PATH is None:
            raise OSError("AGENT_DECOMPILE_CORPUS_DB is unset")
        stat = DB_PATH.stat()
        facts = (f'<div class="kv"><div><b>{stat.st_size / (1 << 20):,.1f} MB</b>'
                 '<span>database size</span></div>'
                 f'<div><b>{esc(ago(stat.st_mtime))}</b><span>last written</span></div>'
                 f'<div><b>{sum(1 for _n, kind in rows if kind == "table")}</b><span>tables</span></div>'
                 f'<div><b>{sum(1 for _n, kind in rows if kind == "index")}</b><span>indexes</span></div></div>')
    except OSError as exc:
        facts = missing_html(str(exc))
    listing = render_table(["object", "type"], [[esc(name), esc(kind)] for name, kind in rows])
    body = ('<p class="sub">This page exposes schema metadata without offering the live '
            'database as a download.</p>' + facts + listing)
    return _drill("Database evidence", trail, body), 200


def _hero_count(n, href: str, title: str) -> str:
    """A headline figure that opens the set it counts (Rule 1 of 09-linked-entities).

    The corpus-wide function list is per build, so `/functions?real_c=1` lands on
    the build picker rather than on 562 rows. That is still the set's door; the
    title says which column produced the number so the reader can tell what they
    are about to open.
    """
    if count_link is not None:
        try:
            return count_link(n, href, title=title)
        except Exception:  # noqa: BLE001
            pass
    if n is None:
        return '<span class="cnt none">not attempted</span>'
    return f'<a class="cnt" href="{esc(href)}" title="{esc(title)}">{fnum(n)}</a>'


def render_hero() -> str:
    n = headline_numbers()
    real_c, queued = n["real_c"], n["queued"]
    frac = 0.0
    if real_c and queued:
        frac = real_c / queued

    if real_c is None or queued is None:
        value = ('<span class="num">&mdash;</span>'
                 '<span class="of"> not measurable</span>')
        state = "unmeasured"
    else:
        value = (
            '<span class="num">'
            + _hero_count(real_c, "/functions?real_c=1",
                          "unique logical functions with assembly-free byte-matched source")
            + '</span><span class="of"> of '
            + _hero_count(queued, f"/artifact?p={rel(QUEUE_SUMMARY)}",
                          "logical functions in the current recovery queue")
            + f'</span> <span class="st">({_pct(real_c, queued)})</span>')
        state = "partial" if real_c else "not started"

    errors = "".join(f'<p class="miss">{esc(e)}</p>' for e in n["errors"])

    return (
        '<section class="hero">'
        '<div class="hero-main">'
        # The landing view had no <h1> at all: its heading rank started at the
        # section titles. The hero's eyebrow is the page's subject, so it is
        # the h1, at the same 12px it already rendered.
        '<h1 class="eyebrow">Recover readable source</h1>'
        f'<p class="hero-n is-{esc(state.replace(" ", "-"))}">{value}</p>'
        f'<div class="bar big st-{esc(state.replace(" ", "-"))}">'
        f'<i style="width:{frac * 100:.5f}%"></i></div>'
        '<p class="hero-sub">Both numbers are logical functions. '
        'A result counts only when C or C++ compiles to the shipped bytes. '
        'Wrappers and assembly exports never count.</p>'
        f'<p class="hero-meta">{fnum(n.get("placed_concrete"))} concrete instances are '
        f'address-bound. {fnum(n.get("unplaced_real_c"))} assembly-free artifacts remain '
        'unplaced and are not included in this ratio.</p>'
        f'{errors}</div>'
        '<div class="srcs">'
        + (_src_chip(DB_PATH, "recovered_function table") if DB_PATH is not None else
           '<span class="src broken">AGENT_DECOMPILE_CORPUS_DB unset</span>')
        + _src_chip(QUEUE_SUMMARY,
                    _hero_count(n["queued"],
                                f"/artifact?p={rel(QUEUE_SUMMARY)}",
                                "logical_functions_queued in "
                                "logical_queue_summary.json")
                    + " logical functions queued")
        + "</div></section>"
    )


# --------------------------------------------------------------------------
# page assembly
# --------------------------------------------------------------------------


def render_statusbar() -> str:
    probes = render_status_probes()
    chips = "".join(
        f'<span class="chip st-{esc(p["state"].replace(" ", "-"))}">{esc(p["text"])}</span>'
        for p in probes)
    return (
        '<header class="topbar">'
        f'<a class="brand" href="/dashboard">{esc(WORKSPACE_NAME)}</a>'
        '<nav aria-label="Primary"><a href="/dashboard">Overview</a>'
        '<a href="/dashboard/functions">Functions</a>'
        '<a href="/atlas">Atlas</a>'
        '</nav>'
        f'<span class="chips">{chips}</span>'
        '<span class="pulse" id="pulse">loading</span>'
        "</header>"
    )


def render_status_probes() -> list[dict]:
    """Health chips shared by the classic overview and the React workbench."""
    return [
        _probe("db", _probe_db),
        _probe("ghidra", _probe_ghidra),
        _probe("disk", _probe_disk),
    ]


def _headline_byte_exact() -> tuple[int | str, list[str]]:
    """Receipt-backed byte identity only. Never added to real_c.

    recovered_function has no byte_exact column. Missing measurement is
    the word unmeasured, not 0.
    """
    errors: list[str] = []
    cov, cov_err = load_json(COVERAGE)
    if cov_err:
        errors.append(cov_err)
    if isinstance(cov, dict) and cov.get("byte_exact") is not None:
        try:
            return int(cov.get("byte_exact")), errors
        except (TypeError, ValueError):
            pass
    if isinstance(cov, list):
        total = 0
        found = False
        for item in cov:
            if not isinstance(item, dict) or item.get("byte_exact") is None:
                continue
            found = True
            try:
                total += int(item.get("byte_exact") or 0)
            except (TypeError, ValueError):
                pass
        if found:
            return total, errors
    root = as_root()
    for cand in (
        root / "output" / "objdiff-check.json",
        root / "objdiff-check.json",
    ):
        data, _err = load_json(cand)
        if isinstance(data, dict) and data.get("byte_exact") is not None:
            try:
                return int(data.get("byte_exact")), errors
            except (TypeError, ValueError):
                pass
    return "unmeasured", errors


def render_corpus_status() -> dict:
    """JSON for the workbench Overview / Pipeline React surfaces."""
    from agentdecompile_recovery.corpus.dashboard.panels import steps

    n = headline_numbers()
    byte_exact, byte_errs = _headline_byte_exact()
    errors = list(n.get("errors") or []) + byte_errs
    try:
        ladder = steps.as_payload()
    except Exception as exc:  # noqa: BLE001 — panel must stay up
        ladder = {"at": None, "errors": [str(exc)], "corpus_steps": [], "binaries": []}
    errors.extend(ladder.get("errors") or [])
    atlas_host = os.environ.get("DECOMP_ATLAS_HOST") or "127.0.0.1"
    atlas_port = os.environ.get("DECOMP_ATLAS_PORT") or "5173"
    return {
        "ok": True,
        "claimBoundary": CLAIM,
        "headline": {
            "real_c": n.get("real_c"),
            "byte_exact": byte_exact if byte_exact is not None else "unmeasured",
            "placed_concrete": n.get("placed_concrete"),
            "unplaced_real_c": n.get("unplaced_real_c"),
            "queued": n.get("queued"),
        },
        "probes": render_status_probes(),
        "atlas": {
            "in_tree": "/atlas",
            "decomp": f"http://{atlas_host}:{atlas_port}/",
        },
        "ladder": ladder,
        "report": recovery_report_json(),
        "mission": _mission_json(),
        "review": review_queue_json(),
        "errors": errors,
    }


def review_queue_json(limit: int = 40) -> dict:
    """Review-tier match rows for the React review tab."""
    out = {"ok": True, "by_status": {}, "rows": [], "errors": []}
    counts, err = query_db("SELECT status, COUNT(*) FROM match GROUP BY status")
    if err:
        out["ok"] = False
        out["errors"].append(err)
        return out
    out["by_status"] = {str(s or ""): int(n or 0) for s, n in counts}
    rows, rerr = query_db(
        "SELECT src_binary, src_addr, dst_binary, dst_addr, score, status, id, evidence "
        "FROM match WHERE status='review' ORDER BY score DESC LIMIT ?",
        (int(limit),),
        ignore_missing=True,
    )
    if rerr:
        out["errors"].append(rerr)
        return out
    out["rows"] = [
        {
            "match_id": r[6],
            "evidence": r[7],
            "src_binary_id": r[0],
            "src_addr": r[1],
            "dst_binary_id": r[2],
            "dst_addr": r[3],
            "score": r[4],
            "status": r[5],
            "src_name": "",
            "dst_name": "",
        }
        for r in rows
    ]
    return out


def logical_listing_json(q: str = "", after: int = 0, limit: int | str = "all") -> dict:
    """Logical identities for the React identities window."""
    from agentdecompile_recovery.corpus.dashboard.common import page_window

    _, cap = page_window(0, limit)
    out = {"ok": True, "q": q or "", "after": int(after or 0), "rows": [], "more": False, "limit": "all" if cap is None else cap, "errors": []}
    has_names = table_exists("logical_name")
    name = "COALESCE(ln.name, lf.best_name, lf.canon_key)" if has_names else "COALESCE(lf.best_name, lf.canon_key)"
    tier = "ln.tier_name" if has_names else "NULL"
    name_join = "LEFT JOIN logical_name ln ON ln.logical_id=lf.id " if has_names else ""
    binds: list[object] = [int(after or 0)]
    where = "WHERE lf.id>?"
    if q:
        where += f" AND ({name} LIKE ? ESCAPE '\\' OR lf.canon_key LIKE ? ESCAPE '\\')"
        escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        binds.extend([f"%{escaped}%", f"%{escaped}%"])
    sql = (
        f"SELECT lf.id, {name}, {tier}, "
        "COUNT(i.binary_id), MAX(i.confidence), lf.source_file "
        "FROM logical_function lf " + name_join +
        "LEFT JOIN identity i ON i.logical_id=lf.id " + where +
        " GROUP BY lf.id ORDER BY lf.id"
    )
    if cap is not None:
        sql += " LIMIT ?"
        binds.append(cap)
    rows, err = query_db(sql, tuple(binds), ignore_missing=True)
    if err:
        out["ok"] = False
        if "no such table" in str(err).lower():
            out["empty_reason"] = "No logical identities yet. They appear after cross-build matching."
        else:
            out["errors"].append(err)
        return out
    out["more"] = False
    out["rows"] = [
        {
            "id": r[0],
            "name": r[1] or "unnamed",
            "tier": r[2] or "unresolved",
            "members": r[3],
            "confidence": r[4],
            "source_file": Path(r[5]).name if r[5] else "",
        }
        for r in rows
    ]
    return out


def logical_detail_json(raw_id: str) -> tuple[dict, int]:
    try:
        lid = int(raw_id)
    except (TypeError, ValueError):
        return {"ok": False, "error": f"{raw_id} is not a logical function id"}, 404
    lf, err = query_db(
        "SELECT canon_key, canon_class, canon_method, game, best_name, best_signature, "
        "source_file, object_file, n_members FROM logical_function WHERE id=?",
        (lid,),
        ignore_missing=True,
    )
    if err:
        return {"ok": False, "error": err}, 503
    if not lf:
        return {"ok": False, "error": f"no logical function #{lid}"}, 404
    keys = (
        "canon_key", "canon_class", "canon_method", "game", "best_name",
        "best_signature", "source_file", "object_file", "n_members",
    )
    g = dict(zip(keys, lf[0]))
    members, merr = query_db(
        "SELECT b.slug, i.addr, i.confidence, i.method, i.evidence FROM identity i "
        "JOIN binary b ON b.id=i.binary_id WHERE i.logical_id=? ORDER BY b.slug",
        (lid,),
        ignore_missing=True,
    )
    rows = []
    if not merr:
        for slug, addr, conf, method, evidence in members or []:
            rows.append({
                "slug": slug,
                "addr": format_address(int(addr)) if addr is not None else "",
                "confidence": conf,
                "method": method or "",
                "evidence": evidence,
            })
    payload = {
        "ok": True,
        "id": lid,
        "name": g.get("best_name") or g.get("canon_key") or f"#{lid}",
        "members": rows,
        "errors": [merr] if merr else [],
    }
    payload.update(g)
    return payload, 200


def binary_page_json(slug: str) -> tuple[dict, int]:
    rec = _binary(slug)
    if rec is None:
        return {"ok": False, "error": f"no build called {slug} is in the binary table"}, 404
    bid = int(rec["id"])
    ident_rows, ident_err = query_db(
        "SELECT COUNT(*), COUNT(DISTINCT logical_id) FROM identity WHERE binary_id=?",
        (bid,),
        ignore_missing=True,
    )
    bound = logicals = 0
    if not ident_err and ident_rows:
        bound, logicals = (ident_rows[0][0] or 0, ident_rows[0][1] or 0)
    recov_rows, recov_err = query_db(
        "SELECT COUNT(*), COUNT(DISTINCT logical_id), "
        "COUNT(DISTINCT CASE WHEN addr IS NOT NULL THEN addr END) "
        "FROM recovered_function WHERE binary_id=? AND real_c=1",
        (bid,),
        ignore_missing=True,
    )
    artifacts = logical = concrete = None
    if not recov_err and recov_rows and recov_rows[0][0]:
        artifacts, logical, concrete = recov_rows[0]
    total = rec.get("func_count") or 0
    wanted = [
        (as_root() / "output" / "export_cpp" / str(rec["slug"]), "readable source package"),
        (as_root() / "extract" / "stabs" / f"{rec['slug']}.json", "STABS dump"),
        (as_root() / str(rec["repo_path"]).lstrip("/"), "the binary itself"),
    ]
    disk = []
    for path, label in wanted:
        disk.append({
            "label": label,
            "path": rel(path) if path else "",
            "exists": bool(path and path.exists()),
        })
    errors = [e for e in (ident_err, recov_err) if e]
    return {
        "ok": True,
        "slug": rec["slug"],
        "id": bid,
        "repo_path": rec.get("repo_path") or "",
        "game": rec.get("game") or "",
        "platform": rec.get("platform") or "",
        "arch": rec.get("arch") or "",
        "bits": rec.get("bits"),
        "format": rec.get("format") or "",
        "md5": rec.get("md5") or "",
        "func_count": rec.get("func_count"),
        "named_count": rec.get("named_count"),
        "role": rec.get("role") or "",
        "identity": {
            "bound": bound,
            "logicals": logicals,
            "unbound": max(0, int(total or 0) - int(bound or 0)),
        },
        "recovery": {
            "artifacts": artifacts,
            "logical": logical,
            "concrete": concrete,
        },
        "artifacts": disk,
        "errors": errors,
    }, 200


def session_overview_json(slugs: list[str], programs: list[str] | None = None) -> dict:
    slug_set = {str(item).strip() for item in slugs if str(item).strip()}
    program_names = [str(item).strip() for item in (programs or []) if str(item).strip()]
    headline = headline_numbers_for_slugs(slug_set) if slug_set else {}
    by_slug, _, err = _binaries()
    rows = []
    for name in sorted(slug_set):
        rec = by_slug.get(name)
        if rec:
            rows.append({
                "slug": rec["slug"],
                "game": rec.get("game"),
                "platform": rec.get("platform"),
                "func_count": rec.get("func_count"),
                "named_count": rec.get("named_count"),
                "role": rec.get("role"),
            })
        else:
            rows.append({"slug": name, "missing": True})
    return {
        "ok": True,
        "slugs": sorted(slug_set),
        "programs": program_names,
        "programsTitle": "Project programs",
        "programHint": "Program in the open Ghidra project",
        "headline": headline,
        "binaries": rows,
        "empty": not slug_set and not program_names,
        "errors": [err] if err else [],
    }


def database_evidence_json() -> tuple[dict, int]:
    rows, err = query_db(
        "SELECT name, type FROM sqlite_master WHERE type IN ('table','index') "
        "AND name NOT LIKE 'sqlite_%' ORDER BY type, name"
    )
    if err:
        return {"ok": False, "error": err, "objects": []}, 503
    size_mb = None
    mtime = None
    if DB_PATH is None:
        return {"ok": False, "error": "AGENT_DECOMPILE_CORPUS_DB is unset", "objects": []}, 503
    try:
        stat = DB_PATH.stat()
        size_mb = round(stat.st_size / (1 << 20), 1)
        mtime = ago(stat.st_mtime)
    except OSError as exc:
        return {"ok": False, "error": str(exc), "objects": []}, 503
    objects = [{"name": name, "type": kind} for name, kind in rows]
    return {
        "ok": True,
        "path": rel(DB_PATH),
        "size_mb": size_mb,
        "mtime": mtime,
        "tables": sum(1 for item in objects if item["type"] == "table"),
        "indexes": sum(1 for item in objects if item["type"] == "index"),
        "objects": objects,
    }, 200


def artifact_json(raw: str = "") -> tuple[dict, int]:
    work = _work_dir()
    if not raw:
        if work is not None and work.is_dir():
            return _artifact_dir_json(work.resolve(), rel(work.resolve())), 200
        return {"ok": False, "error": "Set AGENT_DECOMPILE_CORPUS_WORK_DIR to a run directory."}, 200
    target, err = _resolve_artifact(raw)
    if target is None:
        status = 403 if err and str(err).startswith("refused") else 404
        return {"ok": False, "error": err or "not found"}, status
    parent = ""
    allowed_roots = []
    if ROOT is not None:
        allowed_roots.extend((ROOT.resolve() / name).resolve() for name in ARTIFACT_ROOT_NAMES)
    if work is not None:
        allowed_roots.append(work.resolve())
    if target not in allowed_roots:
        parent = rel(target.parent)
    if target.is_dir():
        payload = _artifact_dir_json(target, rel(target))
        payload["parent"] = parent
        return payload, 200
    return _artifact_file_json(target, rel(target), parent), 200


def _artifact_dir_json(target: Path, relpath: str) -> dict:
    try:
        entries = sorted(os.scandir(target), key=lambda e: (not e.is_dir(), e.name))
    except OSError as exc:
        return {"ok": False, "error": str(exc), "path": relpath, "kind": "dir", "entries": []}
    rows = []
    for entry in entries[:MAX_DIR_ENTRIES]:
        child = rel(Path(entry.path))
        public_child, denied = _resolve_artifact(child)
        if denied or public_child is None:
            continue
        try:
            stat = public_child.stat()
            size = None if public_child.is_dir() else stat.st_size
            when = ago(stat.st_mtime)
        except OSError:
            size, when = None, "?"
        rows.append({
            "name": entry.name,
            "path": child,
            "dir": public_child.is_dir(),
            "size": size,
            "mtime": when,
        })
    return {
        "ok": True,
        "kind": "dir",
        "path": relpath,
        "entries": rows,
        "truncated": len(entries) > MAX_DIR_ENTRIES,
    }


def _artifact_file_json(target: Path, relpath: str, parent: str) -> dict:
    try:
        size = target.stat().st_size
    except OSError as exc:
        return {"ok": False, "error": str(exc), "path": relpath, "kind": "file"}
    if target.suffix.lower() in BINARY_SUFFIXES:
        return {
            "ok": True,
            "kind": "file",
            "path": relpath,
            "parent": parent,
            "size": size,
            "text": "",
            "binary": True,
        }
    try:
        with target.open("rb") as fh:
            head = fh.read(ARTIFACT_SNIFF_BYTES)
            if b"\x00" in head:
                return {
                    "ok": True,
                    "kind": "file",
                    "path": relpath,
                    "parent": parent,
                    "size": size,
                    "text": "",
                    "binary": True,
                }
            rest = fh.read(max(0, MAX_ARTIFACT_BYTES - len(head)))
    except OSError as exc:
        return {"ok": False, "error": str(exc), "path": relpath, "kind": "file"}
    text = (head + rest).decode("utf-8", "replace")
    if target.suffix.lower() == ".json" and size <= MAX_ARTIFACT_BYTES:
        try:
            text = json.dumps(json.loads(text), indent=1)
        except ValueError:
            pass
    return {
        "ok": True,
        "kind": "file",
        "path": relpath,
        "parent": parent,
        "size": size,
        "text": text,
        "truncated": size > MAX_ARTIFACT_BYTES,
        "binary": False,
    }


PANEL_WINDOW = {
    "steps": "wb-pipeline",
    "knowledge": "wb-knowledge",
    "stabs": "wb-stabs",
    "processes": "wb-processes",
    "recovery": "wb-recovery",
    "roundtrip": "wb-roundtrip",
    "binaries": "wb-corpus",
    "crossmatch": "wb-match",
    "directives": "wb-mission",
    "callgraph": "wb-graph",
    "entities": "wb-fnbrowse",
}


def panel_payload_json(sid: str) -> tuple[dict, int]:
    section = SECTION_BY_ID.get(sid or "")
    if section is None:
        return {"ok": False, "error": f"no such panel {sid}"}, 404
    payload = None
    if section.module is not None:
        as_payload = getattr(section.module, "as_payload", None)
        if callable(as_payload):
            try:
                payload = as_payload()
            except Exception as exc:  # noqa: BLE001
                payload = {"error": str(exc)}
    return {
        "ok": True,
        "id": section.id,
        "title": section.title,
        "why": section.why,
        "window": PANEL_WINDOW.get(section.id, "wb-overview"),
        "payload": payload,
    }, 200


def browse_block_json(block: str, query: dict) -> tuple[dict, int]:
    name = (block or "").strip().lower()
    if name not in BROWSE_BLOCKS:
        return {"ok": False, "error": f"no browse block called {block or ''}"}, 404
    params = {k: (v[0] if v else "") for k, v in query.items()}
    if name == "logical":
        return logical_listing_json(
            q=params.get("lq") or params.get("logical_q") or "",
            after=int(params.get("logical_after") or 0 or 0) if str(params.get("logical_after") or "").isdigit() else 0,
            limit=params.get("limit") or "all",
        ), 200
    if name == "review":
        return review_queue_json(), 200
    if name == "builds":
        from agentdecompile_recovery.corpus.dashboard.panels import steps
        return {"ok": True, "block": name, "binaries": (steps.as_payload() or {}).get("binaries") or []}, 200
    if name == "graph":
        return {"ok": True, "block": name, "window": "wb-graph"}, 200
    slug = (params.get("binary") or params.get("slug") or "").strip()
    from agentdecompile_recovery.corpus.dashboard.workbench import list_functions
    payload = list_functions(slug, q=params.get("q") or "", offset=0, limit="all")
    payload["block"] = name
    return payload, 200


def _mission_json() -> dict:
    from agentdecompile_recovery.corpus.dashboard.panels import directives

    goal, err = directives._load_goal()
    if err or not isinstance(goal, dict):
        return {"ok": False, "error": err or "mission contract missing"}
    evidence = [x for x in goal.get("evidence", []) if isinstance(x, str)]
    return {
        "ok": True,
        "id": goal.get("id") or "MASTER",
        "title": goal.get("title") or "",
        "objective": goal.get("objective") or "",
        "status": goal.get("status") or "in_progress",
        "acceptance": [x for x in goal.get("acceptance_criteria", []) if isinstance(x, str)],
        "evidence": evidence,
    }


def render_section(section: Section, level: int = 2) -> str:
    """One <details> per panel, with a stable key so a refresh cannot close it.

    `level` is the heading rank for this section's title. The nine producer-
    named panels nest inside one "more about the corpus" wrapper (Rule A), so
    their titles render as <h3>, not <h2> — a reader's h2 outline should list
    the page's actual subjects, not eight scripts one level down.
    """
    attrs = (f'class="sec" data-sec="{esc(section.id)}" '
             f'data-k="sec.{esc(section.id)}"')
    if section.open_default:
        attrs += " open"

    if section.lazy:
        body = ('<div class="sec-body" data-loaded="0">'
                '<p class="annot">expand to load this panel</p></div>')
        meta = '<span class="age">loads on expand</span>'
        return (f'<details {attrs} data-lazy="{esc(section.id)}" data-etag="lazy">'
                f"<summary>{_summary(section, meta, level)}</summary>{body}</details>")

    if section.heavy:
        html, pending = section_body_async(section)
        meta = ('<span class="age">reading now</span>' if pending
                else '<span class="age">up to date</span>')
        return (f'<details {attrs} data-etag="{_etag(html)}">'
                f"<summary>{_summary(section, meta, level)}</summary>"
                f'<div class="sec-body" data-loaded="1">{html}</div></details>')

    entry = section_body(section)
    meta = (f'<span class="age">rendered {esc(ago(entry.at))} '
            f'in {entry.duration:.2f}s</span>')
    return (f'<details {attrs} data-etag="{esc(entry.etag)}">'
            f"<summary>{_summary(section, meta, level)}</summary>"
            f'<div class="sec-body" data-loaded="1">{entry.html}</div></details>')


def _summary(section: Section, meta: str, level: int = 2) -> str:
    extra = ""
    if section.id == "directives" and section.module is not None:
        # The summary counts the same evidence files the body stats, so it gets
        # the same treatment: last known answer now, fresh one on a worker.
        entry, _pending = render_async("secsum:directives",
                                       section.module.summary, section.ttl)
        if entry is not None and not entry.failed:
            extra = f'<span class="secsum">{entry.html}</span>'
    tag = f"h{max(2, min(6, level))}"
    return (f'<{tag} class="sec-title">{esc(section.title)}</{tag}>{extra}'
            f'<p class="sec-why">{esc(section.why)}</p>{meta}')


# --------------------------------------------------------------------------
# Subject 1 — the corpus: the pipeline rail and the per-build comparison.
#
# Both are read from data other panels already compute (steps.collect(), the
# cached binary table), rendered as SVG via viz.py rather than as text tables,
# per Rule C. Neither scans `func`: the rail's numbers come from steps.py's
# own facts cache, and the bars use `binary.code_func_count` /
# `binary.func_count`, which the extractor already wrote per build.
# --------------------------------------------------------------------------

# steps.py's state vocabulary (done/partial/running/not started/unmeasured/
# failed) predates viz.py's five-state palette (proven/partial/unproven/
# failed/excluded). This is the one place the two meet.
_RAIL_STATE = {
    "done": "proven",
    "partial": "partial",
    "running": "partial",
    "not started": "unproven",
    "unmeasured": "unproven",
    "failed": "failed",
}


def _rail_state(raw) -> str:
    return _RAIL_STATE.get(str(raw or "").strip().lower(), "unproven")


def _step_fraction(step: dict) -> float:
    """Same rule steps.py's own renderer uses, kept local: dashboard.py must
    not depend on a leading-underscore name in a module another agent is
    concurrently editing."""
    done, total = step.get("done"), step.get("total")
    if step.get("state") in ("not started", "unmeasured"):
        return 0.0
    try:
        if not total:
            return 0.0
        return max(0.0, min(1.0, float(done) / float(total)))
    except (TypeError, ValueError):
        return 0.0


def _rail_rows(steps: list[dict]) -> list[tuple]:
    rows = []
    for s in steps or []:
        title = s.get("title") or s.get("label") or "step"
        href = s.get("done_href") or s.get("total_href")
        rows.append((title, _step_fraction(s), _rail_state(s.get("state")), href))
    return rows


def render_pipeline_rail() -> tuple[str, bool]:
    """The 8-step pipeline as one SVG rail (Rule D item 2), async and cached.

    `steps.collect()` reads the same fact snapshot `steps.render()` does, which
    has taken minutes on a busy disk (see steps.py, `_warm_steps` below). A
    request thread must not wait on that, so this shares the render_async
    worker pattern `_steps_for_binary` already uses.
    """
    section = SECTION_BY_ID.get("steps")
    module = section.module if section else None
    if module is None:
        return (_late_missing("steps", section.error if section else None,
                              "The pipeline rail"), False)
    collect = getattr(module, "collect", None)
    if collect is None:
        return ('<div class="callout"><b>steps.py has no collect().</b> '
                'Falling back to the full ladder in "More about the corpus".'
                '</div>', False)

    def _build() -> str:
        return viz.rail(_rail_rows(collect()))

    entry, pending = render_async("rail:corpus", _build, section.ttl)
    if entry is None:
        return (f'<p class="annot">reading the pipeline &mdash; {pending:.0f}s '
                'so far. This shares one read of the artifact tree with the '
                'per-build pages, on a disk the recovery jobs are also using.'
                '</p>', True)
    html = entry.html
    if pending:
        html += (f'<p class="annot" data-pending="1">re-reading now, '
                 f"{pending:.0f}s so far</p>")
    return html, bool(pending)


def render_binary_bars(*, slugs: set[str] | None = None) -> str:
    """One bar per build (Rule D item 3), each a door to `/binary/<slug>`.

    Reads only the cached `binary` table snapshot `_binaries()` already keeps
    for the drill-down pages — no query beyond what the page was already
    paying for. `code_func_count` is preferred over `func_count` where present
    (kx/fix_func_counts.py); a count is a magnitude, not a verification claim,
    so every bar takes the neutral state, same reasoning viz.py uses for its
    histogram and heatmap.

    When ``slugs`` is set, only those corpus rows are shown (workbench tab scope).
    """
    try:
        by_slug, _, err = _binaries()
        if err:
            return missing_html(err)
        rows = []
        for slug, rec in sorted(by_slug.items()):
            if slugs is not None and slug not in slugs:
                continue
            repo = str(rec.get("repo_path") or "")
            if repo in DRM_EXCLUDED:
                continue
            count = rec.get("code_func_count")
            if not count:
                count = rec.get("func_count") or 0
            rows.append((slug, count, "unproven"))
        if not rows:
            return missing_html("no binaries loaded yet")
        # Two columns, not one: 22 builds stacked cost 380px, which is most of
        # the one-screen budget Rule D allows the whole landing view. Sorted
        # globally first, then split, so the two columns read as one ranked
        # list rather than as two unrelated charts.
        rows.sort(key=lambda r: (-(r[1] or 0), r[0]))
        peak = max((r[1] or 0) for r in rows) or 1
        half = (len(rows) + 1) // 2
        # A shorter bar than viz.bars' own default: 22+ builds at the default
        # 14px would alone blow the one-screen budget (Rule D). 9px keeps every
        # build visible without a table, the fallback Rule C forbids.
        cols = [
            viz.bars(chunk, height=9, sort=False, max_value=peak,
                     href_fn=lambda label, value, state: _href_binary(label))
            # One shared max_value across both columns. Letting each column
            # scale to its own peak would draw the 11th build as long as the
            # 1st, which is the kind of quiet lie the charts exist to stop.
            for chunk in (rows[:half], rows[half:]) if chunk
        ]
        return '<div class="barcols">' + "".join(cols) + "</div>"
    except Exception:  # noqa: BLE001 - one bad chart, not one bad page
        return ('<p class="miss">this panel raised while rendering</p>'
                f'<pre class="log">{esc(traceback.format_exc(limit=4))}</pre>')


# The nine sections named after the script that produced them (Rule A: "nine
# panels named after nine scripts is the thing being deleted"). Everything
# binary-specific among them already lives on /binary/<slug>
# (_binary_facts/_binary_identity/_binary_recovery/_binary_artifacts, below).
# What is left is genuinely corpus-wide, so it stays reachable from the
# landing view as one closed section rather than nine open ones.
OLD_SECTION_IDS = ("steps", "processes")


def render_more_section() -> str:
    inner = "".join(render_section(SECTION_BY_ID[sid], level=3)
                    for sid in OLD_SECTION_IDS if sid in SECTION_BY_ID)
    return (
        '<details class="sec" data-sec="more" data-k="sec.more">'
        '<summary><h2 class="sec-title">More about the corpus</h2>'
        '<p class="sec-why">Pipeline detail and current jobs. Build, function, '
        'identity, recovery, and relationship data each have a direct workspace above.'
        '</p></summary>'
        f'<div class="sec-body">{inner}</div></details>'
    )


HERO_TTL = 10.0
LIVE_TTL = 5.0

def _live_corpus() -> tuple[str, Path, Path, int]:
    """Active program, recovered-source dir, workspace dir, function denominator."""
    program = os.environ.get("AGENT_DECOMPILE_CORPUS_PROGRAM", "").strip()
    bulk_root = as_root() / "data" / "recovered-source-ghidra"
    if not program and bulk_root.is_dir():
        dirs = sorted(p.name for p in bulk_root.iterdir() if p.is_dir())
        program = dirs[0] if dirs else ""
    bulk = bulk_root / program if program else bulk_root
    donor = os.environ.get("AGENT_DECOMPILE_CORPUS_DONOR", "").strip()
    ws = as_root() / "output" / "workspaces" / donor if donor else as_root() / "output" / "workspaces"
    denom = 0
    rows, _err = query_db("SELECT COALESCE(SUM(func_count), 0) FROM binary")
    if rows:
        try:
            denom = int(rows[0][0] or 0)
        except (TypeError, ValueError):
            denom = 0
    return program, bulk, ws, denom


def _scandir_c_count(path: Path) -> int:
    try:
        return sum(1 for e in os.scandir(path) if e.name.endswith(".c") and e.is_file())
    except OSError:
        return 0


def _tail1(path: Path) -> str:
    try:
        with path.open("rb") as fh:
            fh.seek(0, 2)
            n = fh.tell()
            fh.seek(max(0, n - 1200))
            lines = fh.read().decode("utf-8", "replace").strip().splitlines()
        return lines[-1] if lines else ""
    except OSError:
        return ""


def _cmdline_has(needle: str) -> bool:
    """True if some process cmdline contains needle. /proc only, no pgrep."""
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                raw = Path("/proc", pid, "cmdline").read_bytes()
            except OSError:
                continue
            if needle.encode() in raw.replace(b"\x00", b" "):
                return True
    except OSError:
        return False
    return False


def render_live_priority() -> str:
    """Landing-page strip for the current compile-first + identity-match work.

    The hero is byte-exact logical recovery (a different claim). This strip is
    what the standalone dashboard was missing: Ghidra-C compile count, whether the bulk
    pass and the corpus matcher are alive, and the last log line of each.
    """
    program, bulk_dir, ws_dir, denom = _live_corpus()
    compiled = _scandir_c_count(bulk_dir)
    logs = sorted((as_root() / "logs").glob("ghidra_bulk*.log"),
                  key=lambda p: p.stat().st_mtime if p.exists() else 0,
                  reverse=True)
    bulk_line = _tail1(logs[0]) if logs else ""
    bulk_on = _cmdline_has("ghidra_bulk.py")
    match_on = _cmdline_has("propagate.py")
    match_line = _tail1(as_root() / "logs" / "cross_match_all.log")
    ws_files = 0
    if ws_dir.is_dir():
        for dirpath, _dns, fnames in os.walk(ws_dir):
            ws_files += sum(1 for n in fnames if n.endswith((".c", ".cpp", ".cp", ".h")))
    pct = 100.0 * compiled / denom if denom else 0
    width = min(100.0, pct)
    bulk_st = "running" if bulk_on else "idle"
    match_st = "running" if match_on else "idle"
    label = program or "active program"
    return (
        '<div class="block livepri">'
        '<div class="blockhead"><h2 class="h-sec">Live now</h2>'
        '<span class="sub">Ghidra-C compile is the current job for '
        f'{esc(label)}. Identity match does not use Wine. Byte-exact recovery '
        'is a different count.</span></div>'
        f'<div class="kv">'
        f'<div><b>{compiled:,} / {denom:,}</b>'
        f'<span>{esc(label)} Ghidra C compiling ({pct:.1f}%)</span></div>'
        f'<div><b>{esc(bulk_st)}</b><span>ghidra_bulk.py</span></div>'
        f'<div><b>{esc(match_st)}</b><span>propagate.py identity match</span></div>'
        f'<div><b>{ws_files:,}</b><span>debug-donor workspace files</span></div>'
        f'</div>'
        f'<div class="bar big"><i style="width:{width:.1f}%"></i></div>'
        f'<p class="sub"><code>ghidra_bulk</code> {esc(bulk_line or "(no log line yet)")}</p>'
        f'<p class="sub"><code>propagate</code> {esc(match_line or "(not started — no log yet)")}</p>'
        '</div>'
    )


def render_hero_block() -> str:
    """The hero, refreshed on a worker like every other disk reader.

    It is two small reads — one indexed aggregate, one 24-entry JSON — and it
    still blocked a request for seconds when the recovery jobs had the disk.
    The warm thread at boot means a reader effectively never sees the
    measuring state; when they do, it says so rather than showing a stale
    number without a date.
    """
    entry, pending = render_async("hero", render_hero, HERO_TTL)
    if entry is None:
        return ('<section class="hero"><div class="hero-main">'
                '<p class="eyebrow">Recovered source &mdash; real C <b>and</b> '
                'byte-identical</p>'
                '<p class="hero-n is-unmeasured"><span class="num">unmeasured</span>'
                f'<span class="of"> measuring, {pending:.0f}s so far</span></p>'
                '<p class="hero-sub">Read from <code>recovered_function</code> and '
                'from the coverage artifact, on a disk the recovery jobs are also '
                'using. The page fills this in.</p></div></section>')
    return entry.html


def render_body() -> str:
    # Each block is hashed from the html actually sent, so the client can skip a
    # swap when nothing moved — that is what keeps expanded sections expanded.
    bar = render_statusbar()
    hero = render_hero_block()
    live, _ = render_async("livepri", render_live_priority, LIVE_TTL)
    live_html = live.html if live is not None else (
        '<div class="block livepri"><p class="sub">measuring live jobs</p></div>')
    store_html = _complete_executable_strip()
    parts = [
        f'<div data-sec="statusbar" data-etag="{_etag(bar)}">{bar}</div>',
        f'<div data-sec="hero" data-etag="{_etag(hero)}">{hero}</div>',
        f'<div data-sec="store" data-etag="{_etag(store_html)}">{store_html}</div>',
        f'<div data-sec="livepri" data-etag="{_etag(live_html)}">{live_html}</div>',
    ]

    # Heading, one-line explanation and freshness share a row rather than
    # stacking: three stacked 18px lines above each chart cost more of the
    # one-screen budget than the charts they label.
    rail_html, rail_pending = render_pipeline_rail()
    rail_meta = ('<span class="age">reading now</span>' if rail_pending
                else '<span class="age">up to date</span>')
    parts.append(
        f'<div class="block" data-sec="rail" data-etag="{_etag(rail_html)}">'
        '<div class="blockhead"><h2 class="h-sec">Corpus-wide steps</h2>'
        '<span class="sub">Each step is a link to what proves it.</span>'
        f'{rail_meta}</div>{rail_html}</div>')

    bars_html = render_binary_bars()
    parts.append(
        f'<div class="block" data-sec="binbars" data-etag="{_etag(bars_html)}">'
        '<div class="blockhead"><h2 class="h-sec">Every build, compared</h2>'
        '<span class="sub">Functions per build, one scale. Click a bar to '
        'open that build.</span></div>'
        f'{bars_html}</div>')

    # One line, not a callout box: this is a signpost to another view, and a
    # bordered panel would make it a peer of the two charts above it.
    parts.append(
        '<p class="sub" data-sec="graphlink" data-etag="static">'
        'The call graph is for one function. It is not drawn on load. '
        '<a href="/dashboard?window=wb-graph">Open the call graph</a> · '
        '<a href="/dashboard#run">Run work on this page</a>.</p>')

    # Collapsed, these two are summaries and sit side by side; opened, either one
    # takes the full width back (CSS `[open]{grid-column:1/-1}`). That is what
    # buys the landing view its last 100px without hiding anything.
    parts.append(_home_workspace_sections())
    parts.append('<div class="tail">'
                 + render_section(SECTION_BY_ID["directives"])
                 + render_more_section() + "</div>")

    # No wall clock here: the status strip carries artifact ages and the pulse
    # carries the last update, so a footer that changed every second would make
    # "no change" impossible to say truthfully.
    parts.append(
        '<footer class="foot" data-sec="foot" data-etag="static">'
        f"<span>{esc(str(ROOT) if ROOT is not None else 'AGENT_DECOMPILE_CORPUS_ROOT unset')}</span>"
        f"<span>server started {esc(STARTED_AT.strftime('%Y-%m-%d %H:%M:%S'))}</span>"
        "<span>every number on this page names the file it came from</span>"
        "</footer>")
    return '<div class="wrap">' + _page_context(page="home") + "".join(parts) + "</div>"


def _static_text(name: str, fallback: str) -> str:
    try:
        return (STATIC_ROOT / name).read_text(encoding="utf-8")
    except OSError:
        return fallback


def render_page(body: str | None = None, title: str | None = None) -> str:
    # Only the overview refreshes itself. A drill-down carries no `data-sec`
    # blocks, so polling /fragment there would find nothing to patch and replace
    # the whole page with the overview — the reader would be thrown back up a
    # level mid-read.
    live = body is None
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{esc(title or WORKSPACE_NAME)}</title>"
        f"<style>{CSS}</style>"
        '<link rel="stylesheet" href="/dashboard/static/dashboard.css">'
        '<link rel="stylesheet" href="/dashboard/static/workbench.css"></head>'
        '<body class="workbench-page">'
        '<a class="skip-link" href="#app">Skip to content</a>'
        f'<main id="app" data-live="{1 if live else 0}" tabindex="-1">'
        f"{body if body is not None else render_body()}</main>"
        + _action_dock_html()
        + '<script src="/dashboard/static/dashboard.js" defer></script>'
        + '<script src="/dashboard/static/actions.js" defer></script>'
        + f"<script>{JS}</script></body></html>"
    )


# --------------------------------------------------------------------------
# /graph — Implementer B's panel, mounted defensively
# --------------------------------------------------------------------------


def _graph_params(query: dict) -> dict:
    def as_decimal(name):
        raw = (query.get(name) or [""])[0].strip()
        if not raw:
            return None
        try:
            return int(raw)
        except ValueError:
            return None

    params = {
        # Only addr is an address. IDs and pagination controls remain decimal;
        # applying legacy padded-address rules to them would silently change an
        # eight-digit ID into hexadecimal.
        "binary_id": as_decimal("binary_id"),
        "slug": (query.get("slug") or query.get("binary") or [None])[0],
        "addr": parse_address((query.get("addr") or [""])[0]),
        "logical_id": as_decimal("logical_id"),
        "depth": as_decimal("depth") or 2,
        "limit": as_decimal("limit") or 40,
        "direction": (query.get("direction") or ["both"])[0][:16],
        "density": (query.get("density") or ["comfortable"])[0][:16],
        "labels": (query.get("labels") or ["both"])[0][:16],
        "edges": (query.get("edges") or ["curved"])[0][:16],
        "ink": (query.get("ink") or ["default"])[0][:16],
        "heading": (query.get("heading") or ["1"])[0],
    }
    return params


def function_workspace_href(slug: str, addr: int, *, bits: int = 32, **params) -> str:
    hexed = format_address(addr, bits)
    keep = {"window": "wb-fnbrowse", "binary": slug, "addr": hexed}
    extra = {k: v for k, v in params.items()
             if v not in (None, "", "both", "comfortable", "curved", "default", 2, "2")}
    if params.get("depth") in (1, "1"):
        extra["depth"] = params["depth"]
    keep.update(extra)
    return "/dashboard?" + urlencode(keep)


def graph_to_function_target(query: dict) -> str:
    """Send /graph?slug=&addr= to the function workspace. Picker stays on Functions."""
    params = _graph_params(query)
    slug = params.get("slug")
    addr = params.get("addr")
    extra = {
        "depth": params.get("depth"),
        "direction": params.get("direction"),
        "density": params.get("density"),
        "labels": params.get("labels"),
        "edges": params.get("edges"),
        "ink": params.get("ink"),
    }
    if slug and addr is not None:
        rec = _binary(str(slug))
        bits = int((rec or {}).get("bits") or 32)
        return function_workspace_href(str(slug), int(addr), bits=bits, **extra)
    binary_id = params.get("binary_id")
    if binary_id and addr is not None:
        rows, err = query_db("SELECT slug, bits FROM binary WHERE id=? LIMIT 1", (int(binary_id),))
        if not err and rows:
            return function_workspace_href(str(rows[0][0]), int(addr), bits=int(rows[0][1] or 32), **extra)
    lid = params.get("logical_id")
    if lid:
        rows, err = query_db(
            "SELECT b.slug, i.addr, b.bits FROM identity i JOIN binary b ON b.id=i.binary_id "
            "WHERE i.logical_id=? ORDER BY i.confidence DESC, i.binary_id LIMIT 1",
            (int(lid),),
        )
        if not err and rows:
            return function_workspace_href(str(rows[0][0]), int(rows[0][1]), bits=int(rows[0][2] or 32), **extra)
    return "/dashboard?window=wb-graph"


def _call_fragment(fn, params: dict) -> str:
    """Call render_fragment however it chose to declare itself.

    The signature belongs to another author's module, so this adapts to it
    rather than dictating one: a single positional parameter gets the whole dict,
    named parameters get the subset they accept.
    """
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return fn(params)
    names = list(sig.parameters)
    has_var_kw = any(p.kind is inspect.Parameter.VAR_KEYWORD
                     for p in sig.parameters.values())
    if not names:
        return fn()
    if len(names) == 1 and not has_var_kw and \
            sig.parameters[names[0]].kind in (inspect.Parameter.POSITIONAL_ONLY,
                                              inspect.Parameter.POSITIONAL_OR_KEYWORD):
        try:
            return fn(params)
        except TypeError:
            pass
    accepted = {n for n, p in sig.parameters.items()
                if p.kind in (inspect.Parameter.POSITIONAL_OR_KEYWORD,
                              inspect.Parameter.KEYWORD_ONLY)}
    kwargs = {k: v for k, v in params.items() if has_var_kw or k in accepted}
    return fn(**kwargs)


def render_graph_embed(query: dict) -> str:
    """Call-graph fragment for the browse workspace. Never draws on poll."""
    params = json.dumps(_graph_params(query), sort_keys=True)
    if callgraph is None:
        return (
            '<div class="callout warn"><b>The call graph panel is not loaded.</b> '
            'The rest of the dashboard is unaffected.</div>'
            f'<pre class="log">{esc(CALLGRAPH_ERR or "callgraph panel missing")}</pre>'
        )
    fn = getattr(callgraph, "render_fragment", None) or getattr(callgraph, "render", None)
    if fn is None:
        return '<div class="callout warn"><b>callgraph.py has no render_fragment().</b></div>'
    try:
        body = _call_fragment(fn, _graph_params(query))
    except Exception:  # noqa: BLE001
        body = ('<div class="callout warn"><b>The call graph panel raised.</b></div>'
                f'<pre class="log">{esc(traceback.format_exc(limit=6))}</pre>')
    return f'<div data-sec="callgraph" data-params=\'{esc(params)}\'>{body}</div>'


def render_graph(query: dict) -> str:
    return (
        '<div class="wrap">' + render_statusbar()
        + '<h2 class="h-sec">Call graph</h2>'
        + render_graph_embed(query)
        + '<p class="annot">This view now lives on Functions. '
        '<a href="/dashboard?window=wb-graph">Open the browse workspace</a>.</p></div>'
    )


# --------------------------------------------------------------------------
# /artifact — evidence, path-confined and size-capped
# --------------------------------------------------------------------------


def _resolve_artifact(raw: str):
    """Resolve a public evidence path, or refuse.

    Repository containment alone is not an access boundary: this server binds
    publicly and the checkout contains credentials and source material.  Only
    explicit evidence roots and known text artifact types are publishable.
    """
    if raw is None or raw == "":
        return None, "no path given"
    if "\x00" in raw:
        return None, "path contains a null byte"
    work = _work_dir()
    live = ROOT or live_root()
    if live is None and work is None:
        return None, "AGENT_DECOMPILE_CORPUS_ROOT / AGENT_DECOMPILE_CORPUS_WORK_DIR is unset"
    root = (live or work).resolve()
    try:
        target = (root / raw).resolve()
    except (OSError, ValueError, RuntimeError) as exc:
        return None, f"path could not be resolved: {exc}"
    allowed_roots = []
    if ROOT is not None:
        allowed_roots.extend((ROOT.resolve() / name).resolve() for name in ARTIFACT_ROOT_NAMES)
    if work is not None:
        allowed_roots.append(work.resolve())
    if not any(target == base or target.is_relative_to(base) for base in allowed_roots):
        return None, "refused: that path is outside the public evidence roots"
    if not target.exists():
        return None, f"not on disk: {esc(raw)}"
    rel_parts = target.relative_to(root).parts
    lowered = "/".join(rel_parts).lower()
    if any(word in lowered for word in ARTIFACT_DENIED_WORDS):
        return None, "refused: sensitive artifact names are never served"
    if target.is_file() and target.suffix.lower() not in ARTIFACT_TEXT_SUFFIXES:
        return None, "refused: that file type is not a public text artifact"
    return target, None


def _artifact_dir(target: Path) -> str:
    try:
        entries = sorted(os.scandir(target), key=lambda e: (not e.is_dir(), e.name))
    except OSError as exc:
        return f'<p class="miss">{esc(str(exc))}</p>'
    rows = []
    for entry in entries[:MAX_DIR_ENTRIES]:
        child = rel(Path(entry.path))
        public_child, denied = _resolve_artifact(child)
        if denied or public_child is None:
            continue
        try:
            stat = public_child.stat()
            size = "&mdash;" if public_child.is_dir() else f"{stat.st_size:,}"
            when = ago(stat.st_mtime)
        except OSError:
            size, when = "?", "?"
        rows.append(
            f'<tr><td><a href="/artifact?p={esc(child)}">{esc(entry.name)}'
            f'{"/" if public_child.is_dir() else ""}</a></td>'
            f'<td class="num">{size}</td><td>{esc(when)}</td></tr>')
    more = ("" if len(entries) <= MAX_DIR_ENTRIES else
            f'<p class="annot">{fnum(len(entries) - MAX_DIR_ENTRIES)} more entries '
            "not listed</p>")
    return ('<div class="tablewrap"><table><thead><tr><th>Name</th>'
            '<th class="num">Bytes</th><th>Changed</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table></div>{more}')


def _artifact_file(target: Path) -> str:
    try:
        size = target.stat().st_size
    except OSError as exc:
        return f'<p class="miss">{esc(str(exc))}</p>'
    if target.suffix.lower() in BINARY_SUFFIXES:
        return ('<p class="miss">This is a binary artifact. The dashboard serves '
                'text and JSON only.</p>')
    try:
        with target.open("rb") as fh:
            head = fh.read(ARTIFACT_SNIFF_BYTES)
            if b"\x00" in head:
                return ('<p class="miss">This file contains null bytes, so it is '
                        'not text. The dashboard serves text and JSON only.</p>')
            rest = fh.read(max(0, MAX_ARTIFACT_BYTES - len(head)))
    except OSError as exc:
        return f'<p class="miss">{esc(str(exc))}</p>'

    text = (head + rest).decode("utf-8", "replace")
    truncated = size > MAX_ARTIFACT_BYTES
    if target.suffix.lower() == ".json" and not truncated:
        try:
            text = json.dumps(json.loads(text), indent=1)
        except ValueError:
            pass
    note = (f'<p class="miss">Showing the first {fnum(MAX_ARTIFACT_BYTES)} bytes of '
            f'{fnum(size)}.</p>' if truncated else "")
    return note + f'<pre class="log tall">{esc(text)}</pre>'


def render_artifact(query: dict) -> tuple[str, int]:
    raw = (query.get("p") or [""])[0]
    head = '<div class="wrap">' + render_statusbar()
    work = _work_dir()
    if not raw:
        if work is not None and work.is_dir():
            listing = _artifact_dir(work.resolve())
            return (head + '<h1 class="h-sec">Artifacts</h1>'
                    f'<p class="sub">listing <code>{esc(str(work))}</code></p>'
                    f"{listing}</div>"), 200
        return (head + '<h1 class="h-sec">Artifacts</h1>'
                '<p class="sub">Set AGENT_DECOMPILE_CORPUS_WORK_DIR to a run directory.</p></div>'), 200
    target, err = _resolve_artifact(raw)
    if target is None:
        return (head + f'<h1 class="h-sec">Artifact</h1>'
                f'<div class="callout warn">{esc(err)}</div></div>'), \
            (403 if err and err.startswith("refused") else 404)

    relpath = rel(target)
    allowed_roots = []
    if ROOT is not None:
        allowed_roots.extend((ROOT.resolve() / name).resolve() for name in ARTIFACT_ROOT_NAMES)
    if work is not None:
        allowed_roots.append(work.resolve())
    parent = "" if target in allowed_roots else rel(target.parent)
    try:
        stat = target.stat()
        meta = (f'<span class="age">{fnum(stat.st_size)} bytes</span>'
                f'<span class="age">changed {esc(ago(stat.st_mtime))}</span>')
    except OSError:
        meta = ""
    up = (f'<a href="/dashboard/artifact?p={esc(parent)}">&uarr; {esc(parent or ".")}</a>'
          if parent else "")
    body = _artifact_dir(target) if target.is_dir() else _artifact_file(target)
    return (head + f'<h1 class="h-sec">{esc(relpath)}</h1>'
            f'<div class="srcs">{meta}{up}</div>{body}</div>'), 200


# --------------------------------------------------------------------------
# drill-down pages — /functions, /function, /logical, /binary
#
# A drill-down is the same application one level down, so it is built from the
# same shell, the same status strip and the same stylesheet as `/`. Only the
# breadcrumb tells the reader where they are.
# --------------------------------------------------------------------------

BIN_COLUMNS = ("id", "slug", "repo_path", "game", "platform", "arch", "bits",
               "format", "md5", "image_base", "func_count", "named_count", "role")

# The binary table is 24 rows, but a drill-down page can ask for it several
# times per request. One short-lived snapshot keeps that free.
_BIN_LOCK = threading.Lock()
_BIN: dict = {"at": 0.0, "by_slug": {}, "by_repo": {}, "err": None, "db": ""}
BIN_TTL = 30.0


def _binaries() -> tuple[dict, dict, str | None]:
    """Return (by_slug, by_repo_path, error). Never raises."""
    from agentdecompile_recovery.corpus.dashboard.common import live_db

    now = time.time()
    db_key = str(live_db() or "")
    with _BIN_LOCK:
        if _BIN["by_slug"] and now - _BIN["at"] < BIN_TTL and _BIN.get("db") == db_key:
            return _BIN["by_slug"], _BIN["by_repo"], _BIN["err"]
    rows, err = query_db(f"SELECT {', '.join(BIN_COLUMNS)} FROM binary")
    by_slug, by_repo = {}, {}
    for row in rows:
        rec = dict(zip(BIN_COLUMNS, row))
        by_slug[str(rec["slug"])] = rec
        by_repo[str(rec["repo_path"])] = rec
    with _BIN_LOCK:
        _BIN.update(at=now, by_slug=by_slug, by_repo=by_repo, err=err, db=db_key)
    return by_slug, by_repo, err


def _binary(slug: str):
    by_slug, _, _ = _binaries()
    return by_slug.get(slug)


def _href_binary(slug: str) -> str:
    return "/dashboard?" + urlencode({"window": "wb-corpus", "binary": slug})


def _crumbs(trail: list[tuple[str, str | None]]) -> str:
    """Breadcrumb. The last item is the current page and carries no link."""
    parts = []
    for label, href in trail:
        if href:
            parts.append(f'<a href="{esc(href)}">{esc(label)}</a>')
        else:
            parts.append(f"<b>{esc(label)}</b>")
    return '<nav class="crumbs">' + '<span class="sep">/</span>'.join(parts) + "</nav>"


def _page_context(*, page: str, **fields: object) -> str:
    attrs = [f'data-page="{esc(page)}"']
    for key, value in fields.items():
        if value in (None, ""):
            continue
        attrs.append(f'data-{key.replace("_", "-")}="{esc(value)}"')
    return f'<div id="page-context" hidden {" ".join(attrs)}></div>'


def _action_dock_html() -> str:
    return (
        '<div id="action-dock" hidden>'
        '<div class="action-dock-bar">'
        '<button type="button" class="action-toggle" aria-expanded="false">Jobs</button>'
        '<span id="job-pulse" class="chip">no jobs</span>'
        "</div>"
        '<div class="action-dock-panel" hidden>'
        '<form id="action-form" hidden></form>'
        '<div id="action-jobs" class="action-jobs"></div>'
        "</div></div>"
    )


def _drill(
    title: str,
    trail: list[tuple[str, str | None]],
    body: str,
    *,
    page: str = "home",
    **context: object,
) -> str:
    return (
        '<div class="wrap">' + _page_context(page=page, **context) + render_statusbar()
        + _crumbs(trail) + f'<h1 class="h-sec">{esc(title)}</h1>'
        + '<div class="action-bar" id="action-bar"></div>'
        + body + "</div>"
    )


def _not_found(what: str, trail: list[tuple[str, str | None]]) -> str:
    return _drill("Not found", trail,
                  f'<div class="callout warn">{esc(what)}</div>'
                  '<p class="sub">Pick a build from the overview.</p>')


def _late_missing(name: str, err: str | None, what: str) -> str:
    """Say plainly that a page is not built yet, and show why, once."""
    detail = f'<pre class="log">{esc(err)}</pre>' if err else ""
    return ('<div class="callout warn">'
            f'<b>{esc(what)} is not available yet.</b> '
            f'<code>panels/{esc(name)}.py</code> did not load. Everything '
            'else on the dashboard still works.</div>' + detail)


def _entity_call(fname: str, *args, **kwargs):
    """Call one entity renderer. Returns (html, ok)."""
    mod, err = _late_module("entities")
    if mod is None:
        return _late_missing("entities", err, "This view"), False
    fn = getattr(mod, fname, None)
    if fn is None:
        return (_late_missing("entities", f"entities.py has no {fname}()",
                              "This view"), False)
    try:
        return fn(*args, **kwargs), True
    except Exception:  # noqa: BLE001 - a half-written renderer must not 500
        return ('<div class="callout warn"><b>This view raised while '
                'rendering.</b> The numbers it needed are still on the '
                'overview.</div>'
                f'<pre class="log">{esc(traceback.format_exc(limit=6))}</pre>'), False


STEPS_FILE = Path(__file__).resolve().parent / "panels" / "steps.py"
_STEPS_LOCK = threading.Lock()


def _mtime_or_none(path: Path):
    try:
        return path.stat().st_mtime
    except OSError:
        return None


# Recorded at boot, which is the version the loaded module reflects.
_STEPS_SEEN: dict = {"mtime": _mtime_or_none(STEPS_FILE)}


def _steps_file_changed() -> bool:
    mtime = _mtime_or_none(STEPS_FILE)
    if mtime is None:
        return False
    with _STEPS_LOCK:
        seen = _STEPS_SEEN["mtime"]
        _STEPS_SEEN["mtime"] = mtime
    return seen is not None and mtime != seen


def _steps_for_binary(slug: str) -> str:
    """Per-build step ladder from steps.py, which is gaining render_for_binary()."""
    section = SECTION_BY_ID.get("steps")
    module = section.module if section else None
    if module is None:
        return _late_missing("steps", section.error if section else None,
                             "The step ladder")
    fn = getattr(module, "render_for_binary", None)
    if fn is None and _steps_file_changed():
        # The function is being added right now, and the file on disk has moved
        # since we last looked. Reload only then: steps.py holds a 30-second
        # fact cache, so reloading on every request would throw that cache away
        # and make the overview recompute from a busy disk each time.
        try:
            import importlib

            module = importlib.reload(module)
            if section:
                section.module = module
            fn = getattr(module, "render_for_binary", None)
        except Exception:  # noqa: BLE001
            fn = None
    if fn is None:
        return ('<div class="callout"><b>The per-build step ladder is still being '
                'written.</b> The corpus-wide ladder is on the '
                '<a href="/dashboard">overview</a>.</div>')
    # The ladder itself is instant; the facts behind it read the whole artifact
    # tree and have taken minutes while the recovery jobs hold the disk. So it
    # renders on a worker: the page arrives now and says the read is running,
    # and the client comes back for it. A request thread never waits on a disk
    # another job is holding.
    entry, pending = render_async(f"steps:binary:{slug}", lambda: fn(slug), 60.0)
    if entry is None:
        return ('<div class="callout" data-pending="1"><b>Reading this build\'s '
                f'ladder &mdash; {pending:.0f}s so far.</b> It shares one read of '
                'the artifact tree with the overview, on a disk the recovery jobs '
                'are also using. This page will fill it in.</div>')
    if pending:
        return entry.html + ('<p class="annot" data-pending="1">re-reading now, '
                             f"{pending:.0f}s so far</p>")
    return entry.html


def _count_cell(n, href: str, unit: str = "") -> str:
    """Every count on a drill-down page is a door, same as on the overview.

    One spelling of the idea lives in common.count_link. This wrapper only
    survives that helper being absent.
    """
    if count_link is not None:
        try:
            return count_link(n, href, unit=unit or None)
        except Exception:  # noqa: BLE001
            pass
    if n is None:
        return '<span class="cnt none">not attempted</span>'
    text = fnum(n) + (f' <span class="unit">{esc(unit)}</span>' if unit else "")
    return f'<a class="cnt" href="{esc(href)}">{text}</a>'


def _artifact_row(path: Path, label: str) -> tuple[str, str] | None:
    """A (label, link) pair for an artifact, or None when it is not on disk."""
    if not path.exists():
        return None
    return (label, f'<a href="/dashboard/artifact?p={esc(rel(path))}">{esc(rel(path))}</a>')


def _binary_facts(rec: dict) -> str:
    slug = str(rec["slug"])
    fq = "/functions?binary=" + quote(slug, safe="")
    pairs = [
        ("File", f'<a href="/artifact?p={esc(str(rec["repo_path"]).lstrip("/"))}">'
                 f'<code>{esc(rec["repo_path"])}</code></a>'),
        ("Game", esc(rec.get("game") or "?")),
        ("Platform", esc(rec.get("platform") or "?")),
        ("Architecture", esc(f'{rec.get("arch") or "?"} / {rec.get("bits") or "?"}-bit')),
        ("Format", esc(rec.get("format") or "?")),
        ("MD5", f'<code>{esc(rec.get("md5") or "?")}</code>'),
        ("Functions", _count_cell(rec.get("func_count"), fq)),
        ("Named functions", _count_cell(rec.get("named_count"), fq + "&named=1")),
        ("Still a placeholder name",
         _count_cell(
             (rec.get("func_count") or 0) - (rec.get("named_count") or 0),
             fq + "&placeholder=1")),
        ("Call graph", f'<a href="/graph?binary_id={int(rec["id"])}">open the call '
                       "graph for this build</a>"),
    ]
    return kv_pairs(pairs)


def kv_pairs(pairs) -> str:
    items = "".join(f"<div>{esc(k)}</div><div>{v}</div>" for k, v in pairs)
    return f'<div class="kv">{items}</div>'


def _binary_identity(rec: dict) -> str:
    """Cross-match rows for one build. Indexed, so it costs nothing."""
    bid, slug = int(rec["id"]), str(rec["slug"])
    fq = "/functions?binary=" + quote(slug, safe="")
    rows, err = query_db(
        "SELECT COUNT(*), COUNT(DISTINCT logical_id) FROM identity WHERE binary_id=?",
        (bid,))
    if err:
        return missing_html(err)
    bound, logicals = (rows[0][0] or 0, rows[0][1] or 0) if rows else (0, 0)
    total = rec.get("func_count") or 0
    pairs = [
        ("Addresses bound to a logical function", _count_cell(bound, fq + "&bound=1")),
        ("Logical functions this build reaches", _count_cell(logicals, fq + "&bound=1")),
        ("Addresses bound to nothing",
         _count_cell(max(0, total - bound), fq + "&unbound=1")),
    ]
    # No breakdown by binding method here. `identity` is indexed on
    # (binary_id, addr, logical_id), so the counts above are read from the index
    # alone, but `method` lives in the row: grouping by it costs one random read
    # per binding — 11,853 of them for the Mac build — and that took minutes on
    # this disk. The method mix is on the cross-match panel, measured once.
    return kv_pairs(pairs)


def _binary_recovery(rec: dict) -> str:
    """Readable source evidence for one build."""
    bid, slug = int(rec["id"]), str(rec["slug"])
    fq = "/functions?binary=" + quote(slug, safe="")
    rows, err = query_db(
        "SELECT COUNT(*), COUNT(DISTINCT logical_id), "
        "COUNT(DISTINCT CASE WHEN addr IS NOT NULL THEN addr END) "
        "FROM recovered_function WHERE binary_id=? AND real_c=1",
        (bid,))
    artifacts = logical = concrete = None
    if not err and rows and rows[0][0]:
        # A zero here means no recovery run has touched this build, not that a
        # run found nothing. It stays None so it renders "not attempted".
        artifacts, logical, concrete = rows[0]
    pairs = [
        ("Verified source artifacts", _count_cell(artifacts, fq + "&real_c=1")),
        ("Logical functions represented", _count_cell(logical, fq + "&real_c=1")),
        ("Concrete addresses represented", _count_cell(concrete, fq + "&real_c=1")),
    ]
    note = ('<p class="sub">A verified source artifact contains no inline assembly or '
            'emitted machine code. It compiled to the shipped function bytes.</p>')
    out = kv_pairs(pairs) + note
    if err:
        out += missing_html(err)
    return out


def _binary_artifacts(rec: dict) -> str:
    """Where this build's evidence lives, as links rather than a file list."""
    repo = str(rec["repo_path"]).lstrip("/")
    slug = str(rec["slug"])
    wanted = [
        (as_root() / "output" / "export_cpp" / slug, "readable source package"),
        (as_root() / "extract" / "stabs" / f"{slug}.json", "STABS dump"),
        (as_root() / repo, "the binary itself"),
    ]
    pairs = [row for row in (_artifact_row(p, label) for p, label in wanted) if row]
    if not pairs:
        return missing_html("no artifact for this build is on disk yet")
    return kv_pairs(pairs)


def missing_html(msg: str) -> str:
    return f'<p class="miss">{esc(msg)}</p>'


def _work_dir() -> Path | None:
    raw = (os.environ.get("AGENT_DECOMPILE_CORPUS_WORK_DIR") or "").strip()
    if not raw:
        return None
    try:
        return Path(raw).expanduser()
    except (OSError, RuntimeError, ValueError):
        return None


def _func_source_sql() -> str:
    rows, err = query_db("PRAGMA table_info(func)")
    if err:
        return "f.source AS source_file"
    cols = {r[1] for r in rows if len(r) > 1}
    if "source_file" in cols:
        return "COALESCE(f.source_file, f.source) AS source_file"
    return "f.source AS source_file"


def _receipts() -> dict:
    work = _work_dir()
    if work is None or not work.is_dir():
        return {}
    out = {}
    for name in ("corpus-run.json", "compile.json", "extract.json", "identify.json"):
        path = work / name
        if path.is_file():
            try:
                out[name] = read_json(path)
            except (OSError, json.JSONDecodeError):
                continue
    return out


def _store_binary_table(limit: int = 80) -> str:
    rows, err = query_db(
        "SELECT slug, game, platform, func_count, named_count, role FROM binary ORDER BY slug"
    )
    if err:
        return f'<p class="sub">{esc(err)}</p>'
    if not rows:
        return '<p class="sub">No binaries in the corpus store.</p>'
    body_rows = []
    for slug, game, platform, funcs, named, role in rows[:limit]:
        href = _href_binary(str(slug))
        body_rows.append(
            f"<tr><td><a href=\"{esc(href)}\">{esc(slug)}</a></td>"
            f"<td>{esc(game or '')}</td><td>{esc(platform or '')}</td>"
            f"<td class=\"num\">{funcs or 0}</td><td class=\"num\">{named or 0}</td>"
            f"<td>{esc(role or '')}</td></tr>"
        )
    return (
        "<h2 class=\"h-sec\">Binaries</h2>"
        "<table><thead><tr><th>slug</th><th>game</th><th>platform</th>"
        "<th>funcs</th><th>named</th><th>role</th></tr></thead>"
        f"<tbody>{''.join(body_rows)}</tbody></table>"
    )


def _store_functions_table(slug: str | None = None, limit: int = 50, offset: int = 0) -> str:
    src = _func_source_sql()
    where = ""
    args: list = []
    if slug:
        where = "WHERE b.slug=?"
        args.append(slug)
    rows, err = query_db(
        f"""SELECT b.slug, f.addr, f.name, f.canon_key, {src}, f.n_instr
              FROM func f JOIN binary b ON b.id=f.binary_id
              {where}
             ORDER BY b.slug, f.addr LIMIT ? OFFSET ?""",
        tuple([*args, limit, offset]),
    )
    if err:
        return f'<p class="sub">{esc(err)}</p>'
    body_rows = []
    for row_slug, addr, name, canon, source_file, n_instr in rows:
        body_rows.append(
            f"<tr><td><a href=\"{_href_binary(str(row_slug))}\">{esc(row_slug)}</a></td>"
            f"<td><a href=\"/dashboard/function/{quote(str(row_slug), safe='')}/0x{int(addr):x}\">"
            f"0x{int(addr):x}</a></td>"
            f"<td>{esc(name or '')}</td><td>{esc(canon or '')}</td>"
            f"<td>{esc(source_file or '')}</td><td class=\"num\">{n_instr or 0}</td></tr>"
        )
    return (
        "<table><thead><tr><th>binary</th><th>addr</th><th>name</th>"
        "<th>canon</th><th>source</th><th>instr</th></tr></thead>"
        f"<tbody>{''.join(body_rows) or '<tr><td colspan=6>none</td></tr>'}</tbody></table>"
    )


def _store_function_detail(slug: str, addr: int) -> str:
    src = _func_source_sql()
    rows, err = query_db(
        f"""SELECT f.name, f.canon_key, {src}, f.n_instr, f.size, f.signature
              FROM func f JOIN binary b ON b.id=f.binary_id
             WHERE b.slug=? AND f.addr=?""",
        (slug, addr),
    )
    if err or not rows or len(rows[0]) < 6:
        return ""
    name, canon, source_file, n_instr, size, signature = rows[0]
    return (
        f"<p>name <code>{esc(name or '')}</code> · size {size or 0} · instr {n_instr or 0}</p>"
        f"<p>canon <code>{esc(canon or '')}</code></p>"
        f"<p>source <code>{esc(source_file or '')}</code></p>"
        f"<p>signature <code>{esc(signature or '')}</code></p>"
    )


def _complete_executable_strip() -> str:
    receipts = _receipts()
    compile_rec = receipts.get("compile.json") or (receipts.get("corpus-run.json") or {}).get("receipts", {}).get("compile") or {}
    run = receipts.get("corpus-run.json") or {}
    complete = bool(compile_rec.get("completeExecutable") or run.get("completeExecutable"))
    return (
        '<div class="block">'
        f'<p class="claim">{esc(CLAIM)}</p>'
        '<p>Real C and byte-accuracy are never summed. A linked image is compile proof only.</p>'
        '<div class="kv">'
        f"<div><b>{'yes' if complete else 'no'}</b><span>complete executable</span></div>"
        f"<div><b>{len(receipts)}</b><span>receipts on disk</span></div>"
        "</div>"
        f"{_store_binary_table()}"
        "</div>"
    )


def _sub_panel(title: str, body: str) -> str:
    return (f'<div class="panel"><div class="ptitle"><b>{esc(title)}</b></div>'
            f"{body}</div>")


def is_partial_query(query: dict) -> bool:
    raw = ((query.get("partial") or [""])[0] or "").strip().lower()
    return raw in {"1", "true", "yes"}


def _workspace_nav() -> str:
    items = (
        ("functions", "Functions"),
        ("logical", "Logical"),
        ("review", "Review"),
        ("graph", "Graph"),
        ("builds", "Builds"),
    )
    links = "".join(
        f'<a href="#{esc(anchor)}">{esc(label)}</a>' for anchor, label in items
    )
    return f'<nav class="workspace-nav" aria-label="Browse sections">{links}</nav>'


def _named_block(anchor: str, title: str, why: str, body: str, *, open_default: bool = False) -> str:
    attrs = f'class="sec" id="{esc(anchor)}" data-sec="{esc(anchor)}"'
    if open_default:
        attrs += " open"
    return (
        f"<details {attrs}>"
        f'<summary><h2 class="sec-title">{esc(title)}</h2>'
        f'<p class="sec-why">{esc(why)}</p></summary>'
        f'<div class="sec-body">{body}</div></details>'
    )


def _builds_table_html(*, slugs: set[str] | None = None) -> str:
    rows, err = query_db(
        "SELECT b.slug, b.repo_path, b.role, b.platform, b.arch, b.bits, b.format, "
        "b.func_count, b.named_count, b.md5, "
        "(SELECT COUNT(*) FROM binary d WHERE d.md5=b.md5 AND b.md5 IS NOT NULL), "
        "(SELECT MIN(d.slug) FROM binary d WHERE d.md5=b.md5 AND b.md5 IS NOT NULL) "
        "FROM binary b ORDER BY COALESCE(b.role,''), b.slug"
    )
    if err:
        return missing_html(err)
    table_rows = []
    for slug, repo_path, role, platform, arch, bits, fmt, funcs, named, _md5, copies, canonical in rows:
        if slugs is not None and str(slug) not in slugs:
            continue
        duplicate = int(copies or 0) > 1 and slug != canonical
        scope = "duplicate" if duplicate else (role or "included")
        table_rows.append([
            f'<a href="{_href_binary(slug)}">{esc(slug)}</a>',
            f'<span class="badge badge-{esc(scope)}">{esc(scope)}</span>',
            esc(platform or "—"), esc(f"{arch or '—'} / {bits or '—'}"), esc(fmt or "—"),
            _count_cell(funcs, "/functions?binary=" + quote(slug, safe="")),
            _count_cell(named, "/functions?binary=" + quote(slug, safe="") + "&named=1"),
            f'<code title="{esc(repo_path)}">{esc(Path(repo_path).name)}</code>',
        ])
    if not table_rows:
        return missing_html("No binaries in the corpus store.")
    return render_table(
        ["build", "scope", "platform", "architecture", "format", "functions", "named", "file"],
        table_rows,
        numeric={5, 6},
    )


def _recovery_embed_html() -> str:
    return _recovery_inner_html()


def _operations_embed_html() -> str:
    section = SECTION_BY_ID.get("processes")
    if section is None:
        return missing_html("Operations are unavailable.")
    return section_body(section).html


def _review_embed_html(params: dict | None = None) -> str:
    html, _ok = _entity_call("render_review", params or {})
    return html


def _run_work_html() -> str:
    return (
        '<p class="sub">These buttons run the same CLI and MCP tools as the terminal. '
        "Destructive actions ask first. A finished job is not a match.</p>"
        '<div class="action-bar" id="action-bar"></div>'
        '<label class="action-filter-label" for="action-filter">Filter actions</label>'
        '<input id="action-filter" class="action-filter" type="search" '
        'placeholder="ghidra-bulk, decompile, cross-place">'
        '<div id="action-catalog" class="action-catalog"></div>'
    )


def _home_workspace_sections() -> str:
    return (
        _named_block(
            "run",
            "Run work",
            "Run the same catalog verbs here. Stay on this page.",
            _run_work_html(),
            open_default=True,
        )
        + _named_block(
            "recovery",
            "Recovery",
            "Assembly-free C artifacts only. Real C and byte-accuracy stay separate.",
            _recovery_embed_html(),
        )
        + _named_block(
            "operations",
            "Jobs and logs",
            "Running jobs and log tails.",
            _operations_embed_html(),
        )
    )


def render_binary_page(slug: str) -> tuple[str, int]:
    trail = [("overview", "/dashboard"), (slug, None)]
    rec = _binary(slug)
    if rec is None:
        return _not_found(f"no build called {slug} is in the binary table",
                          [("overview", "/dashboard"), ("unknown build", None)]), 404

    def _safe(fn, label: str) -> str:
        try:
            return fn(rec)
        except Exception as exc:  # noqa: BLE001 - one bad block, not one bad page
            return missing_html(f"{label} unavailable: {exc}")

    body = "".join([
        '<p class="sub">One build. Each count opens the set it counts.</p>',
        _sub_panel("This build", _safe(_binary_facts, "build facts")),
        _steps_for_binary(slug),
        _sub_panel("Cross-match", _safe(_binary_identity, "identity rows")),
        _sub_panel("Source recovery", _safe(_binary_recovery, "recovery rows")),
        _sub_panel("Evidence on disk", _safe(_binary_artifacts, "artifact list")),
        _sub_panel("Functions in the store", _store_functions_table(slug, limit=80)),
    ])
    return _drill(
        slug, trail, body,
        page="binary",
        slug=slug,
        program=rec.get("repo_path") or slug,
        repo=rec.get("repo_path") or "",
    ), 200


def render_functions_page(query: dict) -> tuple[str, int]:
    """Browse workspace: functions, logical identities, review, graph, builds."""
    params = {k: (v[0] if v else "") for k, v in query.items()}
    slug = (params.get("binary") or params.get("slug") or "").strip()
    if slug and not params.get("binary"):
        params["binary"] = slug
    if is_partial_query(query):
        richer, _ = _entity_call("render_functions", params)
        return richer, 200

    trail: list[tuple[str, str | None]] = [("overview", "/dashboard")]
    title = "Functions"
    if slug:
        if _binary(slug) is None:
            return _not_found(f"no build called {slug} is in the binary table",
                              trail + [("functions", None)]), 404
        trail.append((slug, _href_binary(slug)))
        title = f"Functions in {slug}"
    trail.append(("functions", None))

    richer, _ = _entity_call("render_functions", params)
    open_graph = bool(params.get("addr") or params.get("logical_id"))
    open_review = bool(params.get("review_after"))
    open_logical = bool((params.get("lq") or params.get("logical_q") or "").strip())
    body = (
        _workspace_nav()
        + _named_block(
            "functions",
            "Functions",
            "Search and page this build.",
            richer,
            open_default=not (open_graph or open_review or open_logical),
        )
        + _named_block(
            "logical",
            "Logical identities",
            "Same function across builds. Search uses its own box.",
            _logical_listing_html(query, carry=params),
            open_default=open_logical,
        )
        + _named_block(
            "review",
            "Review",
            "Match rows that still need a human. Real C and byte-accuracy stay separate.",
            _review_embed_html(params),
            open_default=open_review,
        )
        + _named_block(
            "graph",
            "Relationships",
            "Pick a function from the list. Type a name or address to filter.",
            render_graph_embed(query),
            open_default=open_graph,
        )
        + _named_block(
            "builds",
            "Builds",
            "Every registered binary and its function counts.",
            _builds_table_html(),
        )
    )
    return _drill(title, trail, body, page="functions", slug=slug or ""), 200


BROWSE_BLOCKS = ("functions", "logical", "review", "graph", "builds")


def render_browse_block(block: str, query: dict) -> tuple[str, int]:
    """One block of the old browse workspace, bare, for a workbench window.

    The browse page used to be a second full page with five collapsed blocks.
    The workbench now owns navigation, so each block is served on its own and
    mounted as a window instead of nesting a page inside a page.
    """
    name = (block or "").strip().lower()
    if name not in BROWSE_BLOCKS:
        return f'<p class="miss">no browse block called {esc(block or "")}</p>', 404
    params = {k: (v[0] if v else "") for k, v in query.items()}
    slug = (params.get("binary") or params.get("slug") or "").strip()
    if slug and not params.get("binary"):
        params["binary"] = slug
    if name == "functions":
        body, _ok = _entity_call("render_functions", params)
        return body, 200
    if name == "logical":
        return _logical_listing_html(query, carry=params), 200
    if name == "review":
        return _review_embed_html(params), 200
    if name == "graph":
        return render_graph_embed(query), 200
    return _builds_table_html(), 200


def render_builds_page() -> tuple[str, int]:
    """Kept for redirects; the table now lives on the overview."""
    return _drill(
        "Builds",
        [("overview", "/dashboard"), ("builds", None)],
        '<p class="sub">Builds are on the overview.</p>' + _builds_table_html(),
        page="home",
    ), 200


def render_function_page(slug: str, raw_addr: str, query: dict | None = None) -> tuple[str, int]:
    trail: list[tuple[str, str | None]] = [("overview", "/dashboard")]
    rec = _binary(slug)
    if rec is None:
        return _not_found(f"no build called {slug} is in the binary table",
                          trail + [("function", None)]), 404
    addr = parse_address(raw_addr)
    if addr is None:
        return _not_found(f"{raw_addr} is not an address",
                          trail + [(slug, _href_binary(slug)),
                                   ("function", None)]), 404
    found, lookup_err = query_db(
        "SELECT name FROM func WHERE binary_id=? AND addr=? LIMIT 1",
        (int(rec["id"]), addr),
    )
    if not lookup_err and not found:
        return _not_found(f"no function at 0x{addr:x} in {slug}",
                          trail + [(slug, _href_binary(slug)),
                                   ("function", None)]), 404

    bits = int(rec.get("bits") or 32)
    hexed = format_address(addr, bits)
    trail += [(slug, _href_binary(slug)),
              ("functions", "/functions?binary=" + quote(slug, safe="")),
              (hexed, None)]
    facts, _ = _entity_call("render_function", slug, addr)
    graph_q = {
        "slug": [slug],
        "addr": [hexed],
        "heading": ["0"],
    }
    incoming = query or {}
    display = {}
    for key in ("depth", "direction", "density", "labels", "edges", "ink"):
        if incoming.get(key):
            graph_q[key] = incoming[key]
            display[key] = incoming[key][0]
    from agentdecompile_recovery.corpus.dashboard.function_choices import neighbor_addrs
    from agentdecompile_recovery.corpus.dashboard.panels import callgraph as graph_mod

    prev_addr, next_addr = neighbor_addrs(int(rec["id"]), addr)
    nav = ['<nav class="fn-step" aria-label="Nearby functions">']
    if prev_addr is not None:
        nav.append(f'<a rel="prev" href="{esc(function_workspace_href(slug, prev_addr, bits=bits, **display))}">Previous</a>')
    else:
        nav.append('<span class="note">No previous</span>')
    nav.append(f'<button type="button" class="copy-addr" data-copy="{esc(hexed)}">Copy address</button>')
    if next_addr is not None:
        nav.append(f'<a rel="next" href="{esc(function_workspace_href(slug, next_addr, bits=bits, **display))}">Next</a>')
    else:
        nav.append('<span class="note">No next</span>')
    nav.append("</nav>")

    binaries, _berr = ({}, None)
    try:
        binaries, _berr = graph_mod._binaries()
    except Exception:
        binaries = {}
    picker = graph_mod._search_form(binaries or {}, slug, hexed, compact=True, display=display)
    graph = render_graph_embed(graph_q)
    store_bits = _store_function_detail(slug, addr)
    jump = (
        '<nav class="fn-jump" aria-label="On this page">'
        '<a href="#graph">Graph</a>'
        '<a href="#facts">Facts</a>'
        '<a href="#source">Source</a>'
        '<button type="button" class="fn-help-open">Keys</button>'
        "</nav>"
    )
    help_box = (
        '<dialog class="fn-help" id="fn-help">'
        "<h2>Keys</h2>"
        "<ul>"
        "<li><kbd>/</kbd> find a function</li>"
        "<li><kbd>[</kbd> previous · <kbd>]</kbd> next</li>"
        "<li><kbd>+</kbd> <kbd>-</kbd> zoom · <kbd>0</kbd> reset</li>"
        "<li><kbd>w</kbd> wide graph · <kbd>?</kbd> this list</li>"
        "</ul>"
        '<form method="dialog"><button>Close</button></form>'
        "</dialog>"
    )
    body = (
        '<div class="fn-workspace" data-fn-workspace="1">'
        + jump
        + '<div class="fn-toolbar">' + picker + "".join(nav)
        + '<p class="fn-keys note">/ find · [ previous · ] next · + − zoom</p>'
        + "</div>"
        + '<div class="fn-grid">'
        + '<section id="graph" class="fn-graph"><h2 class="sec-title">Call graph</h2>'
        + graph + "</section>"
        + '<section id="facts" class="fn-facts"><h2 class="sec-title">This function</h2>'
        + store_bits + facts + "</section>"
        + "</div>" + help_box + "</div>"
    )
    func_name = found[0][0] if found else ""
    title = f"{func_name or hexed} in {slug}" if func_name else f"{hexed} in {slug}"
    return _drill(
        title, trail, body,
        page="function",
        slug=slug,
        addr=hexed,
        program=rec.get("repo_path") or slug,
        repo=rec.get("repo_path") or "",
        name=func_name or "",
    ), 200


def recovery_report_fragment() -> str:
    """Live SQL tiles for recovered_function — same body as /recovery in kotorxid."""
    return _recovery_inner_html()


def recovery_report_json(limit: int = 80) -> dict:
    """Same recovered_function tiles as the HTML report, for the React report tab."""
    out = {
        "ok": True,
        "logical": None,
        "artifacts": None,
        "unplaced": None,
        "unbound": None,
        "by_build": [],
        "functions": [],
        "errors": [],
    }
    rows, err = query_db(
        "SELECT b.slug, COUNT(*), COUNT(DISTINCT r.logical_id), "
        "COUNT(DISTINCT printf('%d:%lld', r.binary_id, r.addr)) "
        "FROM recovered_function r JOIN binary b ON b.id=r.binary_id "
        "WHERE r.real_c=1 GROUP BY b.id, b.slug ORDER BY 3 DESC"
    )
    if err:
        out["ok"] = False
        out["errors"].append(err)
        return out
    out["artifacts"] = sum(int(r[1] or 0) for r in rows)
    out["by_build"] = [
        {
            "slug": r[0],
            "artifacts": r[1],
            "logical": r[2],
            "concrete": r[3],
        }
        for r in rows
    ]
    logical_rows, logical_err = query_db(
        "SELECT COUNT(DISTINCT logical_id), "
        "SUM(logical_id IS NULL), SUM(binary_id IS NULL OR addr IS NULL) "
        "FROM recovered_function WHERE real_c=1"
    )
    if logical_err:
        out["errors"].append(logical_err)
    elif logical_rows:
        out["logical"], out["unbound"], out["unplaced"] = logical_rows[0]
    recent, rerr = query_db(
        "SELECT r.name, b.slug, r.size, r.convention, r.logical_id "
        "FROM recovered_function r JOIN binary b ON b.id = r.binary_id "
        "WHERE r.real_c=1 ORDER BY r.size DESC LIMIT ?",
        (int(limit),),
    )
    if rerr:
        out["errors"].append(rerr)
    else:
        out["functions"] = [
            {
                "name": r[0],
                "slug": r[1],
                "size": r[2],
                "convention": r[3] or "",
                "logical_id": r[4],
            }
            for r in recent
        ]
    return out


def render_report_page(query: dict) -> tuple[str, int]:
    """Recovery results live on the overview; this URL stays as a deep link."""
    _ = query
    return _drill(
        "Recovery",
        [("overview", "/dashboard"), ("recovery", None)],
        _recovery_inner_html(),
        page="report",
    ), 200


def _recovery_inner_html() -> str:
    rows, err = query_db(
        "SELECT b.slug, COUNT(*), COUNT(DISTINCT r.logical_id), "
        "COUNT(DISTINCT printf('%d:%lld', r.binary_id, r.addr)) "
        "FROM recovered_function r JOIN binary b ON b.id=r.binary_id "
        "WHERE r.real_c=1 GROUP BY b.id, b.slug ORDER BY 3 DESC")
    if err:
        return f'<div class="callout warn">{esc(err)}</div>'
    if not rows:
        return (
            '<div class="callout warn">No recovered functions are in '
            'the database. An ingest rebuilds this table. '
            'Files stay on disk either way.</div>'
        )

    artifacts = sum(int(r[1]) for r in rows)
    logical_rows, logical_err = query_db(
        "SELECT COUNT(DISTINCT logical_id), "
        "SUM(logical_id IS NULL), SUM(binary_id IS NULL OR addr IS NULL) "
        "FROM recovered_function WHERE real_c=1"
    )
    unique_logical, unbound, unplaced = (logical_rows[0] if logical_rows and not logical_err
                                         else (None, None, None))

    tiles = (
        '<div class="kv">'
        f"<div><b>{fnum(unique_logical)}</b><span>logical functions recovered</span></div>"
        f"<div><b>{fnum(artifacts)}</b><span>assembly-free source artifacts</span></div>"
        f"<div><b>{fnum(unplaced)}</b><span>artifacts without a concrete address</span></div>"
        f"<div><b>{fnum(unbound)}</b><span>artifacts without a logical identity</span></div>"
        "</div>"
        '<p class="sub">These counts include only assembly-free C or C++. '
        'They omit emitted bytes, wrappers, and assembly exports.</p>')

    body = ["<table><thead><tr><th>build</th><th class=\"num\">artifacts</th>"
            "<th class=\"num\">logical functions</th><th class=\"num\">concrete instances</th>"
            "</tr></thead><tbody>"]
    for slug, n, logical_n, concrete_n in rows:
        body.append(
            f'<tr><td><a href="/binary/{quote(str(slug), safe="")}">{esc(str(slug))}</a></td>'
            f'<td class="num">{fnum(n)}</td>'
            f'<td class="num">{fnum(logical_n)}</td>'
            f'<td class="num">{fnum(concrete_n)}</td></tr>')
    body.append("</tbody></table>")

    limit = 200
    recent, rerr = query_db(
        "SELECT r.name, b.slug, r.size, r.convention, r.logical_id"
        "  FROM recovered_function r JOIN binary b ON b.id = r.binary_id"
        " WHERE r.real_c=1 ORDER BY r.size DESC LIMIT ?", (limit,))
    listing = ""
    if not rerr and recent:
        lines = ["<h2 class=\"h-sec\">Recovered functions</h2>",
                 f'<p class="sub">Largest {len(recent)} of {fnum(artifacts)}. '
                 'Each row compiled to the original bytes.</p>',
                 "<table><thead><tr><th>function</th><th>build</th>"
                 "<th class=\"num\">bytes</th><th>convention</th><th>logical function</th>"
                 "</tr></thead><tbody>"]
        for name, slug, size, conv, logical_id in recent:
            lines.append(
                f"<tr><td><code>{esc(str(name))}</code></td>"
                f'<td><a href="/binary/{quote(str(slug), safe="")}">{esc(str(slug))}</a></td>'
                f'<td class="num">{fnum(int(size or 0))}</td>'
                f"<td>{esc(str(conv or ''))}</td>"
                f'<td>{f"<a href=/logical/{int(logical_id)}>#{int(logical_id)}</a>" if logical_id is not None else "unmapped"}</td></tr>')
        lines.append("</tbody></table>")
        listing = "".join(lines)

    return tiles + "".join(body) + listing


def render_review_page(query: dict) -> tuple[str, int]:
    """Paged review-tier match worklist. entities.py owns the rows."""
    params = {k: (v[0] if v else "") for k, v in query.items()}
    trail: list[tuple[str, str | None]] = [
        ("overview", "/dashboard"),
        ("review queue", None),
    ]
    body, _ = _entity_call("render_review", params)
    return _drill("Review queue", trail, body), 200


def render_logical_page(raw_id: str) -> tuple[str, int]:
    trail: list[tuple[str, str | None]] = [("overview", "/dashboard")]
    try:
        logical_id = int(raw_id)
    except (TypeError, ValueError):
        return _not_found(f"{raw_id} is not a logical function id",
                          trail + [("logical function", None)]), 404
    trail.append((f"logical function {logical_id}", None))
    body, _ = _entity_call("render_logical", logical_id)
    body += (f'<p class="sub"><a href="/dashboard/functions?logical_id={logical_id}#graph">Open this '
             "identity group in the call graph</a>.</p>")
    return _drill(f"Logical function {logical_id}", trail, body, page="logical", logical_id=logical_id), 200


def _logical_listing_html(query: dict, carry: dict | None = None) -> str:
    from agentdecompile_recovery.corpus.dashboard.panels.entities import (
        PAGE,
        _page_size,
        _page_size_control,
    )

    q = ((query.get("lq") or query.get("logical_q") or [""])[0]).strip()
    after_raw = ((query.get("logical_after") or ["0"])[0]).strip()
    try:
        after = max(0, int(after_raw or 0))
    except ValueError:
        after = 0
    page_size, show_all = _page_size(carry or {k: (v[0] if v else "") for k, v in query.items()})
    binds: list[object] = [after]
    where = "WHERE lf.id>?"
    if q:
        where += " AND (ln.name LIKE ? ESCAPE '\\' OR lf.canon_key LIKE ? ESCAPE '\\')"
        escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        binds.extend([f"%{escaped}%", f"%{escaped}%"])
    binds.append(page_size + 1)
    rows, err = query_db(
        "SELECT lf.id, COALESCE(ln.name, lf.best_name, lf.canon_key), ln.tier_name, "
        "COUNT(i.binary_id), MAX(i.confidence), lf.source_file "
        "FROM logical_function lf LEFT JOIN logical_name ln ON ln.logical_id=lf.id "
        "LEFT JOIN identity i ON i.logical_id=lf.id " + where +
        " GROUP BY lf.id ORDER BY lf.id LIMIT ?", tuple(binds))
    if err:
        # A store that has never had cross-build matching run has no identity
        # tables at all. That is a stage nobody reached, not a broken query.
        if "no such table" in str(err).lower():
            return (
                '<p class="sub">No logical identities yet. They appear after '
                "cross-build matching. Use Match, or run "
                "<code>corpus.cross-place</code> from Commands.</p>"
            )
        return missing_html(err)
    more = len(rows) > page_size
    rows = rows[:page_size]
    hidden = []
    carry = carry or {}
    hidden.append('<input type="hidden" name="window" value="wb-logical">')
    for key in ("binary", "slug", "q", "page_size", "size_band"):
        val = carry.get(key) or ""
        if val:
            hidden.append(f'<input type="hidden" name="{esc(key)}" value="{esc(val)}">')
    form = (
        '<form class="search-form" action="/dashboard" method="get" role="search">'
        + "".join(hidden) +
        '<label for="logical-search">Find a logical function</label>'
        f'<input id="logical-search" name="lq" value="{esc(q)}" '
        'placeholder="Name or canonical key" autocomplete="off">'
        + _page_size_control(page_size, show_all, field="page_size", control_id="logical-page-size")
        + '<button type="submit">Search identities</button></form>'
    )
    table_rows = []
    for lid, name, tier, members, confidence, source_file in rows:
        table_rows.append([
            f'<a href="/logical/{int(lid)}">#{int(lid)}</a>',
            f'<a href="/logical/{int(lid)}">{esc(name or "unnamed")}</a>',
            esc(tier or "unresolved"), fnum(members),
            esc(f"{confidence:.2f}" if confidence is not None else "—"),
            esc(Path(source_file).name if source_file else "—"),
        ])
    listing = (
        render_table(
            ["id", "name", "name source", "members", "best confidence", "source file"],
            table_rows,
            numeric={3, 4},
        )
        if table_rows
        else missing_html("No logical function matched this search.")
    )
    pager = ""
    if more and rows:
        nxt = {"lq": q, "logical_after": rows[-1][0]}
        if carry.get("binary"):
            nxt["binary"] = carry["binary"]
        if page_size != PAGE or show_all:
            nxt["page_size"] = "all" if show_all else str(page_size)
        nxt["window"] = "wb-logical"
        href = "/dashboard?" + urlencode(nxt)
        next_label = "all remaining" if show_all else f"Next {page_size}"
        pager = f'<p class="pager"><a href="{esc(href)}">{esc(next_label)}</a></p>'
    return form + listing + pager


def render_logical_index(query: dict) -> tuple[str, int]:
    """Logical identities now sit on the functions page; this URL stays as a deep link."""
    return _drill(
        "Functions",
        [("overview", "/dashboard"), ("functions", None)],
        '<p class="sub">Logical identities are on the functions page.</p>' + _logical_listing_html(query),
        page="functions",
    ), 200


# --------------------------------------------------------------------------
# styles
# --------------------------------------------------------------------------

CSS = """
:root{
 --bg-base:#0c0f14;--bg-panel:#131924;--bg-raised:#1a212e;--bg-sunken:#070a0f;
 --line:#1e242e;--line-strong:#2a3342;
 --fg-max:#f2f6fb;--fg-body:#d7dde7;--fg-head:#9aa7bb;--fg-annot:#8b98ab;--fg-dim:#7d8aa0;
 --st-proven:#5ee79b;--st-proven-bd:#46916a;--st-proven-bg:#0f2a1c;
 --st-partial:#fbbf24;--st-partial-bd:#9a8340;--st-partial-bg:#2b2411;
 --st-unproven:var(--fg-head);--st-unproven-bd:#6a7688;--st-unproven-bg:var(--bg-raised);
 --st-failed:#f87171;--st-failed-bd:#a45a5a;--st-failed-bg:#2c1618;
 --link:#6cc6ff;--focus:var(--link);
 --s1:4px;--s2:8px;--s3:12px;--s4:16px;--s5:24px;--s6:32px;--s7:48px;--s8:64px;
 --radius:10px;
 --font-ui:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
 --font-mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"DejaVu Sans Mono",monospace;
}
*,*::before,*::after{box-sizing:border-box}
body{margin:0;background:
 radial-gradient(circle at 50% -20%,#152136 0,transparent 42%),var(--bg-base);
 color:var(--fg-body);font:400 15px/1.55 var(--font-ui)}
a{color:var(--link);text-underline-offset:2px}
code{font-family:var(--font-mono);font-size:12px;color:var(--fg-max)}
/* Rule D is a height budget, so the page's own chrome is spent sparingly:
   24px of gutter above the status strip and 64px below the footer were 88px
   of the one screen the landing view is allowed. */
.wrap{max-width:1380px;margin:0 auto;padding:var(--s5) var(--s6) var(--s5)}

/* status strip */
.topbar{display:flex;align-items:center;gap:var(--s3);flex-wrap:wrap;
 padding-bottom:var(--s2);border-bottom:1px solid var(--line);margin-bottom:var(--s3)}
.topbar .brand{font-weight:800;letter-spacing:.16em;text-transform:uppercase;
 color:var(--fg-max);font-size:13px}
.topbar nav{display:flex;gap:var(--s3);font-size:13px;flex-wrap:wrap}
.topbar .chips{display:flex;gap:var(--s2);flex-wrap:wrap;margin-left:auto}
.chip{font-size:11px;padding:2px 8px;border-radius:999px;border:1px solid var(--line-strong);
 color:var(--fg-annot);font-variant-numeric:tabular-nums}
.chip.st-done{border-color:var(--st-proven-bd);color:var(--st-proven)}
.chip.st-partial{border-color:var(--st-partial-bd);color:var(--st-partial)}
.chip.st-failed{border-color:var(--st-failed-bd);color:var(--st-failed)}
.pulse{font-size:11px;color:var(--fg-annot);font-variant-numeric:tabular-nums}

/* hero — the metric and its disclaimer sit side by side, because stacking them
   spent 180px of vertical budget on two blocks that are read together. */
.hero{display:grid;grid-template-columns:minmax(0,1.1fr) minmax(0,1fr);
 gap:var(--s3) var(--s5);align-items:start;padding:0;margin:0 0 var(--s3)}
.hero-main{min-width:0}
.eyebrow{font-size:12px;font-weight:600;letter-spacing:.12em;text-transform:uppercase;
 color:var(--fg-head);margin:0}
.hero-n{font-size:clamp(26px,4vw,38px);font-weight:700;line-height:1.05;
 color:var(--fg-max);margin:var(--s1) 0 var(--s2);letter-spacing:-.02em}
.hero-n .of{color:var(--fg-head);font-weight:400;font-size:.5em}
.hero-n .st{color:var(--st-partial);font-size:.5em}
.hero-n.is-not-started .st,.hero-n.is-unmeasured .st{color:var(--st-unproven)}
.hero-n a.cnt{color:inherit;border-bottom:2px solid var(--line-strong)}
.hero-n a.cnt:hover{border-bottom-color:var(--st-partial)}
.hero-sub{max-width:78ch;margin:var(--s2) 0 0;color:var(--fg-body);font-size:14px}
.also{margin:0;padding:var(--s2) var(--s3);border-radius:var(--radius);
 background:var(--st-partial-bg);border:1px solid var(--st-partial-bd)}
.also > summary{list-style:none;cursor:pointer;border-radius:var(--radius)}
.also > summary:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
.also > summary::-webkit-details-marker{display:none}
.also > summary::marker{content:""}
.also p,.also .alsop{display:block;margin:var(--s1) 0 0;font-size:12px;color:var(--fg-body)}
.also .alsohead::after{content:"show the rest";float:right;font-size:11px;
 font-weight:400;letter-spacing:0;text-transform:none;color:var(--link)}
.also[open] .alsohead::after{content:"hide the rest"}
.alsohead{display:block;font-size:11px;font-weight:700;letter-spacing:.12em;
 text-transform:uppercase;color:var(--st-partial);margin:0}
.livepri .kv{margin:var(--s2) 0}
.livepri .sub code{font-size:12px}
.also a.cnt{color:var(--fg-max)}

/* progress bars — true scale, no minimum width */
.bar{height:8px;border-radius:999px;background:var(--bg-raised);overflow:hidden;
 margin:var(--s2) 0}
.bar.big{height:12px}
.bar > i{display:block;height:100%;background:var(--st-proven)}
.bar.st-partial > i,.bar.st-running > i{background:var(--st-partial)}
.bar.st-not-started > i,.bar.st-unmeasured > i{background:var(--st-unproven)}
.bar.st-failed > i{background:var(--st-failed)}

/* section shell */
.h-sec{font-size:13px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;
 color:var(--fg-head);margin:0}
.block{margin:0 0 var(--s3)}
.blockhead{display:flex;align-items:baseline;gap:var(--s3);flex-wrap:wrap;
 margin:0 0 var(--s1)}
.blockhead .sub{margin:0;flex:1 1 20ch;min-width:0}
.sec{border:1px solid var(--line);border-radius:var(--radius);background:var(--bg-panel);
 margin:0 0 var(--s2)}
.sec > summary{display:flex;align-items:center;gap:var(--s3);flex-wrap:wrap;
 padding:var(--s3) var(--s4);cursor:pointer;list-style:none;border-radius:var(--radius)}
.sec > summary::-webkit-details-marker{display:none}
.sec > summary::marker{content:""}
.sec > summary::before{content:"";flex:0 0 auto;width:7px;height:7px;
 border-right:2px solid var(--fg-head);border-bottom:2px solid var(--fg-head);
 transform:rotate(-45deg);transition:transform .12s ease}
.sec[open] > summary::before{transform:rotate(45deg)}
.sec > summary:hover{background:var(--bg-raised)}
.sec > summary:focus-visible{outline:2px solid var(--link);outline-offset:2px}
.sec-title{font-size:13px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;
 color:var(--fg-head);margin:0}
.sec-why{flex-basis:100%;margin:var(--s1) 0 0;color:var(--fg-annot);font-size:12px}
.sec-body{padding:var(--s4);border-top:1px solid var(--line)}
.secsum{display:flex;gap:var(--s3);flex-wrap:wrap;font-size:12px;
 font-variant-numeric:tabular-nums}
/* Two closed summaries are two answers, so they sit as a pair; whichever one
   the reader opens takes the whole width back. */
.tail{display:grid;grid-template-columns:1.35fr 1fr;gap:var(--s2) var(--s3);
 align-items:start}
.tail > details[open]{grid-column:1 / -1}
@media (max-width:900px){.tail{grid-template-columns:1fr}}
@media (prefers-reduced-motion:reduce){.sec > summary::before{transition:none}}

/* step ladder */
.ladderhead{margin:0 0 var(--s4)}
.ladderline{display:flex;align-items:baseline;gap:var(--s3)}
.ladderline b{font-size:20px;color:var(--fg-max)}
.ladderline .pct{color:var(--fg-annot);font-size:12px;font-variant-numeric:tabular-nums}
.step{border:1px solid var(--line);border-radius:var(--radius);background:var(--bg-panel);
 margin:0 0 var(--s2)}
.step > summary{display:grid;grid-template-columns:52px 1fr auto auto auto;gap:var(--s3);
 align-items:center;padding:var(--s3) var(--s4);cursor:pointer;list-style:none}
.step > summary::-webkit-details-marker{display:none}
.step > summary::marker{content:""}
.step > summary:hover{background:var(--bg-raised)}
.step > summary:focus-visible{outline:2px solid var(--link);outline-offset:2px}
.step .bar{grid-column:1 / -1;margin:var(--s1) 0 0}
.stepno{font-family:var(--font-mono);font-size:12px;color:var(--fg-head);
 border:1px solid var(--line-strong);border-radius:6px;padding:2px 0;text-align:center}
.stepname{color:var(--fg-max);font-weight:600}
.stepcount{font-variant-numeric:tabular-nums;color:var(--fg-max);white-space:nowrap}
.stepcount .of{color:var(--fg-head)}
.stepcount .unit{color:var(--fg-annot);font-size:11px}
.step-run{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;
 padding:2px 8px;border-radius:6px;text-decoration:none;color:var(--link);
 border:1px solid var(--line-strong);white-space:nowrap;justify-self:end}
.step-run:hover{background:var(--bg-raised)}
.step-run.disabled{color:var(--fg-annot);border-color:var(--line);opacity:.65;cursor:not-allowed}
.step.st-done{box-shadow:inset 3px 0 0 var(--st-proven-bd)}
.step.st-partial,.step.st-running{box-shadow:inset 3px 0 0 var(--st-partial-bd)}
.step.st-not-started,.step.st-unmeasured{box-shadow:inset 3px 0 0 var(--st-unproven-bd)}
.step.st-failed{box-shadow:inset 3px 0 0 var(--st-failed-bd)}
.stepbody{padding:0 var(--s4) var(--s4);border-top:1px solid var(--line);
 padding-top:var(--s3)}
.why{margin:0 0 var(--s2);color:var(--fg-body)}
.next{margin:var(--s3) 0 0;font-size:12px;color:var(--fg-body)}
.next .k{font-size:10px;letter-spacing:.1em;text-transform:uppercase;
 color:var(--fg-head);margin-right:var(--s2)}
@media (max-width:720px){.step > summary{grid-template-columns:44px 1fr}
 .step .pill,.step .stepcount,.step .step-run{grid-column:2}}

/* state pills */
.pill{font-size:11px;letter-spacing:.06em;text-transform:uppercase;padding:2px 8px;
 border-radius:999px;border:1px solid var(--st-unproven-bd);color:var(--st-unproven);
 background:var(--st-unproven-bg);white-space:nowrap}
.pill.st-done{border-color:var(--st-proven-bd);color:var(--st-proven);background:var(--st-proven-bg)}
.pill.st-partial,.pill.st-running{border-color:var(--st-partial-bd);color:var(--st-partial);
 background:var(--st-partial-bg)}
.pill.st-failed{border-color:var(--st-failed-bd);color:var(--st-failed);background:var(--st-failed-bg)}
.st-done{color:var(--st-proven)}.st-partial,.st-running{color:var(--st-partial)}
.st-failed{color:var(--st-failed)}.st-not-started,.st-unmeasured{color:var(--st-unproven)}

/* a drill-down's own title keeps the air the landing blocks gave up */
.wrap > .h-sec{margin-bottom:var(--s3)}

/* two charts of 11 builds each, read as one ranked list on one shared scale */
.barcols{display:grid;grid-template-columns:1fr 1fr;gap:var(--s2) var(--s4);
 align-items:start}
@media (max-width:900px){.barcols{grid-template-columns:1fr}
 .hero{grid-template-columns:1fr}}
@media (max-width:720px){.wrap{padding:var(--s4)}.topbar .chips{margin-left:0}
 .topbar nav{order:3;width:100%;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));
  overflow:visible;gap:var(--s2);padding-bottom:var(--s1)}
 .topbar nav a{display:flex;min-height:44px;align-items:center;justify-content:center;
  border:1px solid var(--line-strong);border-radius:7px;text-decoration:none}
 .barcols{display:block}.barcols>*{margin-bottom:var(--s3)}
 .tablewrap{max-height:none}.sec > summary,.step > summary{min-height:48px}}

/* evidence chips */
.srcs{display:flex;gap:var(--s3);flex-wrap:wrap;align-items:center;margin-top:var(--s2);
 padding-top:var(--s2);border-top:1px dashed var(--line)}
.hero > .srcs{grid-column:1 / -1;margin-top:0}
.src{font-family:var(--font-mono);font-size:11px}
.src.broken{color:var(--st-failed);text-decoration:line-through}
.age{font-size:11px;color:var(--fg-annot);font-variant-numeric:tabular-nums}

/* directives */
.dsummary{display:flex;gap:var(--s4);flex-wrap:wrap;align-items:baseline;
 margin-bottom:var(--s3);font-variant-numeric:tabular-nums}
.dcount{font-size:24px;font-weight:800;color:var(--fg-max)}
.dstats,.dbroken{font-size:12px;display:flex;gap:var(--s3);flex-wrap:wrap}
.drows{display:grid;gap:var(--s3)}
.drow{border:1px solid var(--line);border-radius:var(--radius);padding:var(--s3) var(--s4);
 background:var(--bg-raised)}
.drow.st-done{box-shadow:inset 3px 0 0 var(--st-proven-bd)}
.drow.st-partial,.drow.st-running{box-shadow:inset 3px 0 0 var(--st-partial-bd)}
.drow.st-failed{box-shadow:inset 3px 0 0 var(--st-failed-bd)}
.drow header{display:flex;gap:var(--s3);align-items:center;flex-wrap:wrap}
.did{font-family:var(--font-mono);font-weight:700;color:var(--fg-max)}
.dcat{font-size:11px;color:var(--fg-annot);letter-spacing:.08em;text-transform:uppercase}
.drow blockquote{margin:var(--s2) 0;padding-left:var(--s3);
 border-left:2px solid var(--line-strong);color:var(--fg-body)}
.paths{list-style:none;margin:var(--s2) 0 0;padding:0;display:grid;gap:2px}
.paths li{font-size:12px;display:flex;gap:var(--s2);align-items:baseline;flex-wrap:wrap}
.ev.broken code{color:var(--st-failed);text-decoration:line-through}

/* callout */
.callout{border:1px solid var(--line-strong);border-radius:var(--radius);
 padding:var(--s3) var(--s4);background:var(--bg-panel);margin:0 0 var(--s4);font-size:13px}
.callout.warn{border-color:var(--st-failed-bd);background:var(--st-failed-bg)}

/* shared classes the existing panels emit — kept working, unchanged markup */
.panel{background:var(--bg-panel);border:1px solid var(--line);border-radius:var(--radius);
 padding:var(--s4);margin-bottom:var(--s3)}
.grid3{display:grid;gap:var(--s3);grid-template-columns:repeat(auto-fit,minmax(340px,1fr))}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;font-size:11px;letter-spacing:.08em;text-transform:uppercase;
 color:var(--fg-head);font-weight:600;padding:var(--s2) var(--s3);
 border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--bg-panel)}
td{padding:6px var(--s3);border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:none}
tbody tr:hover{background:var(--bg-raised)}
.num{text-align:right;font-variant-numeric:tabular-nums}
.tablewrap{overflow:auto;max-height:460px;border-radius:var(--radius)}
.tablewrap{max-width:100%;overscroll-behavior-inline:contain}
.graph-search{max-width:100%}.graph-search label{min-width:0;max-width:100%}
.graph-search select,.graph-search input{width:100%;min-width:0;max-width:100%;min-height:44px}
.graph-search button{min-height:44px}
@media (max-width:720px){
 .tablewrap{max-height:none;box-shadow:inset -12px 0 12px -14px var(--fg-head)}
 .graph-search{display:grid!important;grid-template-columns:minmax(0,1fr)!important}
 .graph-search .note{max-width:100%;overflow-wrap:anywhere}}
.tag{display:inline-block;font-size:10px;letter-spacing:.08em;text-transform:uppercase;
 padding:2px 7px;border-radius:999px;border:1px solid var(--line-strong);color:var(--fg-annot)}
.tag.ok,.tag.live{border-color:var(--st-proven-bd);color:var(--st-proven)}
.tag.dead{border-color:var(--st-failed-bd);color:var(--st-failed)}
.tag.warn{border-color:var(--st-partial-bd);color:var(--st-partial)}
.tag.prio{border-color:var(--line-strong);color:var(--fg-annot)}
.log{background:var(--bg-sunken);border:1px solid var(--line);border-radius:6px;
 padding:var(--s2) var(--s3);max-height:280px;overflow:auto;white-space:pre-wrap;
 word-break:break-word;font-size:12px;line-height:1.45;font-family:var(--font-mono);
 color:var(--fg-annot)}
.log.tall{max-height:70vh;white-space:pre}
.miss{color:var(--st-partial);font-size:13px}
.note{color:var(--fg-annot);font-size:12px;margin:var(--s2) 0}
.annot{color:var(--fg-annot);font-size:11px;margin:var(--s2) 0 0}
.sub{color:var(--fg-annot);font-size:12px;margin:var(--s1) 0}
.kv{display:grid;grid-template-columns:1fr auto;gap:2px var(--s4);font-size:13px}
.kv div:nth-child(odd){color:var(--fg-annot)}
.kv div:nth-child(even){text-align:right;font-variant-numeric:tabular-nums;color:var(--fg-max)}
.ptitle{display:flex;align-items:center;gap:var(--s2);flex-wrap:wrap;margin-bottom:var(--s1)}
.ptitle b{font-size:14px;color:var(--fg-max)}
.headline{font-size:20px;font-weight:700;color:var(--fg-max);margin:0 0 var(--s1)}
.hl{color:var(--st-partial)}
.mono{font-family:var(--font-mono);font-size:12px}
.good{color:var(--st-proven)}.bad{color:var(--st-failed)}.warnt{color:var(--st-partial)}
.prio{background:transparent}
.foot{margin-top:var(--s3);padding-top:var(--s2);border-top:1px solid var(--line);
 color:var(--fg-annot);font-size:11px;display:flex;gap:var(--s4);flex-wrap:wrap}
/* drill-down: the same page, one level down */
.crumbs{display:flex;align-items:center;gap:var(--s2);flex-wrap:wrap;
 font-size:12px;color:var(--fg-annot);margin:var(--s3) 0 0}
.crumbs a{color:var(--fg-annot);text-decoration:none;border-bottom:1px solid var(--line-strong)}
.crumbs a:hover{color:var(--fg-max)}
.crumbs b{color:var(--fg-max);font-weight:600}
.crumbs .sep{color:var(--fg-dim)}
.unit{color:var(--fg-annot);font-size:11px}
.dim{color:var(--fg-dim)}
/* common.count_link: the number itself is the control, everywhere it appears */
.cnt{font-variant-numeric:tabular-nums}
a.cnt{color:var(--fg-max);text-decoration:none;border-bottom:1px solid var(--line-strong)}
a.cnt:hover{color:var(--fg-max);border-bottom-color:var(--st-partial)}
.cnt.none{color:var(--fg-dim);font-style:italic}
/* A count that leads somewhere has to look like it does, in tables too. */
td a,.kv a{border-bottom:1px solid var(--line-strong)}
td a:hover,.kv a:hover{color:var(--fg-max)}
""" + viz.CSS


# --------------------------------------------------------------------------
# client
# --------------------------------------------------------------------------

JS = r"""
(function(){
 var app=document.getElementById('app');
 if(!app) return;
 var portLinks=document.querySelectorAll('[data-port-link]');
 for(var pi=0;pi<portLinks.length;pi++){
  portLinks[pi].href=location.protocol+'//'+location.hostname+':'+portLinks[pi].dataset.portLink+'/';
 }
 var KEY='kx.ui.v1';
 var state={open:{},scroll:{},win:0};
 try{var s=JSON.parse(sessionStorage.getItem(KEY)); if(s&&typeof s==='object') state=s;}catch(e){}
 if(!state.open) state.open={};
 if(!state.scroll) state.scroll={};

 var saveTimer=null;
 function save(){
  if(saveTimer) return;
  saveTimer=setTimeout(function(){
   saveTimer=null;
   try{sessionStorage.setItem(KEY,JSON.stringify(state));}catch(e){}
  },150);
 }

 /* <details> toggle does not bubble, so it is caught in the capture phase.
    Recording on interaction rather than during the swap is what makes the open
    set survive a response that arrived after the user clicked. */
 document.addEventListener('toggle',function(ev){
  var el=ev.target;
  if(!el||!el.dataset||!el.dataset.k) return;
  state.open[el.dataset.k]=el.open;
  save();
  if(el.open) lazyLoad(el,false);
 },true);

 var scrollTimer=null;
 document.addEventListener('scroll',function(ev){
  var el=ev.target;
  if(el&&el.dataset&&el.dataset.k&&el!==document) state.scroll[el.dataset.k]=el.scrollTop;
  if(scrollTimer) return;
  scrollTimer=setTimeout(function(){scrollTimer=null;state.win=window.scrollY;save();},200);
 },true);

 function applyState(root){
  var d=root.querySelectorAll('details[data-k]');
  for(var i=0;i<d.length;i++){
   var want=state.open[d[i].dataset.k];
   if(want===true&&!d[i].open) d[i].open=true;
   else if(want===false&&d[i].open) d[i].open=false;
  }
  var logs=root.querySelectorAll('.log[data-k],.tablewrap[data-k]');
  for(var j=0;j<logs.length;j++){
   var v=state.scroll[logs[j].dataset.k];
   if(typeof v==='number') logs[j].scrollTop=v;
   else logs[j].scrollTop=logs[j].scrollHeight;
  }
 }

 function lazyLoad(d,force){
  var id=d.getAttribute('data-lazy');
  if(!id) return;
  var body=d.querySelector('.sec-body');
  if(!body||body.dataset.loading==='1') return;
  if(body.dataset.loaded==='1'&&!force) return;
  body.dataset.loading='1';
  if(body.dataset.loaded!=='1') body.innerHTML='<p class="annot">loading&hellip;</p>';
  fetch('/panel?id='+encodeURIComponent(id),{cache:'no-store'}).then(function(r){
   if(!r.ok) throw new Error('HTTP '+r.status);
   return r.text();
  }).then(function(t){
   body.innerHTML=t; body.dataset.loaded='1'; body.dataset.loading='';
   applyState(body);
   /* The server answered without waiting for a slow read. Ask again shortly
      rather than leaving a half-answer on screen with no way forward. */
   if(body.querySelector('[data-pending="1"]')) setTimeout(function(){
    if(d.open) lazyLoad(d,true);
   },3000);
  }).catch(function(e){
   body.dataset.loading='';
   body.innerHTML='<p class="miss">panel failed to load: '+e.message+'</p>';
  });
 }

 function loadOpenLazy(force){
  var d=app.querySelectorAll('details[data-lazy][open]');
  for(var i=0;i<d.length;i++) lazyLoad(d[i],force);
 }

 /* Never replace a section the user is working inside: an active input or a
    live text selection is state no restore step can rebuild. */
 function busy(el){
  var a=document.activeElement;
  if(a&&a!==document.body&&el.contains(a)) return true;
  var sel=window.getSelection&&window.getSelection();
  if(sel&&!sel.isCollapsed&&sel.anchorNode&&el.contains(sel.anchorNode)) return true;
  return false;
 }

 var scratch=document.createElement('div');
 function patch(text){
  scratch.innerHTML=text;
  var incoming=scratch.querySelectorAll('[data-sec]');
  var matched=0,changed=0;
  for(var i=0;i<incoming.length;i++){
   var nw=incoming[i];
   var cur=app.querySelector('[data-sec="'+nw.getAttribute('data-sec')+'"]');
   if(!cur) continue;
   matched++;
   if(nw.getAttribute('data-lazy')) continue;      /* client owns lazy bodies */
   if(cur.getAttribute('data-etag')===nw.getAttribute('data-etag')) continue;
   if(busy(cur)) continue;
   cur.parentNode.replaceChild(nw.cloneNode(true),cur);
   changed++;
  }
  if(matched===0){                                  /* layout changed under us */
   app.innerHTML=text; applyState(app); loadOpenLazy(true); return -1;
  }
  if(changed) applyState(app);
  return changed;
 }

 function stamp(){
  var d=new Date();
  return d.toTimeString().slice(0,8);
 }
 function setPulse(t){
  var el=document.getElementById('pulse');
  if(el) el.textContent=t;
 }

 var BASE=5000,interval=BASE,fails=0,timer=null;
 function schedule(){
  if(timer) clearTimeout(timer);
  if(document.hidden){ setPulse('paused — tab hidden'); return; }
  timer=setTimeout(poll,interval);
 }
 function poll(){
  var sy=window.scrollY;
  fetch('/fragment',{cache:'no-store'}).then(function(r){
   if(!r.ok) throw new Error('HTTP '+r.status);
   return r.text();
  }).then(function(t){
   var n=patch(t);
   if(Math.abs(window.scrollY-sy)>2) window.scrollTo(0,sy);
   fails=0; interval=BASE;
   setPulse('updated '+stamp()+(n>0?(' · '+n+' section'+(n>1?'s':'')+' changed')
            :(n<0?' · full redraw':' · no change')));
   schedule();
  }).catch(function(e){
   fails++;
   interval=Math.min(60000,BASE*Math.pow(2,fails));
   setPulse('refresh failed: '+e.message+' · retry in '+Math.round(interval/1000)+'s');
   schedule();
  });
 }

 document.addEventListener('visibilitychange',function(){
  if(app.getAttribute('data-live')!=='1') return;
  if(document.hidden){ if(timer) clearTimeout(timer); setPulse('paused — tab hidden'); }
  else{ interval=BASE; fails=0; poll(); }
 });

 applyState(app);
 if(state.win) window.scrollTo(0,state.win);
 loadOpenLazy(false);
 if(app.getAttribute('data-live')!=='1'){
  /* A drill-down does not poll: it has no data-sec blocks to patch, so a poll
     would replace it with the overview. It only comes back for a block the
     server said it was still reading. */
  if(app.querySelector('[data-pending="1"]')){
   setPulse('one block is still being read — reloading shortly');
   setTimeout(function(){ if(!document.hidden) location.reload(); },5000);
  }else{
   setPulse('this page holds still');
  }
 }else{
  setPulse('waiting for first update');
  schedule();
  setInterval(function(){ if(!document.hidden) loadOpenLazy(true); },45000);
 }

 /* Test handle. The refresh path is the part of this page most likely to break
    silently — it can only fail by discarding something the reader was doing —
    so it stays reachable for a scripted check instead of being verifiable only
    by a human watching a section slam shut. */
 window.__kx={poll:poll,patch:patch,state:state,applyState:applyState};
})();
"""


def query_from_mapping(query) -> dict:
    """Normalize FastAPI / parse_qs query maps to {key: [value, ...]}."""
    out: dict[str, list[str]] = {}
    if not query:
        return out
    items = query.multi_items() if hasattr(query, "multi_items") else query.items()
    for key, value in items:
        if isinstance(value, (list, tuple)):
            out.setdefault(str(key), []).extend("" if v is None else str(v) for v in value)
        else:
            out.setdefault(str(key), []).append("" if value is None else str(value))
    return out


def render_operations_page() -> tuple[str, int]:
    return _drill(
        "Overview",
        [("overview", None)],
        '<p class="sub">Jobs and logs are on the overview.</p>' + _operations_embed_html(),
        page="home",
    ), 200


def render_session_overview(
    slugs: list[str],
    programs: list[str] | None = None,
) -> str:
    """Corpus overview scoped to the active workbench tab (project + imports)."""
    slug_set = {str(item).strip() for item in slugs if str(item).strip()}
    program_names = [
        str(item).strip()
        for item in (programs or [])
        if str(item).strip()
    ]
    if not slug_set and not program_names:
        return (
            '<p class="sub">No project is open in this tab. Open or create a project first.</p>'
        )
    title = ", ".join(sorted(slug_set)) if slug_set else "project programs only"
    program_rows = [
        [
            esc(name),
            '<span class="badge">Ghidra program</span>',
            "Program in the open Ghidra project. Add and Remove in Explorer change this list.",
        ]
        for name in program_names
    ]
    program_block = ""
    if program_rows:
        program_block = (
            '<div class="block"><div class="blockhead">'
            '<h2 class="h-sec">Project programs</h2></div>'
            '<p class="sub">These names come from the open Ghidra project. '
            "They match Explorer. "
            "Add and Remove change this project.</p>"
            + render_table(
                ["program", "kind", "note"],
                program_rows,
            )
            + "</div>"
        )
    bars = render_binary_bars(slugs=slug_set) if slug_set else missing_html(
        "No corpus slugs in this tab."
    )
    table = _builds_table_html(slugs=slug_set) if slug_set else missing_html(
        "No corpus slugs in this tab."
    )
    return (
        render_session_hero(slug_set)
        + f'<p class="sub">Showing the open project'
        f"{(': <strong>' + esc(title) + '</strong>') if slug_set else ''}. "
        "Ghidra program names are listed separately — they are not store rows.</p>"
        f"{program_block}"
        f'<div class="block"><div class="blockhead"><h2 class="h-sec">Tab builds</h2></div>{bars}</div>'
        f'<div class="block"><div class="blockhead"><h2 class="h-sec">Tab store rows</h2></div>{table}</div>'
    )


def render_home() -> str:
    return render_page(None, WORKSPACE_NAME)


PAGE_INDEX = {
    "app": "/dashboard",
    "dashboard": "/dashboard",
    "explorer": "/dashboard/explorer",
    "overview": "/dashboard/overview",
    "atlas": "/atlas",
    "report": "/report",
    "recovery": "/report",
    "docs": "/docs",
    "swagger": "/docs",
    "functions": "/dashboard?window=wb-fnbrowse",
    "logical": "/dashboard?window=wb-logical",
    "graph": "/dashboard?window=wb-graph",
    "review": "/dashboard?window=wb-review",
    "artifact": "/dashboard?window=wb-artifacts",
    "evidence": "/dashboard?window=wb-evidence",
    "builds": "/dashboard?window=wb-corpus",
    "operations": "/dashboard?window=wb-processes",
    "healthz": "/dashboard/healthz",
    "static": "/dashboard/static",
    "actions": "/api/v1/actions",
}


def page_index() -> dict[str, str]:
    return dict(PAGE_INDEX)

