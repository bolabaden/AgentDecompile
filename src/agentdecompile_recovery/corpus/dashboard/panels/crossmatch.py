"""Cross-build identity layer and BSim — how a name in one fork reaches the others.

Every number here is read live from db/kotorxid.sqlite, bsim/, logs/ and
output/mizuchi/. Nothing is cached and nothing is hardcoded.

Two rules shape what this panel shows rather than what would look better:

1. Precision beats recall on this project, so a count is never shown without the
   confidence or score that earned it. 287k bindings is not 287k trustworthy
   bindings, and the page must not let anyone read it that way.
2. The `func` table is ~500 MB on an external disk. Nothing here touches it —
   func-side denominators come from `binary.func_count`, a stored per-binary
   integer, and where that is not good enough the number is reported as
   unavailable instead of being bought with a minutes-long scan.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from urllib.parse import quote

from agentdecompile_recovery.corpus.dashboard.panels.common import (
    DRM_EXCLUDED,
    esc,
    fnum,
    fpct,
    kv,
    load_json,
    missing,
    query_db,
    rel,
    table,
    tag,
)
from agentdecompile_recovery.corpus.dashboard.panels.viz import bars, donut, heatmap, stacked_bar

try:  # count_link is landing in common.py from another author.
    from agentdecompile_recovery.corpus.dashboard.panels.common import count_link
except ImportError:  # the panel still renders, with plain links
    count_link = None


def _details(inner: str, summary: str = "raw numbers") -> str:
    """Collapsed-by-default expansion of a chart, per Rule C.

    10-relationship-layout.md: "a table is only ever the expansion of a
    visual, never a replacement" — visible on click, not open by default.
    """
    return f'<details><summary>{esc(summary)}</summary>{inner}</details>'


def _conf_state(avg) -> str:
    """Map a confidence average onto the page's verification-state vocabulary.

    Mirrors `_conf()`'s good/warnt/bad split so a bar's hue and a table cell's
    class never disagree about the same number.
    """
    try:
        v = float(avg)
    except (TypeError, ValueError):
        return "unproven"
    if v >= 0.90:
        return "proven"
    if v >= TRUST_FLOOR:
        return "partial"
    return "failed"


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


def _file_link(path: Path) -> str:
    """Every artifact this panel quotes is one click from the number it fed."""
    return f'<a href="/artifact?p={esc(rel(path))}"><code>{esc(rel(path))}</code></a>'


def _slug_of(name: str) -> str:
    """Map a signature-set or repo name onto a build slug. 24 rows, so it is free."""
    rows, err = query_db("SELECT slug, repo_path FROM binary")
    if err:
        return ""
    for slug, repo in rows:
        if name in (str(slug), str(repo), os.path.basename(str(repo))):
            return str(slug)
    return ""

TITLE = "Cross-matching — bridging the forks"

from agentdecompile_recovery.corpus.dashboard.common import as_root
BSIM_DIR = as_root() / "bsim"
BSIM_SIGS = BSIM_DIR / "sigs"
BSIM_DB = BSIM_DIR / "kotor.mv.db"
BSIM_BATCH_LOG = as_root() / "logs" / "bsim_all16.log"
BSIM_JOB_LOGS = as_root() / "logs" / "bsim"
REUSE_SUMMARY = as_root() / "output" / "identity" / "identity_reuse_summary.json"
REUSE_CANDIDATES = as_root() / "output" / "identity" / "reuse_candidates.jsonl"
MATCH_REPORT = as_root() / "reports" / "_gen_matches.md"
MATCH_REPORT_ROW = re.compile(
    r"^\| `([^`]+)` \| `([^`]+)` \| [^|]+ \| ([\d,]+) \|", re.MULTILINE)

# A binding at or below this confidence is a lead, not an identification. The
# threshold exists so a weak method cannot hide inside a large row count.
TRUST_FLOOR = 0.70

# Markers Ghidra's bsim launcher prints. The launcher exits 0 on several of
# these, which is exactly why the batch log cannot be trusted on its own.
BSIM_FAILURES = (
    ("Connection to server failed", "Ghidra server unreachable on localhost:13300"),
    ("Invalid Ghidra URL", "program URL did not resolve"),
    ("No signature files found", "job wrote no signature files"),
    ("contains no functions with signatures", "program had zero signable functions"),
)
BSIM_SUCCESS = "Writing signatures for"


def _human_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:,.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{size:,.1f} GB"


def _conf(value, floor: float = TRUST_FLOOR) -> str:
    """Colour a confidence/score so a weak average cannot read as a strong one."""
    try:
        v = float(value)
    except (TypeError, ValueError):
        return "-"
    cls = "good" if v >= 0.90 else ("warnt" if v >= floor else "bad")
    return f'<span class="{cls}">{v:.3f}</span>'


def _read_log_lines(path: Path, nbytes: int = 1 << 20) -> list[str]:
    """Last nbytes of a log as lines. Job logs are small; the K1 mac one is 37 KB."""
    try:
        with path.open("rb") as fh:
            size = fh.seek(0, os.SEEK_END)
            fh.seek(max(0, size - nbytes))
            data = fh.read()
        return [ln.rstrip() for ln in data.decode("utf-8", "replace").splitlines() if ln.strip()]
    except OSError:
        return []


def _count_lines(path: Path) -> int | None:
    """Newline count without parsing. The candidates file may be large."""
    try:
        total = 0
        with path.open("rb") as fh:
            while True:
                chunk = fh.read(1 << 20)
                if not chunk:
                    break
                total += chunk.count(b"\n")
        return total
    except OSError:
        return None


# --------------------------------------------------------------------------
# sections
# --------------------------------------------------------------------------

def _explainer() -> str:
    return (
        '<p class="note">A <b>logical function</b> is an address-independent identity. '
        "<code>CAppManager::DoSaveGameScreenShot</code> sits at a different address in every "
        "build — one address in the GOG Windows exe, another in the Xbox XBE, another in the "
        "Android <code>.so</code> — but all of those addresses bind to a single logical id. "
        "That binding is the whole point: a name, signature or recovered C body written once "
        "against one fork propagates to every other build that shares the logical id, instead "
        "of being re-derived 15 more times.</p>"
        '<p class="note">The <code>identity</code> table holds those bindings '
        "(logical id &rarr; binary + address, with a method and a confidence). The "
        "<code>match</code> table holds candidate pairings that have not yet become identities. "
        "<b>Read both with their confidence attached</b> — this project trades recall for "
        "precision, so the honest number is always smaller than the row count.</p>"
    )


def _logical_section() -> str:
    totals, err = query_db(
        "SELECT COUNT(*), "
        "SUM(CASE WHEN source_file IS NOT NULL AND source_file <> '' THEN 1 ELSE 0 END) "
        "FROM logical_function"
    )
    if err:
        return missing(f"logical_function: {err}")
    if not totals:
        return missing("logical_function: no rows returned")
    n_logical, n_srcfile = totals[0][0] or 0, totals[0][1] or 0

    # How many builds each logical id reaches. A logical function present in one
    # build bridges nothing — it is identity bookkeeping, not propagation.
    spread, s_err = query_db(
        "SELECT n, COUNT(*) FROM (SELECT logical_id, COUNT(DISTINCT binary_id) n "
        "FROM identity GROUP BY logical_id) GROUP BY n ORDER BY n"
    )
    buckets = {"1 build": 0, "2 builds": 0, "3-4 builds": 0, "5-8 builds": 0, "9+ builds": 0}
    multi = 0
    if not s_err:
        for n, count in spread:
            if n <= 1:
                buckets["1 build"] += count
            else:
                multi += count
                if n == 2:
                    buckets["2 builds"] += count
                elif n <= 4:
                    buckets["3-4 builds"] += count
                elif n <= 8:
                    buckets["5-8 builds"] += count
                else:
                    buckets["9+ builds"] += count

    # Spanning more than one game is the actual fork crossing: K1 knowledge
    # reaching K2, or either reaching the other BioWare engines.
    games, g_err = query_db(
        "SELECT ng, COUNT(*) FROM (SELECT i.logical_id, COUNT(DISTINCT b.game) ng "
        "FROM identity i JOIN binary b ON b.id = i.binary_id GROUP BY i.logical_id) "
        "GROUP BY ng ORDER BY ng"
    )
    cross_game = sum(c for ng, c in games if ng and ng > 1) if not g_err else None

    pairs = [
        ("logical functions", fnum(n_logical)),
        ("with a source_file attributed", f"{fnum(n_srcfile)} &middot; {fpct(n_srcfile, n_logical)}"),
    ]
    if not s_err:
        pairs.append((
            "reach 2+ builds (actually bridge)",
            f'<span class="good">{fnum(multi)}</span> &middot; {fpct(multi, n_logical)}',
        ))
        pairs.append((
            "reach exactly 1 build (bridge nothing)",
            f'<span class="warnt">{fnum(buckets["1 build"])}</span> &middot; '
            f'{fpct(buckets["1 build"], n_logical)}',
        ))
    if cross_game is not None:
        # kv() escapes its labels, so keep entities out of the left column.
        pairs.append((
            "cross a game boundary (K1 / K2 / other engines)",
            f"{fnum(cross_game)} &middot; {fpct(cross_game, n_logical)}",
        ))

    out = [kv(pairs)]
    if s_err:
        out.append(missing(f"build-spread histogram unavailable: {s_err}"))
    else:
        # Bucket order is the build-reach progression, not a magnitude ranking,
        # so it stays unsorted; sorting by count would scramble "1 build" ...
        # "9+ builds" into an order that hides the actual distribution.
        bucket_state = {"1 build": "partial", "2 builds": "proven",
                        "3-4 builds": "proven", "5-8 builds": "proven",
                        "9+ builds": "proven"}
        chart_rows = [(label, count, bucket_state[label]) for label, count in buckets.items()]
        out.append(bars(chart_rows, sort=False))
        rows = [[label, fnum(count), fpct(count, n_logical)] for label, count in buckets.items()]
        out.append(_details(table(["builds reached", "logical functions", "share"],
                                  rows, numeric={1, 2})))
        out.append(
            '<p class="note">Reach is the payoff multiplier. A name written against one of the '
            f'{fnum(buckets["9+ builds"])} logical functions that reach nine or more builds lands '
            "in all of them at once; a name written against a single-build logical function lands "
            "once.</p>"
        )
    return "".join(out)


def _identity_section() -> str:
    head, err = query_db(
        "SELECT COUNT(*), COUNT(DISTINCT binary_id || ':' || addr), COUNT(DISTINCT logical_id), "
        "COUNT(DISTINCT binary_id) FROM identity"
    )
    if err:
        return missing(f"identity: {err}")
    if not head:
        return missing("identity: no rows returned")
    n_rows, n_addr, n_logical, n_bins = (head[0][0] or 0, head[0][1] or 0,
                                         head[0][2] or 0, head[0][3] or 0)

    # Denominator comes from binary.func_count (24 stored integers), never from a
    # COUNT(*) over func. DRM ciphertext is excluded so it cannot inflate it.
    placeholders = ",".join("?" for _ in DRM_EXCLUDED)
    denom, d_err = query_db(
        f"SELECT SUM(func_count), COUNT(*) FROM binary WHERE repo_path NOT IN ({placeholders})",
        tuple(DRM_EXCLUDED),
    )
    total_funcs = denom[0][0] if (not d_err and denom) else None
    total_bins = denom[0][1] if (not d_err and denom) else None

    pairs = [
        ("identity rows", fnum(n_rows)),
        # No single build owns the corpus-wide bound set, so this opens the
        # function browser at its build picker rather than at a filter it cannot
        # honour.
        ("distinct (binary, addr) bound", _clink(n_addr, "/functions?bound=1")),
        ("distinct logical ids covered", fnum(n_logical)),
        ("binaries with at least one binding", fnum(n_bins)),
    ]
    if total_funcs:
        pairs.append((
            "bound share of all functions (binary.func_count sum)",
            f"{fpct(n_addr, total_funcs)} of {fnum(total_funcs)}",
        ))
    if total_bins and n_bins < total_bins:
        pairs.append((
            "binaries with no bindings",
            f'<span class="warnt">{fnum(total_bins - n_bins)}</span>',
        ))

    methods, m_err = query_db(
        "SELECT method, COUNT(*), AVG(confidence), MIN(confidence), MAX(confidence) "
        "FROM identity GROUP BY method ORDER BY AVG(confidence) DESC"
    )
    out = [kv(pairs)]
    if total_funcs is None:
        out.append(missing(
            "per-function bind rate unavailable: it needs a denominator from the 500 MB `func` "
            "table, and that scan is too slow to run on a page load"
        ))
    if m_err:
        out.append(missing(f"identity method breakdown unavailable: {m_err}"))
        return "".join(out)

    weak = sum(c for _, c, avg, _, _ in methods if (avg or 0) < TRUST_FLOOR)
    # Bar hue reuses the same good/warnt/bad split _conf() already draws in the
    # table cell below, so the chart and its own expansion never disagree.
    chart_rows = [(method or "(null)", count, _conf_state(avg)) for method, count, avg, _, _ in methods]
    out.append(bars(chart_rows, href_fn=None))
    rows = []
    for method, count, avg, lo, hi in methods:
        badge = "" if (avg or 0) >= TRUST_FLOOR else " " + tag("lead only", "warn")
        rows.append([
            esc(method or "(null)") + badge,
            fnum(count),
            fpct(count, n_rows),
            _conf(avg),
            f"{(lo or 0):.2f}&ndash;{(hi or 0):.2f}",
        ])
    out.append(_details(table(
        ["method", "bindings", "share", "avg confidence", "range"], rows, numeric={1, 2, 3, 4}
    )))
    out.append(
        f'<p class="note"><b>{fnum(weak)} of {fnum(n_rows)} bindings ({fpct(weak, n_rows)}) come '
        f"from methods whose average confidence is below {TRUST_FLOOR:.2f}.</b> Those are "
        "candidate leads carried in the same table as identifications, not identifications. "
        "The <code>name-*</code> methods bind on name evidence; the <code>match:*</code> methods "
        "are promotions out of the matcher, and carry its score forward.</p>"
    )
    return "".join(out)


def _match_section() -> str:
    rows_db, err = query_db(
        "SELECT status, COUNT(*), AVG(score), MIN(score), MAX(score) "
        "FROM match GROUP BY status ORDER BY COUNT(*) DESC"
    )
    if err:
        return missing(f"match: {err}")
    if not rows_db:
        return missing("match: no rows yet")

    total = sum(r[1] or 0 for r in rows_db)
    auto = sum(r[1] or 0 for r in rows_db if (r[0] or "") == "auto")
    needs_human = sum(r[1] or 0 for r in rows_db if (r[0] or "") in ("review", "verify"))

    # Status is a gate, not a label: only `auto` lands without a human.
    gate = {
        "auto": ("accepted without review", "ok"),
        "verify": ("queued for verification", "warn"),
        "review": ("queued for human review", "warn"),
        "unresolved": ("no confident target", "dead"),
        "rejected": ("discarded", "dead"),
    }
    out_rows = []
    for status, count, avg, lo, hi in rows_db:
        label, kind = gate.get(status or "", ("", ""))
        count_cell = (
            _clink(count, "/review") if (status or "") == "review" else fnum(count)
        )
        out_rows.append([
            esc(status or "(null)") + (" " + tag(label, kind) if label else ""),
            count_cell,
            fpct(count, total),
            _conf(avg),
            f"{(lo or 0):.2f}&ndash;{(hi or 0):.2f}",
        ])

    # Status is the whole match queue broken into states, so the gate's own
    # ok/warn/dead verdict becomes the bar's proven/partial/failed segment —
    # the single value is `total`, and every row is a slice of it.
    gate_state = {"ok": "proven", "warn": "partial", "dead": "failed"}
    chart_rows = [(status or "(null)", count,
                   gate_state.get(gate.get(status or "", ("", ""))[1], "unproven"))
                  for status, count, avg, lo, hi in rows_db]

    return "".join([
        stacked_bar(chart_rows),
        kv([
            ("match rows", fnum(total)),
            ("auto-accepted (no human needed)",
             f'<span class="good">{fnum(auto)}</span> &middot; {fpct(auto, total)}'),
            ("still awaiting a human",
             f'<span class="warnt">{_clink(needs_human, "/review")}</span>'
             f' &middot; {fpct(needs_human, total)}'),
        ]),
        _details(table(["status", "matches", "share", "avg score", "range"],
                       out_rows, numeric={1, 2, 3, 4})),
        '<p class="note"><b>The largest bucket is not the trustworthy one.</b> Only '
        f"{fnum(auto)} matches ({fpct(auto, total)}) cleared the bar to be accepted without a "
        f"human; {fnum(needs_human)} sit in "
        f'<a href="/review">review</a> or verify queues. A high average score inside '
        "a review bucket does not promote it — the bucket is where the matcher declined to "
        "decide.</p>",
    ])


def _bsim_section() -> str:
    out = [
        '<p class="note">BSim is Ghidra\'s structural function-similarity index: it decompiles '
        "each function, reduces it to a feature vector, and finds near neighbours in other "
        "programs. Generating a signature set per binary is a prerequisite for any all-pairs "
        "cross-query — a binary without signatures cannot appear on either side of one.</p>"
    ]

    if not BSIM_DIR.exists():
        return "".join(out) + missing(f"not available yet ({rel(BSIM_DIR)} missing)")

    # --- database file -----------------------------------------------------
    if BSIM_DB.exists():
        try:
            st = BSIM_DB.stat()
            db_line = f"{_human_bytes(st.st_size)} &middot; {_file_link(BSIM_DB)}"
        except OSError as exc:  # noqa: BLE001
            db_line = f'<span class="bad">unreadable: {esc(exc)}</span>'
    else:
        db_line = f'<span class="warnt">absent ({esc(rel(BSIM_DB))})</span>'

    # --- signature sets on disk -------------------------------------------
    signed: list[str] = []
    empty: list[str] = []
    if BSIM_SIGS.exists():
        try:
            for entry in sorted(BSIM_SIGS.iterdir()):
                if not entry.is_dir():
                    continue
                # A committed set writes a sigs_<md5>/ folder; an empty dir is a
                # job that ran and produced nothing.
                (signed if any(entry.iterdir()) else empty).append(entry.name)
        except OSError as exc:  # noqa: BLE001
            out.append(missing(f"could not list {rel(BSIM_SIGS)}: {exc}"))
    else:
        out.append(missing(f"no signature sets yet ({rel(BSIM_SIGS)} missing)"))

    # Corpus-wide view: which binaries in the DB have signatures at all.
    placeholders = ",".join("?" for _ in DRM_EXCLUDED)
    bins, b_err = query_db(
        f"SELECT slug FROM binary WHERE repo_path NOT IN ({placeholders}) ORDER BY slug",
        tuple(DRM_EXCLUDED),
    )
    all_slugs = [r[0] for r in bins] if not b_err else []
    have = [s for s in all_slugs if s in set(signed)]
    lack = [s for s in all_slugs if s not in set(signed)]

    pairs = [("bsim/kotor.mv.db", db_line), ("signature sets with content", fnum(len(signed)))]
    if empty:
        pairs.append(("signature dirs created but empty",
                      f'<span class="bad">{fnum(len(empty))}</span>'))
    if all_slugs:
        pairs.append((
            "corpus binaries covered (DRM pair excluded)",
            f'<span class="{"good" if len(have) == len(all_slugs) else "warnt"}">'
            f"{fnum(len(have))}</span> of {fnum(len(all_slugs))} &middot; "
            f"{fpct(len(have), len(all_slugs))}",
        ))
    if all_slugs:
        # Part of whole: how much of the corpus can even take part in a
        # cross-query. "no signatures yet" is absence of evidence, not a
        # failed check, so it stays the neutral/default state rather than red.
        out.append(donut(
            [("signatures present", len(have), "proven"),
             ("no signatures yet", len(lack), "unproven")],
            total=len(all_slugs), title="BSim signature coverage",
        ))
    out.append(kv(pairs))

    def _name_cell(name: str) -> str:
        slug = _slug_of(name)
        if not slug:
            return esc(name)
        return f'<a href="{esc(_bin_href(slug))}">{esc(name)}</a>'

    if signed or empty:
        srows = [[_name_cell(name), tag("signatures present", "ok")] for name in signed]
        srows += [[_name_cell(name), tag("empty — job produced nothing", "dead")]
                  for name in empty]
        out.append(_details(table(["signature set", "state"], srows)))
    if lack:
        out.append(
            f'<p class="note"><b>{fnum(len(lack))} corpus binaries have no BSim signatures</b>, '
            "so they cannot take part in any cross-query: "
            + ", ".join(f'<a href="{esc(_bin_href(s))}"><code>{esc(s)}</code></a>'
                        for s in lack)
            + ".</p>"
        )
    return "".join(out) + _bsim_logs()


def _bsim_logs() -> str:
    """Reconcile the batch log against the per-job logs.

    The batch script marks a job ok on exit status, but Ghidra's bsim launcher
    exits 0 after printing "Connection to server failed (localhost:13300)". A run
    can therefore look clean at the batch level while most jobs produced nothing.
    Trust the per-job logs, not the batch summary.
    """
    out: list[str] = []

    batch_ok = batch_fail = batch_skip = 0
    batch_done = False
    if BSIM_BATCH_LOG.exists():
        for line in _read_log_lines(BSIM_BATCH_LOG):
            if line.startswith("[ok]"):
                batch_ok += 1
            elif line.startswith("[FAIL]"):
                batch_fail += 1
            elif line.startswith("[skip]"):
                batch_skip += 1
            elif "BATCH DONE" in line:
                batch_done = True
    else:
        out.append(missing(f"not available yet ({rel(BSIM_BATCH_LOG)} missing)"))

    jobs: list[tuple[str, str, str, str, float]] = []  # (name, state, cause, line, mtime)
    if BSIM_JOB_LOGS.is_dir():
        try:
            for log in sorted(BSIM_JOB_LOGS.glob("*.log")):
                lines = _read_log_lines(log)
                blob = "\n".join(lines)
                hit = next(((m, why) for m, why in BSIM_FAILURES if m in blob), None)
                if hit:
                    marker, cause = hit
                    # The trailing line is usually a generic "ERROR Unavailable";
                    # the line carrying the marker names the real cause.
                    detail = next(
                        (ln for ln in reversed(lines) if marker in ln),
                        next((ln for ln in reversed(lines) if "ERROR" in ln), cause),
                    )
                    state = "fail"
                elif BSIM_SUCCESS in blob:
                    cause, detail, state = "signatures written", "", "ok"
                else:
                    cause, detail, state = "no verdict in log", "", "unknown"
                try:
                    mtime = log.stat().st_mtime
                except OSError:
                    mtime = 0.0
                jobs.append((log.stem, state, cause, detail, mtime))
        except OSError as exc:  # noqa: BLE001
            out.append(missing(f"could not list {rel(BSIM_JOB_LOGS)}: {exc}"))
    elif BSIM_BATCH_LOG.exists():
        out.append(missing(f"per-job logs unavailable ({rel(BSIM_JOB_LOGS)} missing)"))

    if not jobs and not BSIM_BATCH_LOG.exists():
        return "".join(out)

    failed = [j for j in jobs if j[1] == "fail"]
    passed = [j for j in jobs if j[1] == "ok"]
    unknown = [j for j in jobs if j[1] == "unknown"]

    pairs = []
    if BSIM_BATCH_LOG.exists():
        pairs.append((
            f"{rel(BSIM_BATCH_LOG)} says",
            f'ok {fnum(batch_ok)} &middot; fail {fnum(batch_fail)} &middot; '
            f"skip {fnum(batch_skip)}"
            + ("" if batch_done else ' &middot; <span class="warnt">no BATCH DONE line</span>')
            + " &middot; " + _file_link(BSIM_BATCH_LOG),
        ))
    if jobs:
        pairs.append(("per-job logs inspected", fnum(len(jobs))))
        pairs.append(("jobs that wrote signatures",
                      f'<span class="good">{fnum(len(passed))}</span>'))
        pairs.append(("jobs that failed",
                      f'<span class="{"bad" if failed else "good"}">{fnum(len(failed))}</span>'))
        if unknown:
            pairs.append(("jobs with no verdict",
                          f'<span class="warnt">{fnum(len(unknown))}</span>'))
    out.append(kv(pairs))

    if failed:
        # The gap between the batch count and the real count is the bug, so name it.
        if BSIM_BATCH_LOG.exists() and len(failed) > batch_fail:
            out.append(
                f'<p class="note"><b class="bad">The batch log undercounts failures: it records '
                f"{fnum(batch_fail)}, the per-job logs show {fnum(len(failed))}.</b> Ghidra's bsim "
                "launcher exits 0 after a connection failure, so the batch script marks those "
                "jobs ok. Any run of this batch must be judged from "
                f"<code>{esc(rel(BSIM_JOB_LOGS))}</code>.</p>"
            )
        # Cluster by cause: one dead server explaining six jobs is the finding,
        # not six unrelated failures.
        by_cause: dict[str, int] = {}
        for _, _, cause, _, _ in failed:
            by_cause[cause] = by_cause.get(cause, 0) + 1
        out.append(bars([(c, n, "failed") for c, n in by_cause.items()]))
        out.append(_details(table(
            ["failure cause", "jobs"],
            [[esc(c), fnum(n)] for c, n in sorted(by_cause.items(), key=lambda kvp: -kvp[1])],
            numeric={1},
        )))

        newest = max(failed, key=lambda j: j[4])
        out.append(
            f'<p class="note">Most recent failure &mdash; <code>{esc(newest[0])}</code>: '
            f'<span class="bad">{esc(newest[3][:240])}</span></p>'
        )
        out.append(_details(table(
            ["failed job", "cause", "log line"],
            [[_file_link(BSIM_JOB_LOGS / f"{n}.log"), esc(c), esc(d[:150])]
             for n, _, c, d, _ in sorted(failed, key=lambda j: -j[4])],
        ), "per-job failure log lines"))
    elif jobs:
        out.append(f'<p class="note">All {fnum(len(passed))} inspected jobs wrote signatures.</p>')
    return "".join(out)


def _reuse_section() -> str:
    out = [
        '<p class="note">The concrete payoff of cross-matching: a function whose C body was '
        "verified byte-exact in one fork, carried into another build through its logical id. "
        "Written for the MizuchiRE effort, which recovers C one function at a time and has no "
        "identity layer of its own.</p>"
    ]

    data, err = load_json(REUSE_SUMMARY)
    if err:
        out.append(missing(err))
    elif not isinstance(data, dict):
        out.append(missing(f"{rel(REUSE_SUMMARY)} is not a JSON object"))
    else:
        scanned = data.get("recovered_functions_scanned")
        exact = data.get("recovered_byte_exact")
        no_identity = data.get("recovered_without_identity")
        reuse_rows = data.get("reuse_rows")
        high_conf = data.get("high_confidence_rows")
        same_size = data.get("same_size_rows")

        pairs = [
            ("recovered functions scanned", fnum(scanned)),
            ("byte-exact in their own build", fnum(exact)),
        ]
        if no_identity is not None:
            cls = "bad" if no_identity else "good"
            pairs.append(("recovered but bound to no logical id",
                          f'<span class="{cls}">{fnum(no_identity)}</span>'))
        pairs.append((
            "reuse candidates emitted",
            f'<span class="{"good" if (reuse_rows or 0) else "warnt"}">{fnum(reuse_rows)}</span>',
        ))
        if high_conf is not None:
            pairs.append(("of those, high confidence", fnum(high_conf)))
        if same_size is not None:
            pairs.append(("of those, same size in the target build", fnum(same_size)))
        pairs.append(("read from", _file_link(REUSE_SUMMARY)))
        # The candidate count alone overstates the payoff (see the note below);
        # splitting it into high-confidence vs the rest is the single value the
        # kv pairs already state, drawn instead of just stated.
        if reuse_rows:
            rest = max(0, reuse_rows - (high_conf or 0))
            out.append(stacked_bar([
                ("high confidence", high_conf or 0, "proven"),
                ("lower confidence", rest, "partial"),
            ]))
        out.append(kv(pairs))

        # State the shortfall plainly; a zero here is the headline, not a footnote.
        if scanned and not (reuse_rows or 0):
            reason = (
                f"all {fnum(no_identity)} of them are bound to no logical id"
                if no_identity else "none of them cleared the reuse test"
            )
            out.append(
                f'<p class="note"><b class="bad">No reuse candidates yet.</b> '
                f"{fnum(scanned)} recovered functions were scanned and {fnum(exact)} are "
                f"byte-exact, but {reason} — with no identity there is no second build to carry "
                "the body into. The bridge is built; nothing has crossed it yet.</p>"
            )
        elif reuse_rows:
            out.append(
                f'<p class="note">{fnum(high_conf)} of {fnum(reuse_rows)} candidates are high '
                f"confidence ({fpct(high_conf or 0, reuse_rows)}). Judge the payoff by that "
                "column, not by the candidate count.</p>"
            )

    if REUSE_CANDIDATES.exists():
        lines = _count_lines(REUSE_CANDIDATES)
        try:
            size = REUSE_CANDIDATES.stat().st_size
        except OSError:
            size = 0
        out.append(kv([(
            rel(REUSE_CANDIDATES),
            ("empty file" if not size
             else f"{fnum(lines)} rows &middot; {_human_bytes(size)}")
            + " &middot; " + _file_link(REUSE_CANDIDATES),
        )]))
    else:
        out.append(missing(f"not available yet ({rel(REUSE_CANDIDATES)} missing)"))
    return "".join(out)


def _matrix_section() -> str:
    """Build x build density from the `match` table — the project in one picture.

    `match.src_binary` / `match.dst_binary` already store this as a real
    matrix; every other view on this page collapses it to a status or method
    breakdown, which is the exact thing 10-relationship-layout.md calls out —
    a relationship shown as prose instead of the grid it already is.
    """
    # `_gen_matches.md` is written by the offline matcher from the same grouped
    # result. Reading its bounded summary avoids regrouping the entire match
    # table whenever this lazy panel's cache expires.
    try:
        report = MATCH_REPORT.read_text(encoding="utf-8")
    except OSError as exc:
        return missing(f"match matrix summary unavailable ({rel(MATCH_REPORT)}: {exc})")
    pairs = {}
    for src, dst, count in MATCH_REPORT_ROW.findall(report):
        pairs[(src, dst)] = pairs.get((src, dst), 0) + int(count.replace(",", ""))
    if not pairs:
        return missing(f"match matrix summary has no rows ({rel(MATCH_REPORT)})")

    bins, b_err = query_db("SELECT id, slug, repo_path FROM binary")
    if b_err:
        return missing(f"binary slugs: {b_err}")
    aliases = {}
    for _bid, slug, repo in bins:
        short_slug = str(slug).split("__", 1)[-1]
        for key in (slug, short_slug, repo, os.path.basename(str(repo))):
            aliases[str(key)] = str(slug)
    cells = {(aliases.get(src, src), aliases.get(dst, dst)): count
             for (src, dst), count in pairs.items()}
    row_labels = sorted({r for r, _ in cells})
    col_labels = sorted({c for _, c in cells})
    matrix = [[cells.get((r, c), 0) for c in col_labels] for r in row_labels]

    chart = heatmap(matrix, row_labels, col_labels,
                    href_fn=lambda r, *_: _bin_href(r))
    note = (
        f'<p class="note">Density from the offline summary {_file_link(MATCH_REPORT)}: '
        f'{fnum(len(row_labels))} builds queried as a source against '
        f"{fnum(len(col_labels))} builds that have "
        "appeared as a target. These are candidate pairings, not identities — see "
        "the match queue above for how many of them clear the bar to be accepted. A "
        "binary missing from the row axis has not been run as a source yet; one "
        "missing from the column axis has never been matched against.</p>"
    )
    return chart + note


# --------------------------------------------------------------------------

_SECTIONS = (
    ("What a logical function is", _explainer),
    ("Cross-match density — build × build (table `match`)", _matrix_section),
    ("Logical functions — the address-independent layer", _logical_section),
    ("Identity bindings — logical id to a real address", _identity_section),
    ("Match queue — candidates that are not identities yet", _match_section),
    ("BSim — structural similarity index", _bsim_section),
    ("Reuse into MizuchiRE — what cross-matching bought", _reuse_section),
)


def render() -> str:
    parts = []
    for heading, fn in _SECTIONS:
        try:
            body = fn()
        except Exception as exc:  # noqa: BLE001 — a panel must degrade, never raise
            body = missing(f"section failed: {type(exc).__name__}: {exc}")
        parts.append(
            f'<div class="panel"><div class="ptitle"><b>{esc(heading)}</b></div>{body}</div>'
        )
    return "".join(parts)
