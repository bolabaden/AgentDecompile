"""Source recovery: Ghidra C -> decomp-permuter -> byte-exact real C.

This panel reports the pipeline in `kx/permuter_harness.py` (run sampling) and
`scripts/compile_tally.py` (compile-failure census). There is no language model
in that loop: Ghidra emits C that behaves right but compiles to different bytes,
decomp-permuter mutates it, and a variant is kept only when its bytes equal the
original function's bytes.

Two properties are tracked separately everywhere on this page, because merging
them is what produced months of misleading results:

* `real_c`     -- the source contains no `__asm` / `naked` / `_emit` / `.byte`
* `byte_exact` -- the compiled bytes equal the original function's bytes

A byte-exact `__asm` shim is the original machine code copied into a C wrapper;
it recovers nothing. So the headline number here is always real-C AND byte-exact,
and any raw byte-exact count is labelled with how many asm shims it contains.

Every figure is read live from a file under `output/`. Nothing is cached and
nothing is hardcoded; a missing artifact is reported as missing.
"""

from __future__ import annotations

import re
import sys
import time
from pathlib import Path
from urllib.parse import quote

if __package__ in (None, ""):
    # The dashboard loader puts the repo root on sys.path; this keeps the module
    # importable when it is exercised directly from a checkout instead.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agentdecompile_recovery.corpus.dashboard.panels.common import (  # noqa: E402
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
from agentdecompile_recovery.corpus.dashboard.panels.viz import bars, donut, stacked_bar  # noqa: E402

try:  # count_link is landing in common.py from another author.
    from agentdecompile_recovery.corpus.dashboard.panels.common import count_link
except ImportError:  # the panel still renders, with plain links
    count_link = None


def _details(inner: str, summary: str = "raw numbers") -> str:
    """Collapsed-by-default expansion of a chart (10-relationship-layout.md
    Rule C: "a table is only ever the expansion of a visual, never a
    replacement" — visible on click, not open by default)."""
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


def _file_link(path: Path) -> str:
    return f'<a href="/artifact?p={esc(rel(path))}"><code>{esc(rel(path))}</code></a>'


def _slugs() -> dict[str, str]:
    """repo_path -> slug, so a sampled function's build is one click away."""
    rows, err = query_db("SELECT repo_path, slug FROM binary")
    return {} if err else {str(r[0]): str(r[1]) for r in rows}


def _build_links(repo_paths) -> str:
    slugs = _slugs()
    out = []
    for repo in repo_paths:
        slug = slugs.get(str(repo))
        out.append(f'<a href="{esc(_bin_href(slug))}">{esc(repo)}</a>' if slug
                   else esc(repo))
    return ", ".join(out) if out else "?"

TITLE = "Source recovery — Ghidra C → permuter → byte-exact"

from agentdecompile_recovery.corpus.dashboard.common import as_root
PERMUTER_DIR = as_root() / "output" / "permuter"
COMPILE_TALLY = PERMUTER_DIR / "compile_tally.json"
RESULT_PATHS = (PERMUTER_DIR / "sample_results.json",
                PERMUTER_DIR / "smoke_results.json")
EXPERIMENT_DIRS = (as_root() / "output" / "ladder", as_root() / "output" / "ab_test")

# A run-results file carries every prompt, every attempt and every plugin
# payload, so it can reach hundreds of MB. Only the small `summary` object is
# needed here, and a huge file is skipped rather than parsed on a request path.
MAX_RESULT_BYTES = 32 << 20

ERR_CODE = re.compile(r"\b(C\d{4})\b")

# Outcome strings are assigned in kx/permuter_harness.py; the gloss is here so
# the page explains itself without the reader opening that file.
OUTCOME_GLOSS = {
    "ghidra_c_matched": "Ghidra's C already compiled to the original bytes",
    "permuter_matched": "a mutated variant compiled to the original bytes",
    "permuter_close": "permuter produced a variant, bytes still differ",
    "permuter_no_output": "permuter ran and produced nothing",
    "permuter_timeout": "permuter hit its time limit",
    "base_c_does_not_compile": "MSVC rejected the decompiled C, permuter never ran",
    "no_ghidra_c": "no decompiled C available for the function",
    "no_target_bytes": "original bytes could not be read",
}


def _band_key(band: str):
    head = str(band).split("-", 1)[0].strip()
    try:
        return (0, int(head))
    except ValueError:
        return (1, str(band))


def _mtime(path: Path):
    try:
        return path.stat().st_mtime
    except OSError:
        return None


def _size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _safe(build, title: str) -> str:
    """One unreadable artifact must cost its own section, not the whole page."""
    try:
        return build()
    except Exception as exc:  # noqa: BLE001
        return panel(missing(f"could not build this section: {exc}"), title)


def _byte_exact(row: dict) -> bool:
    # A permuter-produced variant records `byte_exact`; an unmutated Ghidra body
    # records `base_byte_exact`. Either one is a byte match, and neither one on
    # its own says whether the source is real C.
    return bool(row.get("byte_exact") or row.get("base_byte_exact"))


def _real_c(row: dict) -> bool:
    if "real_c" in row:
        return bool(row.get("real_c"))
    return bool(row.get("base_real_c"))


def _render_run() -> str:
    """Headline metric from the freshest per-function sample run."""
    dated = [(p, _mtime(p)) for p in RESULT_PATHS]
    dated = [(p, m) for p, m in dated if m is not None]
    if not dated:
        names = " or ".join(rel(p) for p in RESULT_PATHS)
        return panel(missing(f"no permuter run recorded yet ({names} missing)"),
                     "Real C and byte-exact, by size band")

    chosen, mtime = max(dated, key=lambda pm: pm[1])
    rows, err = load_json(chosen)
    if err or not isinstance(rows, list) or not rows:
        return panel(missing(err or f"{rel(chosen)} holds no results"),
                     "Real C and byte-exact, by size band")

    total = len(rows)
    recovered = sum(1 for r in rows if isinstance(r, dict)
                    and r.get("real_c_and_byte_exact"))
    byte_hits = sum(1 for r in rows if isinstance(r, dict) and _byte_exact(r))
    shims = max(0, byte_hits - recovered)
    compiles = sum(1 for r in rows if isinstance(r, dict) and r.get("base_compiles"))
    real_c_src = sum(1 for r in rows if isinstance(r, dict) and _real_c(r))
    seconds = sum(float(r.get("permuter_seconds") or 0) for r in rows
                  if isinstance(r, dict))
    binaries = sorted({str(r.get("repo_path")) for r in rows
                       if isinstance(r, dict) and r.get("repo_path")})

    bands: dict[str, list[int]] = {}
    outcomes: dict[str, int] = {}
    for r in rows:
        if not isinstance(r, dict):
            continue
        slot = bands.setdefault(str(r.get("band", "?")), [0, 0, 0])
        slot[0] += 1
        slot[1] += bool(r.get("real_c_and_byte_exact"))
        slot[2] += bool(_byte_exact(r))
        key = str(r.get("outcome", "?"))
        outcomes[key] = outcomes.get(key, 0) + 1

    band_rows = [
        [esc(band), fnum(s[0]), fnum(s[1]), fpct(s[1], s[0]), fnum(s[2])]
        for band, s in sorted(bands.items(), key=lambda kv: _band_key(kv[0]))
    ]
    band_rows.append([
        "<b>all</b>", f"<b>{fnum(total)}</b>", f"<b>{fnum(recovered)}</b>",
        f"<b>{fpct(recovered, total)}</b>", f"<b>{fnum(byte_hits)}</b>",
    ])

    outcome_rows = [
        [esc(name), fnum(count), fpct(count, total),
         esc(OUTCOME_GLOSS.get(name, ""))]
        for name, count in sorted(outcomes.items(), key=lambda kv: (-kv[1], kv[0]))
    ]

    stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(mtime))
    # The sample covers one build in every run written so far. When it covers
    # exactly one, its counts can open that build's recovered set; when it covers
    # several, no single filter describes them and they stay plain.
    slug = _slugs().get(binaries[0]) if len(binaries) == 1 else ""
    recovered_cell = (
        _clink(recovered, _fn_href(slug, "&real_c=1"),
               title="every real-C body recovered in this build")
        if slug else fnum(recovered))
    shim_cell = (_clink(shims, _fn_href(slug, "&shim=1")) if slug and shims
                 else fnum(shims))
    shim_note = (f"includes {shim_cell} __asm/naked shim"
                 f"{'' if shims == 1 else 's'} — not recovered source"
                 if shims else "no __asm/naked shims in this sample")
    where = _build_links(binaries)
    # The band rows count sampled subsets no filter can name, so only the total
    # becomes a door.
    band_rows[-1][2] = f"<b>{recovered_cell}</b>"

    head = (
        f'<p class="headline">{recovered_cell} / {fnum(total)} sampled functions '
        f'real C <em>and</em> byte-exact '
        f'<span class="hl">({fpct(recovered, total)})</span></p>'
        f'<p class="sub">Source: {_file_link(chosen)} &middot; '
        f'written {esc(stamp)} ({esc(ago(mtime))}) &middot; '
        f'freshest of {fnum(len(dated))} run file(s) on disk.</p>'
        f'<p class="sub">Raw byte-exact (source not checked): '
        f'<b>{fnum(byte_hits)}</b> — {shim_note}. '
        f'Ghidra C compiled as-is for {fnum(compiles)} of {fnum(total)}; '
        f'{fnum(real_c_src)} bodies were free of asm. '
        f'Permuter time {seconds:,.1f}s. Binaries: {where}.</p>'
    )

    # The most misleading number on this whole page, drawn instead of stated:
    # a raw byte-exact count silently includes __asm shims, which are the
    # original machine code in a C wrapper and recover nothing. This ring
    # keeps the three outcomes visually distinct so "byte-exact" can never be
    # misread as "recovered source" again.
    misleading_donut = donut(
        [("real C + byte exact", recovered, "proven"),
         ("byte-exact shim only (not real C)", shims, "partial"),
         ("not byte exact", max(0, total - byte_hits), "failed")],
        total=total, title="What the sample actually proved",
    )
    # Size-band order is the meaningful axis here (small functions first), so
    # this stays unsorted rather than reordering bands by count.
    band_chart = bars(
        [(band, s[1], "proven") for band, s in
         sorted(bands.items(), key=lambda kv: _band_key(kv[0]))],
        sort=False,
    )
    outcome_chart = bars(
        [(name, count, "proven" if name == "ghidra_c_matched"
          or name == "permuter_matched" else "unproven")
         for name, count in outcomes.items()],
    )

    body = (
        head
        + misleading_donut
        + '<p class="sub" style="margin:14px 0 6px">Real C + byte-exact, per size '
          "band:</p>"
        + band_chart
        + _details(table(["Band (bytes)", "Sampled", "Real C + byte-exact", "Rate",
                          "Byte-exact incl. shims"],
                        band_rows, numeric={1, 2, 3, 4}))
        + '<p class="sub" style="margin:14px 0 6px">Outcomes recorded by '
          '<code>kx/permuter_harness.py</code>:</p>'
        + outcome_chart
        + _details(table(["Outcome", "Functions", "Share", "Meaning"],
                        outcome_rows, numeric={1, 2}))
    )
    return panel(body, "Real C and byte-exact, by size band")


def _render_tally() -> str:
    """Why Ghidra's C fails MSVC, over a random sample of functions."""
    rows, err = load_json(COMPILE_TALLY)
    if err or not isinstance(rows, list) or not rows:
        return panel(missing(err or f"{rel(COMPILE_TALLY)} holds no results"),
                     "Raw compile rate (Ghidra C, unmodified)")

    total = len(rows)
    ok = sum(1 for r in rows if isinstance(r, dict) and r.get("ok"))
    failed = total - ok

    # Counted per function, not per error line: one bad construct repeats dozens
    # of times inside a single body, and line counts would rank a single ugly
    # function above an error that blocks hundreds.
    counts: dict[str, int] = {}
    examples: dict[str, str] = {}
    for r in rows:
        if not isinstance(r, dict) or r.get("ok"):
            continue
        errors = r.get("errors") or []
        seen = set()
        for line in errors:
            match = ERR_CODE.search(str(line))
            code = match.group(1) if match else "(no code)"
            seen.add(code)
            examples.setdefault(code, str(line))
        if not errors:
            seen.add("(no message captured)")
        for code in seen:
            counts[code] = counts.get(code, 0) + 1

    code_rows = [
        [esc(code), fnum(count), fpct(count, failed),
         f'<code>{esc(examples.get(code, "")[:110])}</code>']
        for code, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    ]

    binaries = sorted({str(r.get("repo_path")) for r in rows
                       if isinstance(r, dict) and r.get("repo_path")})
    sizes = [int(r["size"]) for r in rows
             if isinstance(r, dict) and isinstance(r.get("size"), int)]
    span = (f"{fnum(min(sizes))}–{fnum(max(sizes))} bytes" if sizes else "size unknown")
    mtime = _mtime(COMPILE_TALLY)
    rate_class = "good" if total and ok / total >= 0.5 else "warnt"

    compile_split = stacked_bar([
        ("compiles unmodified", ok, "proven"),
        ("fails to compile", failed, "failed"),
    ])
    error_chart = bars([(code, count, "failed") for code, count in counts.items()])

    body = (
        f'<p class="headline"><span class="{rate_class}">{fpct(ok, total)}</span> '
        f'of Ghidra C compiles unmodified</p>'
        f'<p class="sub">{fnum(ok)} of {fnum(total)} sampled functions '
        f'({esc(span)}) built against era-exact MSVC with no mutation. '
        f'{fnum(failed)} failed. This is the ceiling on what the permuter stage '
        f'ever gets to work on — it says nothing about byte-exactness.</p>'
        f'<p class="sub">Source: {_file_link(COMPILE_TALLY)} '
        f'({esc(ago(mtime))}) &middot; {_build_links(binaries)}</p>'
        + compile_split
        + ('<p class="sub" style="margin:14px 0 6px">MSVC error codes blocking '
           "the failures, by how many functions each one blocks:</p>"
           + error_chart if counts else "")
        + _details(table(["MSVC error", "Functions blocked", "Share of failures",
                          "Example message"],
                        code_rows, numeric={1, 2}))
    )
    return panel(body, "Raw compile rate (Ghidra C, unmodified)")


def _experiment_rows() -> list[list[str]]:
    out: list[list[str]] = []
    for base in EXPERIMENT_DIRS:
        if not base.is_dir():
            continue
        try:
            arms = sorted(p for p in base.iterdir() if p.is_dir())
        except OSError:
            continue
        for arm in arms:
            try:
                files = sorted(arm.glob("run-results-*.json"))
            except OSError:
                continue
            files = [f for f in files if 0 < _size(f) <= MAX_RESULT_BYTES]
            if not files:
                continue
            latest = max(files, key=lambda f: _mtime(f) or 0)
            data, err = load_json(latest)
            if err or not isinstance(data, dict):
                continue
            summary = data.get("summary")
            if not isinstance(summary, dict):
                continue
            manifest, _ = load_json(arm / "manifest.json")
            program = ""
            if isinstance(manifest, dict):
                program = str(manifest.get("program") or "")
            model = ""
            config = data.get("config")
            if isinstance(config, dict):
                model = str(config.get("model") or "")
            total = summary.get("totalPrompts")
            good = summary.get("successfulPrompts")
            ms = summary.get("totalDurationMs")
            secs = f"{float(ms) / 1000:,.0f}s" if isinstance(ms, (int, float)) else "-"
            attempts = summary.get("avgAttempts")
            attempts = (f"{float(attempts):.2f}"
                        if isinstance(attempts, (int, float)) else "-")
            out.append([
                f"{esc(base.name)} / {esc(arm.name)}",
                esc(program.rsplit("/", 1)[-1] or "?"),
                esc(model or "?"),
                fnum(total),
                fnum(good),
                fpct(good, total),
                attempts,
                secs,
                esc(ago(_mtime(latest))),
                # Raw numbers for the chart, trimmed off before the row reaches
                # the table — table() takes rendered cells, bars() takes floats.
                total if isinstance(total, (int, float)) else 0,
                good if isinstance(good, (int, float)) else 0,
            ])
    return out


def _render_experiments() -> str:
    rows = _experiment_rows()
    if not rows:
        return ""
    # Succeeded-prompt count per experiment arm, sorted — the workhorse
    # per-build-style comparison, just over experiment arms instead of builds.
    chart = bars([(r[0], r[10], "proven") for r in rows])
    table_rows = [r[:9] for r in rows]
    body = (
        '<p class="sub">Earlier model-loop experiments, read from each arm\'s '
        '<code>run-results-*.json</code> <code>summary</code> object. Their '
        '<code>success</code> flag is the runner\'s compile-and-diff verdict; it '
        'does not record the real-C check, so it is not comparable to the '
        'real-C-and-byte-exact rate above.</p>'
        + chart
        + _details(table(["Experiment", "Program", "Model", "Prompts", "Succeeded",
                          "Rate", "Avg attempts", "Wall time", "File age"],
                        table_rows, numeric={3, 4, 5, 6, 7}))
    )
    return panel(body, "Earlier experiments (model loop)")


def render() -> str:
    try:
        parts = [
            _safe(_render_run, "Real C and byte-exact, by size band"),
            _safe(_render_tally, "Raw compile rate (Ghidra C, unmodified)"),
            _safe(_render_experiments, "Earlier experiments (model loop)"),
        ]
        note = (
            '<p class="sub" style="margin-bottom:14px">'
            + tag("no LLM in this loop", "ok")
            + ' Ghidra decompiles, decomp-permuter mutates, the era-exact '
              'compiler rebuilds, and a variant is kept only when its bytes '
              'match the original. <b>Byte-exact and real C are separate '
              'properties</b>: a byte-exact <code>__asm</code>/<code>naked</code>'
              ' body is the original machine code in a C wrapper and recovers '
              'nothing, so the headline metric is always both together.</p>'
        )
        return note + "".join(p for p in parts if p)
    except Exception as exc:  # noqa: BLE001
        return missing(f"recovery panel failed to render: {exc}")
