"""The step ladder — the landing view's centrepiece, one ladder per build.

Why this panel exists: every other panel answers "what does artifact X say".
None of them answered "how far along is the whole thing", so the page could
show eight healthy-looking sections while the two steps the project is
actually judged on had never been attempted.

Why it is per binary: "16 / 22 packages" is not a fact about the project, it is
22 separate facts rolled into one number that belongs to no build the reader can
open. The reader's subject is a build, and every step is a property of one. So
the corpus roll-up stays once at the top and each of the 22 non-DRM builds
carries its own eight steps below it, collapsed until asked for.

The ladder ends with the three steps the user named, in their order:

    N-2  cross-match and apply knowledge   (best available name everywhere)
    N-1  compile the generated project     (does export_cpp/<binary> build?)
    N    verify byte-accuracy              (is the build identical to the original?)

Every state is derived from files on disk, never from a stored claim, and every
step names the artifact it read plus that artifact's age. A step that has never
been attempted reports "not attempted" — it never reports 0% dressed as success,
because a green zero is the exact failure this dashboard was rebuilt to remove.

Cost: 23 ladders is 23x the temptation to query per subject. Every fact for
every build is read once, in a handful of GROUP BY queries over small or indexed
tables, and the ladders are pure functions of that one snapshot. The 500 MB
`func` table is never scanned; per-binary function totals come from
`binary.func_count`, which the extractor already wrote.
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from urllib.parse import quote, urlencode

from agentdecompile_recovery.corpus.dashboard.panels.common import (  # noqa: E402
    DRM_EXCLUDED,
    KNOWLEDGE_DB,
    as_root,
    DB_PATH,
    ago,
    count_link,
    esc,
    fnum,
    fpct,
    load_json,
    procs_by_cwd,
    query_db,
    rel,
    table_exists,
)

TITLE = "Pipeline steps"

DB_FILE = DB_PATH or as_root() / "corpus.sqlite"
EXPORT_CPP = as_root() / "output" / "export_cpp"
EXPORT_CPP_MANIFEST = EXPORT_CPP / "_manifest.json"
COVERAGE = as_root() / "output" / "exact_universal" / "_coverage.json"
QUEUE_SUMMARY = as_root() / "output" / "work_queue" / "logical_queue_summary.json"
INVENTORY = as_root() / "extract" / "inventory.json"
STABS_INDEX = as_root() / "extract" / "stabs" / "_index.json"
PERMUTER_DIR = as_root() / "output" / "permuter"
RECON_DIR = as_root() / "output" / "reconstructed"

# Where a verification of the BUILT libraries would land. None of these exist
# yet; the list is the definition of what "attempted" would look like, so the
# step can say what it is waiting for instead of only saying "no".
VERIFY_REPORTS = (
    RECON_DIR / "verify_built.json",
    RECON_DIR / "build" / "verify_built.json",
    as_root() / "output" / "exact_universal" / "_built_verify.json",
    as_root() / "logs" / "verify_built.log",
)

# Build outputs an actually-compiled package would leave behind.
BUILD_ARTIFACT_GLOBS = ("*.a", "*.lib", "*.o", "*.obj", "*.log")

DRM_SQL_LIST = ", ".join("?" for _ in DRM_EXCLUDED)

# Substrings that identify a running job as belonging to a step. Matched against
# /proc cmdlines, which costs a directory walk of /proc and no disk I/O.
STEP_PROCESS_MARKERS = {
    "extract": ("kx/extract.py", "scripts/extract_all.sh"),
    "identify": ("kx/match.py", "kx/logical.py"),
    "calibrate-global": ("calibrate-global", "export-types", "build-types-header"),
    "assembly-floor": ("kx/export_packages.py", "corpus.workspace", "compile-link"),
    "recover-source": ("kx/ghidra_bulk.py", "ghidra_bulk"),
    "apply-cross-build": ("kx/propagate.py", "cross_place"),
    "leftover-recover": ("permuter", "genproject", "reconstruct"),
    "verify-byte-accuracy": ("objdiff-check", "verify_built.py"),
}

# Catalog action ids bound to each pipeline gate (see introspect / corpus.cli).
STEP_ACTION_DEFAULTS = {
    "extract": "corpus.extract-stabs",
    "identify": "corpus.match-pair",
    "calibrate-global": "corpus.calibrate-global",
    "assembly-floor": "corpus.workspace",
    "recover-source": "corpus.ghidra-bulk",
    "apply-cross-build": "corpus.cross-place",
    "leftover-recover": "corpus.genproject",
    "verify-byte-accuracy": "corpus.objdiff-check",
}

# Anchor of the per-binary list inside this panel. Roll-up counts that name a
# number of *builds* link here, because the 22 ladders below are literally the
# set those counts count.
PERBIN_ANCHOR = "#per-binary-ladders"

GAME_ORDER = {"K1": 0, "K2": 1}

# One snapshot serves the roll-up, all 22 ladders and any /binary/<slug> page
# rendered in the same breath. Without it, a page with 23 ladders would issue
# the same GROUP BY 23 times against a database on a spinning disk.
_FACTS_TTL = 30.0
_facts_lock = threading.Lock()
_facts_cache: dict = {"at": 0.0, "data": None}


# --------------------------------------------------------------------------
# links
# --------------------------------------------------------------------------


def _funcs(slug: str | None = None, **filters) -> str:
    """URL of the function list, optionally scoped to one build and filtered."""
    pairs = []
    if slug:
        pairs.append(("binary", slug))
    pairs.extend((k, v) for k, v in filters.items() if v)
    return "/functions" + ("?" + urlencode(pairs) if pairs else "")


def _art(path: Path) -> str:
    return "/artifact?p=" + quote(rel(path))


def _mtime(path: Path):
    if path is None:
        return None
    try:
        return path.stat().st_mtime
    except OSError:
        return None


def _src(path: Path) -> str:
    """One evidence chip: the artifact this step's number came from, plus age.

    A number whose file cannot be named does not belong on this page, so this
    renders the broken case loudly rather than omitting it.
    """
    relpath = rel(path)
    ts = _mtime(path)
    if ts is None:
        return (f'<span class="src broken" title="artifact missing">'
                f'{esc(relpath)} &middot; missing</span>')
    return (f'<a class="src" href="{esc(_art(path))}">{esc(relpath)}</a>'
            f'<span class="age">{esc(ago(ts))}</span>')


def _srcs(paths) -> str:
    return '<div class="srcs">' + "".join(_src(p) for p in paths if p is not None) + "</div>"


def _bar(part, whole, state: str) -> str:
    """True-scale bar. No minimum width: a sliver is the finding, not a bug."""
    try:
        frac = float(part) / float(whole) if whole else 0.0
    except (TypeError, ValueError, ZeroDivisionError):
        frac = 0.0
    frac = max(0.0, min(1.0, frac))
    return (f'<div class="bar st-{esc(state.replace(" ", "-"))}">'
            f'<i style="width:{frac * 100:.4f}%"></i></div>')


def _pill(state: str) -> str:
    glyph = {"done": "●", "partial": "◐", "running": "▸",
             "not started": "○", "failed": "✕",
             "unmeasured": "?"}.get(state, "○")
    return (f'<span class="pill st-{esc(state.replace(" ", "-"))}">'
            f'{glyph} {esc(state)}</span>')


def _step_base(step_key: str) -> str:
    return step_key.split("@", 1)[0]


def _pick_corpus_action(base: str, step: dict, f: dict) -> tuple[str | None, bool]:
    """Return (catalog action id, enabled) for one corpus roll-up gate."""
    state = step.get("state", "")
    if state == "done":
        return STEP_ACTION_DEFAULTS.get(base), False

    bins = f["binaries"]
    total_bins = len(bins)
    funcs = sum(b["func_count"] for b in bins)
    with_funcs = sum(1 for b in bins if b["func_count"] > 0)
    bound = sum(f["bound"].get(b["id"], 0) for b in bins)
    carried = sum(f["named_carried"].get(b["id"], 0) for b in bins)
    cus = sum(f["stabs"].values())
    ingest = [f["ingest"].get(b["program"]) for b in bins]
    complete = sum(1 for x in ingest if x and x[2])
    pkgs = [p for name, p in f["packages"].items() if name in f["by_slug"]]
    n_pkgs = len(pkgs)
    built = sum(1 for p in pkgs if p["built"])
    _bodies, real_c = f["recovered_all"]
    queued = f["queued"]

    if base == "extract":
        aid = "corpus.init" if with_funcs == 0 else "corpus.extract-stabs"
        return aid, total_bins > 0 and with_funcs < total_bins
    if base == "identify":
        if cus > 0 and bound < funcs:
            aid = "corpus.apply-stabs"
        elif bound < funcs:
            aid = "corpus.match-pair"
        else:
            aid = "corpus.logical-build"
        return aid, with_funcs > 0
    if base == "calibrate-global":
        return "corpus.calibrate-global", with_funcs > 0
    if base == "assembly-floor":
        return "corpus.workspace", with_funcs > 0 and n_pkgs < total_bins
    if base == "recover-source":
        return "corpus.ghidra-bulk", with_funcs > 0
    if base == "apply-cross-build":
        return "corpus.cross-place", bound > 0 and carried < funcs
    if base == "leftover-recover":
        return "corpus.genproject", bool(
            (n_pkgs > 0 or queued) and queued and (real_c or 0) < queued)
    if base == "verify-byte-accuracy":
        return "corpus.objdiff-check", built > 0
    return None, False


def _pick_binary_action(base: str, step: dict, f: dict, b: dict) -> tuple[str | None, bool]:
    """Return (catalog action id, enabled) for one build's gate."""
    state = step.get("state", "")
    if state == "done":
        return STEP_ACTION_DEFAULTS.get(base), False

    bid = b["id"]
    total = b["func_count"]
    bound = f["bound"].get(bid, 0)
    carried = f["named_carried"].get(bid, 0)
    stabs_units = f["stabs"].get(b["slug"])
    ing = f["ingest"].get(b["program"])
    pkg = f["packages"].get(b["slug"])
    _bodies, real_c = f["recovered"].get(bid, (0, 0))
    built = bool(pkg and pkg["built"])

    if base == "extract":
        aid = "corpus.init" if not total else "corpus.extract-stabs"
        return aid, not total
    if base == "identify":
        if stabs_units and bound < total:
            aid = "corpus.apply-stabs"
        elif bound < total:
            aid = "corpus.match-pair"
        else:
            aid = "corpus.logical-build"
        return aid, total > 0
    if base == "calibrate-global":
        return "corpus.calibrate-global", total > 0
    if base == "assembly-floor":
        return "corpus.workspace", total > 0 and not pkg
    if base == "recover-source":
        return "corpus.ghidra-bulk", total > 0
    if base == "apply-cross-build":
        return "corpus.cross-place", bound > 0 and carried < total
    if base == "leftover-recover":
        return "corpus.genproject", total > 0 and real_c < total
    if base == "verify-byte-accuracy":
        return "corpus.objdiff-check", built
    return None, False


def _attach_actions(steps: list[dict], f: dict, b: dict | None = None) -> None:
    for step in steps:
        base = _step_base(step["key"])
        if b is None:
            aid, ok = _pick_corpus_action(base, step, f)
        else:
            aid, ok = _pick_binary_action(base, step, f, b)
            step["action_slug"] = b["slug"]
            step["action_program"] = b["program"]
        step["action_id"] = aid
        step["action_enabled"] = ok


def _run_link(step: dict) -> str:
    action_id = step.get("action_id")
    if not action_id:
        return ""
    enabled = bool(step.get("action_enabled"))
    attrs = [f'data-action-id="{esc(action_id)}"']
    slug = step.get("action_slug")
    program = step.get("action_program")
    if slug:
        attrs.append(f'data-action-slug="{esc(slug)}"')
    if program:
        attrs.append(f'data-action-program="{esc(program)}"')
    attr_s = " ".join(attrs)
    tip = f"Run {action_id}" + ("" if enabled else " — waiting on an earlier gate")
    if enabled:
        return (f'<a class="step-run" href="/dashboard#run" {attr_s} '
                f'title="{esc(tip)}">Run</a>')
    return (f'<span class="step-run disabled" aria-disabled="true" {attr_s} '
            f'title="{esc(tip)}">Run</span>')


def _running_steps() -> set:
    """Which steps have a live process behind them, read from /proc."""
    live = set()
    try:
        cmds = [cmd for procs in procs_by_cwd().values() for _, cmd in procs]
    except Exception:  # noqa: BLE001 - liveness is a nice-to-have, never fatal
        return live
    for key, markers in STEP_PROCESS_MARKERS.items():
        for cmd in cmds:
            if any(m in cmd for m in markers):
                live.add(key)
                break
    return live


def _state_for(done, total, running: bool, attempted: bool) -> str:
    """The honesty rule, in one place.

    `attempted` is the difference between "we measured zero" and "nobody has
    run this yet". Only the second is 'not started', and neither is ever 'done'.
    """
    if done is None or total is None:
        return "unmeasured"
    if not attempted or total == 0:
        return "not started"
    if done >= total:
        return "done"
    if running:
        return "running"
    if done > 0:
        return "partial"
    return "not started"


def _package_build_state(pkg: Path) -> tuple[bool, str]:
    """Did this package produce build output? Bounded scandir, no recursion."""
    build = pkg / "build"
    try:
        if build.is_dir():
            with os.scandir(build) as it:
                for _ in it:
                    return True, "build/ has output"
    except OSError:
        pass
    for pattern in BUILD_ARTIFACT_GLOBS:
        try:
            if next(pkg.glob(pattern), None) is not None:
                return True, f"{pattern} present"
        except OSError:
            continue
    return False, "no build directory, no object or library files"


# --------------------------------------------------------------------------
# the one snapshot every ladder reads
# --------------------------------------------------------------------------


def _rows(sql: str, params: tuple = (), db: Path | None = None, *, optional: str | None = None):
    """Run one query. When *optional* names a table, a missing table is not an error."""
    target = db if db is not None else DB_PATH
    if optional and target is not None and not table_exists(optional, db=target):
        return [], None
    ignore = optional is not None
    rows, err = query_db(sql, params, db=db, ignore_missing=ignore)
    return (rows or []), err


def _collect_facts() -> dict:
    f: dict = {"errors": [], "at": time.time()}

    bins, err = _rows(
        "SELECT id, slug, repo_path, game, platform, func_count, named_count "
        f"FROM binary WHERE repo_path NOT IN ({DRM_SQL_LIST})", DRM_EXCLUDED)
    if err:
        f["errors"].append(err)
    binaries = [{
        "id": r[0], "slug": r[1], "repo_path": r[2], "game": r[3] or "OTHER",
        "platform": r[4] or "?", "func_count": r[5] or 0, "named_count": r[6] or 0,
        "program": (r[2] or "").rsplit("/", 1)[-1],
    } for r in bins]
    binaries.sort(key=lambda b: (GAME_ORDER.get(b["game"], 2), b["slug"]))
    f["binaries"] = binaries
    f["by_slug"] = {b["slug"]: b for b in binaries}
    keep = {b["id"] for b in binaries}

    # identity is 288k rows keyed (binary_id, addr, logical_id): the GROUP BY
    # rides the primary key and costs ~0.1 s, where a per-build loop would pay
    # 22 seeks on a shared disk.
    rows, err = _rows("SELECT binary_id, COUNT(*) FROM "
                      "(SELECT DISTINCT binary_id, addr FROM identity) "
                      "GROUP BY binary_id")
    if err:
        f["errors"].append(err)
    f["bound"] = {r[0]: r[1] for r in rows if r[0] in keep}

    # tier <= 4 is "a real name won"; tier >= 5 is a placeholder, which may fill
    # an empty slot and may never displace a higher tier.
    rows, err = _rows(
        "SELECT i.binary_id, COUNT(DISTINCT i.addr) FROM identity i "
        "JOIN logical_name n ON n.logical_id = i.logical_id "
        "WHERE n.tier <= 4 GROUP BY i.binary_id",
        optional="logical_name")
    if err:
        f["errors"].append(err)
    f["named_carried"] = {r[0]: r[1] for r in rows if r[0] in keep}

    rows, err = _rows("SELECT tier, COALESCE(tier_name, '?'), COUNT(*) "
                      "FROM logical_name GROUP BY tier, tier_name ORDER BY tier",
                      optional="logical_name")
    f["tiers"] = rows
    if err:
        f["errors"].append(err)

    rows, _ = _rows("SELECT COUNT(*) FROM logical_function")
    f["logicals"] = rows[0][0] if rows else None

    # real_c is the column kx/realc.py writes; it is never summed with
    # byte_exact, which is a different property of a different artifact.
    rows, err = _rows("SELECT binary_id, COUNT(*), COUNT(*) "
                      "FROM recovered_function WHERE real_c=1 GROUP BY binary_id",
                      optional="recovered_function")
    if err:
        f["errors"].append(err)
    f["recovered"] = {r[0]: (r[1] or 0, r[2] or 0) for r in rows}
    logical_rows, logical_err = _rows(
        "SELECT COUNT(*), COUNT(DISTINCT logical_id) FROM recovered_function WHERE real_c=1",
        optional="recovered_function",
    )
    if logical_err:
        f["errors"].append(logical_err)
    f["recovered_all"] = logical_rows[0] if logical_rows else (0, 0)
    # Bodies whose binary_id is NULL are recoveries not yet tied to a build.
    f["recovered_unplaced"] = f["recovered"].pop(None, (0, 0))

    rows, err = _rows("SELECT program, functions_done, functions_total, complete "
                      "FROM ingest_status", db=KNOWLEDGE_DB, optional="ingest_status")
    if err:
        f["errors"].append(err)
    f["ingest"] = {r[0]: (r[1] or 0, r[2] or 0, r[3] or 0) for r in rows}

    man, man_err = load_json(EXPORT_CPP_MANIFEST)
    f["manifest_error"] = man_err
    f["manifest"] = {m.get("slug"): m for m in man
                     if isinstance(m, dict)} if isinstance(man, list) else {}

    stabs, _ = load_json(STABS_INDEX)
    f["stabs"] = {}
    if isinstance(stabs, dict):
        for slug, entry in stabs.items():
            if not isinstance(entry, dict):
                continue
            slices = [s for s in entry.get("slices") or [] if isinstance(s, dict)]
            units = sum(int(s.get("units") or 0) for s in slices)
            if units:
                f["stabs"][slug] = units

    cov, cov_err = load_json(COVERAGE)
    f["coverage_error"] = cov_err
    f["coverage"] = {c.get("repo_path"): c for c in cov
                     if isinstance(c, dict)} if isinstance(cov, list) else {}

    queue, qerr = load_json(QUEUE_SUMMARY)
    f["queue_error"] = qerr
    f["queued"] = queue.get("logical_functions_queued") if isinstance(queue, dict) else None

    # One bounded scandir of output/export_cpp, plus one per package. Recursing
    # would walk hundreds of thousands of generated sources on a spinning disk.
    packages: dict[str, dict] = {}
    f["packages_error"] = None
    try:
        for pkg in sorted(p for p in EXPORT_CPP.iterdir() if p.is_dir()):
            ok, reason = _package_build_state(pkg)
            packages[pkg.name] = {"path": pkg, "built": ok, "reason": reason}
    except OSError as exc:
        f["packages_error"] = f"could not read {rel(EXPORT_CPP)}: {exc}"
    f["packages"] = packages

    f["verify_found"] = [p for p in VERIFY_REPORTS if p.exists()]
    recon_build = RECON_DIR / "build"
    try:
        f["recon_libs"] = sum(1 for _ in recon_build.glob("*.a"))
    except OSError:
        f["recon_libs"] = 0
    return f


def facts(max_age: float = _FACTS_TTL) -> dict:
    """The snapshot, at most `max_age` seconds old."""
    with _facts_lock:
        data = _facts_cache["data"]
        if data is not None and (time.time() - _facts_cache["at"]) < max_age:
            return data
        data = _collect_facts()
        _facts_cache["data"] = data
        _facts_cache["at"] = time.time()
        return data


# --------------------------------------------------------------------------
# corpus roll-up steps
# --------------------------------------------------------------------------


def _note(text: str) -> str:
    return f'<p class="note">{text}</p>'


def _corpus_steps(f: dict, live: set) -> list[dict]:
    bins = f["binaries"]
    total_bins = len(bins)
    funcs = sum(b["func_count"] for b in bins)
    with_funcs = sum(1 for b in bins if b["func_count"] > 0)
    named = sum(b["named_count"] for b in bins)
    cus = sum(f["stabs"].values())
    stabs_builds = len(f["stabs"])
    bound = sum(f["bound"].get(b["id"], 0) for b in bins)
    carried = sum(f["named_carried"].get(b["id"], 0) for b in bins)
    bodies, real_c = f["recovered_all"]
    queued = f["queued"]
    pkgs = [p for name, p in f["packages"].items() if name in f["by_slug"]]
    built = [p for p in pkgs if p["built"]]

    steps = []

    steps.append({
        "key": "extract", "label": "1", "title": "Extract every function",
        "why": "Open every included build and record each function boundary. "
               "Nothing downstream can exceed this set.",
        "done": with_funcs, "total": total_bins, "unit": "builds",
        "done_href": PERBIN_ANCHOR, "total_href": PERBIN_ANCHOR,
        "state": _state_for(with_funcs, total_bins, "extract" in live, bool(with_funcs)),
        "notes": [
            _note(f"{count_link(funcs, _funcs(), title='every extracted function')} "
                  "functions found across "
                  f"{count_link(total_bins, PERBIN_ANCHOR, title='the per-build ladders below')} "
                  "builds (the two DRM-encrypted binaries are excluded corpus-wide). "
                  f"{count_link(named, _funcs(named=1))} carry a name from the build itself."),
        ] + ([_note(f"{count_link(cus, _art(STABS_INDEX))} compilation units with an "
                    "original .cpp path, from "
                    f"{count_link(stabs_builds, PERBIN_ANCHOR)} builds carrying "
                    "STABS records.")] if cus else []),
        "sources": [DB_FILE, INVENTORY, STABS_INDEX],
        "next": "Every non-DRM build is extracted." if with_funcs == total_bins
                else "Extract the builds that still report zero functions.",
    })

    steps.append({
        "key": "identify", "label": "2", "title": "Bind functions to one identity",
        "why": "Decide which concrete functions in different builds are the same "
               "function, so one recovery can be tested in every matching build.",
        "done": bound, "total": funcs, "unit": "functions bound",
        "done_href": _funcs(bound=1), "total_href": _funcs(),
        "state": _state_for(bound, funcs, "identify" in live, bool(bound)),
        "notes": [
            _note(f"{count_link(f['logicals'], _funcs(bound=1), title='opens the concrete functions bound into these groups')} "
                  "logical functions; "
                  f"{count_link(bound, _funcs(bound=1))} of "
                  f"{count_link(funcs, _funcs())} concrete functions are bound to one "
                  f"({fpct(bound, funcs)}), and "
                  f"{count_link(funcs - bound, _funcs(unbound=1))} are bound to none. "
                  "Binding says which functions are the same across builds. It says "
                  "nothing about any of them being decompiled."),
        ],
        "sources": [DB_FILE],
        "next": "Bind the remaining unmatched functions, or state why they are "
                "unmatchable." if bound < funcs else "Every extracted function is bound.",
    })

    ingest = [f["ingest"].get(b["program"]) for b in bins]
    progs = sum(1 for x in ingest if x)
    complete = sum(1 for x in ingest if x and x[2])
    cached = sum(x[0] for x in ingest if x)
    steps.append({
        "key": "calibrate-global", "label": "3",
        "title": "Global calibration",
        "why": "Pull each fork's per-function Ghidra data — decompiled C, "
               "disassembly, calling convention, relocations — into one indexed "
               "store instead of 500,000 individual reads on a shared disk.",
        "done": complete, "total": total_bins, "unit": "builds cached",
        "done_href": PERBIN_ANCHOR, "total_href": PERBIN_ANCHOR,
        "state": _state_for(complete, total_bins, "calibrate-global" in live, bool(cached)),
        "notes": [
            _note(f"{count_link(cached, _funcs(), title='opens the function list; the knowledge store has no per-function filter of its own')} "
                  "function records cached, covering "
                  f"{count_link(progs, PERBIN_ANCHOR)} of "
                  f"{count_link(total_bins, PERBIN_ANCHOR)} builds."),
        ],
        "sources": [KNOWLEDGE_DB],
        "next": "Every ingested build reports complete." if complete == total_bins
                else "Finish ingest for the builds still marked partial.",
    })

    man_funcs = sum(int(m.get("functions") or 0) for m in f["manifest"].values())
    man_named = sum(int(m.get("named") or 0) for m in f["manifest"].values())
    n_pkgs = len(pkgs)
    steps.append({
        "key": "assembly-floor", "label": "4", "title": "Link floor",
        "why": "Turn each build into a project tree with headers, sources and a "
               "build file, so there is something to compile at all.",
        "done": n_pkgs, "total": total_bins, "unit": "packages",
        "done_href": _art(EXPORT_CPP), "total_href": PERBIN_ANCHOR,
        "state": _state_for(n_pkgs, total_bins, "assembly-floor" in live, bool(n_pkgs)),
        "notes": [
            # The generator rewrites this directory in place, so the manifest is
            # absent for the length of a run. Zeros read from an absent file are
            # a measurement of nothing and must not be printed as counts.
            _note(f"{count_link(n_pkgs, _art(EXPORT_CPP))} packages hold "
                  f"{count_link(man_funcs, _funcs())} function bodies, "
                  f"{count_link(man_named, _funcs(named=1))} of them named. Generated "
                  "project structure is not source recovery until readable bodies pass "
                  "the compile and comparison gates." if f["manifest"] else
                  f"{count_link(n_pkgs, _art(EXPORT_CPP))} package directories exist. "
                  "How many bodies they hold is unknown: the manifest that records it "
                  "is missing, which is what a generator run in progress looks like."),
        ],
        "error": f["manifest_error"],
        "sources": [EXPORT_CPP_MANIFEST],
        "next": "Generate packages for the builds that still have none."
                if n_pkgs < total_bins else "Every non-DRM build has a package.",
    })

    steps.append({
        "key": "recover-source", "label": "5", "title": "Recover compiling C",
        "why": "Write C that compiles to the original bytes with no __asm, no "
               "naked, no _emit. This is the only number here that cannot be "
               "produced by re-emitting bytes we already had.",
        "done": real_c, "total": queued, "unit": "logical functions",
        "done_href": _funcs(real_c=1), "total_href": _art(QUEUE_SUMMARY),
        "state": _state_for(real_c, queued, "recover-source" in live, bool(bodies)),
        "notes": [
            _note(f"{count_link(real_c or None, _funcs(real_c=1) if real_c else None)} "
                  "logical functions have verified readable source. Denominator is the recovery "
                  f"queue: {count_link(queued, _art(QUEUE_SUMMARY))} logical functions."),
        ] + ([_note(f"{count_link(f['recovered_unplaced'][0], _art(PERMUTER_DIR))} "
                    "recovered bodies are not yet tied to a build, so they appear in "
                    "no ladder below.")] if f["recovered_unplaced"][0] else []),
        "error": f["queue_error"],
        "sources": [DB_FILE, QUEUE_SUMMARY, PERMUTER_DIR / "sample_results.json"],
        "next": "Raise the count of bodies that pass both tests at once — real C "
                "and byte-identical.",
    })

    tiers = f["tiers"]
    total_named = sum(int(r[2] or 0) for r in tiers)
    placeholders = sum(int(r[2] or 0) for r in tiers if (r[0] or 9) >= 5)
    real_named = total_named - placeholders
    tier_rows = "".join(
        f"<tr><td>{esc(r[0])}</td><td>{esc(r[1])}</td>"
        f'<td class="num">'
        f'{count_link(r[2], _funcs(placeholder=1) if (r[0] or 9) >= 5 else _funcs(named=1))}'
        f'</td>'
        f'<td class="num">{fpct(r[2], total_named)}</td></tr>'
        for r in tiers)
    steps.append({
        "key": "apply-cross-build", "label": "6", "title": "Cross-place compiling C",
        "why": "Every binary carries the best available name and the merged Ghidra "
               "data from every fork.",
        "done": carried, "total": funcs, "unit": "function instances named",
        "done_href": _funcs(named=1), "total_href": _funcs(),
        "state": _state_for(carried, funcs, "apply-cross-build" in live, bool(carried)),
        "notes": [
            _note(f"{count_link(real_named, _funcs(named=1))} of "
                  f"{count_link(total_named, _funcs(bound=1))} logical functions carry a "
                  f"name above placeholder tier; {count_link(placeholders, _funcs(placeholder=1))} "
                  f"are still a placeholder. {count_link(carried, _funcs(named=1))} of "
                  f"{count_link(funcs, _funcs())} concrete function instances inherit one "
                  f"({fpct(carried, funcs)})."),
        ],
        "detail": (
            '<div class="tablewrap"><table><thead><tr><th>Tier</th><th>Won by</th>'
            '<th class="num">Logical functions</th><th class="num">Share</th></tr>'
            f'</thead><tbody>{tier_rows}</tbody></table></div>'
            '<p class="note">Precedence, highest first: human-written, STABS, symbol '
            'table, Ghidra-derived, placeholder. A placeholder may fill an empty slot '
            'and may never replace a higher tier.</p>') if tier_rows else "",
        "sources": [DB_FILE],
        "next": "Carry a name to the function instances that still have none, and "
                "resolve the remaining placeholder-tier logical functions.",
    })

    rows = "".join(
        f'<tr><td><a href="{esc(_art(p["path"]))}">{esc(p["path"].name)}</a></td>'
        f'<td>{_pill("done" if p["built"] else "not started")}</td>'
        f'<td>{esc(p["reason"])}</td></tr>' for p in pkgs)
    compile_notes = [
        _note(f"{count_link(len(built) or None, _art(EXPORT_CPP) if built else None)} of "
              f"{count_link(n_pkgs, _art(EXPORT_CPP))} generated packages have produced "
              "build output."),
    ]
    if f["recon_libs"]:
        compile_notes.append(_note(
            f"Separately, {count_link(f['recon_libs'], _art(RECON_DIR / 'build'))} static "
            f"libraries exist under {esc(rel(RECON_DIR / 'build'))}. That is the "
            "byte-emitter's own project, whose bodies are machine code in a C wrapper. "
            "It is not this step."))
    steps.append({
        "key": "leftover-recover", "label": "7", "title": "Leftover recover",
        "why": "A project that does not build has not been verified, whatever any "
               "other number says.",
        "done": len(built), "total": n_pkgs, "unit": "packages built",
        "done_href": _art(EXPORT_CPP), "total_href": _art(EXPORT_CPP),
        "state": _state_for(len(built), n_pkgs, "leftover-recover" in live, bool(built)),
        "notes": compile_notes,
        "detail": ('<div class="tablewrap"><table><thead><tr><th>Package</th>'
                   '<th>Build</th><th>Evidence on disk</th></tr></thead>'
                   f'<tbody>{rows}</tbody></table></div>') if rows else "",
        "error": f["packages_error"],
        "sources": [EXPORT_CPP_MANIFEST],
        "next": "Build one package end to end and record the compiler's verdict "
                "where this step can read it.",
    })

    found = f["verify_found"]
    waiting = "".join(
        f'<li><code>{esc(rel(p))}</code> &mdash; '
        f'{"present" if p.exists() else "not written"}</li>' for p in VERIFY_REPORTS)
    verify_notes = [
        _note(f"{count_link(len(found) or None, _art(RECON_DIR) if found else None)} of "
              f"{count_link(len(VERIFY_REPORTS), _art(RECON_DIR))} verification reports "
              "exist on disk."),
    ]
    steps.append({
        "key": "verify-byte-accuracy", "label": "8", "title": "Objdiff audit",
        "why": "Compare the libraries the build produced against the shipped "
               "binary, byte for byte. This is the only step that proves the "
               "source is correct.",
        "done": len(found) or None, "total": n_pkgs, "unit": "packages verified",
        "done_href": None, "total_href": _art(EXPORT_CPP),
        "state": "not started" if not found else "partial",
        "notes": verify_notes,
        "detail": ('<p class="note">This step reads a verification of the <em>built</em> '
                   'libraries. It looks for:</p>'
                   f'<ul class="paths">{waiting}</ul>'
                   '<p class="note">The check itself already exists at '
                   f'<a href="{esc(_art(RECON_DIR / "tools" / "verify_built.py"))}">'
                   f'{esc(rel(RECON_DIR / "tools" / "verify_built.py"))}</a>. It has not '
                   'written a result this panel can read.</p>'),
        "sources": [COVERAGE, RECON_DIR / "build_manifest.json"],
        "next": "Step N-1 has to pass first: there is no build to compare.",
    })
    return steps


# --------------------------------------------------------------------------
# one build's eight steps
# --------------------------------------------------------------------------


def _binary_steps(f: dict, b: dict) -> list[dict]:
    """The same eight steps, measured for one build only.

    Liveness is deliberately not consulted here: a running `kx/match.py` says
    the corpus is being worked on, not which build it is on, and a "running"
    badge on the wrong ladder is a lie the reader cannot check.
    """
    slug, bid = b["slug"], b["id"]
    total = b["func_count"]
    all_funcs = _funcs(slug)
    steps = []

    stabs_units = f["stabs"].get(slug)
    steps.append({
        "key": f"extract@{slug}", "label": "1", "title": "Extract every function",
        "why": "Open the build and record every function boundary. Nothing "
               "downstream can exceed this set.",
        "done": total if total else 0, "total": total, "unit": "functions extracted",
        "done_href": all_funcs, "total_href": all_funcs,
        "state": _state_for(total, total, False, bool(total)),
        "notes": [
            _note(f"{count_link(total or None, all_funcs if total else None)} functions "
                  f"extracted, {count_link(b['named_count'], _funcs(slug, named=1))} of "
                  "them already carrying a name from the build itself "
                  f"({fpct(b['named_count'], total)}).")
        ] + ([_note(f"{count_link(stabs_units, _art(STABS_INDEX))} compilation units "
                    "with an original .cpp path come from this build's STABS records.")]
             if stabs_units else []),
        "sources": [DB_FILE, STABS_INDEX] if stabs_units else [DB_FILE],
        "next": "This build is extracted." if total
                else "Extract this build: it reports no functions.",
    })

    bound = f["bound"].get(bid, 0)
    steps.append({
        "key": f"identify@{slug}", "label": "2",
        "title": "Bind functions to one identity",
        "why": "Decide which of this build's functions are the same function in "
               "the other 21 builds, so one recovery pays off many times.",
        "done": bound, "total": total, "unit": "functions bound",
        "done_href": _funcs(slug, bound=1), "total_href": all_funcs,
        "state": _state_for(bound, total, False, bool(bound)),
        "notes": [
            _note(f"{count_link(bound or None, _funcs(slug, bound=1) if bound else None)} "
                  f"of {count_link(total, all_funcs)} functions in this build are bound "
                  f"to a logical function ({fpct(bound, total)}); "
                  f"{count_link(max(total - bound, 0), _funcs(slug, unbound=1))} bridge "
                  "to no other build.")
        ],
        "sources": [DB_FILE],
        "next": "Bind this build's remaining functions." if bound < total
                else "Every function in this build is bound.",
    })

    ing = f["ingest"].get(b["program"])
    done_k, total_k = (ing[0], ing[1]) if ing else (None, None)
    steps.append({
        "key": f"calibrate-global@{slug}", "label": "3",
        "title": "Global calibration",
        "why": "Pull this build's per-function Ghidra data into the shared store "
               "so a function page costs one indexed read, not a project open.",
        "done": done_k, "total": total_k or total, "unit": "functions cached",
        "done_href": all_funcs, "total_href": all_funcs,
        "state": _state_for(done_k, total_k, False, bool(ing)),
        "notes": [
            _note(f"{count_link(done_k, all_funcs if ing else None, title='opens the function list for this build; the knowledge store has no per-function filter')} "
                  f"of {count_link(total_k, all_funcs) if ing else count_link(total, all_funcs)} "
                  "functions cached"
                  + (", ingest complete." if ing and ing[2] else ", ingest incomplete.")
                  if ing else
                  f"No ingest row exists for <code>{esc(b['program'])}</code>, so this "
                  "build's Ghidra knowledge has never been merged.")
        ],
        "sources": [KNOWLEDGE_DB],
        "next": "This build is cached." if ing and ing[2]
                else f"Run the knowledge ingest for {b['program']}.",
    })

    pkg = f["packages"].get(slug)
    man = f["manifest"].get(slug) or {}
    pkg_funcs = int(man.get("functions") or 0) or None
    steps.append({
        "key": f"assembly-floor@{slug}", "label": "4",
        "title": "Link floor",
        "why": "Turn this build into a project tree with headers, sources and a "
               "build file, so there is something to compile at all.",
        "done": 1 if pkg else 0, "total": 1, "unit": "package",
        "done_href": _art(pkg["path"]) if pkg else None,
        "total_href": _art(EXPORT_CPP),
        "state": _state_for(1 if pkg else 0, 1, False, bool(pkg)),
        "notes": [
            _note(
                "No package exists for this build under output/export_cpp." if not pkg
                else (f"{count_link(pkg_funcs, all_funcs if pkg_funcs else None)} function "
                      f"bodies were written, "
                      f"{count_link(int(man.get('named') or 0) or None, _funcs(slug, named=1) if man.get('named') else None)} "
                      "of them named. Project generation is not source recovery until "
                      "readable bodies pass the compile and comparison gates.")
                if man else
                "The package directory exists, but output/export_cpp/_manifest.json is "
                "missing, so how many bodies it holds is unknown.")
        ],
        "sources": [EXPORT_CPP_MANIFEST],
        "next": "This build has a package." if pkg
                else "Generate the C/C++ package for this build.",
    })

    bodies, real_c = f["recovered"].get(bid, (0, 0))
    steps.append({
        "key": f"recover-source@{slug}", "label": "5",
        "title": "Recover compiling C",
        "why": "Write C that compiles to this build's original bytes with no "
               "__asm, no naked, no _emit.",
        "done": real_c, "total": total, "unit": "functions with real C",
        "done_href": _funcs(slug, real_c=1) if real_c else None,
        "total_href": all_funcs,
        "state": _state_for(real_c, total, False, bool(bodies)),
        "notes": [
            _note(f"{count_link(real_c or None, _funcs(slug, real_c=1) if real_c else None)} "
                  f"of {count_link(total, all_funcs)} functions in this build have a body "
                  "that is readable C or C++ and matches this build's bytes."
                  if bodies else
                  "No recovery has been attempted against this build.")
        ],
        "sources": [DB_FILE, QUEUE_SUMMARY],
        "next": "Recover real C for this build's functions." if real_c < total
                else "Every function in this build has a real-C body.",
    })

    carried = f["named_carried"].get(bid, 0)
    steps.append({
        "key": f"apply-cross-build@{slug}", "label": "6",
        "title": "Cross-place compiling C",
        "why": "This build carries the best available name and the merged Ghidra "
               "data from every other fork.",
        "done": carried, "total": total, "unit": "functions named",
        "done_href": _funcs(slug, named=1), "total_href": all_funcs,
        "state": _state_for(carried, total, False, bool(carried)),
        "notes": [
            _note(f"{count_link(carried or None, _funcs(slug, named=1) if carried else None)} "
                  f"of {count_link(total, all_funcs)} functions inherit a name above "
                  f"placeholder tier ({fpct(carried, total)}). The rest keep whatever "
                  "this build itself provided, which for a stripped build is nothing.")
        ],
        "sources": [DB_FILE],
        "next": "Carry a name to this build's unnamed functions." if carried < total
                else "Every function in this build carries a name.",
    })

    built = bool(pkg and pkg["built"])
    steps.append({
        "key": f"leftover-recover@{slug}", "label": "7",
        "title": "Leftover recover",
        "why": "A project that does not build has not been verified, whatever any "
               "other number says.",
        "done": 1 if built else 0, "total": 1 if pkg else 0, "unit": "package built",
        "done_href": _art(pkg["path"]) if built else None,
        "total_href": _art(pkg["path"]) if pkg else _art(EXPORT_CPP),
        "state": _state_for(1 if built else 0, 1 if pkg else 0, False, built),
        "notes": [
            _note(esc(pkg["reason"]) if pkg else
                  "Step 4 has to run first: there is no package to build.")
        ],
        "sources": [EXPORT_CPP_MANIFEST],
        "next": "Build this package and record the compiler's verdict where this "
                "step can read it." if pkg else "Generate this build's package first.",
    })

    cov = f["coverage"].get(b["repo_path"]) or {}
    reports = [EXPORT_CPP / slug / "verify_built.json", RECON_DIR / slug / "verify_built.json"]
    found = [p for p in reports if p.exists()]
    verify_notes = [
        _note(f"{count_link(len(found) or None, _art(found[0]) if found else None)} "
              "verification report exists for this build. This step compares the "
              "libraries a build produced against the shipped binary, byte for byte.")
    ]
    if cov:
        verify_notes.append(_note(
            f"Not this step: {count_link(int(cov.get('byte_exact') or 0), _art(COVERAGE))} "
            f"of {count_link(int(cov.get('functions') or 0), all_funcs)} bodies emitted "
            "for this build rebuild to the original bytes. Those bodies are machine code "
            "inside a C wrapper, so matching proves packaging, not recovered source. "
            "byte_exact and real C are different properties and are never added together."))
    steps.append({
        "key": f"verify-byte-accuracy@{slug}", "label": "8",
        "title": "Objdiff audit",
        "why": "Compare the libraries this build produced against the shipped "
               "binary, byte for byte. This is the only step that proves the "
               "source is correct.",
        "done": len(found) or None, "total": 1, "unit": "build verified",
        "done_href": _art(found[0]) if found else None,
        "total_href": _art(pkg["path"]) if pkg else None,
        "state": "not started" if not found else "partial",
        "notes": verify_notes,
        "sources": [COVERAGE],
        "next": "Step N-1 has to pass first: there is no build to compare.",
    })
    return steps


def collect() -> list[dict]:
    """Corpus roll-up steps. Kept for callers that want the data, not the HTML."""
    f = facts()
    steps = _corpus_steps(f, _running_steps())
    _attach_actions(steps, f)
    return steps


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------


def _fraction(step: dict) -> float:
    done, total = step.get("done"), step.get("total")
    if step.get("state") in ("not started", "unmeasured"):
        return 0.0
    try:
        if not total:
            return 0.0
        return max(0.0, min(1.0, float(done) / float(total)))
    except (TypeError, ValueError):
        return 0.0


def _count_html(step: dict) -> str:
    """The summary's count, obeying rule 1 and the not-attempted exception."""
    done, total, state = step.get("done"), step.get("total"), step.get("state")
    unit = (f'<span class="unit">{esc(step.get("unit", ""))}</span>'
            if step.get("unit") else "")
    if total is None:
        return '<span class="unit">not measurable</span>'
    unattempted = state in ("not started", "unmeasured") and not done
    if unattempted and not total:
        return count_link(None, None, title="nobody has run this step for this subject")
    lead = (count_link(None, None) if unattempted
            else count_link(done, step.get("done_href")))
    return (f'{lead} <span class="of">/ '
            f'{count_link(total, step.get("total_href"))}</span> {unit}')


def _render_step(index: int, step: dict, force_closed: bool = False) -> str:
    state = step.get("state", "unmeasured")
    body = [f'<p class="why">{esc(step.get("why", ""))}</p>']
    for note in step.get("notes") or []:
        body.append(note)
    if step.get("error"):
        body.append(f'<p class="miss">{esc(step["error"])}</p>')
    if step.get("detail"):
        body.append(step["detail"])
    if step.get("next"):
        body.append(f'<p class="next"><span class="k">next</span> '
                    f'{esc(step["next"])}</p>')
    body.append(_srcs(step.get("sources") or []))

    # The last three steps are the ones the project is judged on, so an
    # unattempted one opens itself rather than hiding behind a closed triangle.
    open_attr = ("" if force_closed
                 else " open" if state in ("failed", "not started") and index >= 6
                 else "")
    return (
        f'<details class="step st-{esc(state.replace(" ", "-"))}" '
        f'data-k="step.{esc(step.get("key", index))}"{open_attr}>'
        f"<summary>"
        f'<span class="stepno">{esc(step.get("label", index))}</span>'
        f'<span class="stepname">{esc(step.get("title", ""))}</span>'
        f"{_pill(state)}"
        f"{_run_link(step)}"
        f'<span class="stepcount">{_count_html(step)}</span>'
        f'{_bar(step.get("done"), step.get("total"), state)}'
        f"</summary>"
        f'<div class="stepbody">{"".join(body)}</div>'
        f"</details>"
    )


def _summarise(steps: list[dict]) -> tuple[int, float, dict | None]:
    complete = sum(1 for s in steps if s.get("state") == "done")
    blocked = next((s for s in steps if s.get("state") != "done"), None)
    completion = (complete / len(steps)) if steps else 0.0
    return complete, completion, blocked


def _ladder_head(steps: list[dict], subject: str) -> str:
    complete, completion, blocked = _summarise(steps)
    return (
        '<div class="ladderhead">'
        f'<div class="ladderline"><b>{fnum(complete)} of {fnum(len(steps))} steps '
        f'complete</b><span class="pct">Ordered gates for {esc(subject)}</span></div>'
        f'<div class="bar big st-{esc((blocked or {}).get("state", "done").replace(" ", "-"))}">'
        f'<i style="width:{completion * 100:.3f}%"></i></div>'
        + (f'<p class="note">First step not yet complete: '
           f'<b>{esc(blocked.get("label"))} {esc(blocked.get("title"))}</b> '
           f'&mdash; {esc(blocked.get("state"))}. '
           f'{esc(blocked.get("next", ""))}</p>' if blocked else
           '<p class="note">Every step reports complete.</p>')
        + '<p class="note">The bar counts completed gates. Each gate keeps its own '
          'measure and denominator below.</p>'
        "</div>"
    )


def _binary_ladder_body(f: dict, b: dict) -> str:
    steps = _binary_steps(f, b)
    _attach_actions(steps, f, b)
    rendered = "".join(_render_step(i + 1, s, force_closed=True)
                       for i, s in enumerate(steps))
    return _ladder_head(steps, "this build") + rendered


def _binary_details(f: dict, b: dict) -> str:
    """One build's ladder, collapsed. 22 open ladders is not a page."""
    steps = _binary_steps(f, b)
    _attach_actions(steps, f, b)
    complete, overall, blocked = _summarise(steps)
    state = (blocked or {}).get("state", "done")
    slug = b["slug"]
    return (
        f'<details class="step binladder st-{esc(state.replace(" ", "-"))}" '
        f'data-b="{esc(slug)}">'
        "<summary>"
        f'<span class="stepno">{esc(b["game"])} {esc(b["platform"])}</span>'
        f'<span class="stepname"><a href="/binary/{quote(slug)}">{esc(slug)}</a></span>'
        f"{_pill(state)}"
        f'<span class="stepcount">{count_link(b["func_count"], _funcs(slug))} '
        f'<span class="unit">functions</span> '
        f'<span class="of">&middot; {fnum(complete)}/8 steps</span></span>'
        f'{_bar(overall, 1.0, state)}'
        "</summary>"
        f'<div class="stepbody">{_ladder_head(steps, "this build")}'
        + "".join(_render_step(i + 1, s, force_closed=True)
                  for i, s in enumerate(steps))
        + "</div></details>"
    )


def render_for_binary(slug: str) -> str:
    """One build's ladder, for embedding on /binary/<slug>."""
    f = facts()
    b = f["by_slug"].get(slug)
    if b is None:
        return ('<p class="miss">no non-DRM build with slug '
                f'<code>{esc(slug)}</code></p>')
    return (f'<div class="ladder" data-b="{esc(slug)}">'
            f'{_binary_ladder_body(f, b)}</div>')


def _schema_note(f: dict) -> str:
    """One line when optional tables or artifact dirs are not populated yet."""
    hints = []
    if not table_exists("logical_name"):
        hints.append("logical_name")
    if not table_exists("recovered_function"):
        hints.append("recovered_function")
    if KNOWLEDGE_DB is not None and not table_exists("ingest_status", db=KNOWLEDGE_DB):
        hints.append("ingest_status")
    if f.get("packages_error"):
        hints.append(rel(EXPORT_CPP))
    parts = []
    if hints:
        parts.append(
            f'<p class="note">Optional corpus tables or outputs not populated yet: '
            f'{", ".join(f"<code>{esc(h)}</code>" for h in hints)}. '
            "Steps below show honest not-started state instead of SQL errors.</p>"
        )
    for err in f.get("errors") or []:
        parts.append(f'<p class="miss">{esc(err)}</p>')
    return "".join(parts)


def render(*, compact: bool = False) -> str:
    started = time.time()
    f = facts()
    steps = _corpus_steps(f, _running_steps())
    _attach_actions(steps, f)
    head = _ladder_head(steps, "the corpus")
    rollup = "".join(_render_step(i + 1, s) for i, s in enumerate(steps))

    perbin = ""
    if not compact:
        ladders = "".join(_binary_details(f, b) for b in f["binaries"])
        perbin = (
            f'<details class="perbinary" id="{PERBIN_ANCHOR.lstrip("#")}">'
            f'<summary class="note"><b>{fnum(len(f["binaries"]))} per-build ladders</b> '
            "— same eight gates measured per binary. Expand to open one build.</summary>"
            f"{ladders}</details>")

    note = _schema_note(f)
    foot = ""
    if not compact:
        foot = (f'<p class="annot">ladders computed in {time.time() - started:.2f}s '
                f'from one snapshot taken {esc(ago(f["at"]))}, out of the artifacts '
                "linked on each step</p>")
    css = ' class="ladder ladder-compact"' if compact else ' class="ladder"'
    return f"<div{css}>{head}{note}{rollup}{perbin}{foot}</div>"


def render_compact() -> str:
    """Corpus roll-up only — for the workbench embed."""
    return render(compact=True)


def _json_step(step: dict) -> dict:
    step = dict(step)
    stage = str(step.get("key") or "").split("@")[0]
    if stage in {"calibrate-global", "assembly-floor", "apply-cross-build", "leftover-recover"}:
        descriptions = {
            "calibrate-global": ("Global calibration", "Compare candidate compilers, flags, ABIs and layouts against known-source functions. Cached Ghidra facts are context, not calibration results."),
            "assembly-floor": ("Assembly floor", "Generate a complete project with assembly fallbacks, then record a successful link. Package directories alone do not prove linking."),
            "apply-cross-build": ("Cross-place compiling C", "Apply source through logical identity and compile it for each destination. Shared names alone do not prove source placement."),
            "leftover-recover": ("Targeted semantic recovery", "Use bounded compile-and-diff attempts for unresolved functions after global calibration and cheaper repairs. Build artifacts alone do not measure these attempts."),
        }
        step["title"], step["why"] = descriptions[stage]
        step.update(done=None, total=None, state="unmeasured", unit="", next="Inspect or run this stage to obtain its specific evidence.")
    elif stage == "recover-source":
        step.update(title="Recover readable C", why="Recover assembly-free C/C++ candidates. These records do not establish compilation or byte identity.", next="Compile the readable candidates, then independently verify their output.")
    return {
        "key": step.get("key"),
        "label": step.get("label"),
        "title": step.get("title"),
        "why": step.get("why"),
        "done": step.get("done"),
        "total": step.get("total"),
        "unit": step.get("unit") or "",
        "state": step.get("state") or "unmeasured",
        "next": step.get("next") or "",
        "action_id": step.get("action_id") or "",
        "action_enabled": bool(step.get("action_enabled")),
        "action_slug": step.get("action_slug") or "",
        "action_program": step.get("action_program") or "",
    }


def as_payload() -> dict:
    """Same ladder facts the HTML panel uses, without HTML notes."""
    f = facts()
    live = _running_steps()
    corpus = _corpus_steps(f, live)
    _attach_actions(corpus, f)
    binaries = []
    for b in f["binaries"]:
        steps = _binary_steps(f, b)
        _attach_actions(steps, f, b)
        rec = f["recovered"].get(b["id"]) or (0, 0)
        binaries.append({
            "slug": b["slug"],
            "game": b.get("game") or "",
            "platform": b.get("platform") or "",
            "func_count": b.get("func_count") or 0,
            "named_count": b.get("named_count") or 0,
            "bound": f["bound"].get(b["id"], 0),
            "real_c": rec[0] if rec else 0,
            "steps": [_json_step(s) for s in steps],
        })
    return {
        "at": f.get("at"),
        "errors": list(f.get("errors") or []),
        "corpus_steps": [_json_step(s) for s in corpus],
        "binaries": binaries,
    }


if __name__ == "__main__":  # manual check: python scripts/panels/steps.py
    print(render())
