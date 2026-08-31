"""Panel: what is running right now, and the tail of every log.

The point of this panel is that nothing fails silently. A batch script that
exits 0 while every Ghidra step inside it failed to reach the server is worse
than a crash, because the run looks finished. So every log under logs/ is
listed with its size and age, and the tail of each is scanned for failure
markers even when the log is not recent enough to be printed in full.
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path

from agentdecompile_recovery.corpus.dashboard.panels.common import (
    as_external,
    as_root,
    ago,
    esc,
    missing,
    panel,
    table,
    tag,
    tail_lines,
)

LOG_DIR = as_root() / "logs"

# Printed in full only for the newest handful; the rest are scanned for
# failure markers but not rendered, because a 100 MB log is not readable on a
# dashboard and 69 <pre> blocks is not a page anybody scrolls.
TAILS_SHOWN = 8
TAIL_SHOW_LINES = 12

# Marker scanning reads only the last 32 KB of each log. That is one seek per
# file; the corpus lives on an external spinning disk, so the whole sweep is
# also bounded by a wall-clock budget rather than by file count alone.
SCAN_BYTES = 32 << 10
SCAN_LINES = 40
SCAN_BUDGET_S = 1.6

# Literal substrings, deliberately case-sensitive apart from the three spellings
# of "error" that are listed separately: a case-insensitive "fail" would flag
# every log containing the ordinary word "failed" in a per-item status line and
# the whole panel would go yellow, which is the same as no signal at all.
FAIL_MARKERS = ("error", "Error", "ERROR", "FAIL", "Traceback")

# The specific silent failure this panel exists to catch. Ghidra's headless
# launcher prints this and then exits 0, so the batch script above it reported
# success while 10 logs contained nothing but this line.
SERVER_DOWN = "Connection to server failed"

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

# Roles are matched against the cmdline of processes already narrowed down by
# cwd. Order matters: a Ghidra headless run is a java process, and a Mizuchi
# run is a node process, so the more specific pattern has to win first.
GHIDRA_RE = re.compile(r"(?:ghidra|analyzeHeadless|bsim|GhidraRun)", re.I)
JAVA_RE = re.compile(r"(?:^|/)java(?:\s|$)")
PY_JOB_RE = re.compile(r"(?:^|[\s/])(kx|scripts)/([\w.+-]+\.py)")
PY_RE = re.compile(r"(?:^|/)python[\d.]*(?:\s|$)")
NODE_RE = re.compile(r"(?:^|/)node(?:\s|$)")
SHELL_RE = re.compile(r"(?:^|[\s/])scripts/([\w.+-]+\.sh)")


def _clean(text: str) -> str:
    return ANSI_RE.sub("", text)


def _short_path(raw: str) -> str:
    """Collapse the two long absolute prefixes this project lives under."""
    root, miz = str(as_root()), str(as_external())
    if raw == root:
        return "."
    if raw.startswith(root + "/"):
        return raw[len(root) + 1:]
    if raw == miz:
        return "$MIZUCHI"
    if raw.startswith(miz + "/"):
        return "$MIZUCHI/" + raw[len(miz) + 1:]
    return raw


def _fsize(n: int) -> str:
    step = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if step < 1024 or unit == "GB":
            return f"{step:.0f} {unit}" if unit == "B" else f"{step:.1f} {unit}"
        step /= 1024
    return f"{n} B"


def _role(cmd: str) -> tuple[str, str]:
    """Return (label, tag-kind) for a cmdline. Never raises.

    The interpreter is taken from argv[0] only. Matching "python" anywhere in
    the line labels every wrapper shell a python job, because the shell
    snapshot this project's runners source mentions half the toolchain by path.
    """
    exe = os.path.basename(cmd.split(" ", 1)[0]) if cmd else ""
    if exe == "java" or GHIDRA_RE.search(cmd):
        return "ghidra / java", "warn"
    if exe == "node":
        return "node (mizuchi)", "ok"
    job = PY_JOB_RE.search(cmd)
    if exe.startswith("python") or (job and PY_RE.search(cmd)):
        return f"python {job.group(1)}/{job.group(2)}" if job else "python", "live"
    sh = SHELL_RE.search(cmd)
    if sh:
        return f"batch scripts/{sh.group(1)}", "ok"
    if exe in ("bash", "sh", "dash", "zsh"):
        return "shell", ""
    return "process", ""


def _truncate(text: str, limit: int = 150) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


# --------------------------------------------------------------------------
# processes
# --------------------------------------------------------------------------


def _render_procs() -> str:
    # Selection is by cwd, not by process name, on purpose. The Mizuchi node
    # build renames its main thread, so `pgrep -f node`-style matching has both
    # missed live model runs (renamed thread, no match) and matched unrelated
    # launcher shells that merely had the word in their argv. Every job in this
    # project is started from the repo or from MizuchiRE, so cwd is the one
    # discriminator that is neither spoofable by argv nor erased by a rename.
    try:
        from agentdecompile_recovery.corpus.dashboard.panels.common import procs_by_cwd

        by_cwd = procs_by_cwd()
    except Exception as exc:  # noqa: BLE001
        return missing(f"could not read /proc: {exc}")

    roots = (str(as_root()), str(as_external()))
    rows: list[list[str]] = []
    counts: dict[str, int] = {}
    for cwd in sorted(by_cwd):
        if not any(cwd == r or cwd.startswith(r + "/") for r in roots):
            continue
        for pid, cmd in sorted(by_cwd[cwd]):
            label, kind = _role(cmd)
            bucket = label.split(" ")[0]
            counts[bucket] = counts.get(bucket, 0) + 1
            rows.append([
                str(pid),
                tag(label, kind),
                esc(_short_path(cwd)),
                f'<span class="mono">{esc(_truncate(cmd))}</span>',
            ])

    if not rows:
        return missing(
            "no process is running with a cwd inside this repo or MizuchiRE "
            "(nothing is in flight right now)"
        )

    summary = " ".join(
        tag(f"{n} {name}", "live") for name, n in sorted(counts.items()) if n
    )
    head = f'<p class="sub">{len(rows)} live {summary}</p>'
    return head + table(["pid", "role", "cwd", "cmdline"], rows, numeric={0})


# --------------------------------------------------------------------------
# logs
# --------------------------------------------------------------------------


def _scan_logs() -> tuple[list[dict], str | None]:
    """stat every log, tail the ones we can afford. Returns (entries, error)."""
    if not LOG_DIR.is_dir():
        return [], "not available yet (logs/ missing)"

    found: list[tuple[float, Path, int]] = []
    try:
        for base, _dirs, files in os.walk(LOG_DIR):
            for name in files:
                p = Path(base) / name
                try:
                    st = p.stat()
                except OSError:
                    continue
                found.append((st.st_mtime, p, st.st_size))
    except OSError as exc:
        return [], f"could not walk logs/: {exc}"

    found.sort(key=lambda t: t[0], reverse=True)

    deadline = time.monotonic() + SCAN_BUDGET_S
    entries: list[dict] = []
    for idx, (mtime, path, size) in enumerate(found):
        # The newest handful are always tailed because they are rendered; the
        # older ones are tailed only while the budget holds, so a cold external
        # disk degrades to "fewer logs scanned" instead of a slow page.
        tail: list[str] = []
        scanned = False
        if idx < TAILS_SHOWN or time.monotonic() < deadline:
            tail = [_clean(ln) for ln in tail_lines(path, SCAN_LINES, SCAN_BYTES)]
            scanned = True
        # logs/README.md documents the failure strings this panel looks for,
        # so scanning prose alongside output would flag the documentation as a
        # failure and dilute the one signal the panel exists to give.
        joined = "" if path.suffix.lower() in (".md", ".rst", ".txt") else "\n".join(tail)
        entries.append({
            "path": path,
            "name": str(path.relative_to(LOG_DIR)),
            "size": size,
            "mtime": mtime,
            "tail": tail,
            "scanned": scanned,
            "server_down": SERVER_DOWN in joined,
            "failed": any(m in joined for m in FAIL_MARKERS),
        })
    return entries, None


def _flags(e: dict) -> str:
    out = []
    if e["server_down"]:
        out.append(tag("ghidra server unreachable", "dead"))
    if e["failed"]:
        out.append(tag("error in tail", "warn"))
    if not e["scanned"]:
        out.append(tag("not scanned", ""))
    if e["size"] == 0:
        out.append(tag("empty", ""))
    return " ".join(out)


def _render_logs() -> str:
    entries, err = _scan_logs()
    if err:
        return missing(err)
    if not entries:
        return missing("logs/ is empty")

    flagged = [e for e in entries if e["failed"] or e["server_down"]]
    down = [e for e in entries if e["server_down"]]
    unscanned = sum(1 for e in entries if not e["scanned"])

    bits = [tag(f"{len(entries)} logs", "ok")]
    if flagged:
        bits.append(tag(f"{len(flagged)} with errors", "warn"))
    if down:
        bits.append(tag(f"{len(down)} could not reach the ghidra server", "dead"))
    if unscanned:
        bits.append(tag(f"{unscanned} not scanned (time budget)", ""))
    head = f'<p class="sub">{" ".join(bits)}</p>'

    if down:
        names = ", ".join(esc(e["name"]) for e in down[:12])
        head += (
            '<p class="miss">Ghidra headless exits 0 after this, so the batch '
            f"script reports success. Affected: {names}</p>"
        )

    rows = [
        [
            esc(e["name"]),
            _fsize(e["size"]),
            esc(ago(e["mtime"])),
            _flags(e) or "",
        ]
        for e in entries
    ]
    grid = table(["log", "size", "modified", "state"], rows, numeric={1})

    tails = []
    for e in entries[:TAILS_SHOWN]:
        body = "\n".join(e["tail"][-TAIL_SHOW_LINES:]) or "(empty)"
        tails.append(
            f'<p class="sub" style="margin:14px 0 4px">{esc(e["name"])} '
            f'<span style="color:#5f6b7e">{esc(ago(e["mtime"]))}</span> '
            f'{_flags(e)}</p><div class="log">{esc(body)}</div>'
        )
    return head + grid + "".join(tails)


TITLE = "Live jobs and logs"


def render() -> str:
    try:
        procs = _render_procs()
    except Exception as exc:  # noqa: BLE001
        procs = missing(f"process list unavailable: {exc}")
    try:
        logs = _render_logs()
    except Exception as exc:  # noqa: BLE001
        logs = missing(f"log scan unavailable: {exc}")
    return panel(procs, "Running processes (selected by cwd)") + panel(
        logs, "Every log under logs/"
    )
