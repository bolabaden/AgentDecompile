"""Island binary/function explorer. Vite stays on /dashboard; this is /dashboard/explorer."""

from __future__ import annotations

import sqlite3
from typing import Any, Mapping

from agentdecompile_recovery.corpus.dashboard.pages import WORKSPACE_NAME, esc

ACTIVE = frozenset({"queued", "running", "waiting", "cancelling"})


def selection_from_mapping(query: Mapping[str, Any] | None) -> dict[str, str]:
    data = query or {}
    return {
        "locator": str(data.get("locator") or data.get("path") or "").strip(),
        "slug": str(data.get("slug") or data.get("binary") or "").strip(),
        "program": str(data.get("program") or "").strip(),
        "addr": str(data.get("addr") or data.get("fn") or "").strip(),
        "logicalId": str(data.get("logicalId") or data.get("logical") or "").strip(),
    }


def select_preparation(runs: list[dict[str, Any]] | None, selection: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """Pick the live workflow for the open binary. Active beats stale."""
    chosen = selection_from_mapping(selection)
    locator = chosen["locator"]
    program = chosen["program"]
    slug = chosen["slug"]
    if not locator and not slug:
        return None
    applicable: list[dict[str, Any]] = []
    for run in runs or []:
        if not isinstance(run, dict):
            continue
        if locator:
            if str(run.get("locator") or "") != locator:
                continue
            run_program = str(run.get("program") or "")
            programs = [str(item) for item in (run.get("programs") or [])]
            if program and run_program and run_program != program and program not in programs:
                continue
        elif str(run.get("slug") or "") != slug:
            continue
        applicable.append(run)
    applicable.sort(
        key=lambda row: (1 if str(row.get("status") or "") in ACTIVE else 0, float(row.get("updatedAt") or 0)),
        reverse=True,
    )
    return applicable[0] if applicable else None


def explorer_snapshot(locator: str = "", slug: str = "", program: str = "") -> dict[str, Any]:
    """One payload: library, sessions, matching workflow, activity entities."""
    selection = selection_from_mapping({"locator": locator, "slug": slug, "program": program})
    library_error = ""
    binaries: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    sessions: list[dict[str, Any]] = []
    runs: list[dict[str, Any]] = []
    activity: dict[str, Any] = {"ok": False, "entities": [], "revision": 0, "error": ""}

    try:
        from agentdecompile_recovery.corpus.dashboard.workbench import list_binaries

        library = list_binaries()
        binaries = list(library.get("binaries") or [])
        unresolved = list(library.get("unresolvedBinaries") or [])
        library_error = str(library.get("error") or "")
    except (ValueError, OSError) as exc:
        library_error = str(exc)

    try:
        from agentdecompile_recovery.corpus.dashboard.workbench import list_sessions

        sessions = list((list_sessions() or {}).get("sessions") or [])
    except (ValueError, OSError, TypeError):
        sessions = []

    try:
        from agentdecompile_recovery.corpus.dashboard.preparation import list_runs

        runs = list_runs()
    except (ValueError, OSError):
        runs = []

    try:
        from agentdecompile_recovery.corpus.dashboard.entity_activity import snapshot

        activity = snapshot(selection["locator"], selection["slug"])
    except (ValueError, OSError, sqlite3.Error) as exc:
        activity = {"ok": False, "entities": [], "revision": 0, "error": str(exc)}

    return {
        "ok": True,
        "selection": selection,
        "binaries": binaries,
        "unresolvedBinaries": unresolved,
        "libraryError": library_error,
        "sessions": sessions,
        "run": select_preparation(runs, selection),
        "activity": activity,
    }


def render_explorer() -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Explorer — {esc(WORKSPACE_NAME)}</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='8' fill='%234c78cc'/%3E%3Ctext x='16' y='21' text-anchor='middle' font-size='13' font-family='ui-sans-serif,system-ui,sans-serif' font-weight='800' fill='%23e6e6e6'%3EAD%3C/text%3E%3C/svg%3E">
<link rel="stylesheet" href="/dashboard/static/workbench.css">
<link rel="stylesheet" href="/dashboard/static/workbench-tokens.css">
<link rel="stylesheet" href="/dashboard/static/explorer-page.css?v=6">
</head>
<body class="workbench-page explorer-page">
<a class="skip-link" href="#explorer-binaries">Skip to binaries</a>
<header class="explorer-chrome">
  <div class="wb-brand">
    <span class="wb-mark" aria-hidden="true">AD</span>
    <div>
      <strong>Explorer</strong>
      <span>Binaries, functions, and the running workflow.</span>
    </div>
  </div>
  <p class="explorer-chrome-links">
    <a href="/dashboard">Workbench</a>
    <a href="/docs">Docs</a>
  </p>
</header>
<main id="app" class="explorer-shell">
  <section id="explorer-binaries" class="explorer-pane" aria-labelledby="binaries-heading">
    <header>
      <h1 id="binaries-heading">Projects and binaries</h1>
    </header>
    <input id="binary-search" type="search" placeholder="Find binary or SHA-256…" aria-label="Search projects and binaries" autocomplete="off">
    <div id="binary-tree" class="explorer-tree" role="tree" aria-label="Projects and binaries" tabindex="0"></div>
    <p id="binary-empty" class="explorer-empty" hidden>Open a project or add binaries to begin.</p>
  </section>
  <div id="split-x" class="explorer-split" data-axis="x" role="separator" aria-orientation="vertical" aria-label="Resize binary and function panes" tabindex="0"></div>
  <section id="explorer-functions" class="explorer-pane" aria-labelledby="functions-heading">
    <header>
      <h1 id="functions-heading">Functions</h1>
      <select id="function-filter" aria-label="Filter function inventory">
        <option value="all">All functions</option>
        <option value="named">Named</option>
        <option value="bound">Identity bound</option>
        <option value="real-c">Assembly-free C</option>
      </select>
      <span id="function-total"></span>
    </header>
    <input id="function-search" type="search" placeholder="Function name or 0xaddress…" aria-label="Search functions in the selected binary" autocomplete="off">
    <p id="function-context" class="explorer-context">Select a binary</p>
    <div id="function-tree" class="explorer-tree" role="tree" aria-label="Functions by source unit" tabindex="0"></div>
    <footer>
      <span id="function-status" role="status">No binary selected</span>
      <label class="explorer-limit">
        <span>Show</span>
        <select id="function-limit" aria-label="How many functions to show">
          <option value="all">All</option>
          <option value="10">10</option>
          <option value="20">20</option>
          <option value="50">50</option>
          <option value="100">100</option>
          <option value="200">200</option>
        </select>
      </label>
    </footer>
  </section>
  <div id="split-y" class="explorer-split" data-axis="y" role="separator" aria-orientation="horizontal" aria-label="Resize explorer and workflow" tabindex="0"></div>
  <aside id="explorer-workflow" class="explorer-workflow" aria-labelledby="workflow-heading">
    <header>
      <h1 id="workflow-heading">Workflow</h1>
      <span id="workflow-connection" role="status">Connecting</span>
    </header>
    <div id="workflow-body"></div>
  </aside>
</main>
<footer id="explorer-feed" class="explorer-feed">Activity feed</footer>
<script src="/dashboard/static/explorer-page.js?v=6"></script>
</body>
</html>
"""
