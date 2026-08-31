"""One-page AgentDecompile workbench: binaries, functions, tools, live jobs."""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from agentdecompile_recovery.corpus.dashboard.common import (
    as_root,
    format_address,
    live_db,
    live_root,
    parse_address,
    query_db,
)
from agentdecompile_recovery.corpus.dashboard.pages import WORKSPACE_NAME, esc

ASM_MARKS = (b"compile-only-asm", b"__asm", b"_emit")
_CACHE: dict[str, tuple[float, Any]] = {}
_CACHE_TTL = 8.0


def _cached(key: str, fn):
    now = time.time()
    hit = _CACHE.get(key)
    if hit and now - hit[0] < _CACHE_TTL:
        return hit[1]
    value = fn()
    _CACHE[key] = (now, value)
    return value


def recovered_root() -> Path | None:
    raw = (os.environ.get("AGENT_DECOMPILE_RECOVERED_DIR") or "").strip()
    if raw:
        path = Path(raw)
        return path if path.is_dir() else None
    root = live_root()
    if root is None:
        return None
    for cand in (
        root / "data" / "recovered-source-ghidra",
        root / "recovered-source-ghidra",
        as_root() / "data" / "recovered-source-ghidra",
    ):
        if cand.is_dir():
            return cand
    return None


def obj_root() -> Path | None:
    raw = (os.environ.get("AGENT_DECOMPILE_OBJ_DIR") or "").strip()
    if raw:
        path = Path(raw)
        return path if path.is_dir() else None
    root = live_root()
    if root is None:
        return None
    workspace = root / "data" / "workspace"
    if workspace.is_dir():
        try:
            for cand in workspace.glob("*/obj"):
                if cand.is_dir():
                    return cand
        except OSError:
            return None
    fallback = workspace / "obj"
    return fallback if fallback.is_dir() else None


def linked_image() -> Path | None:
    raw = (os.environ.get("AGENT_DECOMPILE_LINK_IMAGE") or "").strip()
    if raw:
        path = Path(raw)
        return path if path.is_file() else None
    return None


def _classify_c(path: Path) -> str:
    try:
        head = path.read_bytes()[:800]
    except OSError:
        return "none"
    if any(mark in head for mark in ASM_MARKS):
        return "asm"
    return "c"


def _decomp_dir(slug: str) -> Path | None:
    root = recovered_root()
    if root is None or not slug:
        return None
    for cand in (root / slug, root):
        if cand.is_dir():
            return cand
    return None


def _find_unit(slug: str, addr: int, name: str) -> Path | None:
    folder = _decomp_dir(slug)
    if folder is None:
        return None
    hex_addr = f"{addr:08x}"
    guesses = [
        folder / f"{name}_{hex_addr}.c",
        folder / f"{name}_{addr:016x}.c",
        folder / f"{name}.c",
    ]
    for path in guesses:
        if path.is_file():
            return path
    try:
        for path in folder.glob(f"*_{hex_addr}.c"):
            return path
    except OSError:
        return None
    return None


def decomp_rollup(slug: str, total: int) -> dict[str, Any]:
    folder = _decomp_dir(slug)

    def _scan() -> dict[str, Any]:
        if folder is None:
            return {"asm": 0, "c": 0, "none": total, "files": 0}
        asm = real = 0
        files = 0
        try:
            paths = list(folder.glob("*.c"))
        except OSError:
            paths = []
        for path in paths:
            files += 1
            kind = _classify_c(path)
            if kind == "asm":
                asm += 1
            elif kind == "c":
                real += 1
        none = max(0, total - files)
        return {"asm": asm, "c": real, "none": none, "files": files}

    return _cached(f"decomp:{slug}:{total}", _scan)


def validate_rollup(slug: str, total: int) -> dict[str, Any]:
    objs = obj_root()
    image = linked_image()

    def _scan() -> dict[str, Any]:
        obj_n = 0
        if objs is not None:
            try:
                obj_n = sum(1 for _ in objs.rglob("*.obj"))
            except OSError:
                obj_n = 0
        linked = 0
        if image is not None:
            try:
                linked = total if image.stat().st_size >= 100_000 else 0
            except OSError:
                linked = 0
        compiling = max(0, obj_n - linked)
        none = max(0, total - obj_n)
        return {"none": none, "obj": compiling, "linked": linked, "objects": obj_n}

    return _cached(f"val:{slug}:{total}", _scan)


def _store_error() -> dict[str, Any] | None:
    if live_db() is None:
        return {"ok": False, "error": "AGENT_DECOMPILE_CORPUS_DB is unset"}
    return None


def _open_store():
    from agentdecompile_recovery.corpus.store import connect

    err = _store_error()
    if err:
        return None, err
    return connect(live_db()), None


def _binary_row(slug: str) -> dict[str, Any] | None:
    listed = list_binaries()
    for row in listed.get("binaries") or []:
        if row.get("slug") == slug:
            return row
    return None


def register_path_binary(
    path: str,
    *,
    slug: str = "",
    role: str = "member",
    label: str = "",
) -> dict[str, Any]:
    src = Path(path).expanduser()
    if not path or not src.is_file():
        return {"ok": False, "error": "path is not a readable file"}
    name = (slug or src.name).strip()
    if not name:
        return {"ok": False, "error": "slug is required"}
    con, err = _open_store()
    if err:
        return err
    try:
        con.execute(
            """INSERT INTO binary(repo_path, slug, role, variant)
               VALUES(?,?,?,?)
               ON CONFLICT(repo_path) DO UPDATE SET
                 slug=excluded.slug, role=excluded.role, variant=excluded.variant""",
            (str(src.resolve()), name, role or "member", label or None),
        )
        con.commit()
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    finally:
        con.close()
    _CACHE.clear()
    row = _binary_row(name)
    if row is None:
        return {"ok": False, "error": "binary was not listed after register"}
    return {"ok": True, "binary": row}


def save_upload_binary(
    filename: str,
    data: bytes,
    *,
    slug: str = "",
    role: str = "member",
    label: str = "",
) -> dict[str, Any]:
    root = live_root()
    if root is None:
        return {"ok": False, "error": "AGENT_DECOMPILE_CORPUS_WORK_DIR is unset"}
    dest_dir = root / "imports"
    dest_dir.mkdir(parents=True, exist_ok=True)
    base = Path(filename or slug or "upload.bin").name or "upload.bin"
    dest = dest_dir / base
    if dest.exists():
        stem, suffix = dest.stem, dest.suffix
        index = 2
        while dest.exists():
            dest = dest_dir / f"{stem}-{index}{suffix}"
            index += 1
    dest.write_bytes(data)
    return register_path_binary(str(dest), slug=slug or dest.name, role=role, label=label)


def remove_registered_binary(slug: str, *, confirm: bool) -> dict[str, Any]:
    if not confirm:
        return {"ok": False, "error": "confirm is required to remove a binary"}
    name = (slug or "").strip()
    if not name:
        return {"ok": False, "error": "slug is required"}
    con, err = _open_store()
    if err:
        return err
    from agentdecompile_recovery.corpus.store import remove_binary

    try:
        removed = remove_binary(con, slug=name)
    except SystemExit as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    finally:
        con.close()
    _CACHE.clear()
    return {"ok": True, "removed": removed}


def update_registered_binary(
    slug: str,
    *,
    role: str | None = None,
    label: str | None = None,
) -> dict[str, Any]:
    name = (slug or "").strip()
    if not name:
        return {"ok": False, "error": "slug is required"}
    con, err = _open_store()
    if err:
        return err
    try:
        row = con.execute("SELECT slug FROM binary WHERE slug=?", (name,)).fetchone()
        if row is None:
            return {"ok": False, "error": f"no binary matching {name!r}"}
        if role is not None:
            con.execute("UPDATE binary SET role=? WHERE slug=?", (role, name))
        if label is not None:
            con.execute("UPDATE binary SET variant=? WHERE slug=?", (label, name))
        con.commit()
    finally:
        con.close()
    _CACHE.clear()
    listed = _binary_row(name)
    return {"ok": True, "binary": listed}


def list_binaries() -> dict[str, Any]:
    rows, err = query_db(
        "SELECT slug, repo_path, role, func_count, named_count, game, platform "
        "FROM binary ORDER BY slug"
    )
    binaries: list[dict[str, Any]] = []
    if err:
        return {"ok": False, "error": err, "binaries": []}
    for slug, repo, role, funcs, named, game, platform in rows:
        total = int(funcs or 0)
        binaries.append(
            {
                "slug": slug,
                "repo": repo or "",
                "program": repo or slug,
                "role": role or "",
                "funcs": total,
                "named": int(named or 0),
                "game": game or "",
                "platform": platform or "",
                "decomp": decomp_rollup(str(slug), total),
                "validate": validate_rollup(str(slug), total),
            }
        )
    return {"ok": True, "binaries": binaries, "recovered": str(recovered_root() or "")}


def list_functions(slug: str, *, q: str = "", offset: int = 0, limit: int = 80) -> dict[str, Any]:
    slug = (slug or "").strip()
    if not slug:
        return {"ok": False, "error": "pick a binary", "results": [], "total": 0}
    rows, err = query_db(
        "SELECT id, bits FROM binary WHERE slug=? LIMIT 1",
        (slug,),
    )
    if err:
        return {"ok": False, "error": err, "results": [], "total": 0}
    if not rows:
        return {"ok": False, "error": f"no build called {slug}", "results": [], "total": 0}
    bid, bits = rows[0][0], rows[0][1] or 32
    cap = max(1, min(int(limit or 80), 200))
    start = max(0, int(offset or 0))
    name_expr = (
        "COALESCE((SELECT ln.name FROM identity ni "
        "JOIN logical_name ln ON ln.logical_id=ni.logical_id "
        "WHERE ni.binary_id=f.binary_id AND ni.addr=f.addr "
        "ORDER BY ni.confidence DESC LIMIT 1), f.name, '')"
    )
    where = "f.binary_id=?"
    params: list[Any] = [bid]
    needle = (q or "").strip()
    if needle:
        addr = parse_address(needle)
        if addr is not None and (needle.lower().startswith("0x") or needle.isdigit()):
            where += " AND f.addr=?"
            params.append(addr)
        else:
            where += f" AND {name_expr} LIKE ?"
            params.append(f"%{needle}%")
    count_rows, cerr = query_db(f"SELECT COUNT(*) FROM func f WHERE {where}", tuple(params))
    total = int(count_rows[0][0]) if count_rows and not cerr else 0
    data, qerr = query_db(
        f"SELECT f.addr, {name_expr}, f.size, "
        "(SELECT ni.logical_id FROM identity ni WHERE ni.binary_id=f.binary_id "
        "AND ni.addr=f.addr ORDER BY ni.confidence DESC LIMIT 1) "
        f"FROM func f WHERE {where} ORDER BY f.addr LIMIT ? OFFSET ?",
        (*params, cap, start),
    )
    if qerr:
        return {"ok": False, "error": qerr, "results": [], "total": total}
    results = []
    for addr, name, size, logical_id in data or []:
        addr_i = int(addr)
        shown = name or f"FUN_{format_address(addr_i, bits)[2:]}"
        unit = _find_unit(slug, addr_i, shown)
        decomp = _classify_c(unit) if unit else "none"
        obj_hit = False
        objs = obj_root()
        if objs is not None and unit is not None:
            guess = objs / unit.with_suffix(".obj").name
            obj_hit = guess.is_file()
        validate = "linked" if obj_hit and linked_image() else ("obj" if obj_hit else "none")
        results.append(
            {
                "addr": format_address(addr_i, bits),
                "address": addr_i,
                "name": shown,
                "size": int(size or 0),
                "logicalId": logical_id,
                "decomp": decomp,
                "validate": validate,
            }
        )
    return {
        "ok": True,
        "slug": slug,
        "q": needle,
        "offset": start,
        "limit": cap,
        "total": total,
        "results": results,
        "hasMore": start + len(results) < total,
    }


def function_detail(slug: str, raw_addr: str) -> dict[str, Any]:
    addr = parse_address(raw_addr)
    if addr is None:
        return {"ok": False, "error": "bad address"}
    listed = list_functions(slug, q=hex(addr), offset=0, limit=1)
    row = listed["results"][0] if listed.get("results") else {}
    unit = _find_unit(slug, addr, str(row.get("name") or ""))
    preview = ""
    if unit is not None:
        try:
            preview = unit.read_text(encoding="utf-8", errors="replace")[:4000]
        except OSError:
            preview = ""
    siblings: list[dict[str, Any]] = []
    rows, err = query_db(
        "SELECT b.slug, i.addr, i.logical_id FROM identity src "
        "JOIN identity i ON i.logical_id=src.logical_id "
        "JOIN binary b ON b.id=i.binary_id "
        "JOIN binary sb ON sb.id=src.binary_id "
        "WHERE sb.slug=? AND src.addr=?",
        (slug, addr),
    )
    if not err:
        for other_slug, other_addr, logical_id in rows:
            siblings.append(
                {
                    "slug": other_slug,
                    "addr": format_address(int(other_addr)),
                    "logicalId": logical_id,
                }
            )
    return {
        "ok": True,
        "slug": slug,
        "addr": format_address(addr),
        "function": row,
        "preview": preview,
        "siblings": siblings,
        "sourcePath": str(unit) if unit else "",
    }


def render_workbench() -> str:
    payload = list_binaries()
    rows = payload.get("binaries") or []
    items = []
    for row in rows:
        items.append(
            f'<li data-slug="{esc(row["slug"])}">'
            f'<a href="/dashboard/binary/{esc(row["slug"])}">{esc(row["slug"])}</a>'
            f' <span>{int(row.get("funcs") or 0)}</span></li>'
        )
    binary_html = "".join(items) or "<li>No binaries. Set AGENT_DECOMPILE_CORPUS_DB.</li>"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentDecompile — {esc(WORKSPACE_NAME)}</title>
<link rel="stylesheet" href="/dashboard/static/dashboard.css">
<link rel="stylesheet" href="/dashboard/static/workbench.css">
</head>
<body class="workbench-page">
<a class="sr-only" href="#function-list">Skip to functions</a>
<header class="wb-toolbar">
  <div class="wb-brand">
    <strong>AgentDecompile</strong>
    <span class="wb-claim">Live view. Real C and a complete executable are separate facts.</span>
  </div>
  <label class="wb-search">
    <span class="sr-only">Find a function</span>
    <input id="wb-q" type="search" placeholder="Name or 0xaddress" autocomplete="off">
  </label>
  <div class="wb-toolbar-actions">
    <button type="button" id="wb-run" class="wb-btn">Run work</button>
    <a href="/docs">Swagger</a>
    <a href="/atlas">Atlas</a>
    <a href="/report">Report</a>
    <a href="/dashboard/overview">Classic overview</a>
    <span id="job-pulse" class="chip">no jobs</span>
  </div>
</header>
<div id="page-context" hidden data-page="home"></div>
<div class="wb-shell">
  <nav class="wb-strip" aria-label="Tools">
    <button type="button" data-tool="graph" class="on">Graph</button>
    <button type="button" data-tool="map">Map</button>
    <button type="button" data-tool="score">Score</button>
    <button type="button" data-tool="prompt">Prompt</button>
    <button type="button" data-tool="review">Review</button>
    <button type="button" data-tool="logical">Logical</button>
    <button type="button" data-tool="pipeline">Pipeline</button>
    <button type="button" data-tool="crossmatch">Match</button>
    <button type="button" data-tool="recovery">Recovery</button>
    <button type="button" data-tool="stabs">STABS</button>
    <button type="button" data-tool="knowledge">Knowledge</button>
    <button type="button" data-tool="roundtrip">Roundtrip</button>
    <button type="button" data-tool="report">Report</button>
    <button type="button" data-tool="artifacts">Artifacts</button>
    <button type="button" data-tool="directives">Mission</button>
    <button type="button" data-tool="mcp">MCP</button>
  </nav>
  <aside class="wb-binaries" aria-label="Binaries">
    <h2>Binaries</h2>
    <div id="wb-drop" class="wb-drop" tabindex="0">Drop binaries here
      <input id="wb-bin-file" type="file" multiple hidden>
    </div>
    <form id="wb-bin-form" class="wb-bin-form">
      <label>Existing path
        <input id="wb-bin-path" name="path" type="text" autocomplete="off" placeholder="/path/to/binary">
      </label>
      <label>Slug
        <input id="wb-bin-slug" name="slug" type="text" autocomplete="off">
      </label>
      <label>Role
        <input id="wb-bin-role" name="role" type="text" value="member">
      </label>
      <label>Label
        <input id="wb-bin-label" name="label" type="text">
      </label>
      <div class="wb-bin-actions">
        <button type="submit" id="wb-bin-add">Register path</button>
        <button type="button" id="wb-bin-remove">Remove</button>
      </div>
    </form>
    <ul id="wb-binary-list">{binary_html}</ul>
  </aside>
  <main class="wb-stage" id="wb-stage">
    <p class="wb-hint">Pick a binary and a function. The graph, prompts, and MCP tools stay on this page.</p>
    <div id="wb-stage-body"></div>
  </main>
  <aside class="wb-inspect" id="wb-inspect" aria-label="Inspector">
    <h2>Inspector</h2>
    <div id="wb-inspect-body"><p class="wb-hint">Select a function to decompile, rename, and match siblings.</p></div>
  </aside>
</div>
<section class="wb-funcs" aria-label="Functions">
  <div class="wb-funcs-head">
    <h2 id="function-list">Functions</h2>
    <span id="wb-func-meta"></span>
  </div>
  <div id="wb-func-window" class="wb-func-window" tabindex="0"></div>
</section>
<div id="action-dock" hidden>
  <div class="action-dock-bar">
    <button type="button" class="action-toggle" aria-expanded="false">Jobs</button>
    <span class="chip" id="job-pulse-dock">no jobs</span>
  </div>
  <div class="action-dock-panel" hidden>
    <form id="action-form" hidden></form>
    <div id="action-jobs" class="action-jobs"></div>
  </div>
</div>
<noscript>
  <p>JavaScript is off. Use <a href="/dashboard/overview">classic overview</a>,
  <a href="/dashboard/functions">functions</a>, or <a href="/docs">Swagger</a>.</p>
</noscript>
<script src="/dashboard/static/actions.js" defer></script>
<script src="/dashboard/static/workbench.js" defer></script>
</body>
</html>
"""
