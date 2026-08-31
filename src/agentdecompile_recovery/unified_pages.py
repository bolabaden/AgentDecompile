"""Browser pages that used to live on 8791 / 5173 / 3000, served from the MCP app.

Mount these on the AgentDecompile HTTP server (default 8080). Reachability is
not recovery progress. Completeness comes from receipts on disk.
"""

from __future__ import annotations

import html
import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from .atlas_server import AtlasServerState, atlas_ui_html, handle_build_prompt, handle_load_project, handle_save_prompt
from .corpus.dashboard import create_dashboard_router
from .corpus.dashboard.pages import (
    WORKSPACE_NAME,
    graph_to_function_target,
    is_partial_query,
    query_from_mapping,
    render_artifact as dashboard_render_artifact,
    render_binary_page,
    render_function_page,
    render_functions_page,
    render_logical_page,
    render_page as dashboard_render_page,
    _action_dock_html,
    _page_context,
)
from .corpus.io import read_json
from .corpus.store import connect as store_connect
from .run_report import html_report_text

CLAIM = (
    "These pages are a live view. They are not completion. Real C and "
    "byte-accuracy are separate columns. A green label is not a match."
)

PAGE_PATHS = {
    "app": "/dashboard",
    "dashboard": "/dashboard",
    "overview": "/dashboard/overview",
    "atlas": "/atlas",
    "report": "/report",
    "docs": "/docs",
    "swagger": "/docs",
    "functions": "/dashboard/functions",
    "logical": "/dashboard/functions#logical",
    "graph": "/dashboard/functions#graph",
    "review": "/dashboard/functions#review",
    "artifact": "/dashboard/artifact",
    "healthz": "/dashboard/healthz",
    "builds": "/dashboard/functions#builds",
    "operations": "/dashboard#operations",
    "actions": "/api/v1/actions",
}

ARTIFACT_CAP = 1_000_000


def _env_path(*keys: str) -> Path | None:
    for key in keys:
        raw = (os.environ.get(key) or "").strip()
        if raw:
            return Path(raw)
    return None


def _nav(active: str) -> str:
    links = [
        ("dashboard", "/dashboard", "Overview"),
        ("atlas", "/atlas", "Atlas"),
        ("report", "/report", "Report"),
        ("docs", "/docs", "MCP docs"),
    ]
    items = []
    for key, href, label in links:
        cls = ' class="on"' if key == active else ""
        items.append(f'<a href="{href}"{cls}>{html.escape(label)}</a>')
    return '<nav class="bar">' + " ".join(items) + "</nav>"


def _shell(title: str, active: str, body: str, *, page: str = "home") -> str:
    page_map = {"app": "home", "dashboard": "home", "report": "report", "atlas": "atlas"}
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{html.escape(title)}</title>
<link rel="stylesheet" href="/dashboard/static/dashboard.css">
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: system-ui, sans-serif; margin: 0; color: #1a1a1a; background: #fafafa; }}
  .bar {{ padding: 0.6rem 1rem; border-bottom: 1px solid #ddd; background: #fff; }}
  .bar a {{ margin-right: 1rem; color: inherit; }}
  .bar a.on {{ font-weight: 700; }}
  main {{ padding: 1rem 1.25rem 2rem; max-width: 1100px; }}
  h1 {{ font-size: 1.15rem; margin: 0 0 0.4rem; }}
  .claim {{ border: 1px solid #c9a227; background: #fff8d8; padding: 0.6rem 0.8rem; margin: 0.8rem 0 1rem; }}
  .kv {{ display: flex; flex-wrap: wrap; gap: 0.75rem; margin: 0.8rem 0; }}
  .kv div {{ border: 1px solid #ddd; background: #fff; padding: 0.5rem 0.75rem; min-width: 8rem; }}
  .kv b {{ display: block; font-size: 1.2rem; }}
  .kv span {{ color: #555; font-size: 0.8rem; }}
  table {{ border-collapse: collapse; width: 100%; background: #fff; }}
  th, td {{ text-align: left; padding: 0.35rem 0.55rem; border-bottom: 1px solid #eee; font-size: 0.9rem; }}
  .sub {{ color: #555; font-size: 0.85rem; }}
  a {{ color: #134; }}
  pre {{ white-space: pre-wrap; font-size: 0.85rem; background: #fff; border: 1px solid #eee; padding: 0.6rem; }}
</style>
</head>
<body>
{_page_context(page=page_map.get(active, page))}
{_nav(active)}
<main>
{body}
</main>
{_action_dock_html()}
<script src="/dashboard/static/dashboard.js" defer></script>
<script src="/dashboard/static/actions.js" defer></script>
</body>
</html>
"""


def _int_q(request: Request, name: str, default: int) -> int:
    raw = (request.query_params.get(name) or "").strip()
    if not raw:
        return default
    try:
        return int(raw, 0)
    except ValueError:
        return default


def _parse_addr(raw: str) -> int | None:
    text = (raw or "").strip()
    if not text:
        return None
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text, 0)
    except ValueError:
        return None


def _func_source_sql(con: Any) -> str:
    cols = {row[1] for row in con.execute("PRAGMA table_info(func)")}
    if "source_file" in cols:
        return "COALESCE(f.source_file, f.source) AS source_file"
    return "f.source AS source_file"


def _confine(root: Path, raw: str) -> Path | None:
    if raw.startswith("/") or raw.startswith("\\"):
        cand = Path(raw)
        try:
            resolved = cand.resolve()
            resolved.relative_to(root.resolve())
            return resolved
        except ValueError:
            return None
    if ".." in Path(raw).parts:
        return None
    dest = (root / raw).resolve()
    try:
        dest.relative_to(root.resolve())
    except ValueError:
        return None
    return dest


def _receipts(work_dir: Path | None) -> dict[str, Any]:
    if work_dir is None or not work_dir.is_dir():
        return {}
    out: dict[str, Any] = {}
    for name in ("corpus-run.json", "compile.json", "extract.json", "identify.json"):
        path = work_dir / name
        if path.is_file():
            try:
                out[name] = read_json(path)
            except (OSError, json.JSONDecodeError):
                continue
    return out


def render_hub() -> str:
    body = f"""
<h1>AgentDecompile</h1>
<p class="claim">{html.escape(CLAIM)}</p>
<p>The MCP transport is on this same server at <code>/mcp</code>. The pages that used to
be separate processes on 8791, 5173, and 3000 are here:</p>
<ul>
  <li><a href="/dashboard">Overview</a> — corpus, recovery, and runnable actions</li>
  <li><a href="/dashboard/functions">Functions</a> — functions, logical identities, review, relationships, and builds</li>
  <li><a href="/atlas">Atlas</a> — decomp prompt authoring</li>
  <li><a href="/report">Report</a> — saved run report when one is configured</li>
</ul>
<p class="sub">Set <code>AGENT_DECOMPILE_CORPUS_DB</code>, <code>AGENT_DECOMPILE_CORPUS_WORK_DIR</code>,
and <code>AGENT_DECOMPILE_ATLAS_PROJECT_ROOT</code> when you want live data. Empty pages are
honest, not complete.</p>
"""
    return _shell("AgentDecompile", "app", body)


def render_dashboard(*, store_path: Path | None, work_dir: Path | None) -> str:
    receipts = _receipts(work_dir)
    compile_rec = receipts.get("compile.json") or (receipts.get("corpus-run.json") or {}).get("receipts", {}).get("compile") or {}
    complete = bool(compile_rec.get("completeExecutable") or (receipts.get("corpus-run.json") or {}).get("completeExecutable"))
    tiles = [
        ("complete executable", "yes" if complete else "no"),
        ("receipts on disk", str(len(receipts))),
    ]
    tables = ""
    if store_path and store_path.is_file():
        con = store_connect(store_path)
        binaries = list(con.execute("SELECT slug, game, platform, func_count, named_count, role FROM binary ORDER BY slug"))
        matches = list(con.execute("SELECT status, COUNT(*) n FROM match GROUP BY status ORDER BY status"))
        tiles.append(("binaries", str(len(binaries))))
        named = sum(int(r["named_count"] or 0) for r in binaries)
        tiles.append(("named (store)", str(named)))
        rows = "".join(
            f"<tr><td><a href=\"/dashboard/binary/{quote(str(r['slug']), safe='')}\">"
            f"{html.escape(str(r['slug']))}</a></td>"
            f"<td>{html.escape(str(r['game'] or ''))}</td>"
            f"<td>{html.escape(str(r['platform'] or ''))}</td><td>{r['func_count'] or 0}</td>"
            f"<td>{r['named_count'] or 0}</td><td>{html.escape(str(r['role'] or ''))}</td></tr>"
            for r in binaries
        )
        tables += (
            "<h2>Binaries</h2><table><thead><tr><th>slug</th><th>game</th><th>platform</th>"
            "<th>funcs</th><th>named</th><th>role</th></tr></thead><tbody>"
            + (rows or "<tr><td colspan=6>none</td></tr>")
            + "</tbody></table>"
        )
        if matches:
            tables += (
                "<h2>Match status</h2><table><thead><tr><th>status</th><th>count</th></tr></thead><tbody>"
                + "".join(f"<tr><td>{html.escape(r['status'] or '')}</td><td>{r['n']}</td></tr>" for r in matches)
                + "</tbody></table>"
            )
        tables += (
            '<p class="sub"><a href="/dashboard/functions">Functions</a> · '
            '<a href="/dashboard/functions#logical">Logical identities</a> · '
            '<a href="/dashboard/functions#graph">Call graph</a> · '
            '<a href="/dashboard/functions#review">Review</a> · '
            '<a href="/dashboard/artifact">Artifacts</a> · '
            '<a href="/report">Report</a></p>'
        )
        con.close()
    else:
        tables = '<p class="sub">No corpus store. Set AGENT_DECOMPILE_CORPUS_DB to a SQLite path the extractor wrote.</p>'

    kv = "".join(f"<div><b>{html.escape(v)}</b><span>{html.escape(k)}</span></div>" for k, v in tiles)
    body = f"""
<h1>Corpus dashboard</h1>
<p class="claim">{html.escape(CLAIM)}</p>
<p>Real C and byte-accuracy are never summed. A linked image is compile proof only.</p>
<div class="kv">{kv}</div>
{tables}
"""
    return _shell("Dashboard", "dashboard", body)


def render_functions(*, store_path: Path | None, limit: int = 50, offset: int = 0, slug: str | None = None) -> str:
    if store_path is None or not store_path.is_file():
        return _shell("Functions", "dashboard", "<h1>Functions</h1><p>No corpus store.</p>")
    con = store_connect(store_path)
    where = ""
    args: list[Any] = []
    if slug:
        where = "WHERE b.slug=?"
        args.append(slug)
    src = _func_source_sql(con)
    rows = list(
        con.execute(
            f"""SELECT b.slug, f.addr, f.name, f.canon_key, {src}, f.n_instr
                  FROM func f JOIN binary b ON b.id=f.binary_id
                  {where}
                 ORDER BY b.slug, f.addr LIMIT ? OFFSET ?""",
            [*args, limit, offset],
        )
    )
    con.close()
    body_rows = "".join(
        f"<tr><td><a href=\"/dashboard/binary/{quote(r['slug'], safe='')}\">{html.escape(r['slug'])}</a></td>"
        f"<td><a href=\"/dashboard/function/{quote(r['slug'], safe='')}/0x{int(r['addr']):x}\">"
        f"0x{int(r['addr']):x}</a></td>"
        f"<td>{html.escape(str(r['name'] or ''))}</td><td>{html.escape(str(r['canon_key'] or ''))}</td>"
        f"<td>{html.escape(str(r['source_file'] or ''))}</td><td>{r['n_instr'] or 0}</td></tr>"
        for r in rows
    )
    body = f"""
<h1>Functions</h1>
<p class="sub"><a href="/dashboard">Back</a></p>
<table><thead><tr><th>binary</th><th>addr</th><th>name</th><th>canon</th><th>source</th><th>instr</th></tr></thead>
<tbody>{body_rows or '<tr><td colspan=6>none</td></tr>'}</tbody></table>
"""
    return _shell("Functions", "dashboard", body)


def render_logical(*, store_path: Path | None, limit: int = 50) -> str:
    if store_path is None or not store_path.is_file():
        return _shell("Logical", "dashboard", "<h1>Logical functions</h1><p>No corpus store.</p>")
    con = store_connect(store_path)
    rows = list(
        con.execute(
            """SELECT id, canon_key, n_members, source_file
                 FROM logical_function ORDER BY n_members DESC, id LIMIT ?""",
            (limit,),
        )
    )
    con.close()
    body_rows = "".join(
        f"<tr><td><a href=\"/dashboard/logical/{r['id']}\">{r['id']}</a></td>"
        f"<td>{html.escape(str(r['canon_key'] or ''))}</td>"
        f"<td>{r['n_members'] or 0}</td><td>{html.escape(str(r['source_file'] or ''))}</td></tr>"
        for r in rows
    )
    body = f"""
<h1>Logical functions</h1>
<p class="sub"><a href="/dashboard">Back</a></p>
<table><thead><tr><th>id</th><th>canon</th><th>members</th><th>source</th></tr></thead>
<tbody>{body_rows or '<tr><td colspan=4>none</td></tr>'}</tbody></table>
"""
    return _shell("Logical functions", "dashboard", body)


def render_store_report(*, store_path: Path | None, work_dir: Path | None) -> str:
    receipts = _receipts(work_dir)
    parts = [f"<h1>Recovery report</h1><p class='claim'>{html.escape(CLAIM)}</p>"]
    run = receipts.get("corpus-run.json")
    if run:
        parts.append(
            f"<p>Corpus <code>{html.escape(str(run.get('corpusId') or ''))}</code> "
            f"completeExecutable={bool(run.get('completeExecutable'))}.</p>"
        )
    if store_path and store_path.is_file():
        con = store_connect(store_path)
        matches = list(con.execute("SELECT status, COUNT(*) n FROM match GROUP BY status"))
        logical = con.execute("SELECT COUNT(*) FROM logical_function").fetchone()[0]
        con.close()
        parts.append(
            "<div class='kv'>"
            f"<div><b>{logical}</b><span>logical functions</span></div>"
            + "".join(f"<div><b>{r['n']}</b><span>match {html.escape(r['status'] or '')}</span></div>" for r in matches)
            + "</div>"
        )
    else:
        parts.append("<p class='sub'>No store and no HTML report file. This page is empty on purpose.</p>")
    return _shell("Report", "report", "".join(parts))


def render_binary(*, store_path: Path | None, slug: str) -> tuple[str, int]:
    if store_path is None or not store_path.is_file():
        return _shell("Binary", "dashboard", "<h1>Binary</h1><p>No corpus store.</p>"), 200
    con = store_connect(store_path)
    rec = con.execute(
        "SELECT id, slug, game, platform, role, func_count, named_count, repo_path FROM binary WHERE slug=?",
        (slug,),
    ).fetchone()
    if rec is None:
        con.close()
        return _shell("Binary", "dashboard", f"<h1>Not found</h1><p>No binary <code>{html.escape(slug)}</code>.</p>"), 404
    src = _func_source_sql(con)
    funcs = list(
        con.execute(
            f"""SELECT addr, name, canon_key, {src}, n_instr
                  FROM func f WHERE binary_id=? ORDER BY addr LIMIT 80""",
            (rec["id"],),
        )
    )
    con.close()
    rows = "".join(
        f"<tr><td><a href=\"/dashboard/function/{quote(slug, safe='')}/0x{int(r['addr']):x}\">"
        f"0x{int(r['addr']):x}</a></td>"
        f"<td>{html.escape(str(r['name'] or ''))}</td>"
        f"<td>{html.escape(str(r['canon_key'] or ''))}</td>"
        f"<td>{html.escape(str(r['source_file'] or ''))}</td>"
        f"<td>{r['n_instr'] or 0}</td></tr>"
        for r in funcs
    )
    body = f"""
<h1>{html.escape(slug)}</h1>
<p class="sub"><a href="/dashboard">Back</a> ·
<a href="/dashboard/functions?binary={quote(slug, safe='')}">All functions</a> ·
<a href="/dashboard/functions?binary={quote(slug, safe='')}#graph">Call graph</a></p>
<div class="kv">
  <div><b>{html.escape(str(rec['role'] or ''))}</b><span>role</span></div>
  <div><b>{rec['func_count'] or 0}</b><span>funcs</span></div>
  <div><b>{rec['named_count'] or 0}</b><span>named</span></div>
  <div><b>{html.escape(str(rec['platform'] or ''))}</b><span>platform</span></div>
</div>
<p class="sub">repo <code>{html.escape(str(rec['repo_path'] or ''))}</code></p>
<table><thead><tr><th>addr</th><th>name</th><th>canon</th><th>source</th><th>instr</th></tr></thead>
<tbody>{rows or '<tr><td colspan=5>none</td></tr>'}</tbody></table>
"""
    return _shell(slug, "dashboard", body), 200


def render_function(*, store_path: Path | None, slug: str, addr: int) -> tuple[str, int]:
    if store_path is None or not store_path.is_file():
        return _shell("Function", "dashboard", "<h1>Function</h1><p>No corpus store.</p>"), 200
    con = store_connect(store_path)
    src = _func_source_sql(con)
    rec = con.execute(
        f"""SELECT f.addr, f.name, f.canon_key, {src}, f.n_instr, f.size, f.signature, b.id AS binary_id
              FROM func f JOIN binary b ON b.id=f.binary_id
             WHERE b.slug=? AND f.addr=?""",
        (slug, addr),
    ).fetchone()
    if rec is None:
        con.close()
        return _shell("Function", "dashboard", "<h1>Not found</h1><p>No function at that address.</p>"), 404
    callers = list(
        con.execute(
            """SELECT caller_addr FROM calledge WHERE binary_id=? AND callee_addr=? LIMIT 40""",
            (rec["binary_id"], addr),
        )
    )
    callees = list(
        con.execute(
            """SELECT callee_addr FROM calledge WHERE binary_id=? AND caller_addr=? LIMIT 40""",
            (rec["binary_id"], addr),
        )
    )
    ident = con.execute(
        """SELECT i.logical_id, i.confidence, i.method FROM identity i
            WHERE i.binary_id=? AND i.addr=?""",
        (rec["binary_id"], addr),
    ).fetchone()
    con.close()
    def _addrs(rows: list[Any], key: str) -> str:
        if not rows:
            return "<li>none</li>"
        return "".join(
            f"<li><a href=\"/dashboard/function/{quote(slug, safe='')}/0x{int(r[key]):x}\">0x{int(r[key]):x}</a></li>"
            for r in rows
        )
    ident_html = ""
    if ident:
        ident_html = (
            f"<p>Logical <a href=\"/dashboard/logical/{ident['logical_id']}\">{ident['logical_id']}</a> "
            f"confidence={ident['confidence']} method={html.escape(str(ident['method'] or ''))}</p>"
        )
    body = f"""
<h1>{html.escape(str(rec['name'] or '')) or hex(addr)}</h1>
<p class="sub"><a href="/dashboard/binary/{quote(slug, safe='')}">{html.escape(slug)}</a> ·
<a href="/dashboard/functions?binary={quote(slug, safe='')}&addr=0x{addr:x}#graph">Graph</a></p>
<p>addr <code>0x{addr:x}</code> · size {rec['size'] or 0} · instr {rec['n_instr'] or 0}</p>
<p>canon <code>{html.escape(str(rec['canon_key'] or ''))}</code></p>
<p>source <code>{html.escape(str(rec['source_file'] or ''))}</code></p>
<p>signature <code>{html.escape(str(rec['signature'] or ''))}</code></p>
{ident_html}
<h2>Callers</h2><ul>{_addrs(callers, 'caller_addr')}</ul>
<h2>Callees</h2><ul>{_addrs(callees, 'callee_addr')}</ul>
"""
    return _shell("Function", "dashboard", body), 200


def render_logical_one(*, store_path: Path | None, logical_id: int) -> tuple[str, int]:
    if store_path is None or not store_path.is_file():
        return _shell("Logical", "dashboard", "<h1>Logical</h1><p>No corpus store.</p>"), 200
    con = store_connect(store_path)
    rec = con.execute(
        "SELECT id, canon_key, n_members, source_file, best_name FROM logical_function WHERE id=?",
        (logical_id,),
    ).fetchone()
    if rec is None:
        con.close()
        return _shell("Logical", "dashboard", "<h1>Not found</h1>"), 404
    members = list(
        con.execute(
            """SELECT b.slug, i.addr, i.confidence, i.method, f.name
                 FROM identity i
                 JOIN binary b ON b.id=i.binary_id
                 LEFT JOIN func f ON f.binary_id=i.binary_id AND f.addr=i.addr
                WHERE i.logical_id=? ORDER BY b.slug""",
            (logical_id,),
        )
    )
    con.close()
    rows = "".join(
        f"<tr><td><a href=\"/dashboard/binary/{quote(r['slug'], safe='')}\">{html.escape(r['slug'])}</a></td>"
        f"<td><a href=\"/dashboard/function/{quote(r['slug'], safe='')}/0x{int(r['addr']):x}\">"
        f"0x{int(r['addr']):x}</a></td>"
        f"<td>{html.escape(str(r['name'] or ''))}</td>"
        f"<td>{r['confidence'] if r['confidence'] is not None else ''}</td>"
        f"<td>{html.escape(str(r['method'] or ''))}</td></tr>"
        for r in members
    )
    body = f"""
<h1>Logical {logical_id}</h1>
<p class="sub"><a href="/dashboard/logical">Back</a> ·
<a href="/dashboard/functions?logical_id={logical_id}#graph">Graph</a></p>
<p>canon <code>{html.escape(str(rec['canon_key'] or ''))}</code> ·
name <code>{html.escape(str(rec['best_name'] or ''))}</code> ·
source <code>{html.escape(str(rec['source_file'] or ''))}</code></p>
<table><thead><tr><th>binary</th><th>addr</th><th>name</th><th>confidence</th><th>method</th></tr></thead>
<tbody>{rows or '<tr><td colspan=5>none</td></tr>'}</tbody></table>
"""
    return _shell("Logical", "dashboard", body), 200


def render_graph(*, store_path: Path | None, slug: str | None, addr: int | None) -> str:
    if store_path is None or not store_path.is_file():
        return _shell("Graph", "dashboard", "<h1>Call graph</h1><p>No corpus store.</p>")
    con = store_connect(store_path)
    args: list[Any] = []
    where = ""
    if slug:
        where = "WHERE b.slug=?"
        args.append(slug)
    if addr is not None:
        where += (" AND " if where else "WHERE ") + "(e.caller_addr=? OR e.callee_addr=?)"
        args.extend([addr, addr])
    rows = list(
        con.execute(
            f"""SELECT b.slug, e.caller_addr, e.callee_addr
                  FROM calledge e JOIN binary b ON b.id=e.binary_id
                  {where}
                 ORDER BY b.slug, e.caller_addr LIMIT 200""",
            args,
        )
    )
    con.close()
    body_rows = "".join(
        f"<tr><td>{html.escape(r['slug'])}</td>"
        f"<td><a href=\"/dashboard/function/{quote(r['slug'], safe='')}/0x{int(r['caller_addr']):x}\">"
        f"0x{int(r['caller_addr']):x}</a></td>"
        f"<td><a href=\"/dashboard/function/{quote(r['slug'], safe='')}/0x{int(r['callee_addr']):x}\">"
        f"0x{int(r['callee_addr']):x}</a></td></tr>"
        for r in rows
    )
    body = f"""
<h1>Call graph</h1>
<p class="claim">{html.escape(CLAIM)}</p>
<p class="sub"><a href="/dashboard">Back</a></p>
<p class="sub">Edges from the store <code>calledge</code> table. A drawing is not a match.</p>
<table><thead><tr><th>binary</th><th>caller</th><th>callee</th></tr></thead>
<tbody>{body_rows or '<tr><td colspan=3>none</td></tr>'}</tbody></table>
"""
    return _shell("Call graph", "dashboard", body)


def render_review(*, store_path: Path | None, work_dir: Path | None) -> str:
    parts = [f"<h1>Review queue</h1><p class='claim'>{html.escape(CLAIM)}</p>"]
    if store_path and store_path.is_file():
        con = store_connect(store_path)
        rows = list(
            con.execute(
                "SELECT status, COUNT(*) n FROM match WHERE status NOT IN ('auto','verified') GROUP BY status"
            )
        )
        con.close()
        if rows:
            parts.append(
                "<table><thead><tr><th>status</th><th>count</th></tr></thead><tbody>"
                + "".join(f"<tr><td>{html.escape(r['status'] or '')}</td><td>{r['n']}</td></tr>" for r in rows)
                + "</tbody></table>"
            )
        else:
            parts.append("<p class='sub'>No unresolved match rows.</p>")
    if work_dir and work_dir.is_dir():
        files = sorted(work_dir.glob("sibling*.json*"))[:12]
        if files:
            items = "".join(
                f"<li><a href=\"/dashboard/artifact?p={quote(path.name)}\">{html.escape(path.name)}</a></li>"
                for path in files
            )
            parts.append(f"<h2>Sibling files</h2><ul>{items}</ul>")
    if len(parts) == 1:
        parts.append("<p class='sub'>Empty on purpose until the store or work dir has a queue.</p>")
    parts.append('<p class="sub"><a href="/dashboard">Back</a></p>')
    return _shell("Review", "dashboard", "".join(parts))


def render_artifact(*, work_dir: Path | None, rel: str) -> tuple[str, int]:
    if work_dir is None or not work_dir.is_dir():
        return _shell(
            "Artifact",
            "dashboard",
            "<h1>Artifacts</h1><p>Set AGENT_DECOMPILE_CORPUS_WORK_DIR to a run directory.</p>",
        ), 200
    dest = _confine(work_dir, rel) if rel else work_dir.resolve()
    if dest is None:
        return _shell("Artifact", "dashboard", "<h1>Refused</h1><p>Path is outside the work directory.</p>"), 403
    if dest.is_dir():
        entries = sorted(dest.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
        rows = "".join(
            f"<tr><td><a href=\"/dashboard/artifact?p={quote(str(entry.relative_to(work_dir.resolve())))}\">"
            f"{html.escape(entry.name)}{'/' if entry.is_dir() else ''}</a></td>"
            f"<td>{entry.stat().st_size if entry.is_file() else ''}</td></tr>"
            for entry in entries[:400]
        )
        body = f"""
<h1>Artifacts</h1>
<p class="sub"><a href="/dashboard">Back</a> · listing <code>{html.escape(str(dest.relative_to(work_dir.resolve()) if dest != work_dir.resolve() else '.'))}</code></p>
<table><thead><tr><th>name</th><th>bytes</th></tr></thead>
<tbody>{rows or '<tr><td colspan=2>empty</td></tr>'}</tbody></table>
"""
        return _shell("Artifacts", "dashboard", body), 200
    if not dest.is_file():
        return _shell("Artifact", "dashboard", "<h1>Not found</h1>"), 404
    size = dest.stat().st_size
    if size > ARTIFACT_CAP:
        return _shell(
            "Artifact",
            "dashboard",
            f"<h1>{html.escape(dest.name)}</h1><p>File is {size} bytes; cap is {ARTIFACT_CAP}.</p>",
        ), 413
    text = dest.read_text(encoding="utf-8", errors="replace")
    body = f"""
<h1>{html.escape(dest.name)}</h1>
<p class="sub"><a href="/dashboard/artifact">Up</a></p>
<pre>{html.escape(text)}</pre>
"""
    return _shell(dest.name, "dashboard", body), 200


_ATLAS: AtlasServerState | None = None


def _atlas_state() -> AtlasServerState | None:
    global _ATLAS
    root = _env_path("AGENT_DECOMPILE_ATLAS_PROJECT_ROOT")
    if root is None:
        return None
    prompts = _env_path("AGENT_DECOMPILE_ATLAS_PROMPTS_DIR") or (root / "prompts")
    platform = (os.environ.get("AGENT_DECOMPILE_ATLAS_PLATFORM") or "unknown").strip()
    map_file = _env_path("AGENT_DECOMPILE_ATLAS_MAP_FILE")
    if (
        _ATLAS is None
        or _ATLAS.project_root != root
        or _ATLAS.prompts_dir != prompts
        or _ATLAS.map_file_path != map_file
    ):
        _ATLAS = AtlasServerState(
            project_root=root, prompts_dir=prompts, platform=platform, map_file_path=map_file
        )
    elif platform and platform != "unknown":
        _ATLAS.platform = platform
    return _ATLAS


def _json_pair(payload: dict[str, Any], status: int) -> JSONResponse:
    return JSONResponse(payload, status_code=status)


def _wrap_dashboard(body: str, status: int = 200, title: str | None = None) -> HTMLResponse:
    page = body if "<!doctype html>" in body[:80].lower() else dashboard_render_page(body, title or WORKSPACE_NAME)
    return HTMLResponse(page, status_code=status)


def create_unified_router() -> APIRouter:
    router = APIRouter(tags=["pages"])
    router.include_router(create_dashboard_router())

    def store_path() -> Path | None:
        return _env_path("AGENT_DECOMPILE_CORPUS_DB")

    def work_dir() -> Path | None:
        return _env_path("AGENT_DECOMPILE_CORPUS_WORK_DIR")

    @router.get("/app")
    async def app_hub() -> RedirectResponse:
        return RedirectResponse("/dashboard", status_code=302)

    @router.get("/healthz")
    async def root_healthz() -> dict[str, Any]:
        return {"ok": True, "service": "agentdecompile-pages", "pages": PAGE_PATHS}

    @router.get("/functions", include_in_schema=False)
    async def functions_alias(request: Request) -> HTMLResponse:
        query = query_from_mapping(request.query_params)
        body, status = render_functions_page(query)
        if is_partial_query(query):
            return HTMLResponse(body, status_code=status)
        return _wrap_dashboard(body, status, f"Functions — {WORKSPACE_NAME}")

    @router.get("/logical", include_in_schema=False)
    async def logical_alias() -> RedirectResponse:
        return RedirectResponse("/dashboard/functions#logical", status_code=302)

    @router.get("/logical/{logical_id}", include_in_schema=False)
    async def logical_one_alias(logical_id: int) -> HTMLResponse:
        body, status = render_logical_page(str(logical_id))
        return _wrap_dashboard(body, status, f"Logical function — {WORKSPACE_NAME}")

    @router.get("/binary/{slug}", include_in_schema=False)
    async def binary_alias(slug: str) -> HTMLResponse:
        body, status = render_binary_page(slug)
        return _wrap_dashboard(body, status, f"{slug} — {WORKSPACE_NAME}")

    @router.get("/function/{slug}/{addr}", include_in_schema=False)
    async def function_alias(slug: str, addr: str, request: Request) -> HTMLResponse:
        body, status = render_function_page(slug, addr, query_from_mapping(request.query_params))
        return _wrap_dashboard(body, status, f"Function — {WORKSPACE_NAME}")

    @router.get("/graph", include_in_schema=False)
    async def graph_alias(request: Request) -> RedirectResponse:
        return RedirectResponse(
            graph_to_function_target(query_from_mapping(request.query_params)),
            status_code=302,
        )

    @router.get("/function-open", include_in_schema=False)
    async def function_open_alias(request: Request) -> RedirectResponse:
        return RedirectResponse(
            graph_to_function_target(query_from_mapping(request.query_params)),
            status_code=302,
        )

    @router.get("/review", include_in_schema=False)
    async def review_alias(request: Request) -> RedirectResponse:
        qs = str(request.query_params)
        target = "/dashboard/functions"
        if qs:
            target += f"?{qs}"
        return RedirectResponse(f"{target}#review", status_code=302)

    @router.get("/artifact", include_in_schema=False)
    async def artifact_alias(request: Request) -> HTMLResponse:
        body, status = dashboard_render_artifact(query_from_mapping(request.query_params))
        return _wrap_dashboard(body, status, "Artifact")

    @router.get("/builds", include_in_schema=False)
    async def builds_alias() -> RedirectResponse:
        return RedirectResponse("/dashboard/functions#builds", status_code=302)

    @router.get("/recovery", include_in_schema=False)
    async def recovery_alias() -> RedirectResponse:
        return RedirectResponse("/dashboard#recovery", status_code=302)

    @router.get("/atlas", response_class=HTMLResponse)
    async def atlas() -> str:
        return atlas_ui_html("/atlas/api")

    @router.post("/atlas/api/loadProject")
    async def atlas_load() -> JSONResponse:
        state = _atlas_state()
        if state is None:
            return _json_pair({"error": "Set AGENT_DECOMPILE_ATLAS_PROJECT_ROOT"}, 404)
        payload, status = handle_load_project(state)
        return _json_pair(payload, status)

    @router.post("/atlas/api/buildPrompt")
    async def atlas_build(request: Request) -> JSONResponse:
        state = _atlas_state()
        if state is None:
            return _json_pair({"error": "Set AGENT_DECOMPILE_ATLAS_PROJECT_ROOT"}, 404)
        body = await request.json()
        payload, status = handle_build_prompt(state, str(body.get("functionId") or ""))
        return _json_pair(payload, status)

    @router.post("/atlas/api/savePrompt")
    async def atlas_save(request: Request) -> JSONResponse:
        state = _atlas_state()
        if state is None:
            return _json_pair({"error": "Set AGENT_DECOMPILE_ATLAS_PROJECT_ROOT"}, 404)
        body = await request.json()
        payload, status = handle_save_prompt(
            state,
            function_name=str(body.get("functionName") or ""),
            prompt_content=str(body.get("promptContent") or ""),
            asm=str(body.get("asm") or ""),
        )
        return _json_pair(payload, status)

    @router.get("/report", response_class=HTMLResponse)
    async def report() -> HTMLResponse:
        html_path = _env_path("AGENT_DECOMPILE_REPORT_HTML")
        if html_path and html_path.is_file():
            return HTMLResponse(html_path.read_text(encoding="utf-8"))
        json_path = _env_path("AGENT_DECOMPILE_REPORT_JSON")
        if json_path and json_path.is_file():
            return HTMLResponse(html_report_text(read_json(json_path)))
        return HTMLResponse(render_store_report(store_path=store_path(), work_dir=work_dir()))

    return router


def mount_unified_pages(app: FastAPI) -> None:
    """Attach hub / dashboard / atlas / report to an existing FastAPI app."""
    app.include_router(create_unified_router())


def page_index() -> dict[str, str]:
    return dict(PAGE_PATHS)
