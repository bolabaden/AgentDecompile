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


_PLATFORM_DIRS = frozenset({
    "win32", "win64", "macos", "darwin",
    "linux-x86", "linux-x64", "linux-arm64", "linux-armhf", "linux-aarch64",
})


def _slug_from_disk_path(path: Path, requested: str) -> str:
    base = (requested or path.stem or path.name or "binary").strip() or "binary"
    if base == path.name and path.suffix:
        base = path.stem or base
    platform = ""
    for part in reversed(path.parts[:-1]):
        key = part.lower()
        if key in _PLATFORM_DIRS:
            platform = key
            break
    if not platform:
        return base
    lower = base.lower()
    if lower.endswith("-" + platform):
        return base
    if platform.startswith("linux-") and lower.endswith("-linux"):
        base = base[: -len("-linux")]
    elif platform.startswith("win") and lower.endswith("-win"):
        base = base[: -len("-win")]
    return f"{base}-{platform}"


def _unique_binary_slug(con, desired: str) -> str:
    base = (desired or "binary").strip() or "binary"
    taken = {str(row[0]) for row in con.execute("SELECT slug FROM binary").fetchall() if row and row[0]}
    if base not in taken:
        return base
    index = 2
    while f"{base}-{index}" in taken:
        index += 1
    return f"{base}-{index}"


def register_path_binary(
    path: str,
    *,
    slug: str = "",
    role: str = "member",
    label: str = "",
    url: str = "",
) -> dict[str, Any]:
    from agentdecompile_recovery.corpus.ghidra_project import classify_locator

    raw = (url or path or "").strip()
    info = classify_locator(raw)
    kind = str(info.get("kind") or "")
    if kind == "empty":
        return {"ok": False, "error": str(info.get("error") or "path is not a readable file")}
    if kind == "shared-project":
        repo = str(info.get("locator") or raw)
        name = (slug or str(info.get("slug") or "shared")).strip()
    elif kind == "shared-fs":
        repo = str(info.get("locator") or raw)
        name = (slug or str(info.get("slug") or Path(repo).name)).strip()
    elif kind == "ghidra-project":
        gpr = info.get("gpr")
        src = Path(gpr) if gpr else Path(str(info.get("path") or raw))
        repo = str(src.resolve())
        name = (slug or src.stem).strip()
    else:
        src = Path(str(info.get("path") or raw)).expanduser()
        if not src.is_file():
            return {"ok": False, "error": "path is not a readable file"}
        repo = str(src.resolve())
        name = (slug or src.name).strip()
    if not name:
        return {"ok": False, "error": "slug is required"}
    if kind == "binary" or kind not in ("shared-project", "shared-fs", "ghidra-project"):
        # An explicitly requested slug is the caller's key for every later call
        # (DELETE/PATCH/select), so it is kept verbatim. Only derive a slug — including
        # the platform suffix that keeps sibling builds apart — when none was requested.
        name = name if slug else _slug_from_disk_path(Path(repo), "")
    con, err = _open_store()
    if err:
        return err
    try:
        existing = con.execute("SELECT slug FROM binary WHERE repo_path=?", (repo,)).fetchone()
        if existing is None:
            name = _unique_binary_slug(con, name)
        elif slug:
            clash = con.execute(
                "SELECT repo_path FROM binary WHERE slug=? AND repo_path!=?",
                (name, repo),
            ).fetchone()
            if clash:
                name = _unique_binary_slug(con, name)
        else:
            name = existing[0]
        con.execute(
            """INSERT INTO binary(repo_path, slug, role, variant)
               VALUES(?,?,?,?)
               ON CONFLICT(repo_path) DO UPDATE SET
                 slug=excluded.slug, role=excluded.role, variant=excluded.variant""",
            (repo, name, role or "member", label or None),
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
    if Path(base).suffix.lower() == ".gpr":
        return {
            "ok": False,
            "error": "A Ghidra project is Name.gpr plus a sibling Name.rep. Register the project path; do not upload the .gpr file.",
        }
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
        "SELECT slug, repo_path, role, variant, func_count, named_count, game, platform "
        "FROM binary ORDER BY slug"
    )
    binaries: list[dict[str, Any]] = []
    if err:
        return {"ok": False, "error": err, "binaries": []}
    from agentdecompile_recovery.corpus.ghidra_project import describe_source

    for slug, repo, role, variant, funcs, named, game, platform in rows:
        total = int(funcs or 0)
        source = describe_source(repo or "")
        binaries.append(
            {
                "slug": slug,
                "repo": repo or "",
                "program": repo or slug,
                "role": role or "",
                "label": variant or "",
                "funcs": total,
                "named": int(named or 0),
                "game": game or "",
                "platform": platform or "",
                "kind": source.get("kind") or "binary",
                "programs": source.get("programs") or [],
                "locator": source.get("locator") or repo or "",
                "decomp": decomp_rollup(str(slug), total),
                "validate": validate_rollup(str(slug), total),
            }
        )
    return {"ok": True, "binaries": binaries, "recovered": str(recovered_root() or "")}


def browse_sources(path: str = "") -> dict[str, Any]:
    from agentdecompile_recovery.corpus.ghidra_project import browse_path

    return browse_path(path, work_dir=live_root())


def classify_source(locator: str) -> dict[str, Any]:
    from agentdecompile_recovery.corpus.ghidra_project import classify_locator

    info = classify_locator(locator)
    info = dict(info)
    gpr = info.get("gpr")
    if isinstance(gpr, Path):
        info["gpr"] = str(gpr)
    return {"ok": info.get("kind") not in (None, "", "empty"), **info}


def ghidra_shared_defaults() -> dict[str, Any]:
    from agentdecompile_recovery.corpus.ghidra_project import shared_defaults

    return {"ok": True, **shared_defaults()}


def inspect_source(locator: str) -> dict[str, Any]:
    from agentdecompile_recovery.corpus.ghidra_project import inspect_locator

    info = inspect_locator(locator)
    gpr = info.get("gpr")
    if hasattr(gpr, "as_posix"):
        info["gpr"] = str(gpr)
    return info


def stage_dropped_files(files: list[tuple[str, bytes]]) -> dict[str, Any]:
    from agentdecompile_recovery.corpus.ghidra_project import stage_drop_files

    root = live_root()
    if root is None:
        return {"ok": False, "error": "AGENT_DECOMPILE_CORPUS_WORK_DIR is unset"}
    return stage_drop_files(root, files)


def resolve_dropped_source(
    name: str = "",
    relative_paths: list[str] | None = None,
    staging_id: str = "",
) -> dict[str, Any]:
    from agentdecompile_recovery.corpus.ghidra_project import resolve_drop

    root = live_root()
    staging_root = None
    if staging_id and root is not None:
        staging_root = root / "drop-staging" / staging_id
    return resolve_drop(
        name=name,
        relative_paths=relative_paths,
        work_dir=root,
        staging_root=staging_root,
    )


def create_ghidra_project(name: str) -> dict[str, Any]:
    from agentdecompile_recovery.corpus.ghidra_project import create_local_project

    root = live_root()
    if root is None:
        return {"ok": False, "error": "AGENT_DECOMPILE_CORPUS_WORK_DIR is unset"}
    return create_local_project(name, work_dir=root)


def save_current_project(locator: str) -> dict[str, Any]:
    from agentdecompile_recovery.corpus.ghidra_project import save_project

    root = live_root()
    if root is None:
        return {"ok": False, "error": "AGENT_DECOMPILE_CORPUS_WORK_DIR is unset"}
    return save_project(locator, work_dir=root)


def save_project_as_kind(
    locator: str,
    *,
    target: str,
    name: str = "",
    dest: str = "",
    url: str = "",
) -> dict[str, Any]:
    from agentdecompile_recovery.corpus.ghidra_project import save_project_as

    root = live_root()
    if root is None:
        return {"ok": False, "error": "AGENT_DECOMPILE_CORPUS_WORK_DIR is unset"}
    return save_project_as(
        locator,
        target=target,
        name=name,
        dest=dest,
        url=url,
        work_dir=root,
    )


def list_sessions() -> dict[str, Any]:
    from agentdecompile_recovery.corpus.ghidra_project import ensure_draft_session

    return ensure_draft_session(live_root())


def write_sessions(payload: dict[str, Any]) -> dict[str, Any]:
    from agentdecompile_recovery.corpus.ghidra_project import fresh_draft_session, save_sessions_merged

    sessions = list((payload or {}).get("sessions") or [])
    if not sessions:
        return fresh_draft_session(live_root())
    return save_sessions_merged(live_root(), payload)


def list_functions(
    slug: str,
    *,
    q: str = "",
    offset: int = 0,
    limit: int = 80,
    program: str = "",
    bsim_url: str = "",
) -> dict[str, Any]:
    slug = (slug or "").strip()
    program = (program or "").strip()
    if not slug and not program:
        return {"ok": False, "error": "pick a binary", "results": [], "total": 0}
    if not slug:
        return _list_functions_from_bsim(program, q=q, offset=offset, limit=limit, bsim_url=bsim_url)
    rows, err = query_db(
        "SELECT id, bits FROM binary WHERE slug=? LIMIT 1",
        (slug,),
    )
    if err:
        return {"ok": False, "error": err, "results": [], "total": 0}
    if not rows:
        if program:
            return _list_functions_from_bsim(program, q=q, offset=offset, limit=limit, bsim_url=bsim_url)
        return {"ok": False, "error": f"no build called {slug}", "results": [], "total": 0}
    bid, bits = rows[0][0], rows[0][1] or 32
    cap = max(1, min(int(limit or 80), 200))
    start = max(0, int(offset or 0))
    from agentdecompile_recovery.corpus.dashboard.common import table_exists

    if table_exists("logical_name"):
        name_expr = (
            "COALESCE((SELECT ln.name FROM identity ni "
            "JOIN logical_name ln ON ln.logical_id=ni.logical_id "
            "WHERE ni.binary_id=f.binary_id AND ni.addr=f.addr "
            "ORDER BY ni.confidence DESC LIMIT 1), f.name, '')"
        )
    else:
        name_expr = "COALESCE(f.name, '')"
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
    if not results and program:
        bsim_listed = _list_functions_from_bsim(
            program, q=q, offset=offset, limit=limit, bsim_url=bsim_url,
        )
        if bsim_listed.get("results"):
            return bsim_listed
        return {
            "ok": True,
            "slug": slug,
            "program": program,
            "q": needle,
            "offset": start,
            "limit": cap,
            "total": 0,
            "results": [],
            "hasMore": False,
            "source": "ghidra-program",
            "next": "bsim-ingest",
            "error": (
                f"{program} is a Ghidra program. Ingest the repository into BSim "
                "(Analyze → Ingest repository into BSim) to list functions here."
            ),
        }
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


def _list_functions_from_bsim(
    program: str,
    *,
    q: str = "",
    offset: int = 0,
    limit: int = 80,
    bsim_url: str = "",
) -> dict[str, Any]:
    from agentdecompile_recovery.corpus import bsim_ops as bo

    listed = bo.list_program_functions(
        program,
        bsim_url=bsim_url,
        offset=offset,
        limit=limit,
    )
    if not listed.get("ok"):
        return {
            "ok": True,
            "program": program,
            "q": q,
            "offset": offset,
            "limit": limit,
            "total": 0,
            "results": [],
            "hasMore": False,
            "source": "bsim",
            "next": "bsim-ingest",
            "error": listed.get("error")
            or (
                f"{program} has no BSim functions yet. "
                "Analyze → Ingest repository into BSim, then Refresh."
            ),
        }
    needle = (q or "").strip().lower()
    rows = listed.get("results") or []
    if needle:
        rows = [
            row for row in rows
            if needle in str(row.get("name") or "").lower() or needle in str(row.get("addr") or "").lower()
        ]
        listed = dict(listed)
        listed["results"] = rows
        listed["total"] = len(rows)
        listed["hasMore"] = False
        listed["q"] = q
    return listed


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
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='8' fill='%23d07a3a'/%3E%3Ctext x='16' y='21' text-anchor='middle' font-size='13' font-family='ui-sans-serif,system-ui,sans-serif' font-weight='800' fill='%231a120c'%3EAD%3C/text%3E%3C/svg%3E">
<link rel="stylesheet" href="/dashboard/static/dashboard.css">
<link rel="stylesheet" href="/dashboard/static/workbench.css?v=onepage1">
<link rel="stylesheet" href="/dashboard/static/workbench-tokens.css?v=onepage1">
<link rel="stylesheet" href="/dashboard/static/workbench-controls.css?v=onepage1">
<link rel="stylesheet" href="/dashboard/static/workbench-chrome.css?v=onepage1">
<link rel="stylesheet" href="/dashboard/static/workbench-sidebar.css?v=instrument1">
<link rel="stylesheet" href="/dashboard/static/workbench-editor.css?v=instrument1">
<link rel="stylesheet" href="/dashboard/static/workbench-dialogs.css?v=onepage1">
<link rel="stylesheet" href="/dashboard/static/workbench-overlays.css?v=onepage1">
</head>
<body class="workbench-page">
<div id="page-context" hidden data-page="home" data-atlas-api="/atlas/api"></div>
<div id="wb-root">
  <div class="wb">
    <a class="skip-link" href="#wb-functions">Skip to functions</a>
    <div class="wb-chrome">
    <header class="wb-toolbar">
      <div class="wb-brand">
        <span class="wb-mark" aria-hidden="true">AD</span>
        <div>
          <strong>AgentDecompile</strong>
          <span class="wb-claim">Real C and a complete executable are separate facts.</span>
        </div>
      </div>
      <label class="wb-search">
        <span class="sr-only">Find a function or jump to a section</span>
        <input id="wb-q" type="search" placeholder="Function, 0xaddress, or section name" autocomplete="off">
      </label>
      <p class="wb-status-line">
        <a class="wb-link" href="/docs">Docs</a>
        <span id="job-pulse">no jobs</span>
      </p>
    </header>
    <nav id="wb-menubar" class="wb-menubar" aria-label="Application">
      <button type="button" class="wb-menu-btn">File</button>
      <button type="button" class="wb-menu-btn">Edit</button>
      <button type="button" class="wb-menu-btn">View</button>
      <button type="button" class="wb-menu-btn">Help</button>
    </nav>
    <div id="wb-sessions" class="wb-sessions" role="tablist" aria-label="Open projects">
      <button type="button" id="wb-tab-new" class="wb-tab-new">New tab</button>
    </div>
    </div>
    <main id="app">
    <section id="wb-ingest" class="wb-surface">
      <h2>Open a project</h2>
      <div id="wb-drop" class="wb-drop" tabindex="0">Drop binaries here
        <span class="wb-drop-sub">PE/ELF, a .gpr, a .rep folder, or a shared-server repos folder</span>
        <input id="wb-bin-file" type="file" multiple hidden>
        <input id="wb-bin-folder" type="file" webkitdirectory hidden>
      </div>
      <button type="button" id="wb-bin-add" class="wb-btn wb-btn-primary">New local project</button>
      <label class="wb-file-label">Project folder</label>
      <div id="wb-browse" class="wb-browse"></div>
      <form id="wb-shared-form" class="wb-bin-form">
        <label>Host <input id="wb-shared-host"></label>
        <label>Port <input id="wb-shared-port" placeholder="13100"></label>
        <label>Repository <input id="wb-shared-repo"></label>
        <label>Program <input id="wb-shared-program"></label>
        <label>URL <input id="wb-shared-url" placeholder="ghidra://host:13100/repo"></label>
        <button type="submit" id="wb-shared-add">Open HTTP server</button>
      </form>
      <div id="wb-dossier"></div>
      <form id="wb-save-as" class="wb-save-as"></form>
      <div id="wb-sources">
        <h3>Sources</h3>
        <ul id="wb-binary-list">{binary_html}</ul>
      </div>
    </section>
    <div class="wb-workspace">
      <section id="wb-functions" class="wb-surface">
        <h2 id="function-list">Functions</h2>
        <span id="wb-func-meta"></span>
        <div id="wb-func-window" class="wb-func-window" tabindex="0"></div>
      </section>
      <section id="wb-inspect" class="wb-surface">
        <h2>Inspector</h2>
        <div id="wb-inspect-body"><p class="wb-hint">Select a function to decompile, rename, and match siblings.</p></div>
      </section>
      <section id="wb-graph" class="wb-surface">
        <h2>Call graph</h2>
        <p class="wb-hint">Select a function to open the call graph.</p>
      </section>
    </div>
    <section id="wb-jobs" class="wb-surface"><h2>Jobs</h2><ul id="action-jobs"><li>no jobs</li></ul></section>
    <section id="wb-atlas" class="wb-surface"><h2>Atlas</h2></section>
    <section id="wb-report" class="wb-surface"><h2>Report</h2></section>
    <section id="wb-fnbrowse" class="wb-surface"><h2>Functions</h2></section>
    <section id="wb-logical" class="wb-surface"><h2>Logical identities</h2></section>
    <section id="wb-review" class="wb-surface">
      <h2>Review</h2>
      <section id="wb-artifacts"><h3>Artifacts</h3></section>
    </section>
    <section id="wb-pipeline" class="wb-surface"><h2>Pipeline</h2></section>
    <section id="wb-match" class="wb-surface"><h2>Cross-match</h2></section>
    <section id="wb-recovery" class="wb-surface"><h2>Recovery</h2></section>
    <section id="wb-stabs" class="wb-surface"><h2>STABS</h2></section>
    <section id="wb-knowledge" class="wb-surface"><h2>Knowledge</h2></section>
    <section id="wb-roundtrip" class="wb-surface"><h2>Roundtrip</h2></section>
    <section id="wb-processes" class="wb-surface"><h2>Process log</h2></section>
    <section id="wb-mission" class="wb-surface"><h2>Mission</h2></section>
    <section id="wb-corpus" class="wb-surface"><h2>Corpus table</h2></section>
    <section id="wb-tools" class="wb-surface"><h2>Commands</h2></section>
    </main>
    <footer class="wb-status" id="wb-status">
      <span id="wb-status-source">No source selected</span>
      <span id="wb-status-kind"></span>
      <a class="wb-link" href="/dashboard/overview-corpus">Full corpus overview</a>
    </footer>
  </div>
</div>
<noscript>
  <p>JavaScript is off. Use <a href="/dashboard/overview-corpus">full corpus overview</a>,
  <a href="/dashboard/browse-block?block=functions">functions</a>, or <a href="/docs">Docs</a>.</p>
</noscript>
<script src="/dashboard/static/react.js"></script>
<script src="/dashboard/static/react-dom.js"></script>
<script src="/dashboard/static/htm.js"></script>
<script src="/dashboard/static/dashboard.js" defer></script>
<script src="/dashboard/static/workbench-app.js?v=instrument1" defer></script>
</body>
</html>
"""
