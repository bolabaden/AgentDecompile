"""One-page AgentDecompile workbench: binaries, functions, tools, live jobs."""

from __future__ import annotations

import os
import hashlib
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from agentdecompile_recovery.corpus.dashboard.common import (
    as_root,
    format_address,
    live_db,
    live_root,
    page_window,
    parse_address,
    query_db,
)
from agentdecompile_recovery.corpus.dashboard.pages import WORKSPACE_NAME, esc

_CACHE: dict[str, tuple[float, Any]] = {}
_CACHE_TTL = 8.0
_STORE_CACHE_TTL = 45.0
_REGISTRATION_LOCK = threading.RLock()


def _cached(key: str, fn):
    now = time.time()
    hit = _CACHE.get(key)
    if hit and now - hit[0] < _CACHE_TTL:
        return hit[1]
    value = fn()
    _CACHE[key] = (now, value)
    return value


def _bsim_datadir() -> Path:
    """Preferred BSim datadir. Missing path is a reportable state, not a corpus."""
    for key in ("GHIDRA_BSIM_DATADIR", "AGENT_DECOMPILE_BSIM_DATADIR"):
        raw = (os.environ.get(key) or "").strip()
        if raw:
            return Path(raw).expanduser()
    home = Path.home()
    candidates = [
        home / "biodecompwarehouse" / "bsim_datadir",
        Path(os.environ.get("AGENT_DECOMPILE_CORPUS_WORK_DIR") or "").expanduser() / "bsim_datadir",
        as_root() / "bsim_datadir",
    ]
    for cand in candidates:
        if cand and str(cand) != "bsim_datadir" and cand.is_dir():
            return cand
    return candidates[0]


def match_status() -> dict[str, Any]:
    """Honest BSim/match state for the Match pane. Never invents a populated corpus."""
    from agentdecompile_recovery.corpus import bsim_ops as bo

    datadir = _bsim_datadir()
    try:
        payload = bo.report(datadir=datadir)
    except Exception as exc:
        return {
            "ok": True,
            "state": "database_unreachable",
            "summary": str(exc)[:400],
            "datadir": str(datadir),
            "executables": 0,
            "exes": [],
        }
    payload["datadir"] = str(datadir)
    return payload


def recover_status(*, program: str = "", slug: str = "") -> dict[str, Any]:
    """Recovered-source tree for the Recover pane. Empty is a first-class state."""
    root = recovered_root(slug=slug, program=program)
    if root is None:
        return {
            "ok": True,
            "state": "none",
            "summary": "No recovered source tree yet.",
            "path": "",
            "files": [],
            "count": 0,
            "leftoverCount": 0,
            "program": program,
            "slug": slug,
        }
    files: list[str] = []
    try:
        for path in root.rglob("*.c"):
            try:
                files.append(str(path.relative_to(root)))
            except ValueError:
                files.append(str(path))
            if len(files) >= 24:
                break
    except OSError:
        pass
    from agentdecompile_recovery.corpus.leftover import count_leftovers

    leftover_n = count_leftovers(root)
    return {
        "ok": True,
        "state": "present" if files else "empty_tree",
        "summary": (
            f"{len(files)} C files under recovered source"
            if files
            else "Recovered directory exists but has no C files yet."
        ),
        "path": str(root),
        "files": files,
        "count": len(files),
        "leftoverCount": leftover_n,
        "program": program,
        "slug": slug,
    }


def recovered_root(*, slug: str = "", program: str = "") -> Path | None:
    raw = (os.environ.get("AGENT_DECOMPILE_RECOVERED_DIR") or "").strip()
    if raw:
        path = Path(raw)
        return path if path.is_dir() else None
    root = live_root()
    if root is None:
        return None
    # Per-program cross-placed trees win over the shared parent directory.
    if slug or program:
        keys: list[str] = []
        for key in (program, slug):
            key = (key or "").strip()
            if key and key not in keys:
                keys.append(key)
            if key and "__" in key:
                stripped = key.split("__", 1)[-1]
                if stripped and stripped not in keys:
                    keys.append(stripped)
        for base in (
            root / "data" / "mizuchi_home" / "recovered-source-ghidra",
            as_root() / "data" / "mizuchi_home" / "recovered-source-ghidra",
        ):
            for key in keys:
                targeted = base / Path(key).name
                if targeted.is_dir():
                    return targeted
    for cand in (
        root / "dump-source",
        root / "data" / "recovered-source-ghidra",
        root / "recovered-source-ghidra",
        as_root() / "data" / "recovered-source-ghidra",
        root / "data" / "mizuchi_home" / "recovered-source-ghidra",
        as_root() / "data" / "mizuchi_home" / "recovered-source-ghidra",
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
    from agentdecompile_recovery.corpus.source_claims import is_machine_code_shim
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "none"
    if not source.strip():
        return "none"
    # Use the recovery pipeline's claim classifier across the whole function.
    # A long preamble must not hide emitted bytes or assembly near the end.
    return "asm" if "compile-only-asm" in source or is_machine_code_shim(source) else "c"


def _signature_from_unit(unit: Path | None) -> str:
    if unit is None:
        return ""
    try:
        text = unit.read_text(encoding="utf-8", errors="replace")[:800]
    except OSError:
        return ""
    for line in text.splitlines():
        snippet = line.strip()
        if not snippet or snippet.startswith(("//", "/*", "*", "#", "{")):
            continue
        if "(" in snippet and ")" in snippet:
            return snippet[:200]
    return ""


def _decompile_payload(slug: str, addr: int, name: str) -> dict[str, Any]:
    unit = _find_unit(slug, addr, name) if slug else None
    text = ""
    if unit is not None:
        try:
            with unit.open(encoding="utf-8", errors="replace") as stream:
                text = stream.read(8001)
        except OSError:
            text = ""
    return {
        "text": text[:8000],
        "truncated": len(text) > 8000,
        "characterLimit": 8000,
        "source": "recovered" if text else "none",
        "path": str(unit) if unit else "",
        "signature": _signature_from_unit(unit),
    }


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
    """Inventory scoped object artifacts without promoting them to function proof."""
    objs = obj_root()
    scoped = (objs / slug) if objs is not None else None
    if objs is not None and objs.name == slug:
        scoped = objs
    count = None
    if scoped is not None and scoped.is_dir():
        try:
            count = sum(1 for p in scoped.rglob("*") if p.suffix in {".obj", ".o"})
        except OSError:
            pass
    return {"none": total, "obj": None, "linked": None, "objects": count,
            "measured": False, "reason": "Object files alone do not establish per-function compilation or byte verification."}


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
    for row in [*(listed.get("binaries") or []), *(listed.get("unresolvedBinaries") or [])]:
        if row.get("slug") == slug or slug in row.get("aliasSlugs", []):
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


def register_path_binary(path: str, *, slug: str = "", role: str = "member", label: str = "", url: str = "") -> dict[str, Any]:
    with _REGISTRATION_LOCK:
        return _register_path_binary(path, slug=slug, role=role, label=label, url=url)


def _register_path_binary(
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
        from .library_identity import binary_sha256
        is_binary = kind not in ("shared-project", "shared-fs", "ghidra-project")
        digest = binary_sha256(repo) if is_binary else ""
        if is_binary and not digest:
            return {"ok": False, "error": "Cannot confirm binary identity. The source must remain readable and unchanged during hashing."}
        con.execute("CREATE TABLE IF NOT EXISTS binary_content_identity (source_path TEXT PRIMARY KEY, sha256 TEXT NOT NULL)")
        previous_identity = con.execute("SELECT sha256 FROM binary_content_identity WHERE source_path=?", (repo,)).fetchone()
        if digest and previous_identity and previous_identity[0] != digest:
            return {"ok": False, "error": "This source path now contains different bytes. Register a separate preserved copy so existing evidence keeps its original identity."}
        if digest:
            con.execute("INSERT OR IGNORE INTO binary_content_identity VALUES(?,?)", (repo, digest))
        candidates = con.execute("SELECT slug,repo_path FROM binary ORDER BY COALESCE(func_count,0) DESC,id").fetchall()
        if digest:
            identical = next((item for item in candidates if binary_sha256(item[1] or "") == digest), None)
            if identical:
                name = identical[0]
                con.execute("CREATE TABLE IF NOT EXISTS binary_source_alias (source_path TEXT PRIMARY KEY, binary_slug TEXT NOT NULL, sha256 TEXT NOT NULL)")
                con.execute("INSERT INTO binary_source_alias VALUES(?,?,?) ON CONFLICT(source_path) DO UPDATE SET binary_slug=excluded.binary_slug,sha256=excluded.sha256", (repo, name, digest))
                con.commit()
                _CACHE.clear()
                return {"ok": True, "binary": _binary_row(name), "reused": True, "sha256": digest}
        existing = con.execute("SELECT slug FROM binary WHERE repo_path=?", (repo,)).fetchone()
        collision = next((item for item in candidates if item[0] == name and item[1] != repo), None)
        if collision and is_binary:
            prior_digest = binary_sha256(collision[1] or "")
            if not prior_digest:
                return {"ok": False, "error": "An entry with this name has unavailable bytes. Resolve its identity or choose an explicit distinct name before importing."}
            name = f"{name}-{digest}"
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
    dest_dir = dest_dir / hashlib.sha256(data).hexdigest()
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / base
    try:
        with dest.open("xb") as handle:
            handle.write(data)
    except FileExistsError:
        pass
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
    game: str | None = None,
    platform: str | None = None,
) -> dict[str, Any]:
    if any(value is not None and not isinstance(value, str) for value in (role, label, game, platform)):
        return {"ok": False, "error": "role, label, game, and platform must be strings"}
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
        if game is not None:
            con.execute("UPDATE binary SET game=? WHERE slug=?", (game.strip() or None, name))
        if platform is not None:
            con.execute("UPDATE binary SET platform=? WHERE slug=?", (platform.strip() or None, name))
        con.commit()
    finally:
        con.close()
    _CACHE.clear()
    listed = _binary_row(name)
    return {"ok": True, "binary": listed}


def record_import_bindings(payload: dict[str, Any]) -> None:
    """Persist the analyzed project location separately from original bytes."""
    locator = str((payload.get("projectContext") or {}).get("projectPath") or "")
    imported = payload.get("importedPrograms") or []
    if not locator or not imported:
        return
    con, error = _open_store()
    if error:
        return
    try:
        con.execute("CREATE TABLE IF NOT EXISTS program_binding (source_path TEXT NOT NULL, locator TEXT NOT NULL, program TEXT NOT NULL, updated REAL NOT NULL, PRIMARY KEY(source_path,locator))")
        for item in imported:
            source, program = item.get("sourcePath"), item.get("programPath")
            if source and program:
                con.execute("INSERT INTO program_binding VALUES(?,?,?,?) ON CONFLICT(source_path,locator) DO UPDATE SET program=excluded.program,updated=excluded.updated", (str(Path(source).resolve()), locator, program, time.time()))
        con.commit()
    finally:
        con.close()
    _CACHE.clear()


def list_binaries() -> dict[str, Any]:
    rows, err = query_db(
        "SELECT id, slug, repo_path, role, variant, func_count, named_count, game, platform "
        "FROM binary ORDER BY slug"
    )
    binaries: list[dict[str, Any]] = []
    if err:
        return {"ok": False, "error": err, "binaries": []}
    from agentdecompile_recovery.corpus.ghidra_project import describe_source

    bindings: dict[str, tuple[str, str]] = {}
    all_bindings: dict[str, list[dict[str, str]]] = {}
    binding_rows, _ = query_db("SELECT source_path,locator,program FROM program_binding ORDER BY updated DESC")
    for source_path, project_locator, project_program in binding_rows:
        bindings.setdefault(source_path, (project_locator, project_program))
        all_bindings.setdefault(source_path, []).append({"locator": project_locator, "program": project_program})

    for binary_id, slug, repo, role, variant, funcs, named, game, platform in rows:
        total = int(funcs or 0)
        source = describe_source(repo or "")
        binaries.append(
            {
                "id": int(binary_id),
                "slug": slug,
                "repo": repo or "",
                "program": bindings[repo][1] if repo in bindings else repo or slug,
                "role": role or "",
                "label": variant or "",
                "funcs": total,
                "named": int(named or 0),
                "game": game or "",
                "platform": platform or "",
                "kind": source.get("kind") or "binary",
                "programs": source.get("programs") or [],
                "locator": bindings[repo][0] if repo in bindings else source.get("locator") or repo or "",
                "imported": repo in bindings,
                "projectBindings": all_bindings.get(repo, []),
                "decomp": decomp_rollup(str(slug), total),
                "validate": validate_rollup(str(slug), total),
            }
        )
    from .library_identity import canonical_library
    canonical, unresolved = canonical_library(binaries)
    aliases, _ = query_db("SELECT source_path,binary_slug,sha256 FROM binary_source_alias")
    for row in canonical:
        for path, alias_slug, digest in aliases:
            if alias_slug in row["aliasSlugs"] and digest == row["sha256"]:
                if path not in row["sourcePaths"]:
                    row["sourcePaths"].append(path)
                for binding in all_bindings.get(path, []):
                    if binding not in row["projectBindings"]:
                        row["projectBindings"].append(binding)
    for row in canonical:
        if row["projectBindings"] and not row["imported"]:
            row.update(imported=True, locator=row["projectBindings"][0]["locator"], program=row["projectBindings"][0]["program"])
    from .protection import inspect_protection
    for row in canonical:
        row["protection"] = inspect_protection(row["repo"]) if row["kind"] == "binary" else {"status": "unknown", "encryption": "unknown", "drm": "unknown"}
    from .variant_groups import annotate_variant_groups
    canonical = annotate_variant_groups(canonical)
    from .library_identity import annotate_containers
    canonical = annotate_containers(canonical)
    return {"ok": True, "binaries": canonical, "unresolvedBinaries": unresolved, "recovered": str(recovered_root() or "")}


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
    import re

    from agentdecompile_recovery.corpus.ghidra_project import resolve_drop

    root = live_root()
    staging_root = None
    if staging_id:
        if not re.fullmatch(r"drop-[0-9]+", staging_id):
            return {"ok": False, "error": "invalid staging_id"}
        if root is None:
            return {"ok": False, "error": "AGENT_DECOMPILE_CORPUS_WORK_DIR is unset"}
        staging_root = root / "drop-staging" / staging_id
        try:
            if not staging_root.resolve().is_relative_to((root / "drop-staging").resolve()):
                return {"ok": False, "error": "invalid staging_id"}
        except OSError:
            return {"ok": False, "error": "invalid staging_id"}
    return resolve_drop(
        name=name,
        relative_paths=relative_paths,
        work_dir=root,
        staging_root=staging_root,
    )


def create_ghidra_project(name: str, destination: str = "") -> dict[str, Any]:
    from agentdecompile_recovery.corpus.ghidra_project import create_local_project

    root = live_root()
    if root is None:
        return {"ok": False, "error": "AGENT_DECOMPILE_CORPUS_WORK_DIR is unset"}
    if destination and not Path(destination).expanduser().is_absolute():
        return {"ok": False, "error": "Project destination must be an absolute server folder."}
    if destination:
        from agentdecompile_recovery.corpus.ghidra_project import _allowed_dest

        dest_path = Path(destination).expanduser()
        if not _allowed_dest(dest_path, root):
            return {"ok": False, "error": "Project destination must stay inside allowed corpus and project roots."}
    return create_local_project(name, work_dir=root, destination=Path(destination).expanduser() if destination else None)


def _destination_store_root(locator: str, *, hint: str = ""):
    from agentdecompile_recovery.corpus.ghidra_project import classify_locator
    from agentdecompile_recovery.ghidra_db.project import find_program, list_programs
    from agentdecompile_recovery.ghidra_db.store import store_roots, write_index_dat

    info = classify_locator(locator)
    kind = str(info.get("kind") or "")
    if kind == "ghidra-project":
        gpr = Path(str(info.get("gpr") or locator)).expanduser()
        versioned = gpr.with_suffix(".rep") / "versioned"
        versioned.mkdir(parents=True, exist_ok=True)
        if not (versioned / "~index.dat").exists():
            write_index_dat(versioned, [])
        return versioned
    roots = store_roots(locator)
    if not roots:
        raise ValueError(f"{locator}: not a Ghidra project or repository store")
    wanted = (hint or "").strip().rstrip("/")
    if wanted:
        for root in roots:
            if find_program(root, wanted) is not None:
                return root
    if len(roots) == 1:
        return roots[0]
    for root in roots:
        if list_programs(root):
            return root
    return roots[0]


def _mcp_imported_names(imported: dict[str, Any]) -> list[str]:
    names: list[str] = []
    parsed = imported.get("parsed")
    blobs: list[Any] = []
    if isinstance(parsed, dict):
        blobs.append(parsed)
        inner = parsed.get("result") or parsed.get("data")
        if isinstance(inner, dict):
            blobs.append(inner)
    for blob in blobs:
        for item in blob.get("importedPrograms") or []:
            if not isinstance(item, dict):
                continue
            for key in ("programName", "programPath"):
                raw = str(item.get(key) or "").replace("\\", "/").strip()
                if raw:
                    names.append(raw.rsplit("/", 1)[-1].lstrip("/"))
    seen: set[str] = set()
    out: list[str] = []
    for name in names:
        if name and name not in seen:
            seen.add(name)
            out.append(name)
    return out


def _add_project_locator(found: list[str], path: Path) -> None:
    try:
        path = path.expanduser().resolve()
    except OSError:
        return
    if path.is_file() and path.suffix.lower() == ".gpr":
        text = str(path)
        if text not in found:
            found.append(text)
        return
    if not path.is_dir():
        return
    text = str(path)
    if text not in found:
        found.append(text)
    for gpr in sorted(path.glob("*.gpr")):
        _add_project_locator(found, gpr)


def _live_project_locators() -> list[str]:
    found: list[str] = []
    for key in ("AGENT_DECOMPILE_PROJECT_PATH", "AGENTDECOMPILE_PROJECT_PATH"):
        raw = (os.environ.get(key) or "").strip()
        if raw:
            _add_project_locator(found, Path(raw))
    root = live_root()
    if root is not None:
        _add_project_locator(found, root / "ghidra-projects")
        _add_project_locator(found, root / "import-staging" / "ghidra-projects")
    _add_project_locator(found, Path.cwd() / "agentdecompile_projects")
    here = Path(__file__).resolve()
    for parent in here.parents:
        cand = parent / "agentdecompile_projects"
        if cand.is_dir():
            _add_project_locator(found, cand)
            break
    return found


def _unique_program_name(locator: str, wanted: str) -> str:
    from agentdecompile_recovery.ghidra_db.store import find_store_program

    name = (wanted or "").strip() or "binary"
    if find_store_program(locator, name) is None:
        return name
    stem, suffix = name, ""
    if "." in name and not name.startswith("."):
        stem, suffix = name.rsplit(".", 1)
        suffix = f".{suffix}"
    index = 2
    while True:
        candidate = f"{stem}-{index}{suffix}"
        if find_store_program(locator, candidate) is None:
            return candidate
        index += 1


def _find_imported_entry(locators: list[str], names: list[str]):
    from agentdecompile_recovery.ghidra_db.store import find_store_program, list_store_programs

    seen_loc: set[str] = set()
    wanted = [n for n in names if n]
    for loc in locators:
        text = (loc or "").strip()
        if not text or text in seen_loc:
            continue
        seen_loc.add(text)
        for name in wanted:
            hit = find_store_program(text, name)
            if hit is not None:
                return hit
        listed = list_store_programs(text)
        if len(listed) == 1 and wanted:
            only = listed[0]
            if only.name in wanted or only.project_path.rsplit("/", 1)[-1] in wanted:
                return only
    return None


def _place_imported(
    entry,
    dest_root,
    loc: str,
    dest_name: str,
    steps: list[dict[str, Any]],
    source: str,
    *,
    requested_name: str = "",
) -> dict[str, Any]:
    from agentdecompile_recovery.ghidra_db.store import copy_program_item, find_store_program, rebuild_index

    wanted = dest_name or entry.name
    requested = (requested_name or "").strip()
    if requested and wanted == requested:
        name = _unique_program_name(loc, entry.name or wanted)
    else:
        name = wanted
    already = find_store_program(loc, name)
    dest_abs = dest_root.resolve()
    in_dest = already is not None and dest_abs in already.property_file.resolve().parents
    if not in_dest:
        copy_program_item(entry, dest_root, dest_name=name)
        rebuild_index(dest_root)
    _CACHE.clear()
    return {
        "ok": True,
        "program": name if find_store_program(loc, name) else entry.name,
        "source": source,
        "steps": steps,
        "inspect": inspect_source(loc),
    }


def import_program_into_project(
    locator: str, *, path: str = "", program: str = "", name: str = "", analyze: bool = False,
) -> dict[str, Any]:
    """Keep project selection and import in the same Ghidra session transaction."""
    from .mcp_bridge import CONTEXT_LOCK

    from .protection import prepare_protected_binary
    from agentdecompile_recovery.corpus.ghidra_project import classify_locator

    with CONTEXT_LOCK:
        protection = None
        source_path = path
        if classify_locator(path).get("kind") == "binary":
            protection = prepare_protected_binary(path, live_root() or Path(path).parent)
            if protection.get("handling") == "blocked":
                return {"ok": False, "error": protection.get("reason") or protection.get("blocker") or "Protection handling is unavailable", "protection": protection}
            path = protection.get("analysisPath") or path
        result = _import_program_into_project(locator, path=path, program=program, name=name or (Path(source_path).name if path != source_path else ""), analyze=analyze)
        if protection:
            result["protection"] = protection
        if protection is not None and result.get("ok") and result.get("program"):
            record_import_bindings({"projectContext": {"projectPath": locator}, "importedPrograms": [{"sourcePath": source_path, "programPath": result["program"]}]})
        if result.get("ok"):
            from .preparation import inventory_changed
            try:
                result["preparation"] = inventory_changed(locator)
            except (OSError, ValueError) as exc:
                result["preparation"] = {"status": "blocked", "error": str(exc)}
        return result


def _import_program_into_project(
    locator: str,
    *,
    path: str = "",
    program: str = "",
    name: str = "",
    analyze: bool = False,
) -> dict[str, Any]:
    """Add a program to the open Ghidra project (item filesystem), not the corpus roster."""
    from agentdecompile_recovery.corpus.ghidra_project import classify_locator, ghidra_connect_args
    from agentdecompile_recovery.ghidra_db.store import (
        copy_program_item,
        find_store_program,
        list_store_programs,
        rebuild_index,
    )

    loc = (locator or "").strip()
    src_text = (path or "").strip()
    if not loc:
        return {"ok": False, "error": "locator is required"}
    if not src_text:
        return {"ok": False, "error": "path is required"}
    src = Path(src_text).expanduser()
    try:
        src = src.resolve()
    except OSError:
        return {"ok": False, "error": f"{src_text}: path is not readable"}
    if not src.exists():
        return {"ok": False, "error": f"{src}: file not found"}

    dest_name = (name or "").strip()
    source_program = (program or "").strip()
    try:
        dest_root = _destination_store_root(loc, hint=source_program or dest_name)
    except (OSError, ValueError) as exc:
        return {"ok": False, "error": str(exc)}

    src_kind = str(classify_locator(str(src)).get("kind") or "")
    store_entries = []
    if src_kind in {"ghidra-project", "shared-fs"} or src.is_dir():
        try:
            store_entries = list_store_programs(src)
        except (OSError, ValueError):
            store_entries = []

    if store_entries:
        entry = find_store_program(src, source_program or dest_name) if (source_program or dest_name) else None
        if entry is None and len(store_entries) == 1:
            entry = store_entries[0]
        if entry is None:
            return {
                "ok": False,
                "error": "path is a Ghidra store; pass program= to pick which binary to add",
                "programs": [item.name for item in store_entries[:40]],
            }
        dest_name = _unique_program_name(loc, dest_name or entry.name)
        copied = copy_program_item(entry, dest_root, dest_name=dest_name)
        rebuild_index(dest_root)
        _CACHE.clear()
        inspected = inspect_source(loc)
        return {
            "ok": True,
            "program": dest_name or copied.name,
            "source": "store-copy",
            "inspect": inspected,
        }

    from .library_identity import binary_sha256
    source_digest = binary_sha256(str(src))
    existing_bindings, _ = query_db("SELECT source_path,program FROM program_binding WHERE locator=?", (loc,))
    for previous_source, previous_program in existing_bindings:
        if source_digest and binary_sha256(previous_source) == source_digest and find_store_program(loc, previous_program) is not None:
            return {"ok": True, "program": previous_program, "source": "existing-content", "reused": True, "sha256": source_digest, "inspect": inspect_source(loc)}
    requested_name = dest_name or src.name
    dest_name = _unique_program_name(loc, requested_name)

    from agentdecompile_recovery.corpus.dashboard.mcp_bridge import call_tool

    dest_info = classify_locator(loc)
    steps: list[dict[str, Any]] = []
    if dest_info.get("kind") == "ghidra-project":
        open_args = ghidra_connect_args(dest_info) or {
            "path": loc,
            "analyze_after_import": False,
            "open_all_programs": False,
        }
        opened = call_tool("open", open_args, timeout=180.0)
        steps.append({"tool": "open", "ok": opened.get("ok"), "error": opened.get("error")})
        imported = call_tool(
            "import-binary",
            {
                "path": str(src),
                "programName": dest_name,
                "analyzeAfterImport": bool(analyze),
            },
            timeout=180.0,
        )
        steps.append({"tool": "import-binary", "ok": imported.get("ok"), "error": imported.get("error")})
        if imported.get("ok"):
            rebuild_index(dest_root)
            names = [dest_name, requested_name, *_mcp_imported_names(imported)]
            landed = _find_imported_entry([*_live_project_locators()], names)
            if landed is None:
                landed = _find_imported_entry([loc], [dest_name])
            if landed is not None:
                return _place_imported(
                    landed, dest_root, loc, dest_name, steps, "mcp-import",
                    requested_name=requested_name,
                )
            steps.append({
                "tool": "verify-store",
                "ok": False,
                "error": "Ghidra accepted the import but it did not land in this project store",
            })

    root = live_root()
    if root is None:
        last = next((step.get("error") for step in reversed(steps) if step.get("error")), "")
        return {
            "ok": False,
            "error": last or "AGENT_DECOMPILE_CORPUS_WORK_DIR is unset",
            "steps": steps,
        }
    from agentdecompile_recovery.corpus.ghidra_project import create_local_project

    staging_dir = root / "import-staging"
    staging_dir.mkdir(parents=True, exist_ok=True)
    staging = create_local_project(f"import-{dest_name}", work_dir=staging_dir)
    staging_loc = str(staging.get("locator") or staging.get("gpr") or "")
    if not staging.get("ok") or not staging_loc:
        return {"ok": False, "error": staging.get("error") or "could not create a staging project", "steps": steps}
    opened = call_tool(
        "open",
        {"path": staging_loc, "analyze_after_import": False, "open_all_programs": False},
        timeout=180.0,
    )
    steps.append({"tool": "open-staging", "ok": opened.get("ok"), "error": opened.get("error")})
    imported = call_tool(
        "import-binary",
        {
            "path": str(src),
            "programName": dest_name,
            "analyzeAfterImport": bool(analyze),
        },
        timeout=180.0,
    )
    steps.append({"tool": "import-binary-staging", "ok": imported.get("ok"), "error": imported.get("error")})
    if not imported.get("ok"):
        return {
            "ok": False,
            "error": imported.get("error") or "Ghidra could not import that file into the project",
            "steps": steps,
        }
    names = [dest_name, requested_name, *_mcp_imported_names(imported)]
    rebuild_index(dest_root)
    landed = _find_imported_entry(
        [staging_loc, *_live_project_locators()],
        names,
    )
    if landed is None:
        landed = _find_imported_entry([loc], [dest_name])
    if landed is None:
        return {
            "ok": False,
            "error": (
                "Import finished, but the program is not in this project yet. "
                "Ghidra may still have it in the open session project."
            ),
            "steps": steps,
        }
    return _place_imported(
        landed, dest_root, loc, dest_name or landed.name, steps, "mcp-import-copy",
        requested_name=requested_name,
    )


def remove_program_from_project(
    locator: str,
    program: str,
    *,
    confirm: bool,
) -> dict[str, Any]:
    """Remove a Ghidra program item from the open project store."""
    from agentdecompile_recovery.ghidra_db.store import find_store_program, remove_program_item

    if not confirm:
        return {"ok": False, "error": "confirm is required to remove a program from the project"}
    loc = (locator or "").strip()
    name = (program or "").strip()
    if not loc:
        return {"ok": False, "error": "locator is required"}
    if not name:
        return {"ok": False, "error": "program is required"}
    entry = find_store_program(loc, name)
    if entry is None:
        return {"ok": False, "error": f"{name} is not in this project"}
    try:
        root = remove_program_item(entry)
    except (OSError, ValueError) as exc:
        return {"ok": False, "error": str(exc)}
    _CACHE.clear()
    inspected = inspect_source(loc)
    return {
        "ok": True,
        "removed": entry.name,
        "root": str(root),
        "inspect": inspected,
    }


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
    try:
        return save_project_as(
            locator,
            target=target,
            name=name,
            dest=dest,
            url=url,
            work_dir=root,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def workbench_context_payload(
    *,
    program: str = "",
    slug: str = "",
    locator: str = "",
) -> dict[str, Any]:
    """Env defaults plus active session hints for subagents and the workbench UI."""
    from agentdecompile_recovery.corpus.dashboard.actions.catalog import env_defaults
    from agentdecompile_recovery.corpus.ghidra_project import load_sessions

    defaults = dict(env_defaults())
    raw_root = (os.environ.get("AGENT_DECOMPILE_CORPUS_ROOT") or "").strip()
    defaults["corpus_root"] = (
        str(Path(raw_root).expanduser()) if raw_root else defaults.get("work_dir") or ""
    )

    session = {
        "program": program.strip(),
        "slug": slug.strip(),
        "locator": locator.strip(),
    }
    if not any(session.values()):
        data = load_sessions(live_root())
        active_id = str(data.get("active") or "")
        sessions = list(data.get("sessions") or [])
        active = next(
            (item for item in sessions if str(item.get("id") or "") == active_id),
            None,
        )
        if active is None and sessions:
            active = sessions[0]
        if active:
            session = {
                "program": str(active.get("program") or ""),
                "slug": str(active.get("projectSlug") or ""),
                "locator": str(active.get("locator") or ""),
            }
    return {"ok": True, "defaults": defaults, "session": session}


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
    record_filter: str = "all",
    q: str = "",
    offset: int = 0,
    limit: int | str = "all",
    program: str = "",
    bsim_url: str = "",
    locator: str = "",
) -> dict[str, Any]:
    slug = (slug or "").strip()
    program = (program or "").strip()
    locator = (locator or "").strip()
    if not slug and not program:
        return {"ok": False, "error": "pick a binary", "results": [], "total": 0}
    if not slug:
        return _list_functions_fallback(
            program, q=q, offset=offset, limit=limit, bsim_url=bsim_url, locator=locator,
        )
    rows, err = query_db(
        "SELECT id, bits FROM binary WHERE slug=? LIMIT 1",
        (slug,),
    )
    if err:
        return {"ok": False, "error": err, "results": [], "total": 0}
    if not rows:
        if program:
            return _list_functions_fallback(
                program, q=q, offset=offset, limit=limit, bsim_url=bsim_url, locator=locator,
            )
        return {"ok": False, "error": f"no build called {slug}", "results": [], "total": 0}
    bid, bits = rows[0][0], rows[0][1] or 32
    start, cap = page_window(offset, limit)
    from agentdecompile_recovery.corpus.dashboard.common import table_exists

    if table_exists("logical_name"):
        name_expr = (
            "CASE WHEN (f.source='USER_DEFINED' OR lower(COALESCE(f.name_origin,'')) IN ('human','human-authored','user','user_defined')) AND f.name IS NOT NULL AND f.name!='' THEN f.name ELSE COALESCE((SELECT ln.name FROM identity ni "
            "JOIN logical_name ln ON ln.logical_id=ni.logical_id "
            "WHERE ni.binary_id=f.binary_id AND ni.addr=f.addr "
            "ORDER BY ni.confidence DESC LIMIT 1), f.name, '') END"
        )
    else:
        name_expr = "COALESCE(f.name, '')"
    where = "f.binary_id=?"
    params: list[Any] = [bid]
    if record_filter == "bound":
        where += " AND EXISTS(SELECT 1 FROM identity ni WHERE ni.binary_id=f.binary_id AND ni.addr=f.addr)"
    elif record_filter == "named":
        where += " AND f.name IS NOT NULL AND f.name!='' AND f.name NOT LIKE 'FUN_%' AND f.name NOT LIKE 'sub_%'"
    elif record_filter == "real-c":
        if not table_exists("recovered_function"):
            where += " AND 0"
        else:
            where += " AND f.addr IN (SELECT r.addr FROM recovered_function r WHERE r.binary_id=? AND r.real_c=1 AND r.addr IS NOT NULL)"
            params.append(bid)
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
    sql = (
        f"SELECT f.addr, {name_expr}, f.size, "
        "(SELECT ni.logical_id FROM identity ni WHERE ni.binary_id=f.binary_id "
        "AND ni.addr=f.addr ORDER BY ni.confidence DESC LIMIT 1), "
        "f.namespace, f.source_file, f.name_origin, f.source "
        f"FROM func f WHERE {where} ORDER BY f.addr"
    )
    if cap is None:
        data, qerr = query_db(sql, tuple(params))
    else:
        data, qerr = query_db(sql + " LIMIT ? OFFSET ?", (*params, cap, start))
    shown_limit: int | str = "all" if cap is None else cap
    if qerr:
        return {"ok": False, "error": qerr, "results": [], "total": total}
    results = []
    for addr, name, size, logical_id, namespace, source_file, name_origin, source_type in data or []:
        addr_i = int(addr)
        shown = name or f"FUN_{format_address(addr_i, bits)[2:]}"
        unit = _find_unit(slug, addr_i, shown)
        decomp = _classify_c(unit) if unit else "none"
        obj_hit = False
        objs = obj_root()
        if objs is not None and unit is not None:
            guess = objs / unit.with_suffix(".obj").name
            obj_hit = guess.is_file()
        validate = "object-present" if obj_hit else "unmeasured"
        results.append(
            {
                "addr": format_address(addr_i, bits),
                "address": addr_i,
                "name": shown,
                "size": int(size or 0),
                "logicalId": logical_id,
                "namespace": namespace or "",
                "sourceFile": source_file or "",
                "nameOrigin": name_origin or source_type or "unknown",
                "humanAuthored": source_type == "USER_DEFINED" or str(name_origin or "").lower() in {"human", "human-authored", "user", "user_defined"},
                "decomp": decomp,
                "validate": validate,
                "signature": _signature_from_unit(unit),
            }
        )
    if not results and program and record_filter == "all":
        fallback = _list_functions_fallback(
            program, q=q, offset=offset, limit=limit, bsim_url=bsim_url, locator=locator,
        )
        if fallback.get("results"):
            fallback.setdefault("slug", slug)
            return fallback
        return {
            "ok": True,
            "slug": slug,
            "program": program,
            "q": needle,
            "offset": start,
            "limit": shown_limit,
            "total": 0,
            "results": [],
            "hasMore": False,
            "source": fallback.get("source") or "ghidra-program",
            "next": fallback.get("next") or "analyze-program",
            "error": fallback.get("error") or (
                f"{program} has no functions yet. Analyze → Analyze program "
                "opens it in Ghidra and fills this list."
            ),
        }
    return {
        "ok": True,
        "slug": slug,
        "q": needle,
        "offset": start,
        "limit": shown_limit,
        "total": total,
        "results": results,
        "hasMore": cap is not None and start + len(results) < total,
    }


def _bits_from_language(language_id: str | None) -> int:
    for part in str(language_id or "").split(":"):
        if part in {"16", "32", "64", "128"}:
            return int(part)
    return 32


def _list_functions_from_store(
    locator: str,
    program: str,
    *,
    q: str = "",
    offset: int = 0,
    limit: int | str = "all",
) -> dict[str, Any]:
    loc = (locator or "").strip()
    name = (program or "").strip()
    start, cap = page_window(offset, limit)
    shown_limit: int | str = "all" if cap is None else cap
    empty = {
        "ok": True,
        "program": name,
        "locator": loc,
        "q": q,
        "offset": start,
        "limit": shown_limit,
        "total": 0,
        "results": [],
        "hasMore": False,
        "source": "ghidra-store",
        "opened": False,
    }
    if not loc or not name:
        return empty
    cache_key = f"store-funcs:{loc}:{name}:{q}:{start}:{shown_limit}"
    hit = _CACHE.get(cache_key)
    if hit and time.time() - hit[0] < _STORE_CACHE_TTL:
        return hit[1]
    from agentdecompile_recovery.ghidra_db.buffer_file import BufferFileError
    from agentdecompile_recovery.ghidra_db.program import GhidraProgramError
    from agentdecompile_recovery.ghidra_db.project import ProjectLayoutError
    from agentdecompile_recovery.ghidra_db.store import find_store_program

    try:
        entry = find_store_program(loc, name)
    except (OSError, ValueError, ProjectLayoutError):
        return empty
    if entry is None:
        return empty

    needle = (q or "").strip().lower()
    results: list[dict[str, Any]] = []
    total = 0
    bits = 32
    try:
        with entry.open() as prog:
            bits = _bits_from_language(prog.language_id)
            for func in prog.functions():
                if func.entry is None:
                    continue
                addr = format_address(func.entry, bits)
                shown = func.name or f"FUN_{addr[2:]}"
                if needle and needle not in shown.lower() and needle not in addr.lower():
                    continue
                take = cap is None or (total >= start and len(results) < cap)
                if take and total >= start:
                    results.append(
                        {
                            "addr": addr,
                            "address": int(func.entry),
                            "name": shown,
                            "size": 0,
                            "logicalId": None,
                            "decomp": "none",
                            "validate": "none",
                            "source": "ghidra-store",
                        }
                    )
                total += 1
                if cap is not None and not needle and len(results) >= cap:
                    break
    except (GhidraProgramError, ProjectLayoutError, BufferFileError, OSError, ValueError) as exc:
        empty["opened"] = True
        empty["error"] = str(exc)[:800]
        empty["next"] = "analyze-program"
        return empty
    payload = {
        "ok": True,
        "program": name,
        "program_path": entry.project_path,
        "locator": loc,
        "q": q,
        "offset": start,
        "limit": shown_limit,
        "total": total,
        "results": results,
        "hasMore": cap is not None and start + len(results) < total,
        "source": "ghidra-store",
        "opened": True,
        "analysisComplete": bool(results),
        "next": "" if results else "analyze-program",
        **(
            {}
            if results
            else {
                "error": (
                    f"{name} is on disk in the Ghidra store but has no functions yet. "
                    "Analyze → Analyze program fills this list."
                )
            }
        ),
    }
    if results:
        _CACHE[cache_key] = (time.time(), payload)
    return payload


def _list_functions_fallback(
    program: str,
    *,
    q: str = "",
    offset: int = 0,
    limit: int | str = "all",
    bsim_url: str = "",
    locator: str = "",
) -> dict[str, Any]:
    stored = _list_functions_from_store(
        locator, program, q=q, offset=offset, limit=limit,
    )
    if stored.get("results") or stored.get("opened"):
        return stored
    bsim_listed = _list_functions_from_bsim(
        program, q=q, offset=offset, limit=limit, bsim_url=bsim_url,
    )
    if bsim_listed.get("results"):
        return bsim_listed
    from agentdecompile_recovery.corpus.dashboard.mcp_bridge import list_functions as mcp_list

    ghidra_listed = mcp_list(program, q=q, offset=offset, limit=limit)
    if ghidra_listed.get("results"):
        return ghidra_listed
    if ghidra_listed.get("error") and not bsim_listed.get("error"):
        return ghidra_listed
    merged = dict(bsim_listed)
    if ghidra_listed.get("error"):
        merged["error"] = ghidra_listed["error"]
        merged["next"] = ghidra_listed.get("next") or "analyze-program"
        merged["source"] = ghidra_listed.get("source") or merged.get("source")
    return merged


def ensure_ghidra_program(locator: str, program: str = "") -> dict[str, Any]:
    from agentdecompile_recovery.corpus.dashboard.mcp_bridge import ensure_program

    return ensure_program(locator, program)


def _list_functions_from_bsim(
    program: str,
    *,
    q: str = "",
    offset: int = 0,
    limit: int | str = "all",
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


_REF_KIND = {
    1: "data",
    2: "data",
    3: "call",
    4: "jump",
    5: "call",
    6: "jump",
    7: "computed-call",
    8: "computed-call",
}


def _format_store_node(entry: int, name: str, bits: int, *, kind: str = "", refs: int = 0) -> dict[str, Any]:
    addr = format_address(entry, bits)
    shown = name or f"FUN_{addr[2:]}"
    return {
        "addr": addr,
        "address": int(entry),
        "name": shown,
        "kind": kind,
        "refs": refs,
    }


def _parse_ref_blob(prog, data: bytes, count: int) -> list[tuple[int, int]]:
    if not data or count <= 0:
        return []
    rec = len(data) // int(count)
    if rec < 9:
        return []
    out: list[tuple[int, int]] = []
    for index in range(int(count)):
        chunk = data[index * rec : (index + 1) * rec]
        encoded = int.from_bytes(chunk[:8], "big")
        va = prog.virtual_address(encoded)
        if va is None:
            continue
        out.append((int(va), int(chunk[8])))
    return out


def _lookup_ref_row(prog, table_name: str, key_name: str, wanted: int) -> dict[str, Any] | None:
    from agentdecompile_recovery.ghidra_db.master_table import find_table, iter_rows

    table = find_table(prog.buffer_file, table_name)
    if table is None:
        return None
    for row in iter_rows(prog.buffer_file, table):
        va = prog.virtual_address(row.get(key_name))
        if va == wanted:
            return row
    return None


def program_workspace(
    locator: str,
    program: str,
    *,
    addr: str = "",
    slug: str = "",
) -> dict[str, Any]:
    """Listing + call graph + program hero from the on-disk Ghidra store."""
    loc = (locator or "").strip()
    name = (program or "").strip()
    if not loc or not name:
        return {"ok": False, "error": "locator and program are required"}
    cache_key = f"ws:{loc}:{name}:{addr}:{slug}"
    hit = _CACHE.get(cache_key)
    if hit and time.time() - hit[0] < _STORE_CACHE_TTL:
        return hit[1]
    from agentdecompile_recovery.ghidra_db.master_table import find_table
    from agentdecompile_recovery.ghidra_db.program import GhidraProgramError
    from agentdecompile_recovery.ghidra_db.project import ProjectLayoutError
    from agentdecompile_recovery.ghidra_db.store import find_store_program

    wanted = parse_address(addr)
    try:
        entry = find_store_program(loc, name)
    except (OSError, ValueError, ProjectLayoutError) as exc:
        return {"ok": False, "error": str(exc)[:800]}
    if entry is None:
        return {"ok": False, "error": f"{name} is not in {loc}"}
    try:
        with entry.open() as prog:
            bits = _bits_from_language(prog.language_id)
            functions: list[tuple[int, str]] = []
            named = 0
            for func in prog.functions():
                if func.entry is None:
                    continue
                functions.append((int(func.entry), func.name or ""))
                if func.name and not func.name.startswith(("FUN_", "Unwind@", "thunk_")):
                    named += 1
            functions.sort(key=lambda item: item[0])
            if not functions:
                overview = {
                    "program": name,
                    "path": entry.project_path,
                    "imageBase": format_address(prog.image_base, bits),
                    "language": prog.language_id or "",
                    "functionCount": 0,
                    "namedCount": 0,
                    "memory": [block.to_json() for block in prog.memory_blocks()[:24]],
                }
                return {
                    "ok": True,
                    "source": "ghidra-store",
                    "overview": overview,
                    "listing": {},
                    "decompile": {"text": "", "source": "none", "path": "", "signature": ""},
                    "graph": {"center": None, "callers": [], "callees": [], "neighbors": []},
                    "selected": None,
                }
            pick = functions[0][0]
            if wanted is not None:
                for start, _fname in functions:
                    if start <= wanted:
                        pick = start
                    else:
                        break
                if wanted < functions[0][0]:
                    pick = functions[0][0]
            idx = next((i for i, item in enumerate(functions) if item[0] == pick), 0)
            pick_name = functions[idx][1]
            nxt = functions[idx + 1][0] if idx + 1 < len(functions) else pick + 0x1000
            comments: list[dict[str, str]] = []
            for comment_set in prog.comments():
                if pick <= comment_set.entry < nxt:
                    for kind, text in comment_set.comments.items():
                        if text:
                            comments.append(
                                {
                                    "addr": format_address(comment_set.entry, bits),
                                    "kind": kind,
                                    "text": text[:400],
                                }
                            )
                if len(comments) >= 24:
                    break
            incoming = _lookup_ref_row(prog, "TO REFS", "To Address", pick)
            outgoing = _lookup_ref_row(prog, "FROM REFS", "From Address", pick)
            by_entry = {start: fname for start, fname in functions}

            def owning(va: int) -> tuple[int, str]:
                lo, hi = 0, len(functions) - 1
                hit = functions[0]
                while lo <= hi:
                    mid = (lo + hi) // 2
                    if functions[mid][0] <= va:
                        hit = functions[mid]
                        lo = mid + 1
                    else:
                        hi = mid - 1
                return hit

            callers: list[dict[str, Any]] = []
            if incoming is not None:
                for va, rtype in _parse_ref_blob(
                    prog, incoming.get("Ref Data") or b"", int(incoming.get("Number of Refs") or 0)
                ):
                    owner, owner_name = owning(va)
                    callers.append(
                        _format_store_node(
                            owner,
                            owner_name,
                            bits,
                            kind=_REF_KIND.get(rtype, f"ref-{rtype}"),
                            refs=int(incoming.get("Number of Refs") or 0),
                        )
                    )
            callees: list[dict[str, Any]] = []
            if outgoing is not None:
                for va, rtype in _parse_ref_blob(
                    prog, outgoing.get("Ref Data") or b"", int(outgoing.get("Number of Refs") or 0)
                ):
                    owner, owner_name = owning(va)
                    callees.append(
                        _format_store_node(
                            owner if rtype in {3, 5, 7, 8} else va,
                            owner_name if rtype in {3, 5, 7, 8} else by_entry.get(va, ""),
                            bits,
                            kind=_REF_KIND.get(rtype, f"ref-{rtype}"),
                        )
                    )
            seen: set[str] = set()
            unique_callers: list[dict[str, Any]] = []
            self_addr = format_address(pick, bits)
            for node in callers:
                key = node["addr"]
                if key in seen or key == self_addr:
                    continue
                seen.add(key)
                unique_callers.append(node)
            seen.clear()
            unique_callees: list[dict[str, Any]] = []
            for node in callees:
                key = node["addr"]
                if key in seen or key == format_address(pick, bits):
                    continue
                seen.add(key)
                unique_callees.append(node)
            neighbors: list[dict[str, Any]] = []
            for start, fname in functions[max(0, idx - 6) : idx + 7]:
                if start == pick:
                    continue
                neighbors.append(_format_store_node(start, fname, bits, kind="near"))
            blocks = [block.to_json() for block in prog.memory_blocks()[:24]]
            listing_lines = [
                f"// {name}  {entry.project_path}",
                f"// language {prog.language_id or '?'}  image {format_address(prog.image_base, bits)}",
                f"{pick_name or ('FUN_' + format_address(pick, bits)[2:])}  @ {format_address(pick, bits)}",
            ]
            if comments:
                listing_lines.append("")
                for item in comments[:16]:
                    listing_lines.append(f"/* {item['kind']} {item['addr']}: {item['text']} */")
            if unique_callers:
                listing_lines.append("")
                listing_lines.append(f"// callers {len(unique_callers)}")
                for node in unique_callers[:12]:
                    listing_lines.append(f"//   {node['addr']}  {node['name']}  {node['kind']}")
            if unique_callees:
                listing_lines.append("")
                listing_lines.append(f"// callees {len(unique_callees)}")
                for node in unique_callees[:12]:
                    listing_lines.append(f"//   {node['addr']}  {node['name']}  {node['kind']}")
            center = _format_store_node(pick, pick_name, bits, kind="center")
            overview = {
                "program": name,
                "path": entry.project_path,
                "imageBase": format_address(prog.image_base, bits),
                "language": prog.language_id or "",
                "functionCount": len(functions),
                "namedCount": named,
                "commentHits": len(comments),
                "hasRefs": bool(find_table(prog.buffer_file, "TO REFS")),
                "memory": blocks,
            }
    except (GhidraProgramError, ProjectLayoutError, OSError, ValueError) as exc:
        return {"ok": False, "error": str(exc)[:800], "source": "ghidra-store"}
    payload = {
        "ok": True,
        "source": "ghidra-store",
        "slug": slug,
        "program": name,
        "locator": loc,
        "overview": overview,
        "selected": center,
        "listing": {
            "addr": center["addr"],
            "name": center["name"],
            "preview": "\n".join(listing_lines),
            "previewKind": "listing-metadata",
            "comments": comments,
            "callers": unique_callers[:24],
            "callees": unique_callees[:24],
            "siblings": [],
            "fields": [
                {"name": "Address", "value": center["addr"]},
                {"name": "Label", "value": center["name"]},
            ],
        },
        "decompile": _decompile_payload(slug, pick, pick_name),
        "graph": {
            "center": center,
            "callers": unique_callers[:16],
            "callees": unique_callees[:16],
            "neighbors": neighbors,
        },
    }
    _CACHE[cache_key] = (time.time(), payload)
    return payload


def function_detail(slug: str, raw_addr: str, *, locator: str = "", program: str = "") -> dict[str, Any]:
    from agentdecompile_recovery.corpus.dashboard.function_evidence import read, ensure_observation
    request_state = ensure_observation(locator, program, raw_addr)
    observed = read(locator, program, raw_addr)
    addr = parse_address(raw_addr)
    if addr is None:
        return {"ok": False, "error": "bad address"}
    def with_source_witness(payload: dict[str, Any]) -> dict[str, Any]:
        payload['evidenceRequest'] = request_state
        if observed and observed.get('evidenceComplete'):
            # A current Ghidra observation can explicitly report an import,
            # thunk, or decompiler failure. Do not fill that absence with an
            # unrelated historical source candidate.
            return payload
        # Workflow output is shared evidence, even before it compiles. Never
        # replace an explicit recorded observation or stronger display name.
        if (payload.get("decompile") or {}).get("text") and (payload.get("assembly") or {}).get("text"):
            return payload
        from .analysis_view import read_function_witness
        try:
            witness = read_function_witness(slug, addr, locator, program)
        except (OSError, ValueError, sqlite3.Error) as exc:
            payload["sourceWitnessError"] = str(exc)
            return payload
        for field in ("decompile", "assembly"):
            if not (payload.get(field) or {}).get("text") and (witness.get(field) or {}).get("text"):
                payload[field] = witness[field]
                payload["sourceWitnessProvenance"] = witness.get("provenance")
        return payload
    if (locator or "").strip() and (program or "").strip():
        workspace = program_workspace(locator, program, addr=raw_addr, slug=slug)
        if workspace.get("ok"):
            listing = dict(workspace.get("listing") or {})
            listing["ok"] = True
            listing["slug"] = slug
            listing["function"] = workspace.get("selected") or {}
            listing["graph"] = workspace.get("graph") or {}
            listing["overview"] = workspace.get("overview") or {}
            listing["decompile"] = workspace.get("decompile") or {}
            listing["source"] = "ghidra-store"
            if observed:
                listing.update(observed)
            return with_source_witness(listing)
    listed = list_functions(slug, q=hex(addr), offset=0, limit=1, program=program, locator=locator)
    row = listed["results"][0] if listed.get("results") else {}
    unit = _find_unit(slug, addr, str(row.get("name") or ""))
    preview = ""
    if unit is not None:
        try:
            with unit.open(encoding="utf-8", errors="replace") as stream:
                preview = stream.read(4001)
        except OSError:
            preview = ""
    siblings: list[dict[str, Any]] = []
    rows, err = query_db(
        "SELECT b.slug, i.addr, i.logical_id, i.confidence, i.method, i.evidence FROM identity src "
        "JOIN identity i ON i.logical_id=src.logical_id "
        "JOIN binary b ON b.id=i.binary_id "
        "JOIN binary sb ON sb.id=src.binary_id "
        "WHERE sb.slug=? AND src.addr=?",
        (slug, addr),
    )
    if not err:
        for other_slug, other_addr, logical_id, confidence, method, evidence in rows:
            siblings.append(
                {
                    "slug": other_slug,
                    "addr": format_address(int(other_addr)),
                    "logicalId": logical_id,
                    "confidence": confidence, "method": method, "evidence": evidence,
                }
            )
    graph: dict[str, Any] = {"center": row, "callers": [], "callees": []}
    for direction, selected, other in (("callers", "callee_addr", "caller_addr"), ("callees", "caller_addr", "callee_addr")):
        edges, edge_error = query_db(
            f"SELECT DISTINCT e.{other}, f.name FROM calledge e JOIN binary b ON b.id=e.binary_id "
            f"LEFT JOIN func f ON f.binary_id=e.binary_id AND f.addr=e.{other} "
            f"WHERE b.slug=? AND e.{selected}=? ORDER BY e.{other} LIMIT 101",
            (slug, addr), ignore_missing=True,
        )
        graph[direction] = [{"addr": format_address(int(a)), "name": n or format_address(int(a)), "slug": slug} for a, n in edges[:100]]
        graph[direction + "Truncated"] = len(edges) > 100
        if edge_error:
            graph[direction + "Error"] = edge_error
    result = {
        "ok": True,
        "slug": slug,
        "addr": format_address(addr),
        "function": row,
        "graph": graph,
        "preview": preview[:4000],
        "previewKind": "source-excerpt" if preview else "unavailable",
        "previewTruncated": len(preview) > 4000,
        "previewCharacterLimit": 4000,
        "siblings": siblings,
        "sourcePath": str(unit) if unit else "",
    }
    if observed:
        result.update(observed)
    return with_source_witness(result)


def render_workbench() -> str:
    payload = list_binaries()
    rows = payload.get("binaries") or []
    items = []
    for row in rows:
        items.append(
            f'<li data-slug="{esc(row["slug"])}">'
            f'<a href="/dashboard?window=wb-corpus&amp;binary={esc(row["slug"])}">{esc(row["slug"])}</a>'
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
<link rel="stylesheet" href="/dashboard/static/workbench.css?v=live12">
<link rel="stylesheet" href="/dashboard/static/workbench-tokens.css?v=onepage1">
<link rel="stylesheet" href="/dashboard/static/workbench-controls.css?v=onepage1">
<link rel="stylesheet" href="/dashboard/static/workbench-chrome.css?v=onepage1">
<link rel="stylesheet" href="/dashboard/static/workbench-sidebar.css?v=live11">
<link rel="stylesheet" href="/dashboard/static/workbench-editor.css?v=live24">
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
        <span class="sr-only">Find a function</span>
        <input id="wb-q" type="search" placeholder="Function or address" autocomplete="off">
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
        <span class="wb-drop-sub">A PE, ELF, .gpr, or repos folder</span>
        <input id="wb-bin-file" type="file" multiple hidden>
        <input id="wb-bin-folder" type="file" webkitdirectory hidden>
      </div>
      <button type="button" id="wb-bin-add" class="wb-btn wb-btn-primary">Create local project</button>
      <label class="wb-file-label">Project folder</label>
      <div id="wb-browse" class="wb-browse"></div>
      <form id="wb-shared-form" class="wb-bin-form">
        <label>Host <input id="wb-shared-host"></label>
        <label>Port <input id="wb-shared-port" placeholder="13100"></label>
        <label>Repository <input id="wb-shared-repo"></label>
        <label>Program <input id="wb-shared-program"></label>
        <label>URL <input id="wb-shared-url" placeholder="ghidra://host:13100/repo"></label>
        <button type="submit" id="wb-shared-add">Open shared server</button>
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
        <div id="wb-inspect-body"><p class="wb-hint">Pick a function to decompile.</p></div>
      </section>
      <section id="wb-graph" class="wb-surface">
        <h2>Call graph</h2>
        <p class="wb-hint">Pick a function to open the call graph.</p>
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
    <section id="wb-match" class="wb-surface"><h2>Match</h2></section>
    <section id="wb-recovery" class="wb-surface"><h2>Recover</h2></section>
    <section id="wb-stabs" class="wb-surface"><h2>STABS</h2></section>
    <section id="wb-knowledge" class="wb-surface"><h2>Knowledge</h2></section>
    <section id="wb-roundtrip" class="wb-surface"><h2>Roundtrip</h2></section>
    <section id="wb-processes" class="wb-surface"><h2>Process log</h2></section>
    <section id="wb-mission" class="wb-surface"><h2>Mission</h2></section>
    <section id="wb-corpus" class="wb-surface"><h2>Corpus table</h2></section>
    <section id="wb-tools" class="wb-surface"><h2>Commands</h2></section>
    </main>
    <footer class="wb-status" id="wb-status">
      <span id="wb-status-source">No project</span>
      <span id="wb-status-kind"></span>
      <span id="wb-status-program"></span>
      <span id="wb-status-selection"></span>
    </footer>
  </div>
</div>
<noscript>
  <p>JavaScript is off. Use <a href="/dashboard?window=wb-overview">Overview</a>,
  <a href="/dashboard?window=wb-fnbrowse">Functions</a>, or <a href="/docs">Docs</a>.</p>
</noscript>
<script src="/dashboard/static/react.js"></script>
<script src="/dashboard/static/react-dom.js"></script>
<script src="/dashboard/static/htm.js"></script>
<script src="/dashboard/static/dashboard.js" defer></script>
<script src="/dashboard/static/workbench-app.js?v=live29" defer></script>
</body>
</html>
"""
