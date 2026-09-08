"""Locate local Ghidra projects (.gpr / .rep) and shared repository URLs.

A local project is a ``Name.gpr`` file plus a sibling ``Name.rep`` folder.
Shared projects are ``ghidra://host:port/repository[/folder/program]`` or an
HTTP(S) Ghidra-server / shared-folder URL. This module does not talk to a
live Ghidra JVM — it only classifies locators and lists on-disk program names.
"""

from __future__ import annotations

import getpass
import json
import os
import shutil
import time
from pathlib import Path
from urllib.parse import urlparse

SAVE_KINDS = ("ghidra-project", "shared-fs", "shared-project")

_SHARED_SCHEMES = ("ghidra", "http", "https")
_REP_META = {"idata", "user", "versioned"}
_DEFAULT_SERVER_PORT = 13100


def is_shared_locator(raw: str) -> bool:
    text = (raw or "").strip().lower()
    return text.startswith(("ghidra://", "http://", "https://"))


def is_local_ghidra_url(raw: str) -> bool:
    text = (raw or "").strip().lower()
    return text.startswith("ghidra:") and not text.startswith("ghidra://")


def find_gpr(path: Path) -> Path | None:
    """Return the .gpr for a file, project directory, or .rep folder."""
    cand = Path(path).expanduser()
    try:
        if cand.is_file() and cand.suffix.lower() == ".gpr":
            return cand
        if cand.is_dir():
            hits = sorted(p for p in cand.glob("*.gpr") if p.is_file())
            if hits:
                return hits[0]
            name = cand.name
            if name.endswith(".rep"):
                sibling = cand.with_name(name[: -len(".rep")] + ".gpr")
                if sibling.is_file():
                    return sibling
            sibling = cand / f"{cand.name}.gpr"
            if sibling.is_file():
                return sibling
    except OSError:
        return None
    return None


def list_local_programs(gpr: Path) -> list[str]:
    """Best-effort program names from the sibling ``.rep`` tree."""
    try:
        root = Path(gpr).expanduser().resolve()
    except OSError:
        return []
    rep = root.with_suffix(".rep")
    if not rep.is_dir():
        return []
    names: set[str] = set()
    try:
        from agentdecompile_recovery.ghidra_db.store import list_store_programs

        for entry in list_store_programs(root):
            if entry.name:
                names.add(entry.name)
    except (OSError, ValueError):
        pass
    try:
        for child in rep.iterdir():
            if child.name.startswith(".") or child.name in _REP_META:
                continue
            if child.is_dir():
                names.add(child.name)
        for index in (rep / "~index.dat", rep / "versioned" / "~index.dat", rep / "user" / "~index.dat"):
            if not index.is_file():
                continue
            parsed = parse_index_dat(index.read_text(encoding="utf-8", errors="replace"))
            for item in parsed.get("programs") or []:
                if isinstance(item, dict) and item.get("name"):
                    names.add(str(item["name"]))
        for prop in rep.rglob("propertyList.xml"):
            parent = prop.parent
            if parent.name in _REP_META or parent == rep:
                continue
            try:
                rel = parent.relative_to(rep)
            except ValueError:
                continue
            if rel.parts and rel.parts[0] in _REP_META:
                continue
            names.add(str(rel).replace("\\", "/"))
    except OSError:
        return sorted(names)
    return sorted(names)


def parse_shared_locator(raw: str) -> dict[str, object]:
    url = (raw or "").strip()
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in _SHARED_SCHEMES:
        raise ValueError("shared locator must be ghidra://, http://, or https://")
    host = parsed.hostname or "localhost"
    port = int(parsed.port or _DEFAULT_SERVER_PORT)
    parts = [p for p in (parsed.path or "").split("/") if p]
    repository = parts[0] if parts else ""
    inner = "/" + "/".join(parts[1:]) if len(parts) > 1 else ""
    program = "/".join(parts[1:]) if len(parts) > 1 else ""
    if port == _DEFAULT_SERVER_PORT:
        canonical = f"ghidra://{host}/{repository}{inner}" if repository else f"ghidra://{host}"
    else:
        canonical = (
            f"ghidra://{host}:{port}/{repository}{inner}" if repository else f"ghidra://{host}:{port}"
        )
    slug = parts[-1] if parts else (repository or host)
    return {
        "kind": "shared-project",
        "locator": url,
        "canonical": canonical,
        "host": host,
        "port": port,
        "repository": repository,
        "path": inner,
        "slug": slug,
        "programs": [program] if program else [],
        "access": "rmi",
        "protocol": "ghidra-rmi-ssl",
        "ports": [port, port + 1, port + 2],
        "portRoles": {
            "registry": port,
            "rmiSsl": port + 1,
            "blockStream": port + 2,
        },
    }


def classify_locator(raw: str) -> dict[str, object]:
    text = (raw or "").strip()
    if not text:
        return {"kind": "empty", "error": "path, .gpr, project folder, or URL is required"}
    if is_shared_locator(text):
        try:
            return parse_shared_locator(text)
        except ValueError as exc:
            return {"kind": "empty", "error": str(exc)}
    if is_local_ghidra_url(text):
        body = text.split(":", 1)[1]
        loc, _, program = body.partition("?")
        gpr = find_gpr(Path(loc))
        if gpr is None:
            return {"kind": "empty", "error": "ghidra: URL is not a local .gpr / .rep project"}
        programs = list_local_programs(gpr)
        if program and program not in programs:
            programs = [program] + programs
        return {
            "kind": "ghidra-project",
            "path": loc,
            "gpr": gpr,
            "locator": str(gpr.resolve()) if gpr.exists() else str(gpr),
            "canonical": str(gpr.resolve()) if gpr.exists() else str(gpr),
            "slug": gpr.stem,
            "programs": programs,
        }
    if text.lower().startswith("file://"):
        parsed = urlparse(text)
        text = parsed.path or text
    path = Path(text).expanduser()
    if path.is_dir():
        shared = inspect_shared_fs(path)
        if shared is not None:
            return shared
    gpr = find_gpr(path)
    if gpr is not None:
        programs = list_local_programs(gpr)
        return {
            "kind": "ghidra-project",
            "path": str(path),
            "gpr": gpr,
            "locator": str(gpr.resolve()) if gpr.exists() else str(gpr),
            "canonical": str(gpr.resolve()) if gpr.exists() else str(gpr),
            "slug": gpr.stem,
            "programs": programs,
        }
    if path.is_file():
        packed = False
        try:
            from agentdecompile_recovery.ghidra_db.packed import is_packed_file

            packed = is_packed_file(path)
        except Exception:
            packed = path.suffix.lower() == ".gzf"
        kind = "packed-program" if packed else "binary"
        return {
            "kind": kind,
            "path": str(path),
            "locator": str(path.resolve()),
            "canonical": str(path.resolve()),
            "slug": path.stem if packed else path.name,
            "programs": [path.stem] if packed else [],
        }
    if path.is_dir():
        shared = inspect_shared_fs(path)
        if shared is not None:
            return shared
        return {
            "kind": "empty",
            "error": "directory is not a Ghidra project (.gpr / .rep) or shared-server repos folder",
        }
    return {"kind": "empty", "error": "path is not a readable file, Ghidra project, or URL"}


def describe_source(repo_path: str) -> dict[str, object]:
    info = classify_locator(repo_path)
    kind = str(info.get("kind") or "binary")
    if kind == "empty":
        kind = "binary"
    return {
        "kind": kind,
        "programs": list(info.get("programs") or []),
        "locator": str(info.get("locator") or repo_path or ""),
        "canonical": str(info.get("canonical") or repo_path or ""),
    }


def shared_defaults() -> dict[str, object]:
    host = (os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_HOST") or "127.0.0.1").strip()
    port_raw = (os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_PORT") or "").strip()
    try:
        port = int(port_raw or _DEFAULT_SERVER_PORT)
    except ValueError:
        port = _DEFAULT_SERVER_PORT
    repository = (os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY") or "").strip()
    user = (os.environ.get("AGENT_DECOMPILE_GHIDRA_SERVER_USER") or "").strip()
    if not user:
        try:
            user = getpass.getuser() or ""
        except Exception:
            user = ""
    return {
        "host": host or "127.0.0.1",
        "port": port,
        "repository": repository,
        "user": user,
        "protocol": "ghidra-rmi-ssl",
        "defaultPort": _DEFAULT_SERVER_PORT,
        "ports": [port, port + 1, port + 2],
        "portRoles": {
            "registry": port,
            "rmiSsl": port + 1,
            "blockStream": port + 2,
        },
    }


def ghidra_program_path(info: dict[str, object] | None, program: str) -> str:
    """Folder-qualified Ghidra path (``/JE/JadeEmpire.exe``) when the dossier has it."""
    name = (program or "").strip()
    if not name:
        return ""
    if name.startswith("/"):
        return name
    payload = info or {}
    mapped = payload.get("program_paths")
    if isinstance(mapped, dict) and mapped.get(name):
        return str(mapped[name])
    for repo in payload.get("repositories") or []:
        if not isinstance(repo, dict):
            continue
        for item in repo.get("programs") or []:
            if isinstance(item, dict) and str(item.get("name") or "") == name:
                folder = str(item.get("folder") or "/").rstrip("/")
                return f"{folder}/{name}" if folder else f"/{name}"
    return name


def ghidra_connect_args(info: dict[str, object] | None) -> dict[str, object]:
    """Arguments for MCP ``open`` from an inspect/classify payload."""
    payload = dict(info or {})
    kind = str(payload.get("kind") or "")
    if kind == "shared-project":
        return {
            "path": str(payload.get("canonical") or payload.get("locator") or ""),
            "shared": True,
            "server_host": str(payload.get("host") or shared_defaults()["host"]),
            "server_port": int(payload.get("port") or shared_defaults()["port"]),
            "repository_name": str(payload.get("repository") or ""),
            "analyze_after_import": False,
            "open_all_programs": False,
        }
    if kind == "ghidra-project":
        return {
            "path": str(payload.get("gpr") or payload.get("locator") or ""),
            "analyze_after_import": False,
            "open_all_programs": False,
        }
    if kind == "shared-fs":
        # Native open materializes/reuses an owned local checkout, retaining
        # existing analysis and keeping the repository source untouched.
        return {"path": str(payload.get('locator') or payload.get('path') or ''), "analyze_after_import": False, "open_all_programs": False}
    return {}


def browse_roots(work_dir: Path | None = None) -> list[dict[str, object]]:
    seen: set[str] = set()
    roots: list[dict[str, object]] = []
    extra = (os.environ.get("AGENT_DECOMPILE_GHIDRA_REPOS_DIR") or "").strip()
    discovered = Path.home() / "biodecompwarehouse" / "repos"
    for label, cand in (
        ("work", work_dir),
        ("home", Path.home()),
        ("cwd", Path.cwd()),
        ("repos", Path(extra) if extra else None),
        ("repos", discovered if discovered.is_dir() else None),
        ("projects", Path.home() / "biodecompwarehouse" / "projects"),
    ):
        if cand is None:
            continue
        try:
            path = Path(cand).expanduser().resolve()
        except OSError:
            continue
        key = str(path)
        if key in seen or not path.is_dir():
            continue
        seen.add(key)
        shared = inspect_shared_fs(path)
        gpr = find_gpr(path)
        if shared is not None:
            kind = "shared-fs"
            programs = list(shared.get("programs") or [])
        elif gpr is not None:
            kind = "project-dir"
            programs = list_local_programs(gpr)
        else:
            kind = "dir"
            programs = []
        roots.append({
            "name": f"{label}: {path.name or path}",
            "kind": kind,
            "path": key,
            "programs": programs,
        })
    return roots


_BROWSE_BINARY_SUFFIXES = frozenset({
    ".bin",
    ".dll",
    ".dylib",
    ".elf",
    ".exe",
    ".gzf",
    ".o",
    ".obj",
    ".scr",
    ".so",
    ".sys",
    ".xbe",
})


def _is_packed_program(path: Path) -> bool:
    if path.suffix.lower() == ".gzf":
        return True
    try:
        from agentdecompile_recovery.ghidra_db.packed import is_packed_file

        return is_packed_file(path)
    except Exception:
        return False


def _browse_binary_entry(path: Path) -> dict[str, object] | None:
    if not path.is_file():
        return None
    if _is_packed_program(path):
        return {
            "name": path.name,
            "kind": "packed-program",
            "path": str(path),
            "programs": [path.stem],
        }
    if path.suffix.lower() not in _BROWSE_BINARY_SUFFIXES:
        return None
    return {
        "name": path.name,
        "kind": "binary",
        "path": str(path),
        "programs": [],
    }


def browse_path(raw: str, *, work_dir: Path | None = None) -> dict[str, object]:
    text = (raw or "").strip()
    if not text:
        return {"ok": True, "path": "", "parent": "", "entries": browse_roots(work_dir)}
    try:
        path = Path(text).expanduser().resolve()
    except OSError as exc:
        return {"ok": False, "error": str(exc), "path": text, "parent": "", "entries": []}
    allowed_roots = search_roots(work_dir)
    if allowed_roots and not any(_path_within(path, root) for root in allowed_roots):
        return {
            "ok": False,
            "error": "path is outside allowed corpus and project roots",
            "path": str(path),
            "parent": "",
            "entries": [],
        }
    if path.is_file() and path.suffix.lower() == ".gpr":
        info = classify_locator(str(path))
        return {
            "ok": True,
            "path": str(path),
            "parent": str(path.parent),
            "kind": "ghidra-project",
            "programs": list(info.get("programs") or []),
            "entries": [],
        }
    binary_entry = _browse_binary_entry(path)
    if binary_entry is not None:
        return {
            "ok": True,
            "path": str(path),
            "parent": str(path.parent),
            "kind": str(binary_entry.get("kind") or "binary"),
            "programs": list(binary_entry.get("programs") or []),
            "entries": [],
        }
    if not path.is_dir():
        return {"ok": False, "error": "path is not a directory or .gpr", "path": str(path), "parent": "", "entries": []}
    entries: list[dict[str, object]] = []
    try:
        children = list(path.iterdir())
    except OSError as exc:
        return {"ok": False, "error": str(exc), "path": str(path), "parent": str(path.parent), "entries": []}
    children.sort(key=lambda item: (not item.is_dir(), item.name.lower()))
    for child in children:
        if child.name.startswith("."):
            continue
        try:
            if child.is_file() and child.suffix.lower() == ".gpr":
                entries.append({
                    "name": child.name,
                    "kind": "gpr",
                    "path": str(child),
                    "programs": list_local_programs(child),
                })
                continue
            binary = _browse_binary_entry(child)
            if binary is not None:
                entries.append(binary)
                continue
            if child.is_dir():
                shared = inspect_shared_fs(child)
                if shared is not None:
                    entries.append({
                        "name": child.name,
                        "kind": "shared-fs",
                        "path": str(child),
                        "programs": list(shared.get("programs") or []),
                    })
                    continue
                gpr = find_gpr(child)
                entries.append({
                    "name": child.name,
                    "kind": "project-dir" if gpr is not None else "dir",
                    "path": str(child),
                    "programs": list_local_programs(gpr) if gpr is not None else [],
                })
        except OSError:
            continue
    return {
        "ok": True,
        "path": str(path),
        "parent": str(path.parent),
        "kind": "ghidra-project" if find_gpr(path) is not None else "dir",
        "programs": list_local_programs(find_gpr(path)) if find_gpr(path) is not None else [],
        "entries": entries,
    }


_SKIP_WALK = {
    "node_modules", ".git", ".cache", "__pycache__", "proc", "sys", "dev",
}


def parse_index_dat(text: str) -> dict[str, object]:
    folders: list[str] = []
    programs: list[dict[str, str]] = []
    current = "/"
    for raw in (text or "").splitlines():
        line = raw.rstrip()
        if not line or line.startswith(("VERSION", "NEXT-ID", "MD5")):
            continue
        if line.startswith("/"):
            current = line.strip()
            folders.append(current)
            continue
        parts = line.strip().split(":")
        if len(parts) >= 2 and parts[0]:
            programs.append({"id": parts[0], "name": parts[1], "folder": current})
    return {"folders": folders, "programs": programs}


def _server_usernames(path: Path) -> list[str]:
    names: list[str] = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            name = line.split(":", 1)[0].strip()
            if name:
                names.append(name)
    except OSError:
        return names
    return names


def _repo_listing(root: Path) -> dict[str, object] | None:
    """One item-filesystem root: real ``.prp`` items, else ``~index.dat`` names."""
    from agentdecompile_recovery.ghidra_db.store import list_store_programs

    items: list[dict[str, object]] = []
    folders: list[str] = []
    try:
        entries = list_store_programs(root)
    except (OSError, ValueError):
        entries = []
    for entry in entries:
        items.append(
            {
                "id": entry.storage_name,
                "name": entry.name,
                "folder": entry.folder_path or "/",
                "path": entry.project_path,
                "file_id": entry.file_id or "",
                "version": entry.version,
            }
        )
        folders.append(entry.folder_path or "/")
    index = root / "~index.dat"
    if not items and index.is_file():
        parsed = parse_index_dat(index.read_text(encoding="utf-8", errors="replace"))
        items = [dict(item) for item in parsed.get("programs") or [] if isinstance(item, dict)]
        folders = [str(folder) for folder in parsed.get("folders") or []]
    if not items and not index.is_file():
        return None
    names = [str(item.get("name") or "") for item in items if item.get("name")]
    return {
        "name": root.name.lstrip("_") or root.name,
        "path": str(root),
        "programs": items,
        "folders": sorted(set(folders)),
        "names": names,
    }


def inspect_shared_fs(path: Path) -> dict[str, object] | None:
    try:
        root = Path(path).expanduser().resolve()
    except OSError:
        return None
    if not root.is_dir():
        return None
    from agentdecompile_recovery.ghidra_db.store import store_roots

    repos: list[dict[str, object]] = []
    programs: list[str] = []
    roots = store_roots(root)
    if not roots:
        if (root / "~index.dat").is_file():
            roots = [root]
        else:
            try:
                children = list(root.iterdir())
            except OSError:
                return None
            roots = [
                child
                for child in children
                if child.is_dir() and child.name.startswith("_") and (child / "~index.dat").is_file()
            ]
    for repo_root in roots:
        listing = _repo_listing(repo_root)
        if listing is None:
            continue
        programs.extend(str(name) for name in listing.pop("names") or [])
        repos.append(listing)
    users = root / "users"
    has_users = users.is_file()
    has_log = (root / "server.log").is_file()
    if not repos:
        return None
    paths: dict[str, str] = {}
    for repo in repos:
        for item in repo.get("programs") or []:
            if not isinstance(item, dict) or not item.get("name"):
                continue
            name = str(item["name"])
            folder = str(item.get("folder") or "/").rstrip("/")
            qualified = str(item.get("path") or (f"{folder}/{name}" if folder else f"/{name}"))
            paths[name] = qualified
            paths[qualified] = qualified
    return {
        "kind": "shared-fs",
        "access": "fs",
        "requires_server": False,
        "path": str(root),
        "locator": str(root),
        "canonical": str(root),
        "slug": root.name,
        "programs": programs,
        "program_paths": paths,
        "repositories": repos,
        "users": _server_usernames(users) if has_users else [],
        "has_server_log": has_log,
    }


def _stat_brief(path: Path) -> dict[str, object]:
    try:
        st = path.stat()
    except OSError:
        return {"path": str(path), "exists": False}
    return {
        "path": str(path),
        "exists": True,
        "size": int(st.st_size),
        "mtime": int(st.st_mtime),
    }


def _bind_shared_project_to_fs(repository: str) -> dict[str, object] | None:
    """Map ``ghidra://…/Repo`` to an on-disk server repository when one exists."""
    name = (repository or "").strip().lstrip("_")
    if not name:
        return None
    wanted = name.lower()
    for root in search_roots():
        direct = root / f"_{name}"
        if not direct.is_dir():
            direct = root / name
        if direct.is_dir():
            hit = inspect_shared_fs(direct)
            if hit:
                return hit
        parent = inspect_shared_fs(root)
        if not parent:
            continue
        for repo in parent.get("repositories") or []:
            if not isinstance(repo, dict):
                continue
            label = str(repo.get("name") or "")
            folder = Path(str(repo.get("path") or "")).name
            if label.lower() == wanted or folder.lstrip("_").lower() == wanted:
                child = inspect_shared_fs(Path(str(repo.get("path") or "")))
                return child or parent
        labels = [
            str(repo.get("name") or Path(str(repo.get("path") or "")).name).lstrip("_").lower()
            for repo in (parent.get("repositories") or [])
            if isinstance(repo, dict)
        ]
        if wanted in labels:
            return parent
    return None


def inspect_locator(raw: str) -> dict[str, object]:
    info = classify_locator(raw)
    kind = str(info.get("kind") or "empty")
    if kind == "empty":
        return {"ok": False, **info}
    out = dict(info)
    out["ok"] = True
    gpr = out.get("gpr")
    if isinstance(gpr, Path):
        out["gpr"] = str(gpr)
        rep = gpr.with_suffix(".rep")
        out["rep"] = str(rep)
        out["gpr_stat"] = _stat_brief(gpr)
        out["rep_stat"] = _stat_brief(rep)
        files: list[dict[str, object]] = [out["gpr_stat"]]
        if rep.is_dir():
            try:
                for child in sorted(rep.iterdir(), key=lambda p: p.name.lower())[:80]:
                    files.append(_stat_brief(child))
            except OSError:
                pass
        out["files"] = files
        out["program_count"] = len(out.get("programs") or [])
    if kind == "ghidra-project":
        out["access"] = "local"
    if kind in ("binary", "packed-program"):
        loc = Path(str(out.get("locator") or raw))
        out["access"] = "local"
        out["files"] = [_stat_brief(loc)]
        if kind == "packed-program":
            try:
                from agentdecompile_recovery.ghidra_db.packed import read_packed_header

                header = read_packed_header(loc)
                out["packed"] = header.to_json()
                if header.item_name:
                    out["programs"] = [header.item_name]
                    out["slug"] = header.item_name
            except Exception:
                pass
    if kind == "shared-fs":
        out["program_count"] = len(out.get("programs") or [])
        out["repository_count"] = len(out.get("repositories") or [])
        out["access"] = "fs"
        paths = {}
        for name in out.get("programs") or []:
            if isinstance(name, str) and name:
                paths[name] = ghidra_program_path(out, name)
        if paths:
            out["program_paths"] = paths
    if kind == "shared-project":
        host = str(out.get("host") or "")
        port = int(out.get("port") or 0)
        reachable = False
        if host and port:
            try:
                import socket

                with socket.create_connection((host, port), timeout=1.2):
                    reachable = True
            except OSError:
                reachable = False
        out["reachable"] = reachable
        out["access"] = "rmi"
        out["protocol"] = "ghidra-rmi-ssl"
        out["ports"] = [port, port + 1, port + 2] if port else []
        out["portRoles"] = {
            "registry": port,
            "rmiSsl": port + 1,
            "blockStream": port + 2,
        } if port else {}
        out["requires_server"] = True
        out["connected"] = False
        out["user"] = str(shared_defaults().get("user") or "")
        bound = _bind_shared_project_to_fs(str(out.get("repository") or ""))
        if bound:
            out["ghidra_locator"] = str(out.get("canonical") or raw)
            out["filesystem_mirror"] = {
                "kind": bound.get("kind"),
                "locator": bound.get("locator") or bound.get("path"),
                "programs": list(bound.get("programs") or []),
                "repositories": list(bound.get("repositories") or []),
            }
            if not out.get("programs") and bound.get("programs"):
                out["programs"] = list(bound.get("programs") or [])
            out["program_count"] = len(out.get("programs") or [])
            if bound.get("program_paths"):
                out["program_paths"] = bound.get("program_paths")
            out["mirror_available"] = True
            out["note"] = (
                "This is a Ghidra Server (RMI) locator. "
                "A local repository copy is bound for listing."
            )
            if origin := _read_origin_for(bound):
                out["origin"] = origin
    origin = _read_origin_for(out)
    if origin:
        out["origin"] = origin
        if not out.get("programs") and origin.get("programs"):
            out["programs"] = list(origin.get("programs") or [])
            out["program_count"] = len(out["programs"])
        if origin.get("note"):
            out["origin_note"] = origin["note"]
    return out


def _walk_hits(root: Path, filename: str, *, max_depth: int = 5) -> list[Path]:
    hits: list[Path] = []
    try:
        base = root.resolve()
    except OSError:
        return hits
    if not base.is_dir():
        return hits
    for dirpath, dirnames, filenames in os.walk(base):
        rel = Path(dirpath)
        try:
            depth = len(rel.relative_to(base).parts)
        except ValueError:
            dirnames.clear()
            continue
        if depth >= max_depth:
            dirnames.clear()
            continue
        dirnames[:] = [name for name in dirnames if name not in _SKIP_WALK and not name.startswith(".")]
        if filename in filenames:
            hits.append(Path(dirpath) / filename)
        if len(hits) >= 20:
            break
    return hits


def search_roots(work_dir: Path | None = None) -> list[Path]:
    roots: list[Path] = []
    extra = (os.environ.get("AGENT_DECOMPILE_GHIDRA_REPOS_DIR") or "").strip()
    for cand in (
        work_dir,
        Path.cwd(),
        Path(work_dir) / "ghidra-projects" if work_dir is not None else None,
        Path(extra) if extra else None,
        Path.home() / "biodecompwarehouse" / "repos",
        Path.home() / "biodecompwarehouse" / "projects",
        Path.home() / "agentdecompile_projects",
    ):
        if cand is None:
            continue
        try:
            path = Path(cand).expanduser().resolve()
        except OSError:
            continue
        if path.is_dir() and path not in roots:
            roots.append(path)
    return roots


def _sanitize_path_component(name: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in (name or "").strip())
    return cleaned or "file"


def _sanitize_relative_path(rel: str) -> Path:
    parts = [part for part in Path(rel).parts if part and part not in (".", "..")]
    if not parts:
        return Path(_sanitize_path_component(Path(rel).name))
    return Path(*[_sanitize_path_component(part) for part in parts])


def stage_drop_files(work_dir: Path, items: list[tuple[str, bytes]]) -> dict[str, object]:
    """Write browser-dropped files under ``drop-staging/{id}/`` preserving relative paths."""
    staging_id = f"drop-{int(time.time() * 1000)}"
    root = Path(work_dir) / "drop-staging" / staging_id
    relative_paths: list[str] = []
    for rel_path, data in items:
        safe = _sanitize_relative_path(rel_path)
        dest = root / safe
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        relative_paths.append(str(safe).replace("\\", "/"))
    return {
        "ok": True,
        "staging_id": staging_id,
        "root": str(root),
        "relative_paths": relative_paths,
    }


def _drop_search_roots(work_dir: Path | None, staging_root: Path | None) -> list[Path]:
    roots: list[Path] = []
    if staging_root is not None:
        try:
            staged = Path(staging_root).expanduser().resolve()
        except OSError:
            staged = None
        if staged is not None and staged.is_dir() and staged not in roots:
            roots.append(staged)
    for root in search_roots(work_dir):
        if root not in roots:
            roots.append(root)
    return roots


def resolve_drop(
    *,
    name: str = "",
    relative_paths: list[str] | None = None,
    work_dir: Path | None = None,
    staging_root: Path | None = None,
) -> dict[str, object]:
    rels = [item for item in (relative_paths or []) if item]
    filename = Path(name or (rels[0] if rels else "")).name
    roots = _drop_search_roots(work_dir, staging_root)
    if any(part == "users" or part.endswith("~index.dat") for item in rels for part in Path(item).parts):
        marker = next((Path(item).parts[0] for item in rels if item.startswith("_") or item.split("/")[0].startswith("_")), "")
        for root in roots:
            if (root / "users").is_file() and inspect_shared_fs(root):
                return {"ok": True, **inspect_locator(str(root))}
            if marker:
                hits = _walk_hits(root, "~index.dat")
                for hit in hits:
                    if hit.parent.name == marker or hit.parent.name.startswith("_"):
                        cand = hit.parent.parent if (hit.parent.parent / "users").is_file() else hit.parent
                        info = inspect_locator(str(cand))
                        if info.get("ok"):
                            return info
    if filename.lower().endswith(".gpr"):
        hits = []
        for root in roots:
            hits.extend(_walk_hits(root, filename))
        unique = list(dict.fromkeys(hits))
        if len(unique) == 1:
            return inspect_locator(str(unique[0]))
        if unique:
            return {
                "ok": False,
                "error": "several matching .gpr files",
                "candidates": [str(item) for item in unique[:12]],
            }
        return {"ok": False, "error": f"no on-disk project named {filename}"}
    if filename.lower().endswith(".rep") or any(".rep" in Path(item).parts[0] for item in rels if Path(item).parts):
        stem = filename[:-4] if filename.lower().endswith(".rep") else Path(rels[0]).parts[0][:-4]
        return resolve_drop(name=stem + ".gpr", work_dir=work_dir)
    return {"ok": False, "error": "drop a .gpr, a .rep folder, or a shared-server repos folder"}


def create_local_project(name: str, *, work_dir: Path, destination: Path | None = None) -> dict[str, object]:
    stem = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in (name or "").strip()) or "Project"
    folder = destination if destination is not None else Path(work_dir) / "ghidra-projects"
    folder.mkdir(parents=True, exist_ok=True)
    gpr = folder / f"{stem}.gpr"
    index = 2
    while gpr.exists():
        gpr = folder / f"{stem}-{index}.gpr"
        index += 1
    gpr.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n<FILE_INFO>\n  <BASIC_INFO>\n'
        "    <CREATE_DATE>0</CREATE_DATE>\n  </BASIC_INFO>\n</FILE_INFO>\n",
        encoding="utf-8",
    )
    rep = gpr.with_suffix(".rep")
    for sub in ("idata", "user", "versioned"):
        (rep / sub).mkdir(parents=True, exist_ok=True)
    return inspect_locator(str(gpr))


def _safe_stem(name: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in (name or "").strip()) or "Project"


def _unique_gpr(folder: Path, stem: str) -> Path:
    gpr = folder / f"{stem}.gpr"
    index = 2
    while gpr.exists():
        gpr = folder / f"{stem}-{index}.gpr"
        index += 1
    return gpr


def _store_has_programs(locator: str) -> bool:
    from agentdecompile_recovery.ghidra_db.store import list_store_programs

    try:
        return bool(list_store_programs(locator))
    except (OSError, ValueError):
        return False


def _program_names(info: dict[str, object]) -> list[str]:
    names: list[str] = []
    for item in info.get("programs") or []:
        if isinstance(item, str) and item:
            names.append(item)
        elif isinstance(item, dict) and item.get("name"):
            names.append(str(item["name"]))
    return names


def _origin_payload(source: dict[str, object], target: str) -> dict[str, object]:
    return {
        "saved_as": target,
        "source_kind": source.get("kind"),
        "source_locator": source.get("locator") or source.get("path") or "",
        "source_canonical": source.get("canonical") or "",
        "source_access": source.get("access") or "",
        "programs": _program_names(source),
        "repositories": list(source.get("repositories") or []),
        "host": source.get("host"),
        "port": source.get("port"),
        "repository": source.get("repository"),
        "saved_at": int(time.time()),
    }


def _write_origin(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _read_origin(path: Path) -> dict[str, object] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _read_origin_for(info: dict[str, object]) -> dict[str, object] | None:
    kind = str(info.get("kind") or "")
    if kind == "ghidra-project" and info.get("rep"):
        return _read_origin(Path(str(info["rep"])) / "user" / "origin.json")
    if kind == "shared-fs" and (info.get("path") or info.get("locator")):
        return _read_origin(Path(str(info.get("path") or info.get("locator"))) / "origin.json")
    return None


def _write_index_dat(path: Path, programs: list[str]) -> None:
    lines = ["VERSION=1", "/"]
    for index, name in enumerate(programs, start=1):
        lines.append(f"  {index:08d}:{name}:")
    lines.append(f"NEXT-ID:{len(programs) + 1}")
    lines.append("MD5:0")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _copy_gpr_rep(src_gpr: Path, dest_gpr: Path) -> None:
    dest_gpr.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src_gpr, dest_gpr)
    src_rep = src_gpr.with_suffix(".rep")
    dest_rep = dest_gpr.with_suffix(".rep")
    if dest_rep.exists():
        shutil.rmtree(dest_rep)
    if src_rep.is_dir():
        shutil.copytree(src_rep, dest_rep)
    else:
        for sub in ("idata", "user", "versioned"):
            (dest_rep / sub).mkdir(parents=True, exist_ok=True)


def _allowed_dest(path: Path, work_dir: Path) -> bool:
    try:
        resolved = path.expanduser().resolve()
    except OSError:
        return False
    bases = [Path(work_dir).resolve()]
    bases.extend(search_roots(work_dir))
    for base in bases:
        try:
            resolved.relative_to(base)
            return True
        except ValueError:
            continue
    return False


def _path_within(path: Path, base: Path) -> bool:
    try:
        path.expanduser().resolve().relative_to(base.expanduser().resolve())
        return True
    except (OSError, ValueError):
        return False


def _write_skeleton_gpr(gpr: Path) -> None:
    gpr.parent.mkdir(parents=True, exist_ok=True)
    gpr.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n<FILE_INFO>\n  <BASIC_INFO>\n'
        "    <CREATE_DATE>0</CREATE_DATE>\n  </BASIC_INFO>\n</FILE_INFO>\n",
        encoding="utf-8",
    )
    rep = gpr.with_suffix(".rep")
    for sub in ("idata", "user", "versioned"):
        (rep / sub).mkdir(parents=True, exist_ok=True)


def save_project(locator: str, *, work_dir: Path) -> dict[str, object]:
    text = (locator or "").strip()
    if not text:
        created = create_local_project("Untitled", work_dir=work_dir)
        created["saved"] = True
        return created
    info = inspect_locator(text)
    if not info.get("ok"):
        return info
    origin = _origin_payload(info, str(info.get("kind") or ""))
    origin["saved"] = True
    kind = str(info.get("kind") or "")
    if kind == "ghidra-project" and info.get("rep"):
        _write_origin(Path(str(info["rep"])) / "user" / "origin.json", origin)
    elif kind == "shared-fs" and (info.get("path") or info.get("locator")):
        _write_origin(Path(str(info.get("path") or info.get("locator"))) / "origin.json", origin)
    else:
        folder = Path(work_dir) / "ghidra-projects"
        folder.mkdir(parents=True, exist_ok=True)
        sidecar = folder / f"{_safe_stem(str(info.get('slug') or 'shared'))}.remote.json"
        _write_origin(sidecar, origin)
        info["origin_file"] = str(sidecar)
    refreshed = inspect_locator(str(info.get("locator") or text))
    refreshed["saved"] = True
    return refreshed


def save_project_as(
    locator: str,
    *,
    target: str,
    name: str = "",
    dest: str = "",
    url: str = "",
    work_dir: Path,
) -> dict[str, object]:
    kind = (target or "").strip()
    if kind not in SAVE_KINDS:
        return {"ok": False, "error": "Save As target must be ghidra-project, shared-fs, or shared-project"}
    source = (
        inspect_locator(locator)
        if (locator or "").strip()
        else {"ok": True, "kind": "draft", "programs": [], "locator": "", "slug": name or "Project"}
    )
    if (locator or "").strip() and not source.get("ok"):
        return source
    stem = _safe_stem(name or str(source.get("slug") or "Project"))
    origin = _origin_payload(source, kind)
    dest_text = (dest or "").strip()
    dest_path = Path(dest_text).expanduser() if dest_text else None
    if dest_path is not None and not _allowed_dest(dest_path, work_dir):
        return {"ok": False, "error": "Save As path must be inside the work directory or a known project root"}

    if kind == "ghidra-project":
        folder = dest_path if dest_path is not None else Path(work_dir) / "ghidra-projects"
        if folder.suffix.lower() == ".gpr":
            dest_gpr = folder
            folder = dest_gpr.parent
        else:
            dest_gpr = _unique_gpr(folder, stem)
        folder.mkdir(parents=True, exist_ok=True)
        src_gpr = source.get("gpr")
        src_kind = str(source.get("kind") or "")
        src_loc = str(source.get("locator") or locator or "")
        if src_kind == "ghidra-project" and src_gpr and Path(str(src_gpr)).is_file():
            _copy_gpr_rep(Path(str(src_gpr)), dest_gpr)
            origin["note"] = "Copied local Ghidra project files (.gpr and .rep)."
        elif src_kind == "shared-fs" and src_loc and _store_has_programs(src_loc):
            from agentdecompile_recovery.ghidra_db.store import materialize_local_project, ProjectLayoutError

            try:
                materialize_local_project(src_loc, dest_gpr)
            except (OSError, ValueError, ProjectLayoutError) as exc:
                return {"ok": False, "error": str(exc)}
            origin["note"] = (
                "Copied program databases from the filesystem store into .rep/versioned. "
                "No Ghidra server was used."
            )
        else:
            _write_skeleton_gpr(dest_gpr)
            if src_kind == "shared-project":
                origin["note"] = (
                    "Local checkout of a Ghidra Server (RMI) locator. "
                    "Program databases were not downloaded; open-project still uses the source locator."
                )
            elif src_kind == "shared-fs":
                origin["note"] = (
                    "Local checkout of a filesystem shared-server tree. "
                    "Program names came from ~index.dat."
                )
            else:
                origin["note"] = "New local Ghidra project."
        _write_origin(dest_gpr.with_suffix(".rep") / "user" / "origin.json", origin)
        out = inspect_locator(str(dest_gpr))
        out["converted_from"] = source.get("kind")
        return out

    if kind == "shared-fs":
        root = dest_path if dest_path is not None else Path(work_dir) / "shared-exports" / stem
        existing = inspect_shared_fs(root) if root.is_dir() else None
        if existing is None:
            root.mkdir(parents=True, exist_ok=True)
            users = root / "users"
            if not users.is_file():
                users.write_text("# usernames only; no passwords stored\n", encoding="utf-8")
        repo_dir = root / f"_{stem}"
        index = 2
        while repo_dir.exists():
            repo_dir = root / f"_{stem}-{index}"
            index += 1
        src_loc = str(source.get("locator") or locator or "")
        if src_loc and _store_has_programs(src_loc):
            from agentdecompile_recovery.ghidra_db.store import materialize_server_repo

            materialize_server_repo(src_loc, repo_dir, name=stem)
            origin["note"] = (
                "Wrote a Ghidra-server-shaped repository and copied program databases. "
                "No Ghidra server was used."
            )
        else:
            _write_index_dat(repo_dir / "~index.dat", _program_names(source))
            origin["note"] = (
                "Wrote a Ghidra-server-shaped index checkout. "
                "This is not a live server publish; versioned program DBs were not uploaded."
            )
        _write_origin(root / "origin.json", origin)
        out = inspect_locator(str(root))
        out["converted_from"] = source.get("kind")
        return out

    remote = (url or dest_text or "").strip()
    if not remote:
        return {"ok": False, "error": "Save As HTTP needs a ghidra:// or http(s) URL"}
    if not is_shared_locator(remote):
        return {"ok": False, "error": "Save As HTTP URL must be ghidra://, http://, or https://"}
    classified = inspect_locator(remote)
    if not classified.get("ok"):
        return classified
    # HTTP Save As is a reopenable ghidra:// bookmark plus a tiny .gpr stub.
    # Never copy program databases here — a bound shared-fs repo can be tens of
    # gigabytes, and an unbound URL has nothing on disk to copy.
    folder = Path(work_dir) / "ghidra-projects"
    dest_gpr = _unique_gpr(folder, stem)
    _write_skeleton_gpr(dest_gpr)
    http_locator = str(
        classified.get("http_locator") or classified.get("canonical") or remote
    )
    origin["http_locator"] = http_locator
    origin["bound_locator"] = classified.get("locator") if classified.get("kind") == "shared-fs" else ""
    origin["local_locator"] = str(dest_gpr)
    origin["programs"] = _program_names(classified)
    if classified.get("kind") == "shared-fs" or classified.get("requires_server") is False:
        origin["note"] = (
            "Linked ghidra:// to the on-disk repository. "
            "Program databases were not copied. No Ghidra server is required."
        )
    else:
        origin["note"] = (
            "Linked a Ghidra Server (RMI) locator and wrote a local checkout stub "
            "so the project can be reopened. Program databases were not downloaded."
        )
    _write_origin(dest_gpr.with_suffix(".rep") / "user" / "origin.json", origin)
    out = dict(classified)
    out["origin"] = origin
    out["local_checkout"] = str(dest_gpr)
    out["http_locator"] = http_locator
    out["converted_from"] = source.get("kind")
    out["saved"] = True
    return out


def session_store_path(work_dir: Path | None) -> Path | None:
    if work_dir is None:
        return None
    return Path(work_dir) / "workbench-sessions.json"


def load_sessions(work_dir: Path | None) -> dict[str, object]:
    path = session_store_path(work_dir)
    empty = {"revision": 0, "active": "", "sessions": []}
    if path is None or not path.is_file():
        return empty
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return empty
    sessions = list(data.get("sessions") or [])
    active = str(data.get("active") or "")
    if sessions and not any(item.get("id") == active for item in sessions):
        active = str(sessions[0].get("id") or "")
    revision = int(data.get("revision") or 0)
    return {"revision": revision, "active": active, "sessions": sessions}


def _normalize_import(item: object) -> str:
    if isinstance(item, str):
        return item.strip()
    if isinstance(item, dict):
        for field in ("slug", "id", "name"):
            value = item.get(field)
            if value:
                return str(value).strip()
    return ""


def _coerce_imports(items: list[object]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        normalized = _normalize_import(item)
        if normalized and normalized not in seen:
            seen.add(normalized)
            out.append(normalized)
    return out


def _import_key(item: object) -> str:
    if isinstance(item, str):
        return item.strip()
    if not isinstance(item, dict):
        return json.dumps(item, sort_keys=True, default=str)
    normalized = _normalize_import(item)
    if normalized:
        return normalized
    for field in ("path", "locator"):
        value = item.get(field)
        if value:
            return str(value)
    return json.dumps(item, sort_keys=True, default=str)


def merge_session_records(
    stored_sessions: list[dict[str, object]],
    incoming_sessions: list[dict[str, object]],
) -> list[dict[str, object]]:
    stored_by_id = {
        str(item.get("id")): dict(item)
        for item in stored_sessions
        if item.get("id")
    }
    merged: list[dict[str, object]] = []
    seen: set[str] = set()
    for session in incoming_sessions:
        sid = str(session.get("id") or "")
        if not sid:
            continue
        base = stored_by_id.get(sid, {})
        merged_session = dict(base)
        merged_session.update(session)
        stored_imports = list(base.get("imports") or [])
        incoming_imports = list(session.get("imports") or [])
        if stored_imports or incoming_imports:
            imports: dict[str, object] = {}
            for item in stored_imports:
                imports[_import_key(item)] = item
            for item in incoming_imports:
                imports[_import_key(item)] = item
            merged_session["imports"] = _coerce_imports(list(imports.values()))
        elif merged_session.get("imports"):
            merged_session["imports"] = _coerce_imports(list(merged_session.get("imports") or []))
        merged.append(merged_session)
        seen.add(sid)
    for session in stored_sessions:
        sid = str(session.get("id") or "")
        if sid and sid not in seen:
            copy = dict(session)
            if copy.get("imports"):
                copy["imports"] = _coerce_imports(list(copy.get("imports") or []))
            merged.append(copy)
    return merged


def _normalize_session_imports(sessions: list[dict[str, object]]) -> list[dict[str, object]]:
    normalized: list[dict[str, object]] = []
    for session in sessions:
        copy = dict(session)
        if copy.get("imports"):
            copy["imports"] = _coerce_imports(list(copy.get("imports") or []))
        normalized.append(copy)
    return normalized


def save_sessions(work_dir: Path | None, payload: dict[str, object]) -> dict[str, object]:
    path = session_store_path(work_dir)
    if path is None:
        return {"ok": False, "error": "AGENT_DECOMPILE_CORPUS_WORK_DIR is unset"}
    stored = load_sessions(work_dir)
    revision = int(stored.get("revision") or 0) + 1
    sessions = _normalize_session_imports(list(payload.get("sessions") or []))
    out = {
        "revision": revision,
        "active": str(payload.get("active") or ""),
        "sessions": sessions,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    return {"ok": True, **out}


def save_sessions_merged(work_dir: Path | None, payload: dict[str, object]) -> dict[str, object]:
    path = session_store_path(work_dir)
    if path is None:
        return {"ok": False, "error": "AGENT_DECOMPILE_CORPUS_WORK_DIR is unset"}
    stored = load_sessions(work_dir)
    stored_revision = int(stored.get("revision") or 0)
    client_revision = payload.get("revision")
    sessions = list(payload.get("sessions") or [])
    active = str(payload.get("active") or stored.get("active") or "")
    merged = False
    if client_revision is not None and int(client_revision) != stored_revision:
        sessions = merge_session_records(list(stored.get("sessions") or []), sessions)
        merged = True
    else:
        sessions = _normalize_session_imports(sessions)
    revision = stored_revision + 1
    out = {"revision": revision, "active": active, "sessions": sessions}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    result: dict[str, object] = {"ok": True, **out}
    if merged:
        result["merged"] = True
    return result


def _draft_session_item() -> dict[str, object]:
    return {
        "id": f"s{int(time.time() * 1000)}",
        "title": "Untitled",
        "kind": "draft",
        "locator": "",
        "projectSlug": "",
        "imports": [],
        "program": "",
        "created": int(time.time()),
    }


def fresh_draft_session(work_dir: Path | None) -> dict[str, object]:
    """Replace session state with a single new draft tab (explicit reset)."""
    item = _draft_session_item()
    payload = {"active": item["id"], "sessions": [item]}
    saved = save_sessions(work_dir, payload)
    if not saved.get("ok"):
        return {"ok": True, **payload}
    return saved


def ensure_draft_session(work_dir: Path | None) -> dict[str, object]:
    data = load_sessions(work_dir)
    sessions = list(data.get("sessions") or [])
    if sessions:
        return {"ok": True, **data}
    return fresh_draft_session(work_dir)
