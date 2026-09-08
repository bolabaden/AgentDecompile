"""Shared bootstrap for talking to Ghidra / a configured server.

Workspace and project paths are arguments or ``AGENT_DECOMPILE_PROJECT_PATH``.
There is no kotorxid/repo-root default. ``start()`` boots pyghidra if needed
and returns False when Ghidra is unavailable.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path

from .corpus_config import load_ghidra_server

_STARTED = False
_ROOT = None
_WRAPPED = None
_CONSUMER = None


def resolve_workspace(path: Path | str | None = None) -> Path:
    """Resolve the project workspace. Argument or AGENT_DECOMPILE_PROJECT_PATH."""
    if path is not None:
        return Path(path)
    env = os.environ.get("AGENT_DECOMPILE_PROJECT_PATH", "").strip()
    if env:
        return Path(env)
    raise ValueError("workspace path required (argument or AGENT_DECOMPILE_PROJECT_PATH)")


def pyghidra_available() -> bool:
    try:
        import pyghidra  # noqa: F401
    except ImportError:
        return False
    return True


def start(max_heap: str = "4g", *, install_dir: str | None = None, project_path: Path | str | None = None) -> bool:
    """Boot the JVM with Ghidra. Returns False when pyghidra/install is missing."""
    global _STARTED
    if _STARTED:
        return True
    ghidra_install = install_dir or os.environ.get("GHIDRA_INSTALL_DIR", "").strip()
    if not ghidra_install or not pyghidra_available():
        return False
    if project_path is not None:
        resolve_workspace(project_path)
    os.environ.setdefault("GHIDRA_INSTALL_DIR", ghidra_install)
    java_home = os.environ.get("JAVA_HOME", "").strip()
    if java_home:
        os.environ.setdefault("JAVA_HOME", java_home)
    os.environ["JDK_JAVA_OPTIONS"] = "-XX:-UseContainerSupport"
    os.environ.setdefault("_JAVA_OPTIONS", f"-Xmx{max_heap} -XX:-UseContainerSupport")

    import pyghidra

    pyghidra.start(verbose=False, install_dir=ghidra_install)

    from ghidra.framework.client import HeadlessClientAuthenticator

    cfg = load_ghidra_server()
    user = str(cfg.get("username") or "")
    key = str(cfg.get("ssh_key") or "")
    if user and key:
        HeadlessClientAuthenticator.installHeadlessClientAuthenticator(user, key, False)
    _STARTED = True
    return True


def monitor():
    from ghidra.util.task import TaskMonitor

    return TaskMonitor.DUMMY


def consumer():
    global _CONSUMER
    if _CONSUMER is None:
        from java.lang import Object  # type: ignore

        _CONSUMER = Object()
    return _CONSUMER


def repo_url(path: str = "/", *, config_dir_path=None):
    from ghidra.framework.protocol.ghidra import GhidraURL

    cfg = load_ghidra_server(config_dir_path)
    return GhidraURL.makeURL(str(cfg["host"]), int(cfg["port"] or 0), str(cfg["repository"] or ""), path)


def root_folder():
    global _ROOT, _WRAPPED
    if _ROOT is not None:
        return _ROOT
    if start() is False:
        return None
    conn = repo_url("/").openConnection()
    conn.setReadOnly(True)
    _WRAPPED = conn.getContent()
    _ROOT = _WRAPPED.getContent(consumer())
    return _ROOT


def list_files() -> list[dict]:
    folder = root_folder()
    if folder is None:
        return []
    out: list[dict] = []

    def walk(node, prefix):
        for f in node.getFiles():
            out.append(
                {
                    "path": f"{prefix}/{f.getName()}",
                    "name": str(f.getName()),
                    "content_type": str(f.getContentType()),
                    "version": int(f.getLatestVersion()),
                    "file_id": str(f.getFileID()),
                }
            )
        for sub in node.getFolders():
            walk(sub, f"{prefix}/{sub.getName()}")

    walk(folder, "")
    return sorted(out, key=lambda r: r["path"])


def domain_file(repo_path: str):
    folder = root_folder()
    if folder is None:
        raise FileNotFoundError(repo_path)
    parts = [p for p in repo_path.split("/") if p]
    for part in parts[:-1]:
        folder = folder.getFolder(part)
        if folder is None:
            raise FileNotFoundError(repo_path)
    df = folder.getFile(parts[-1])
    if df is None:
        raise FileNotFoundError(repo_path)
    return df


@contextlib.contextmanager
def open_program(repo_path: str | None, version: int = -1, *, project_path: Path | str | None = None):
    """Open a program read-only. Yields None when *repo_path* is missing or Ghidra is down."""
    del project_path
    if not repo_path:
        yield None
        return
    if repo_path.startswith("local:"):
        with open_local_program(repo_path) as program:
            yield program
        return
    if start() is False:
        yield None
        return
    df = domain_file(repo_path)
    c = consumer()
    program = df.getImmutableDomainObject(c, version, monitor())
    try:
        yield program
    finally:
        program.release(c)


@contextlib.contextmanager
def open_local_program(ref: str):
    """Open ``local:<project_dir>:<project_name>:/<program path>``."""
    if start() is False:
        yield None
        return
    from ghidra.base.project import GhidraProject  # type: ignore

    _, proj_dir, proj_name, prog_path = ref.split(":", 3)
    project = GhidraProject.openProject(proj_dir, proj_name, False)
    try:
        program = project.openProgram("/", prog_path.lstrip("/"), True)
        try:
            yield program
        finally:
            project.close(program)
    finally:
        project.close()
