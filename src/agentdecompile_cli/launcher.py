"""Merged module: launcher, context, and server entry point.

Merged from:
  - context.py         (ProgramInfo dataclass, PyGhidraContext)
  - launcher.py        (AgentDecompileLauncher, _log_config_block)
  - server.py          (init_agentdecompile_context, _env_port, _env_host, main)

ProjectManager lives in project_manager.py and is re-exported here for backward compatibility.

Python MCP Server launcher for AgentDecompile CLI.
Handles PyGhidra initialization, Python MCP server startup, and project management.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import logging
import multiprocessing
import os
import socket
import sys
import tempfile
import time
import uuid

from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

# Chromadb is optional; semantic search features degrade gracefully when unavailable
try:
    import chromadb

    from chromadb.config import Settings
except Exception:
    chromadb = None  # type: ignore[assignment]
    Settings = None  # type: ignore[assignment]

from agentdecompile_cli.app_logger import basename_hint
from agentdecompile_cli.executor import get_client, normalize_backend_url, run_async

try:
    from ghidrecomp.utility import disable_headless_unsafe_analyzers  # type: ignore[attr-defined]
except (ImportError, AttributeError):

    def disable_headless_unsafe_analyzers(program: GhidraProgram) -> None:
        """No-op when ghidrecomp does not export this (e.g. older or different build)."""
        pass


from agentdecompile_cli.project_manager import ProjectManager
from agentdecompile_cli.registry import Tool
from agentdecompile_cli.tools.wrappers import GhidraTools

if TYPE_CHECKING:
    from ghidra.app.decompiler import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        DecompInterface as GhidraDecompInterface,
    )
    from ghidra.app.util.xml import ProgramInfo as GhidraProgramInfo  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
    from ghidra.base.project import GhidraProject  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
    from ghidra.framework.model import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        DomainFile as GhidraDomainFile,
        DomainFolder as GhidraDomainFolder,
    )
    from ghidra.framework.options import Options as GhidraOptions  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
    from ghidra.program.model.listing import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        Function as GhidraFunction,
        Program as GhidraProgram,
    )

    from agentdecompile_cli.mcp_server import PythonMcpServer  # noqa: F401
    from agentdecompile_cli.models import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        DecompiledFunction,
    )

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helper utilities for common launcher patterns
# ---------------------------------------------------------------------------
# _assert_type: consistent type checks for Program/DomainFile/etc. with clear errors.
# _ensure_directory: mkdir(parents=True, exist_ok=True) and return Path for chaining.


def _assert_type(obj: Any, expected_type: type, name: str) -> None:
    """Assert that an object is of the expected type, raising AssertionError with clear message.

    Consolidates repeated type-checking pattern used in import_binary, delete_program, and
    analyzer methods. Ensures consistent error messages and reduces code duplication across
    ~10+ call sites that manually check isinstance().

    Args:
        obj: The object to validate
        expected_type: The expected type (or tuple of types, e.g., (DomainFile, Folder))
        name: Friendly name for error message (e.g., "Program", "Domain file")

    Raises:
        AssertionError: If type check fails, with clear message showing actual type

    Examples:
        >>> _assert_type(my_program, Program, "Program")
        >>> _assert_type(domain_file, (DomainFile, DomainFolder), "Domain item")
    """
    logger.debug("diag.enter %s", "launcher.py:_assert_type")
    if not isinstance(obj, expected_type):
        type_names = " or ".join(t.__name__ for t in expected_type) if isinstance(expected_type, tuple) else expected_type.__name__
        actual_type = type(obj).__name__
        raise AssertionError(f"{name} is not a {type_names} object (got {actual_type})")


def _ensure_directory(path: Path | str) -> Path:
    """Create directory if it doesn't exist, returning the Path object.

    Consolidates the repeated pattern of mkdir(parents=True, exist_ok=True) that appears
    ~5+ times throughout the launcher initialization code. Returns Path for easy chaining
    with other Path operations, improving readability and reducing boilerplate.

    Args:
        path: Directory path to create (can be str or Path)

    Returns:
        Path object for the created directory (useful for chaining)

    Examples:
        >>> gzfs_path = _ensure_directory(agentdecompile_dir / "gzfs")
        >>> chromadb_path = _ensure_directory("/tmp/chromadb")
    """
    logger.debug("diag.enter %s", "launcher.py:_ensure_directory")
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _patch_project_owner(project_dir: str, project_name: str) -> None:
    """Rewrite the OWNER field in a Ghidra project's ``project.prp`` to match the current JVM user.

    Ghidra records the creating user's ``System.getProperty("user.name")`` as
    `OWNER` inside ``<project>.rep/project.prp``.  When the JVM user name differs
    (e.g. different OS account, uv-cached build env, or renamed Windows profile),
    ``GhidraProject.openProject()`` throws ``NotOwnerException``.

    This helper reads the XML property file, compares the stored owner with the
    current JVM ``user.name``, and rewrites it in-place when they differ, so the
    subsequent ``openProject`` call succeeds for **any** local project regardless
    of which user originally created it.

    Args:
        project_dir: Directory containing the ``.gpr`` marker and ``.rep`` folder.
        project_name: Ghidra project name (stem of the ``.gpr`` file).
    """
    rep_dir = Path(project_dir) / f"{project_name}.rep"
    prp_file = rep_dir / "project.prp"
    if not prp_file.exists():
        return  # nothing to patch

    try:
        from java.lang import System as JavaSystem  # pyright: ignore[reportMissingImports, reportMissingModuleSource]

        jvm_user: str = str(JavaSystem.getProperty("user.name") or "")
        # Ghidra strips spaces from user.name (see DefaultProjectData.getUserName)
        jvm_user = jvm_user.replace(" ", "")
    except Exception:
        return  # JVM not yet available — caller will handle the exception

    if not jvm_user:
        return

    try:
        content = prp_file.read_text(encoding="utf-8")
    except OSError:
        return

    # Quick XML attribute match: VALUE="<owner_name>" on the OWNER STATE line
    import re

    match = re.search(r'<STATE\s+NAME="OWNER"\s+TYPE="string"\s+VALUE="([^"]*)"', content)
    if not match:
        return

    stored_owner = match.group(1)
    if stored_owner == jvm_user:
        return  # already matches

    logger.info(
        "Patching project OWNER in %s: %r -> %r (JVM user.name)",
        prp_file,
        stored_owner,
        jvm_user,
    )
    new_content = content[: match.start(1)] + jvm_user + content[match.end(1) :]
    try:
        prp_file.write_text(new_content, encoding="utf-8")
    except OSError as exc:
        logger.warning("Could not patch project OWNER: %s", exc)


def _copy_locked_project_data(projects_dir: Path, source_name: str, dest_name: str) -> bool:
    """Copy a locked Ghidra project's data to a new destination project.

    When a local project is locked by another JVM instance we cannot open it,
    but we *can* copy its filesystem representation so the fallback project
    starts with the same programs and analysis already present.

    The copy is done at the filesystem level:
    - ``<source_name>.gpr``  → ``<dest_name>.gpr``   (project marker file)
    - ``<source_name>.rep/`` → ``<dest_name>.rep/``   (project database directory)

    Lock artefacts (``*.lock``, ``*.lock~``) are excluded from the copy.
    Individual file-level errors (e.g. exclusive OS file locks held by the
    other JVM on Windows) are tolerated per-file so a partial copy is still
    better than an empty project.

    Args:
        projects_dir: Directory that contains both the source and destination projects.
        source_name: Name of the *locked* (source) project.
        dest_name:   Name of the new (destination) project.

    Returns:
        ``True`` if the copy completed without fatal errors, ``False`` if the
        source project does not exist or a top-level copy error occurred.
        On failure any partial destination files are cleaned up.
    """
    import shutil

    src_gpr = projects_dir / f"{source_name}.gpr"
    src_rep = projects_dir / f"{source_name}.rep"
    dst_gpr = projects_dir / f"{dest_name}.gpr"
    dst_rep = projects_dir / f"{dest_name}.rep"

    if not src_gpr.exists() and not src_rep.is_dir():
        sys.stderr.write(
            f"[_copy_locked_project_data] Source project {source_name!r} not found in {projects_dir!r}; "
            "starting with empty fallback project.\n"
        )
        return False

    def _ignore_locks(directory: str, contents: list[str]) -> list[str]:
        return [f for f in contents if f.endswith(".lock") or f.endswith(".lock~")]

    def _safe_copy2(src: str, dst: str, *, follow_symlinks: bool = True) -> str:
        try:
            shutil.copy2(src, dst, follow_symlinks=follow_symlinks)
        except (PermissionError, OSError) as exc:
            logger.warning(
                "copy_locked_project_skip_file src=%s reason=%s: %s",
                src,
                type(exc).__name__,
                exc,
            )
        return dst

    try:
        if src_rep.is_dir():
            shutil.copytree(src_rep, dst_rep, ignore=_ignore_locks, copy_function=_safe_copy2)
            sys.stderr.write(f"[_copy_locked_project_data] Copied .rep dir: {src_rep} -> {dst_rep}\n")
        if src_gpr.exists():
            shutil.copy2(str(src_gpr), str(dst_gpr))
            sys.stderr.write(f"[_copy_locked_project_data] Copied .gpr marker: {src_gpr} -> {dst_gpr}\n")
        return True
    except Exception as exc:
        logger.warning(
            "copy_locked_project_failed src=%r dest=%r reason=%s: %s",
            source_name,
            dest_name,
            type(exc).__name__,
            exc,
        )
        # Clean up any partial copy so the caller can create a fresh project
        try:
            if dst_rep.exists():
                shutil.rmtree(dst_rep, ignore_errors=True)
            if dst_gpr.exists():
                dst_gpr.unlink(missing_ok=True)
        except Exception:
            pass
        return False


# ---------------------------------------------------------------------------
# Fallback-origin manifest helpers
# ---------------------------------------------------------------------------

_FALLBACK_ORIGINS_FILENAME = ".agdec_fallback_origins.json"


def _fallback_origins_path(projects_dir: Path) -> Path:
    return projects_dir / _FALLBACK_ORIGINS_FILENAME


def _read_fallback_origins(projects_dir: Path) -> dict[str, dict[str, Any]]:
    """Read the fallback-origin manifest from *projects_dir*.

    Returns the manifest dict (keyed by fallback project name) or ``{}`` when
    the manifest file is missing or cannot be parsed.
    """
    manifest_path = _fallback_origins_path(projects_dir)
    try:
        content = manifest_path.read_text(encoding="utf-8")
        data = json.loads(content)
        if isinstance(data, dict):
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def _write_fallback_origins(projects_dir: Path, data: dict[str, Any]) -> None:
    """Atomically write the fallback-origin manifest to *projects_dir*."""
    manifest_path = _fallback_origins_path(projects_dir)
    tmp_path = manifest_path.with_suffix(".json.tmp")
    try:
        tmp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp_path.replace(manifest_path)
    except Exception as exc:
        logger.warning("Could not write fallback origins manifest: %s", exc)
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass


def _record_fallback_origin(projects_dir: Path, original_name: str, fallback_name: str) -> None:
    """Record that *fallback_name* was created as a locked-project fallback for *original_name*.

    Writes/updates ``<projects_dir>/.agdec_fallback_origins.json``.  The entry
    stores the original project name, the UTC creation time, and
    ``reintegrated: false`` so that reintegration tools can later discover and
    merge the fallback's changes back into the original.
    """
    from datetime import datetime, timezone  # noqa: PLC0415

    data = _read_fallback_origins(projects_dir)
    data[fallback_name] = {
        "original_project": original_name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "reintegrated": False,
    }
    _write_fallback_origins(projects_dir, data)
    sys.stderr.write(
        f"[_record_fallback_origin] Recorded fallback {fallback_name!r} -> original {original_name!r} "
        f"in {_fallback_origins_path(projects_dir)}\n"
    )


def _startup_warn_pending_fallbacks(projects_dir: Path, current_project_name: str) -> None:
    """Warn at startup if unintegrated fallback projects exist for *current_project_name*.

    Called when the original (intended) project opens successfully.  Checks the
    manifest for any entry whose ``original_project`` matches *current_project_name*,
    ``reintegrated`` is ``False``, and whose ``.rep/`` directory still exists on
    disk, then emits a WARNING so the user knows to run ``reintegrate-fallback-projects``.
    """
    data = _read_fallback_origins(projects_dir)
    pending = [
        name
        for name, entry in data.items()
        if entry.get("original_project") == current_project_name
        and not entry.get("reintegrated", False)
        and (projects_dir / f"{name}.rep").is_dir()
    ]
    if not pending:
        return
    names_str = ", ".join(repr(n) for n in pending)
    sys.stderr.write(
        f"[launcher.start] WARNING: {len(pending)} unintegrated fallback project(s) exist for "
        f"{current_project_name!r}: {names_str}. "
        "Run the 'reintegrate-fallback-projects' MCP tool to merge their changes back.\n"
    )
    logger.warning(
        "Unintegrated fallback projects for %r: %s — run reintegrate-fallback-projects to merge.",
        current_project_name,
        names_str,
    )


def _iter_domain_items(
    folder: GhidraDomainFolder,
    content_type: str | None = None,
    recursive: bool = True,
) -> Any:
    """Recursively iterate over domain folder items, optionally filtered by content type.

    Consolidates two nearly-identical methods (_iter_domain_file_paths and _iter_domain_files)
    into a single parameterized helper, reducing code duplication and improving maintainability.
    Supports filtering by content type (e.g., "Program" for binaries only).

    Args:
        folder: The domain folder to iterate over
        content_type: Optional content type filter (e.g., "Program" for binaries)
        recursive: Whether to recurse into subfolders (default: True)

    Yields:
        GhidraDomainFile objects matching the criteria (recursively if recursive=True)

    Examples:
        >>> for file in _iter_domain_items(root_folder, content_type="Program"):
        >>>     print(file.getPathname())
        >>> for file in _iter_domain_items(folder, recursive=False):  # shallow only
        >>>     print(file.getName())
    """
    logger.debug("diag.enter %s", "launcher.py:_iter_domain_items")
    if recursive:
        for subfolder in folder.getFolders():
            yield from _iter_domain_items(subfolder, content_type, recursive=True)

    for file_obj in folder.getFiles():
        if content_type is None or file_obj.getContentType() == content_type:
            yield file_obj


# ---------------------------------------------------------------------------
# ProgramInfo + PyGhidraContext  (formerly context.py)
# ---------------------------------------------------------------------------

from agentdecompile_cli.context import ProgramInfo


class PyGhidraContext:
    """Manages a Ghidra project, including its creation, program imports, and cleanup."""

    def __init__(
        self,
        project_name: str,
        project_path: str | Path,
        agentdecompile_dir: Path | None = None,
        force_analysis: bool = False,
        verbose_analysis: bool = False,
        no_symbols: bool = False,
        gdts: list[str] | None = None,
        program_options: dict[str, Any] | None = None,
        gzfs_path: str | Path | None = None,
        threaded: bool = True,
        max_workers: int | None = None,
        wait_for_analysis: bool = False,
        symbols_path: str | Path | None = None,
        sym_file_path: str | Path | None = None,
    ):
        """Initializes a new Ghidra project context.

        Args:
            project_name: The name of the Ghidra project.
            project_path: The directory where the project will be created.
            force_analysis: Force a new binary analysis each run.
            verbose_analysis: Verbose logging for analysis step.
            no_symbols: Turn off symbols for analysis.
            gdts: List of paths to GDT files for analysis.
            program_options: Dictionary with program options (custom analyzer settings).
            gzfs_path: Location to store GZFs of analyzed binaries.
            threaded: Use threading during analysis.
            max_workers: Number of workers for threaded analysis.
            wait_for_analysis: Wait for initial project analysis to complete.
            symbols_path: Path to local symbol store.
            sym_file_path: Path to a specific PDB file.
        """
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext.__init__")
        sys.stderr.write(f"[PyGhidraContext] Initializing: project_name={project_name!r}, project_path={project_path!r}\n")
        self._init_basic_attributes(project_name, project_path)
        self._init_project_and_programs()
        self._init_agentdecompile_directory(agentdecompile_dir)
        self._init_chromadb_client()
        self._init_analysis_options(force_analysis, verbose_analysis, no_symbols, gdts, program_options)
        self._init_symbol_configuration(symbols_path, sym_file_path, gzfs_path)
        self._init_threading_and_executors(threaded, max_workers, wait_for_analysis)
        sys.stderr.write(f"[PyGhidraContext] Ready: {len(self.programs)} program(s) loaded, chromadb={'yes' if self.chroma_client else 'no'}, max_workers={self.max_workers}\n")

    def _init_basic_attributes(self, project_name: str, project_path: str | Path) -> None:
        """Initialize basic project attributes."""
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext._init_basic_attributes")
        self.project_name: str = project_name
        self.project_path: Path = Path(project_path)
        sys.stderr.write(f"[PyGhidraContext] project_name={self.project_name!r}, project_path={self.project_path!r} (exists={self.project_path.exists()})\n")

    def _init_project_and_programs(self) -> None:
        """Initialize the Ghidra project and existing programs."""
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext._init_project_and_programs")
        self.project: GhidraProject = self._get_or_create_project()
        self.programs: dict[str, ProgramInfo] = {}
        self._init_project_programs()

    def _init_agentdecompile_directory(self, agentdecompile_dir: Path | None) -> None:
        """Initialize the agentdecompile working directory."""
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext._init_agentdecompile_directory")
        self.agentdecompile_dir = self.project_path / "agentdecompile" if agentdecompile_dir is None else Path(agentdecompile_dir)

    def _init_chromadb_client(self) -> None:
        """Initialize the ChromaDB client for semantic search."""
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext._init_chromadb_client")
        self.chroma_client: Any | None = None
        if chromadb is not None and Settings is not None:
            chromadb_path = _ensure_directory(self.agentdecompile_dir / "chromadb")
            self.chroma_client = chromadb.PersistentClient(
                path=str(chromadb_path),
                settings=Settings(anonymized_telemetry=False),
            )
        else:
            logger.warning("chromadb is unavailable; semantic collections are disabled")

    def _init_analysis_options(
        self,
        force_analysis: bool,
        verbose_analysis: bool,
        no_symbols: bool,
        gdts: list[str] | None,
        program_options: dict[str, Any] | None,
    ) -> None:
        """Initialize analysis-related options."""
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext._init_analysis_options")
        self.force_analysis: bool = force_analysis
        self.verbose_analysis: bool = verbose_analysis
        self.no_symbols: bool = no_symbols
        self.gdts: list[str] = [] if gdts is None else gdts
        self.program_options: dict[str, Any] = {} if program_options is None else program_options

    def _init_symbol_configuration(
        self,
        symbols_path: str | Path | None,
        sym_file_path: str | Path | None,
        gzfs_path: str | Path | None,
    ) -> None:
        """Initialize symbol and GZF storage configuration."""
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext._init_symbol_configuration")
        self.symbols_path: Path = Path(symbols_path) if symbols_path else self.agentdecompile_dir / "symbols"
        self.sym_file_path: Path | None = None if sym_file_path is None else Path(sym_file_path)
        self.gzfs_path: Path = _ensure_directory(self.agentdecompile_dir / "gzfs" if gzfs_path is None else Path(gzfs_path))

    def _init_threading_and_executors(
        self,
        threaded: bool,
        max_workers: int | None,
        wait_for_analysis: bool,
    ) -> None:
        """Initialize threading configuration and executors."""
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext._init_threading_and_executors")
        self.threaded: bool = bool(threaded)
        cpu_count: int = multiprocessing.cpu_count() or 4
        self.max_workers: int = cpu_count if max_workers is None else max_workers

        if not self.threaded:
            logger.warning("--no-threaded flag forcing max_workers to 1")
            self.max_workers = 1

        self.executor: concurrent.futures.ThreadPoolExecutor | None = concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) if self.threaded else None
        self.import_executor: concurrent.futures.ThreadPoolExecutor | None = concurrent.futures.ThreadPoolExecutor(max_workers=1) if self.threaded else None
        self.wait_for_analysis: bool = bool(wait_for_analysis)

    def close(self, save: bool = True):
        """Saves changes to all open programs and closes the project."""
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext.close")
        for _program_name, program_info in self.programs.items():
            program: GhidraProgram = program_info.program
            self.project.close(program)

        if self.executor is not None:
            self.executor.shutdown(wait=True)

        if self.import_executor is not None:
            self.import_executor.shutdown(wait=True)

        self.project.close()
        logger.info(f"Project {self.project_name} closed.")

    def _get_or_create_project(self) -> GhidraProject:
        """Creates a new Ghidra project if it doesn't exist, otherwise opens the existing project.

        Returns:
            The Ghidra project object.
        """
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext._get_or_create_project")
        from ghidra.base.project import GhidraProject  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        from ghidra.framework.model import ProjectLocator  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]

        # For standard Ghidra projects, use directory containing .gpr file
        project_dir = _ensure_directory(self.project_path)
        project_dir_str: str = str(project_dir.absolute())

        locator = ProjectLocator(project_dir_str, self.project_name)
        marker_exists = locator.getMarkerFile().exists()
        proj_dir_exists = locator.getProjectDir().exists()
        sys.stderr.write(f"[_get_or_create_project] dir={project_dir_str!r}, name={self.project_name!r}, marker_exists={marker_exists}, proj_dir_exists={proj_dir_exists}\n")

        if proj_dir_exists and marker_exists:
            logger.info(f"Opening existing project: {self.project_name}")
            sys.stderr.write(f"[_get_or_create_project] Opening existing LOCAL project: {self.project_name}\n")
            _patch_project_owner(project_dir_str, self.project_name)
            try:
                return GhidraProject.openProject(project_dir_str, self.project_name, False)
            except Exception as e:
                # NotOwnerException occurs when a stale project lock exists from a
                # previous process (e.g. crashed server, or uv-cached JVM user mismatch).
                # Delete the project and recreate it so the server can start cleanly.
                err_name = type(e).__name__
                err_str = str(e)
                is_not_owner = "NotOwnerException" in err_name or "NotOwnerException" in err_str
                if not is_not_owner:
                    raise
                sys.stderr.write(f"[_get_or_create_project] NotOwnerException opening project {self.project_name!r} — deleting stale project and recreating.\n")
                logger.warning(
                    "NotOwnerException opening project %s — deleting and recreating: %s",
                    self.project_name,
                    e,
                )
                # Remove the .gpr marker and .rep directory
                import shutil

                marker_file = locator.getMarkerFile()
                proj_dir_file = locator.getProjectDir()
                marker_path = Path(str(marker_file))
                proj_dir_path = Path(str(proj_dir_file))
                if marker_path.exists():
                    marker_path.unlink()
                if proj_dir_path.exists():
                    shutil.rmtree(proj_dir_path, ignore_errors=True)
                # Fall through to createProject below
        logger.info(f"Creating new project: {self.project_name}")
        sys.stderr.write(f"[_get_or_create_project] Creating new LOCAL project: {self.project_name}\n")
        return GhidraProject.createProject(
            project_dir_str,
            self.project_name,
            False,
        )

    def _init_project_programs(self):
        """Initializes the programs dictionary with existing programs in the project."""
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext._init_project_programs")
        try:
            binaries = self.list_binaries()
        except Exception as e:
            logger.warning(f"Failed to list binaries in project: {type(e).__name__}: {e}. Starting with empty program list.")
            return

        if not binaries:
            logger.info("No programs found in project. Server will start with empty program list.")
            return

        logger.info(f"Found {len(binaries)} program(s) in project. Opening...")
        success_count = 0
        total_bin = len(binaries)
        for idx, binary_path_str in enumerate(binaries, start=1):
            # Use PurePosixPath because Ghidra virtual paths are always POSIX-style
            # (e.g. "/SomeBinary"). Using pathlib.Path on Windows converts the leading
            # "/" to a Windows root, making str(parent) return "\\" instead of "/",
            # which causes GhidraProject.openProgram to raise:
            # IllegalArgumentException: Absolute path must begin with '/'
            binary_path: PurePosixPath = PurePosixPath(binary_path_str)
            try:
                program: GhidraProgram | None = self.project.openProgram(
                    str(binary_path.parent),
                    binary_path.name,
                    False,
                )
                program_info: ProgramInfo | None = self._init_program_info(program)
                if program_info is None:
                    raise ImportError(f"Failed to initialize program info for: {binary_path_str}")
                self.programs[binary_path_str] = program_info
                success_count += 1
                logger.debug(
                    "startup_batch_open_progress index=%s total=%s basename=%s",
                    idx,
                    total_bin,
                    basename_hint(binary_path.name),
                )
            except Exception as e:
                # Log warning but continue - individual program failures shouldn't crash server
                logger.warning(
                    "pyghidra_startup_open_program_fail index=%s total=%s basename=%s exc_type=%s",
                    idx,
                    total_bin,
                    basename_hint(PurePosixPath(binary_path_str).name),
                    type(e).__name__,
                )
                continue

        logger.info(f"Successfully opened {success_count}/{len(binaries)} program(s). Server is ready.")

    def list_binaries(self) -> list[str]:
        """List all the binaries within the Ghidra project."""
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext.list_binaries")
        root_folder = self.project.getRootFolder()
        return [file_obj.getPathname() for file_obj in _iter_domain_items(root_folder, content_type="Program")]

    def list_binary_domain_files(self) -> list[GhidraDomainFile]:
        """Return a list of DomainFile objects for all binaries in the project.

        This mirrors `list_binaries` but returns the DomainFile objects themselves
        (filtered by content type == "Program").
        """
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext.list_binary_domain_files")
        root_folder = self.project.getRootFolder()
        return list(_iter_domain_items(root_folder, content_type="Program"))

    def delete_program(self, program_name: str) -> bool:
        """Deletes a program from the Ghidra project and saves the project.

        Args:
            program_name: The name of the program to delete.

        Returns:
            True if the program was deleted successfully, False otherwise.
        """
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext.delete_program")
        program_info: ProgramInfo | None = self.programs.get(program_name)
        if program_info is None:
            available_progs: list[str] = list(self.programs.keys())
            raise ValueError(f"Binary {program_name} not found. Available binaries: {available_progs}")

        logger.info("Deleting program: %s", program_name)
        try:
            _assert_type(program_info, ProgramInfo, "Program info")
            program_to_delete: GhidraProgram = program_info.program
            _assert_type(program_to_delete, GhidraProgram, "Program")

            program_to_delete_df: GhidraDomainFile = program_to_delete.getDomainFile()
            _assert_type(program_to_delete_df, GhidraDomainFile, "Domain file")

            self.project.close(program_to_delete)
            program_to_delete_df.delete()
            del self.programs[program_name]
            return True
        except Exception as e:
            logger.error(f"Error deleting program '{program_name}': {e.__class__.__name__}: {e}")
            return False

    def import_binary(
        self,
        binary_path: str | Path,
        analyze: bool = False,
        relative_path: Path | None = None,
    ) -> None:
        """Imports a single binary into the project.

        Args:
            binary_path: Path to the binary file.
            analyze: Perform analysis on this binary. Useful if not importing in bulk.
            relative_path: Relative path within the project hierarchy (Path("bin") or Path("lib")).

        Returns:
            None
        """
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext.import_binary")
        binary_path = Path(binary_path)
        if binary_path.is_dir():
            return self.import_binaries([binary_path], analyze=analyze)

        program_name = PyGhidraContext._gen_unique_bin_name(binary_path)

        program: GhidraProgram | None = None
        root_folder = self.project.getRootFolder()

        # Create folder hierarchy if relative_path is provided
        if relative_path is not None:
            ghidra_folder = self._create_folder_hierarchy(root_folder, relative_path)
        else:
            ghidra_folder = root_folder

        # Check if program already exists at this location
        full_path: str = str(Path(ghidra_folder.pathname) / program_name)
        if self.programs.get(full_path) is not None:
            logger.info("Opening existing program: %s", program_name)
            program = self.programs[full_path].program
            program_info = self.programs[full_path]
        else:
            logger.info("Importing new program: %s", program_name)
            program = self.project.importProgram(binary_path)
            _assert_type(program, GhidraProgram, "Program")
            program.name = program_name
            if program:
                self.project.saveAs(program, ghidra_folder.pathname, program_name, True)

            program_info_candidate = self._init_program_info(program)
            if program_info_candidate is not None:
                _assert_type(program_info_candidate, ProgramInfo, "Program info")
                program_info = program_info_candidate
                self.programs[program.getDomainFile().pathname] = program_info
            else:
                raise ImportError(f"Failed to initialize program info for: {binary_path}")

        if program is None:
            raise ImportError(f"Failed to import binary: {binary_path}")

        # Get the final program_info from programs dictionary since we just added it
        final_domain_file: GhidraDomainFile = program.getDomainFile()
        final_program_info: GhidraProgramInfo | None = self.programs.get(final_domain_file.pathname)

        if analyze and final_program_info is not None:
            self.analyze_program(program)
            self._init_chroma_collections_for_program(final_program_info)

        logger.info("Program %s is ready for use.", program_name)

    @staticmethod
    def _create_folder_hierarchy(root_folder: GhidraDomainFolder, relative_path: Path) -> GhidraDomainFolder:
        """Recursively creates folder hierarchy in Ghidra project.

        Args:
            root_folder: The root folder of the Ghidra project.
            relative_path: The path hierarchy to create (e.g., Path("bin/subfolder")).

        Returns:
            The folder object at the end of the hierarchy.
        """
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext._create_folder_hierarchy")
        current_folder: GhidraDomainFolder = root_folder

        # Split the path into parts and iterate through them
        for part in relative_path.parts:
            existing_folder: GhidraDomainFolder | None = current_folder.getFolder(part)
            if existing_folder is not None:
                current_folder = existing_folder
                logger.debug("Using existing folder: %s", part)
            else:
                current_folder = current_folder.createFolder(part)
                logger.debug("Created folder: %s", part)

        return current_folder

    def import_binaries(
        self,
        binary_paths: list[str | Path],
        analyze: bool = False,
    ) -> None:
        """Imports a list of binaries into the project.
        If an entry is a directory it will be walked recursively
        and all regular files found will be imported, preserving directory structure.

        Note: Ghidra does not directly support multithreaded importing into the same project.

        Args:
            binary_paths: A list of paths to the binary files or directories.
            analyze: Whether to analyze the imported binaries.
        """
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext.import_binaries")
        resolved_paths: list[Path] = [Path(p) for p in binary_paths]

        # Tuple of (full system path, relative path from provided path)
        files_to_import: list[tuple[Path, Path | None]] = []
        for p in resolved_paths:
            _assert_type(p, Path, "Path")
            if p.exists() and p.is_dir():
                logger.info("Discovering files in directory: %s", p)
                for f in p.rglob("*"):
                    if f.is_file() and self._is_binary_file(f):
                        # Store the relative path (e.g., "bin" or "lib/subfolder")
                        relative = f.relative_to(p).parent
                        files_to_import.append((f, relative))
            elif p.exists() and p.is_file() and self._is_binary_file(p):
                files_to_import.append((p, None))

        if not files_to_import:
            logger.info("No files found to import from provided paths.")
            return

        logger.info(f"Importing {len(files_to_import)} binary files into project...")
        for bin_path, relative_path in files_to_import:
            try:
                self.import_binary(
                    bin_path,
                    analyze=analyze,
                    relative_path=relative_path,
                )
            except Exception as e:
                logger.error(f"Failed to import {bin_path}: {e.__class__.__name__}: {e}")

    def _is_binary_file(self, path: Path) -> bool:
        # return self._detect_binary_format(path) is not None
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext._is_binary_file")
        return True

    def _detect_binary_format(self, path: Path) -> str | None:
        # loader = pyghidra.program_loader()

        # try:
        #     loader.source(str(path))
        #     if loader.load() is not None:
        #         return loader
        # except Exception:
        #     return None

        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext._detect_binary_format")
        magic_table: dict[bytes, str] = {
            b"\x7fELF": "ELF",
            b"MZ": "PE",
            b"\xfe\xed\xfa\xce": "MachO32",
            b"\xfe\xed\xfa\xcf": "MachO64",
            b"\xce\xfa\xed\xfe": "MachO32_BE",
            b"\xcf\xfa\xed\xfe": "MachO64_BE",
            b"\xbe\xba\xfe\xca": "FatMachO_BE",
            b"\x00asm": "WASM",
            b"dex\n": "DEX",
            b"oat\n": "OAT",
            b"art\n": "ART",
            b"\xca\xfe\xba\xbe": "JavaClass_or_FatMachO",
            b"!<ar": "Archive",  # .a, .lib
            b"PK\x03\x04": "Zip",  # JAR, APK, etc.,
            b"\x30\x30\x30\x30": "Ghidra_GZF",
        }
        try:
            with path.open("rb") as f:
                header: bytes = f.read(8)
        except Exception:
            return None

        for magic, fmt in magic_table.items():
            if header.startswith(magic):
                return fmt

        return None

    def _import_callback(self, future: concurrent.futures.Future) -> None:
        """A callback function to handle results or exceptions from the import task."""
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext._import_callback")
        try:
            result: concurrent.futures.Future | None = future.result()
            if result is not None:
                logger.info("Background import task completed successfully. Result: %s", result)
        except Exception as e:
            logger.error(
                f"FATAL ERROR during background binary import: {e.__class__.__name__}: {e}",
                exc_info=True,
            )
            raise e

    def import_binary_backgrounded(self, binary_path: str | Path) -> None:
        """Spawns a thread and imports a binary into the project.
        When the binary is analyzed it will be added to the project.

        Args:
            binary_path: The path of the binary to import.
        """
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext.import_binary_backgrounded")
        if not Path(binary_path).exists():
            raise FileNotFoundError(f"The file {binary_path} cannot be found")

        if self.import_executor is not None:
            future: concurrent.futures.Future | None = self.import_executor.submit(
                self.import_binary,
                binary_path,
                analyze=True,
            )
            if future is not None:
                future.add_done_callback(self._import_callback)
        else:
            self.import_binary(binary_path, analyze=True)

    def get_program_info(self, binary_name: str) -> ProgramInfo | None:
        """Get program info or raise ValueError if not found."""
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext.get_program_info")
        program_info: ProgramInfo | None = self.programs.get(binary_name)
        if program_info is None:
            # Exact program name not in the list
            available_progs: list[str] = list(self.programs.keys())

            # If the LLM gave us just the binary name, use that
            available_prog_names: dict[str, ProgramInfo] = {Path(prog).name: prog_info for prog, prog_info in self.programs.items()}
            program_info = available_prog_names.get(binary_name)

            if program_info is None:
                raise ValueError(f"Binary {binary_name} not found. Available binaries: {available_progs}")

        if program_info is None:
            return None

        if not program_info.analysis_complete:
            raise RuntimeError(
                json.dumps(
                    {
                        "message": f"Analysis incomplete for binary '{binary_name}'.",
                        "binary_name": binary_name,
                        "ghidra_analysis_complete": program_info.ghidra_analysis_complete,
                        "code_collection": program_info.code_collection is not None,
                        "strings_collection": program_info.strings_collection is not None,
                        "suggestion": "Wait and try tool call again.",
                    },
                ),
            )
        return program_info

    def _init_program_info(self, program: GhidraProgram | None) -> ProgramInfo | None:
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext._init_program_info")
        from ghidra.program.flatapi import FlatProgramAPI as GhidraFlatProgramAPI  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]

        if program is None:
            logger.error("Program is None")
            return None

        metadata: dict[str, Any] = self.get_metadata(program)

        program_info: ProgramInfo = ProgramInfo(
            name=program.name,
            program=program,
            flat_api=GhidraFlatProgramAPI(program),
            decompiler=self.setup_decompiler(program),
            metadata=metadata,
            ghidra_analysis_complete=False,
            file_path=metadata["Executable Location"],
            load_time=time.time(),
            code_collection=None,
            strings_collection=None,
        )

        return program_info

    @staticmethod
    def _gen_unique_bin_name(path: Path) -> str:
        """Generate unique program name from binary for Ghidra Project"""
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext._gen_unique_bin_name")
        path = Path(path)

        def _sha1_file(local_bind_for_path: Path) -> str:
            sha1 = hashlib.sha1()

            with local_bind_for_path.open("rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha1.update(chunk)

            return sha1.hexdigest()

        return "-".join((path.name, _sha1_file(path.absolute())[:6]))

    def _init_chroma_collection_for_program(
        self,
        program_info: ProgramInfo,
        collection_suffix: str = "",
        extractor: Any = None,
    ) -> None:
        """Initialize Chroma collection for a program with configurable extraction.

        Args:
            program_info: The program info to process
            collection_suffix: Suffix for collection name (empty string for code, "_strings" for strings)
            extractor: Callable that extracts documents/ids/metadatas from program

        Extractor should return tuple of (documents, ids, metadatas)
        """
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext._init_chroma_collection_for_program")
        if self.chroma_client is None:
            return

        collection_name: str = f"{program_info.name}{collection_suffix}"
        logger.info(f"Initializing Chroma collection for {program_info.name} ({collection_suffix or 'code'})")

        try:
            collection = self.chroma_client.get_collection(name=collection_name)
            logger.info("Collection '%s' exists; skipping ingest.", collection_name)
            if collection_suffix == "":
                program_info.code_collection = collection
            else:
                program_info.strings_collection = collection
            return
        except Exception:
            pass  # Collection doesn't exist, will create below

        logger.info("Creating new collection '%s'", collection_name)
        if extractor is None:
            logger.warning("No extractor provided for %s; skipping", collection_name)
            return

        documents, ids, metadatas = extractor(program_info)

        if not documents:
            logger.warning("No documents extracted for %s; skipping", collection_name)
            return

        collection = self.chroma_client.create_collection(name=collection_name)
        try:
            _assert_type(collection, type(collection), "Collection")
            collection.add(
                documents=documents,
                metadatas=metadatas,
                ids=ids,
            )
        except Exception as e:
            logger.error(f"Failed to add items to collection {collection_name}: {e.__class__.__name__}: {e}")
            return

        logger.info("Collection '%s' initialized successfully", collection_name)
        if collection_suffix == "":
            program_info.code_collection = collection
        else:
            program_info.strings_collection = collection

    def _extract_decompiled_code(self, program_info: GhidraProgramInfo) -> tuple[list[str], list[str], list[dict]]:
        """Extract decompiled code from program.

        Returns:
            Tuple of (documents, ids, metadatas)
        """
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext._extract_decompiled_code")
        tools = GhidraTools(program_info)
        functions = tools.get_all_functions()
        decompiles: list[str] = []
        ids: list[str] = []
        metadatas: list[dict[str, Any]] = []

        for i, func in enumerate(functions):
            func: GhidraFunction
            try:
                if i % 10 == 0:
                    logger.debug(f"Decompiling {i}/{len(functions)}")
                decompiled: DecompiledFunction = tools.decompile_function(func)
                decompiles.append(decompiled.code)
                ids.append(decompiled.name)
                metadatas.append(
                    {
                        "function_name": decompiled.name,
                        "entry_point": str(func.getEntryPoint()),
                    },
                )
            except Exception as e:
                logger.error(f"Failed to decompile {func.getSymbol().getName(True)}: {e}")

        return decompiles, ids, metadatas

    def _extract_strings(self, program_info: ProgramInfo) -> tuple[list[str], list[str], list[dict]]:
        """Extract strings from program.

        Returns:
            Tuple of (documents, ids, metadatas)
        """
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext._extract_strings")
        tools = GhidraTools(program_info)
        strings = tools.get_all_strings()  # TYPE_CHECKING: list of String objects

        documents: list[str] = [s.value for s in strings]
        ids: list[str] = [str(s.address) for s in strings]
        metadatas: list[dict[str, Any]] = [{"address": str(s.address)} for s in strings]

        return documents, ids, metadatas

    def _init_chroma_code_collection_for_program(self, program_info: ProgramInfo):
        """Initialize Chroma code collection for a single program (legacy compatibility)."""
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext._init_chroma_code_collection_for_program")
        self._init_chroma_collection_for_program(
            program_info,
            collection_suffix="",
            extractor=self._extract_decompiled_code,
        )

    def _init_chroma_strings_collection_for_program(self, program_info: ProgramInfo):
        """Initialize Chroma strings collection for a single program (legacy compatibility)."""
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext._init_chroma_strings_collection_for_program")
        self._init_chroma_collection_for_program(
            program_info,
            collection_suffix="_strings",
            extractor=self._extract_strings,
        )

    def _init_chroma_collections_for_program(self, program_info: ProgramInfo):
        """Initializes all Chroma collections (code and strings) for a single program."""
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext._init_chroma_collections_for_program")
        self._init_chroma_code_collection_for_program(program_info)
        self._init_chroma_strings_collection_for_program(program_info)

    def _init_all_chroma_collections(self):
        """Initializes Chroma collections for all programs in the project.

        If an executor is available, tasks are submitted asynchronously.
        Otherwise, initialization runs in the main thread.
        """
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext._init_all_chroma_collections")
        if self.chroma_client is None:
            logger.info("Skipping Chroma collection initialization; chromadb unavailable")
            return

        programs: list[ProgramInfo] = list(self.programs.values())
        mode: str = "background" if self.executor is not None else "main thread"
        logger.info("Initializing Chroma DB collections in %s...", mode)

        # ensure analysis complete before init
        assert all(prog.analysis_complete for prog in programs), "Analysis is not complete for all programs"

        if self.executor is not None:
            # executor.map submits all tasks at once, returns an iterator of futures
            self.executor.map(self._init_chroma_collections_for_program, programs)
        else:
            for program_info in programs:
                self._init_chroma_collections_for_program(program_info)

    # Callback function that runs when the future is done to catch any exceptions
    def _analysis_done_callback(self, future: concurrent.futures.Future) -> None:
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext._analysis_done_callback")
        try:
            future.result()
            logging.info("Asynchronous analysis finished successfully.")
        except Exception as e:
            logging.exception("Asynchronous analysis failed with exception: %s", e)
            raise e

    def analyze_project(
        self,
        require_symbols: bool = True,
        force_analysis: bool = False,
        verbose_analysis: bool = False,
    ) -> concurrent.futures.Future | None:
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext.analyze_project")
        if self.executor is not None:
            future = self.executor.submit(
                self._analyze_project,
                require_symbols,
                force_analysis,
                verbose_analysis,
            )

            future.add_done_callback(self._analysis_done_callback)

            if self.wait_for_analysis:
                logger.info("Waiting for analysis to complete...")
                try:
                    future.result()
                    logger.info("Analysis complete.")
                except Exception as e:
                    logger.error("Analysis completed with an exception: %s", e)
                return None
            return future
        # No executor: just run synchronously
        self._analyze_project(require_symbols, force_analysis, verbose_analysis)
        return None

    def _analyze_project(
        self,
        require_symbols: bool = True,
        force_analysis: bool = False,
        verbose_analysis: bool = False,
    ) -> None:
        """Analyzes all files found within the Ghidra project"""
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext._analyze_project")
        domain_files: list[GhidraDomainFile] = self.list_binary_domain_files()

        logger.info(f"Starting analysis for {len(domain_files)} binaries")

        prog_count: int = len(domain_files)
        completed_count: int = 0

        if self.executor is not None:
            futures: list[concurrent.futures.Future[GhidraDomainFile | GhidraProgram | None]] = [
                self.executor.submit(
                    self.analyze_program,
                    domainFile,
                    require_symbols,
                    force_analysis,
                    verbose_analysis,
                )
                for domainFile in domain_files
            ]

            for future in concurrent.futures.as_completed(futures):
                result: GhidraDomainFile | GhidraProgram | None = future.result()
                if result is None:
                    logger.error("Analysis result is None, expected DomainFile or GhidraProgram?")
                    continue
                if isinstance(result, GhidraDomainFile):
                    logger.info(f"Analysis complete for {result.getName()}")
                elif isinstance(result, GhidraProgram):
                    logger.info(f"Analysis complete for {result.name}")
                else:
                    logger.error(f"Analysis result is {type(result)}, expected DomainFile or GhidraProgram?")
                    continue
                completed_count += 1
                logger.info("Completed %s/%s programs", completed_count, prog_count)
        else:
            for domain_file in domain_files:
                self.analyze_program(
                    domain_file,
                    require_symbols,
                    force_analysis,
                    verbose_analysis,
                )
                completed_count += 1
                logger.info("Completed %s/%s programs", completed_count, prog_count)

        logger.info("All programs analyzed.")
        # The chroma collections need to be initialized after analysis is complete
        # At this point, threaded or not, all analysis is done
        self._init_all_chroma_collections()  # DO NOT MOVE

    def analyze_program(  # noqa C901
        self,
        df_or_prog: GhidraDomainFile | GhidraProgram,
        require_symbols: bool = True,
        force_analysis: bool = False,
        verbose_analysis: bool = False,
    ):
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext.analyze_program")
        from ghidra.app.script import GhidraScriptUtil  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
        from ghidra.framework.model import DomainFile as GhidraDomainFile  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
        from ghidra.program.flatapi import FlatProgramAPI as GhidraFlatProgramAPI  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
        from ghidra.program.model.listing import Program as GhidraProgram  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
        from ghidra.program.util import GhidraProgramUtilities  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
        from ghidra.util.task import ConsoleTaskMonitor as GhidraConsoleTaskMonitor  # pyright: ignore[reportMissingImports, reportMissingModuleSource]

        # Import symbol utilities from ghidrecomp
        from ghidrecomp.utility import (
            get_pdb,
            set_pdb,
            set_remote_pdbs,
            setup_symbol_server,
        )

        df: GhidraDomainFile | None = None
        if isinstance(df_or_prog, GhidraDomainFile):
            df = df_or_prog
        elif isinstance(df_or_prog, GhidraProgram):
            df = df_or_prog.getDomainFile()
        else:
            raise ValueError(f"Invalid domain file or program: {df_or_prog}")

        prog_info: ProgramInfo | None = None if df is None else self.programs.get(df.pathname)
        if prog_info is not None:
            # program already opened and initialized
            program = prog_info.program
        else:
            # open program from Ghidra Project
            program = self.project.openProgram(
                None if df is None else df.getParent().pathname,
                df_or_prog.getName(),
                False,
            )
            prog_info_candidate: ProgramInfo | None = self._init_program_info(program)
            if prog_info_candidate is not None:
                self.programs[df_or_prog.getName() if df is None else df.pathname] = prog_info_candidate
            else:
                logger.error(f"Failed to initialize program info for {df_or_prog.getName()}")
                return df_or_prog

        logger.info("Analyzing program: %s", program)

        assert isinstance(program, GhidraProgram), "Program is not a GhidraProgram object"

        for gdt in self.gdts:
            logger.info("Loading GDT: %s", gdt)
            if not Path(gdt).exists():
                raise FileNotFoundError(f"GDT Path not found {gdt}")
            self.apply_gdt(program, gdt)

        gdt_names: list[str] = [name for name in program.getDataTypeManager().getSourceArchives()]
        if len(gdt_names) > 0:
            logger.debug("Using file gdts: %s", gdt_names)

        if verbose_analysis or self.verbose_analysis:
            monitor = GhidraConsoleTaskMonitor()
            flat_api = GhidraFlatProgramAPI(program, monitor)
        else:
            flat_api = GhidraFlatProgramAPI(program)

        if GhidraProgramUtilities.shouldAskToAnalyze(program) or force_analysis or self.force_analysis:
            GhidraScriptUtil.acquireBundleHostReference()

            program_options: dict[str, Any] = self.program_options.get("program_options", {})
            if program is not None and program.getFunctionManager().getFunctionCount() > 1000:
                # Force Decomp Param ID is not set
                analyzers_options: dict[str, Any] = program_options.get("Analyzers", {})
                decompiler_parameter_id: str | None = analyzers_options.get("Decompiler Parameter ID")
                if decompiler_parameter_id is not None:
                    self.set_analysis_option(program, decompiler_parameter_id, True)

            if self.program_options:
                analyzer_options: dict[str, Any] = (
                    self.program_options.get("program_options", {}).get(
                        "Analyzers",
                        {},
                    )
                    or {}
                )
                for k, v in analyzer_options.items():
                    logger.info("Setting prog option:%s with value:%s", k, v)
                    self.set_analysis_option(program, k, v)

            if self.no_symbols:
                logger.warning(f"Disabling symbols for analysis! --no-symbols flag: {self.no_symbols}")
                self.set_analysis_option(program, "PDB Universal", False)

            else:
                # Configure symbols if enabled
                if self.sym_file_path is not None:
                    logger.info(f"Setting PDB file: {self.sym_file_path}")
                    set_pdb(program, self.sym_file_path)
                elif self.symbols_path is not None:
                    logger.info(f"Setting up symbol server at {self.symbols_path}")
                    setup_symbol_server(self.symbols_path)
                    set_remote_pdbs(program, True)
                else:
                    logger.warning("No symbols path provided, skipping symbol server setup")

                # Verify PDB loaded
                pdb: File | None = get_pdb(program)
                if pdb is None:
                    logger.warning(f"Failed to find PDB for {program.name}")
                else:
                    logger.info(f"Loaded PDB: {'None' if pdb is None else pdb.getName()}")

            # Disable analyzers that NPE in headless (GhidraScriptUtil.bundleHost is null)
            disable_headless_unsafe_analyzers(program)
            logger.info("Starting Ghidra analysis of %s...", program)
            try:
                flat_api.analyzeAll(program)
                if hasattr(GhidraProgramUtilities, "setAnalyzedFlag"):
                    GhidraProgramUtilities.setAnalyzedFlag(program, True)
                elif hasattr(GhidraProgramUtilities, "markProgramAnalyzed"):
                    GhidraProgramUtilities.markProgramAnalyzed(program)
                else:
                    raise Exception("Missing set analyzed flag method!")
            finally:
                GhidraScriptUtil.releaseBundleHostReference()
                self.project.save(program)
        else:
            logger.info("Analysis already complete.. skipping %s!", program)

        # Save program as gzfs
        if self.gzfs_path is not None:
            from java.io import File  # type: ignore

            pathname = df.pathname.replace("/", "_")
            gzf_file = self.gzfs_path / f"{pathname}.gzf"
            self.project.saveAsPackedFile(program, File(str(gzf_file.absolute())), True)

        logger.info(f"Analysis for {df_or_prog.getName()} complete")
        self.programs[df.pathname].ghidra_analysis_complete = True
        return df_or_prog

    def set_analysis_option(  # noqa: C901
        self,
        prog: GhidraProgram,
        option_name: str,
        value: Any,
    ) -> None:
        """Set boolean program analysis options.

        Inspired by: Ghidra/Features/Base/src/main/java/ghidra/app/script/GhidraScript.java#L1272
        """
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext.set_analysis_option")
        from ghidra.program.model.listing import Program as GhidraProgram  # pyright: ignore[reportMissingImports, reportMissingModuleSource]

        prog_options: GhidraOptions = prog.getOptions(GhidraProgram.ANALYSIS_PROPERTIES)
        option_type: str = prog_options.getType(option_name)

        match str(option_type):
            case "INT_TYPE":
                logger.debug("Setting type: INT")
                prog_options.setInt(option_name, int(value))
            case "LONG_TYPE":
                logger.debug("Setting type: LONG")
                prog_options.setLong(option_name, int(value))
            case "STRING_TYPE":
                logger.debug("Setting type: STRING")
                prog_options.setString(option_name, value)
            case "DOUBLE_TYPE":
                logger.debug("Setting type: DOUBLE")
                prog_options.setDouble(option_name, float(value))
            case "FLOAT_TYPE":
                logger.debug("Setting type: FLOAT")
                prog_options.setFloat(option_name, float(value))
            case "BOOLEAN_TYPE":
                logger.debug("Setting type: BOOLEAN")
                if isinstance(value, str):
                    temp_bool: str = value.lower()
                    if temp_bool in {"true", "false"}:
                        prog_options.setBoolean(option_name, temp_bool == "true")
                elif isinstance(value, bool):
                    prog_options.setBoolean(option_name, value)
                else:
                    raise ValueError(
                        f"Failed to setBoolean on {option_name} {option_type}",
                    )
            case "ENUM_TYPE":
                logger.debug("Setting type: ENUM")
                from java.lang import Enum  # type: ignore

                enum_for_option = prog_options.getEnum(option_name, None)
                if enum_for_option is None:
                    raise ValueError(
                        f"Attempted to set an Enum option {option_name} without an existing enum value alreday set.",
                    )
                new_enum = None
                try:
                    new_enum = Enum.valueOf(enum_for_option.getClass(), value)
                except Exception:
                    for enum_value in enum_for_option.values():  # type: ignore
                        if value == enum_value.toString():
                            new_enum = enum_value
                            break
                if new_enum is None:
                    raise ValueError(
                        f"Attempted to set an Enum option {option_name} without an existing enum value alreday set.",
                    )
                prog_options.setEnum(option_name, new_enum)
            case _:
                logger.warning("option %s set not supported, ignoring", option_type)

    def configure_symbols(
        self,
        symbols_path: str | Path,
        symbol_urls: list[str] | None = None,
        allow_remote: bool = True,
    ):
        """Configures symbol servers and attempts to load PDBs for programs."""
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext.configure_symbols")
        from ghidra.app.plugin.core.analysis import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportAttributeAccessIssue]
            PdbAnalyzer as GhidraPdbAnalyzer,  # pyright: ignore[reportAttributeAccessIssue]
            PdbUniversalAnalyzer as GhidraPdbUniversalAnalyzer,  # pyright: ignore[reportAttributeAccessIssue]
        )
        from ghidra.app.util.pdb import PdbProgramAttributes as GhidraPdbProgramAttributes  # pyright: ignore[reportMissingImports, reportMissingModuleSource]

        logger.info("Configuring symbol search paths...")
        # This is a simplification. A real implementation would need to configure the symbol server
        # which is more involved. For now, we'll focus on enabling the analyzers.

        for program_name, program in self.programs.items():
            logger.info("Configuring symbols for %s", program_name)
            try:
                if hasattr(
                    GhidraPdbUniversalAnalyzer,
                    "setAllowUntrustedOption",
                ):  # Ghidra 11.2+
                    GhidraPdbUniversalAnalyzer.setAllowUntrustedOption(program, allow_remote)
                    GhidraPdbAnalyzer.setAllowUntrustedOption(program, allow_remote)
                else:  # Ghidra < 11.2
                    GhidraPdbUniversalAnalyzer.setAllowRemoteOption(program, allow_remote)
                    GhidraPdbAnalyzer.setAllowRemoteOption(program, allow_remote)

                # The following is a placeholder for actual symbol loading logic
                pdb_attr = GhidraPdbProgramAttributes(program)
                if not pdb_attr.pdbLoaded:
                    logger.warning("PDB not loaded for %s. Manual loading might be required.", program_name)

            except Exception as e:
                logger.error("Failed to configure symbols for %s: %s", program_name, e)

    def apply_gdt(
        self,
        program: GhidraProgram,
        gdt_path: str | Path,
        verbose: bool = False,
    ):
        """Apply GDT to program"""
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext.apply_gdt")
        from ghidra.app.cmd.function import ApplyFunctionDataTypesCmd as GhidraApplyFunctionDataTypesCmd  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
        from ghidra.program.model.data import FileDataTypeManager as GhidraFileDataTypeManager  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
        from ghidra.program.model.symbol import SourceType as GhidraSourceType  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
        from ghidra.util.task import ConsoleTaskMonitor as GhidraConsoleTaskMonitor  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
        from java.io import File  # pyright: ignore[reportMissingImports]
        from java.util import List  # pyright: ignore[reportMissingImports]

        gdt_path = Path(gdt_path)

        if verbose:
            monitor = GhidraConsoleTaskMonitor()
        else:
            monitor = GhidraConsoleTaskMonitor().DUMMY_MONITOR

        archive_gdt = File(str(gdt_path))
        archive_dtm: GhidraFileDataTypeManager | None = GhidraFileDataTypeManager.openFileArchive(archive_gdt, False)
        if archive_dtm is None:
            raise ValueError(f"Failed to open file archive {gdt_path}")
        always_replace = True
        create_bookmarks_enabled = True
        cmd: GhidraApplyFunctionDataTypesCmd = GhidraApplyFunctionDataTypesCmd(
            List.of(archive_dtm),
            None,
            GhidraSourceType.USER_DEFINED,
            always_replace,
            create_bookmarks_enabled,
        )
        cmd.applyTo(program, monitor)

    def get_metadata(self, prog: GhidraProgram) -> dict[str, Any]:
        """Generate dict from program metadata"""
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext.get_metadata")
        meta: dict[str, Any] = prog.getMetadata()
        return dict(meta)

    def setup_decompiler(self, program: GhidraProgram) -> GhidraDecompInterface:
        logger.debug("diag.enter %s", "launcher.py:PyGhidraContext.setup_decompiler")
        from ghidra.app.decompiler import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
            DecompInterface as GhidraDecompInterface,
            DecompileOptions as GhidraDecompileOptions,
        )

        prog_options = GhidraDecompileOptions()

        decomp = GhidraDecompInterface()

        # grab default options from program
        prog_options.grabFromProgram(program)

        # increase maxpayload size to 100MB (default 50MB)
        prog_options.setMaxPayloadMBytes(100)

        decomp.setOptions(prog_options)
        decomp.openProgram(program)

        return decomp


# ---------------------------------------------------------------------------
# AgentDecompileLauncher helpers + class  (formerly launcher.py)
# ---------------------------------------------------------------------------
# ProjectManager: single implementation lives in project_manager.py; re-exported here for backward compatibility.


def _has_shared_server_credentials() -> bool:
    """Return True if shared Ghidra server connection env vars are set.

    When a shared server host (and optionally port/repo/credentials) is
    configured, multiple instances must not share the same local project
    directory because Ghidra's file-based locking prevents concurrent access.
    """
    logger.debug("diag.enter %s", "launcher.py:_has_shared_server_credentials")
    host = os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_HOST", "").strip() or os.getenv("AGENTDECOMPILE_HTTP_GHIDRA_SERVER_HOST", "").strip() or os.getenv("AGENTDECOMPILE_GHIDRA_SERVER_HOST", "").strip() or os.getenv("AGENT_DECOMPILE_SERVER_HOST", "").strip() or os.getenv("AGENTDECOMPILE_SERVER_HOST", "").strip()
    result = bool(host)
    sys.stderr.write(f"[_has_shared_server_credentials] AGENT_DECOMPILE_GHIDRA_SERVER_HOST={host!r} -> result={result}\n")
    return result


def _log_config_block(projects_dir: Path, project_name: str) -> None:
    """Write a single readable configuration block to stderr (no password value)."""
    logger.debug("diag.enter %s", "launcher.py:_log_config_block")
    lines = [
        "AgentDecompile configuration:",
        f"  project: {projects_dir / project_name}",
        f"  project_dir: {projects_dir} (exists={projects_dir.exists()})",
        f"  project_name: {project_name}",
    ]
    project_path = os.getenv("AGENT_DECOMPILE_PROJECT_PATH") or os.getenv("AGENTDECOMPILE_PROJECT_PATH")
    if project_path:
        lines.append(f"  AGENT_DECOMPILE_PROJECT_PATH: {project_path}")
    else:
        lines.append("  AGENT_DECOMPILE_PROJECT_PATH: (not set)")
    host = os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_HOST", "").strip()
    port = os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_PORT", "").strip()
    repo = os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY", "").strip()
    username = os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME", "").strip()
    password = os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD", "").strip()
    lines.append(f"  AGENT_DECOMPILE_GHIDRA_SERVER_HOST: {host or '(not set)'}")
    lines.append(f"  AGENT_DECOMPILE_GHIDRA_SERVER_PORT: {port or '(not set)'}")
    lines.append(f"  AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY: {repo or '(not set)'}")
    lines.append(f"  AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME: {'(set)' if username else '(not set)'}")
    lines.append(f"  AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD: {'(set)' if password else '(not set)'}")
    # Also show the HTTP variants to debug alias resolution
    http_host = os.getenv("AGENTDECOMPILE_HTTP_GHIDRA_SERVER_HOST", "").strip()
    http_port = os.getenv("AGENTDECOMPILE_HTTP_GHIDRA_SERVER_PORT", "").strip()
    http_repo = os.getenv("AGENTDECOMPILE_HTTP_GHIDRA_SERVER_REPOSITORY", "").strip()
    if http_host or http_port or http_repo:
        lines.append(f"  AGENTDECOMPILE_HTTP_GHIDRA_SERVER_HOST: {http_host or '(not set)'}")
        lines.append(f"  AGENTDECOMPILE_HTTP_GHIDRA_SERVER_PORT: {http_port or '(not set)'}")
        lines.append(f"  AGENTDECOMPILE_HTTP_GHIDRA_SERVER_REPOSITORY: {http_repo or '(not set)'}")
    # Show bridge legacy variants
    legacy_host = os.getenv("AGENT_DECOMPILE_SERVER_HOST", "").strip()
    legacy_port = os.getenv("AGENT_DECOMPILE_SERVER_PORT", "").strip()
    if legacy_host or legacy_port:
        lines.append(f"  AGENT_DECOMPILE_SERVER_HOST: {legacy_host or '(not set)'}")
        lines.append(f"  AGENT_DECOMPILE_SERVER_PORT: {legacy_port or '(not set)'}")
    lines.append(f"  _has_shared_server_credentials(): {_has_shared_server_credentials()}")
    ghidra_dir = os.getenv("GHIDRA_INSTALL_DIR")
    if ghidra_dir:
        lines.append(f"  GHIDRA_INSTALL_DIR: {ghidra_dir}")
    # Show all AGENT*DECOMPILE* env vars for exhaustive debugging
    lines.append("  [all AGENT*DECOMPILE* env vars]:")
    for k, v in sorted(os.environ.items()):
        if "DECOMPILE" in k.upper() or "GHIDRA" in k.upper():
            _is_sensitive = any(s in k.upper() for s in ("PASSWORD", "SECRET", "TOKEN", "KEY"))
            lines.append(f"    {k}={'***' if _is_sensitive else v}")
    sys.stderr.write("\n".join(lines) + "\n")


def _default_project_name_for_env() -> str:
    """Return the default project name for env-based directory-backed projects."""
    logger.debug("diag.enter %s", "launcher.py:_default_project_name_for_env")
    explicit = (os.getenv("AGENT_DECOMPILE_PROJECT_NAME") or os.getenv("AGENTDECOMPILE_PROJECT_NAME") or "").strip()
    if explicit:
        return explicit

    cwd_name = Path.cwd().name.strip()
    sanitized = "".join(c if c.isalnum() or c in "._-" else "_" for c in cwd_name)
    if not sanitized or sanitized.startswith("."):
        return "default_project"
    return sanitized


def _resolve_project_path_setting(
    project_path_value: str | Path,
    *,
    project_name: str | None,
    source_name: str,
) -> tuple[Path, str, Path | None]:
    """Resolve a project setting into project directory, name, and optional .gpr path.

    A `.gpr` path refers to an existing standard Ghidra project marker file.
    A directory path refers to the project location used with a separate project
    name for directory-backed project creation/opening.
    """
    logger.debug("diag.enter %s", "launcher.py:_resolve_project_path_setting")
    raw_path = Path(project_path_value).expanduser()

    if raw_path.suffix.lower() == ".gpr":
        project_gpr = raw_path.resolve()
        if not project_gpr.exists():
            raise FileNotFoundError(f"Project file specified in {source_name} does not exist: {project_path_value}")
        if not project_gpr.is_file():
            raise ValueError(f"{source_name} must point to a .gpr file, got: {project_path_value}")

        resolved_project_name = project_gpr.stem
        if not resolved_project_name:
            raise ValueError(f"Invalid project name extracted from path: {project_path_value}")
        return project_gpr.parent, resolved_project_name, project_gpr

    if raw_path.exists() and not raw_path.is_dir():
        raise ValueError(f"{source_name} must point to a .gpr file or a project directory, got: {project_path_value}")

    resolved_directory = raw_path.resolve(strict=False)
    resolved_project_name = (project_name or "").strip() or _default_project_name_for_env()
    return resolved_directory, resolved_project_name, None


class AgentDecompileLauncher:
    """Python MCP Server launcher with PyGhidra integration.

    NOTE: Pure Python launcher implementation
    using PyGhidra for Ghidra integration. Uses ephemeral projects in temp directories
    by default for stdio mode. If AGENT_DECOMPILE_PROJECT_PATH environment variable
    is set, uses that project instead.
    """

    def __init__(
        self,
        config_file: Path | None = None,
        use_random_port: bool = True,
    ):
        """Initialize Python MCP server launcher with PyGhidra integration.

        Args:
        ----
            config_file: Optional configuration file path
            use_random_port: Whether to use random available port (default: True)
        """
        logger.debug("diag.enter %s", "launcher.py:AgentDecompileLauncher.__init__")
        self.config_file: Path | None = config_file
        self.use_random_port: bool = use_random_port
        self.mcp_server: PythonMcpServer | None = None
        self.pyghidra_context: PyGhidraContext | None = None
        self.port: int | None = None
        self.temp_project_dir: Path | None = None
        self.user_project_path: Path | None = None
        self.program_info: ProgramInfo | None = None

    def start(
        self,
        port: int | None = None,
        host: str | None = None,
        project_directory: str | Path | None = None,
        project_name: str | None = None,
        auth_config: Any | None = None,
        tls_certfile: str | None = None,
        tls_keyfile: str | None = None,
    ) -> int:
        """Start Python MCP server.

        Args:
            port: Fixed port to bind (default: random). Set env AGENT_DECOMPILE_PORT.
            host: Host to bind (default: 127.0.0.1). Set env AGENT_DECOMPILE_HOST.
            project_directory: Optional project directory (used when AGENT_DECOMPILE_PROJECT_PATH not set).
            project_name: Optional project name (used with project_directory).
            auth_config: Optional AuthConfig for HTTP Basic auth enforcement.
            tls_certfile: Optional path to TLS certificate (PEM) for HTTPS.
            tls_keyfile: Optional path to TLS private key (PEM) for HTTPS.

        Returns:
        -------
            Server port number

        Raises:
        ------
            RuntimeError: If server fails to start
        """
        logger.debug("diag.enter %s", "launcher.py:AgentDecompileLauncher.start")
        try:
            if host is not None:
                os.environ["AGENT_DECOMPILE_HOST"] = host

            selected_host = host or os.getenv("AGENT_DECOMPILE_HOST") or os.getenv("AGENTDECOMPILE_HOST") or "127.0.0.1"
            selected_port: int | None = None
            if port is not None:
                selected_port = int(port)
            elif self.use_random_port:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as temp_sock:
                    temp_sock.bind((selected_host, 0))
                    selected_port = int(temp_sock.getsockname()[1])

            if selected_port is not None:
                os.environ["AGENT_DECOMPILE_PORT"] = str(selected_port)

            project_path_setting = os.getenv("AGENT_DECOMPILE_PROJECT_PATH") or os.getenv("AGENTDECOMPILE_PROJECT_PATH")
            sys.stderr.write(f"[launcher.start] project_directory={project_directory!r}, project_name={project_name!r}, project_path_setting={project_path_setting!r}, selected_host={selected_host!r}, selected_port={selected_port}\n")

            # Track whether the project path/name were explicitly specified by the
            # user (CLI arg or env var) vs. the built-in defaults.  When no
            # explicit project is configured and the default project is already
            # locked by another instance, we automatically fall back to a fresh
            # uniquely-named project instead of crashing.
            _project_is_explicit = False

            if project_path_setting:
                _project_is_explicit = True
                sys.stderr.write("[launcher.start] BRANCH: project_path_setting from env -> resolving...\n")
                projects_dir, resolved_project_name, resolved_project_gpr = _resolve_project_path_setting(
                    project_path_setting,
                    project_name=project_name,
                    source_name="AGENT_DECOMPILE_PROJECT_PATH",
                )
                project_name = resolved_project_name
                self.user_project_path = resolved_project_gpr or projects_dir
                sys.stderr.write(f"[launcher.start] Resolved: projects_dir={projects_dir!r}, project_name={project_name!r}, user_project_path={self.user_project_path!r}\n")
            elif project_directory is not None and project_name:
                # When shared Ghidra server credentials are configured, each
                # instance needs its own local workspace to avoid lock conflicts.
                # If the caller only passed the built-in default directory
                # ("agentdecompile_projects"), use an ephemeral temp directory
                # instead so multiple stdio sessions can coexist.
                _default_dirs = {"agentdecompile_projects", "./agentdecompile_projects"}
                _is_default_dir = Path(project_directory).name in _default_dirs or str(Path(project_directory)).replace("\\", "/").endswith("agentdecompile_projects")
                _has_shared = _has_shared_server_credentials()
                # Consider the project explicit if the user customized the
                # directory path OR the project name (via CLI or env var).
                _env_project_name = (os.getenv("AGENT_DECOMPILE_PROJECT_NAME") or os.getenv("AGENTDECOMPILE_PROJECT_NAME") or "").strip()
                _project_is_explicit = not _is_default_dir or bool(_env_project_name)
                sys.stderr.write(f"[launcher.start] BRANCH: project_directory={project_directory!r}, _is_default_dir={_is_default_dir}, _has_shared_server_credentials={_has_shared}, Path.name={Path(project_directory).name!r}\n")
                if _is_default_dir and _has_shared:
                    self.temp_project_dir = Path(tempfile.mkdtemp(prefix="agentdecompile_shared_"))
                    projects_dir = self.temp_project_dir
                    sys.stderr.write(f"[launcher.start] Using EPHEMERAL workspace for shared server: {projects_dir}\n")
                else:
                    projects_dir = Path(project_directory)
                    projects_dir.mkdir(parents=True, exist_ok=True)
                    sys.stderr.write(f"[launcher.start] Using PERSISTENT project dir: {projects_dir}\n")
            else:
                # Stdio mode: ephemeral projects in temp directory (session-scoped, auto-cleanup)
                # Keeps working directory clean - no .agentdecompile creation in cwd
                self.temp_project_dir = Path(tempfile.mkdtemp(prefix="agentdecompile_project_"))
                self.project_manager = ProjectManager()
                project_name = self.project_manager.get_project_name()

                # Use temp directory for the project (not .agentdecompile/projects)
                projects_dir = self.temp_project_dir
                sys.stderr.write(f"[launcher.start] BRANCH: stdio ephemeral -> {projects_dir}, project_name={project_name!r}\n")

            # Log configuration once in a readable block (no password value)
            _log_config_block(projects_dir, project_name)

            # Create PyGhidra context for proper Ghidra integration.
            # If the project is locked by another instance and no explicit
            # project was requested, fall back to a uniquely-named project so
            # the server can start without user intervention.
            try:
                self.pyghidra_context = PyGhidraContext(
                    project_name=project_name,
                    project_path=str(projects_dir),
                    force_analysis=False,
                    verbose_analysis=False,
                    no_symbols=False,
                )
                # Warn if unintegrated fallback projects exist from previous locked sessions.
                _startup_warn_pending_fallbacks(projects_dir, project_name)
            except Exception as _lock_err:
                _lock_err_name = type(_lock_err).__name__
                _lock_err_str = str(_lock_err)
                _is_lock = "LockException" in _lock_err_name or "LockException" in _lock_err_str
                if not _is_lock or _project_is_explicit:
                    raise
                # Default project is locked — copy its data to a fresh unique project so
                # previously imported/analyzed programs are preserved in the fallback.
                _locked_project_name = project_name
                fallback_name = f"agdec_{uuid.uuid4().hex[:12]}"
                sys.stderr.write(f"[launcher.start] WARNING: Default project {_locked_project_name!r} is locked by another instance. Falling back to unique project: {fallback_name!r}\n")
                logger.warning(
                    "Default project %r locked — falling back to unique project %r: %s",
                    _locked_project_name,
                    fallback_name,
                    _lock_err,
                )
                _copied = _copy_locked_project_data(projects_dir, _locked_project_name, fallback_name)
                if _copied:
                    sys.stderr.write(
                        f"[launcher.start] Copied locked project {_locked_project_name!r} data to {fallback_name!r}; "
                        "existing programs will be available in the fallback session.\n"
                    )
                    logger.info(
                        "Copied locked project %r data to fallback %r.",
                        _locked_project_name,
                        fallback_name,
                    )
                else:
                    sys.stderr.write(
                        f"[launcher.start] Could not copy locked project data; fallback project {fallback_name!r} will start empty.\n"
                    )
                project_name = fallback_name
                _log_config_block(projects_dir, project_name)
                try:
                    self.pyghidra_context = PyGhidraContext(
                        project_name=project_name,
                        project_path=str(projects_dir),
                        force_analysis=False,
                        verbose_analysis=False,
                        no_symbols=False,
                    )
                except Exception as _fallback_err:
                    # The copied project data may be corrupt or partially locked.
                    # Clean it up and retry with a completely fresh empty project.
                    import shutil as _shutil

                    for _stale in (
                        projects_dir / f"{project_name}.rep",
                        projects_dir / f"{project_name}.gpr",
                    ):
                        if _stale.is_dir():
                            _shutil.rmtree(_stale, ignore_errors=True)
                        elif _stale.exists():
                            _stale.unlink(missing_ok=True)
                    sys.stderr.write(
                        f"[launcher.start] Copied project {project_name!r} could not be opened "
                        f"({type(_fallback_err).__name__}); retrying with a fresh empty project.\n"
                    )
                    logger.warning(
                        "Fallback project %r failed to open (%s); recreating empty: %s",
                        project_name,
                        type(_fallback_err).__name__,
                        _fallback_err,
                    )
                    self.pyghidra_context = PyGhidraContext(
                        project_name=project_name,
                        project_path=str(projects_dir),
                        force_analysis=False,
                        verbose_analysis=False,
                        no_symbols=False,
                    )
                # Record the fallback → original mapping so reintegration tools
                # can merge this session's changes back later.
                _record_fallback_origin(projects_dir, _locked_project_name, project_name)

            # Create program info that will be populated when programs are loaded
            self.program_info = ProgramInfo(
                name="main_program",  # Placeholder
                program=None,  # Will be set when programs are loaded
                flat_api=None,
                decompiler=None,
                metadata={},
                ghidra_analysis_complete=False,
            )

            # Set up MCP server configuration (lazy import to avoid circular dependency)
            from agentdecompile_cli.mcp_server import PythonMcpServer, ServerConfig  # noqa: PLC0415

            server_config = ServerConfig()
            server_config.host = selected_host
            if selected_port is not None:
                server_config.port = selected_port
            if tls_certfile:
                server_config.tls_certfile = tls_certfile
            if tls_keyfile:
                server_config.tls_keyfile = tls_keyfile

            # Create and start MCP server
            self.mcp_server = PythonMcpServer(server_config, auth_config=auth_config)
            self.mcp_server.set_program_info(self.program_info)

            # Pass the GhidraProject so providers can checkout from shared repos
            if self.pyghidra_context is not None:
                self.mcp_server.set_ghidra_project(self.pyghidra_context.project)
                self.mcp_server.set_runtime_context(
                    {
                        "projectDirectory": str(projects_dir),
                        "projectName": project_name,
                        "projectPathGpr": str(Path(projects_dir) / f"{project_name}.gpr"),
                        "serverHost": selected_host,
                        "serverPort": selected_port,
                        "transportMode": "local-pyghidra",
                    },
                )

            # Start the server.  When the configured port is already in use
            # (e.g. another agentdecompile-server instance on the same host),
            # auto-recover by picking a random available port so that the stdio
            # bridge still works. The user is warned clearly.
            try:
                self.port = self.mcp_server.start()
            except RuntimeError as _port_err:
                if "already in use" not in str(_port_err):
                    raise
                # Pick a random available port and retry once
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as _tmp:
                    _tmp.bind((selected_host, 0))
                    fallback_port = int(_tmp.getsockname()[1])
                sys.stderr.write(
                    f"[launcher.start] WARNING: Port {server_config.port} on {selected_host} is already in use. "
                    f"Auto-selecting random port {fallback_port} so the server can start.\n"
                    f"  Tip: stop the other process or pass --port <N> to choose a specific port.\n"
                )
                logger.warning(
                    "Port %s in use — falling back to random port %s: %s",
                    server_config.port, fallback_port, _port_err,
                )
                server_config.port = fallback_port
                os.environ["AGENT_DECOMPILE_PORT"] = str(fallback_port)
                self.mcp_server = PythonMcpServer(server_config, auth_config=auth_config)
                self.mcp_server.set_program_info(self.program_info)
                if self.pyghidra_context is not None:
                    self.mcp_server.set_ghidra_project(self.pyghidra_context.project)
                    self.mcp_server.set_runtime_context(
                        {
                            "projectDirectory": str(projects_dir),
                            "projectName": project_name,
                            "projectPathGpr": str(Path(projects_dir) / f"{project_name}.gpr"),
                            "serverHost": selected_host,
                            "serverPort": fallback_port,
                            "transportMode": "local-pyghidra",
                        },
                    )
                self.port = self.mcp_server.start()
            sys.stderr.write(f"AgentDecompile ready on port {self.port}\n")

            return self.port

        except Exception as e:
            sys.stderr.write(f"Error starting AgentDecompile server: {e.__class__.__name__}: {e}\n")
            import traceback

            traceback.print_exc(file=sys.stderr)
            raise

    def get_port(self) -> int | None:
        """Get the server port.

        Returns:
            Server port number, or None if not started
        """
        logger.debug("diag.enter %s", "launcher.py:AgentDecompileLauncher.get_port")
        return self.port

    def getPort(self) -> int | None:
        """Backwards-compatible alias for get_port()."""
        logger.debug("diag.enter %s", "launcher.py:AgentDecompileLauncher.getPort")
        return self.get_port()

    def is_running(self) -> bool:
        """Check if server is running.

        Returns:
        --------
            True if server is running
        """
        logger.debug("diag.enter %s", "launcher.py:AgentDecompileLauncher.is_running")
        return self.mcp_server is not None and self.mcp_server.is_running()

    def isRunning(self) -> bool:
        """Backwards-compatible alias for is_running()."""
        logger.debug("diag.enter %s", "launcher.py:AgentDecompileLauncher.isRunning")
        return self.is_running()

    def isServerReady(self) -> bool:
        """Compatibility readiness check for older tests and callsites."""
        logger.debug("diag.enter %s", "launcher.py:AgentDecompileLauncher.isServerReady")
        if not self.is_running() or self.port is None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", int(self.port)), timeout=0.5):
                return True
        except OSError:
            return False

    def waitForServer(self, timeout_ms: int) -> bool:
        """Compatibility wait method for older tests and callsites."""
        logger.debug("diag.enter %s", "launcher.py:AgentDecompileLauncher.waitForServer")
        deadline = time.time() + max(0, timeout_ms) / 1000.0
        while time.time() <= deadline:
            if self.isServerReady():
                return True
            time.sleep(0.05)
        return False

    def stop(self):
        """Stop the Python MCP server and cleanup PyGhidra context."""
        logger.debug("diag.enter %s", "launcher.py:AgentDecompileLauncher.stop")
        if self.mcp_server is not None:
            sys.stderr.write("Stopping AgentDecompile server...\n")
            try:
                self.mcp_server.stop()
            except Exception as e:
                sys.stderr.write(f"Error stopping server: {e.__class__.__name__}: {e}\n")
            finally:
                self.mcp_server = None
                self.port = None

        # Close PyGhidra context
        if self.pyghidra_context is not None:
            try:
                self.pyghidra_context.close()
                sys.stderr.write("PyGhidra context closed\n")
            except Exception as e:
                sys.stderr.write(f"Error closing PyGhidra context: {e.__class__.__name__}: {e}\n")
            finally:
                self.pyghidra_context = None

        # Clean up temporary project directory (only if using temp project, not user project)
        if self.temp_project_dir is not None and self.temp_project_dir.exists() and self.temp_project_dir.is_dir():
            try:
                import shutil

                shutil.rmtree(self.temp_project_dir)
                sys.stderr.write(f"Cleaned up temporary project directory: {self.temp_project_dir}\n")
            except Exception as e:
                sys.stderr.write(f"Error cleaning up temporary directory: {e.__class__.__name__}: {e}\n")
            finally:
                self.temp_project_dir = None


# ---------------------------------------------------------------------------
# Server entry point  (formerly server.py)
# ---------------------------------------------------------------------------


def init_agentdecompile_context(
    *,
    input_paths: list[Path],
    project_name: str,
    project_directory: str,
    project_path_gpr: Path | None,
    force_analysis: bool = False,
    verbose_analysis: bool = False,
    no_symbols: bool = False,
    gdts: list[str] | None = None,
    program_options_path: str | None = None,
    gzfs_path: str | None = None,
    threaded: bool = True,
    max_workers: int = 0,
    wait_for_analysis: bool = False,
    list_project_binaries: bool = False,
    delete_project_binary: str | None = None,
    symbols_path: str | None = None,
    sym_file_path: str | None = None,
    port: int | None = None,
    host: str | None = None,
    config_file: Path | None = None,
) -> tuple[AgentDecompileLauncher, ProjectManager | None]:
    """Initialize AgentDecompile: project resolution, PyGhidra, launcher, optional list/delete/import.

    When project_path_gpr is set (a .gpr file), sets AGENT_DECOMPILE_PROJECT_PATH so the
    launcher uses that project. Otherwise uses project_directory and project_name for
    an ephemeral or directory-based project.

    If list_project_binaries is True, lists programs via MCP and exits (does not return).
    If delete_project_binary is set, attempts to remove that program and exits (does not return).

    Returns (launcher, project_manager). project_manager is only set when not using a .gpr.
    """
    logger.debug("diag.enter %s", "launcher.py:init_agentdecompile_context")
    bin_paths: list[Path] = [Path(p) for p in input_paths]
    logger.info("Project: %s", project_name)
    logger.info("Project location: %s", project_directory)

    if project_path_gpr is not None and project_path_gpr.suffix.lower() == ".gpr":
        os.environ["AGENT_DECOMPILE_PROJECT_PATH"] = str(project_path_gpr.resolve())

    # Launcher is started by the caller after PyGhidra is initialized (see main()).
    # We only compute launcher args here; actual start happens in main() after pyghidra.start().
    use_random_port = port is None
    launcher = AgentDecompileLauncher(config_file=config_file, use_random_port=use_random_port)
    project_manager: ProjectManager | None = None
    if not (os.getenv("AGENT_DECOMPILE_PROJECT_PATH") or os.getenv("AGENTDECOMPILE_PROJECT_PATH")):
        project_manager = ProjectManager()

    # Start the server (caller must have called pyghidra.start() before)
    started_port = launcher.start(
        port=port,
        host=host,
        project_directory=project_directory if project_path_gpr is None else None,
        project_name=project_name if project_path_gpr is None else None,
    )

    async def _list_and_exit() -> None:
        client = get_client(host="127.0.0.1", port=started_port)
        async with client:
            try:
                result = await client.read_resource("ghidra://programs")
                contents = getattr(result, "contents", None) or []
                for c in contents:
                    text = getattr(c, "text", None)
                    if text:
                        data = json.loads(text) if isinstance(text, str) else text
                        programs = data if isinstance(data, list) else (data.get("programs") if isinstance(data, dict) else [])
                        if isinstance(programs, list) and programs:
                            sys.stderr.write("Project programs:\n")
                            for p in programs:
                                name = p.get("programPath", p.get("name", p)) if isinstance(p, dict) else p
                                sys.stderr.write(f"  - {name}\n")
                            sys.exit(0)
                sys.stderr.write("No programs in project.\n")
            except Exception as e:
                sys.stderr.write(f"Error listing programs: {e}\n")
            sys.exit(0)

    if list_project_binaries:
        run_async(_list_and_exit())

    if delete_project_binary:

        async def _delete_and_exit() -> None:
            sys.stderr.write(
                "Delete program is not implemented via CLI; use MCP tools or Ghidra UI.\n",
            )
            sys.exit(0)

        run_async(_delete_and_exit())

    if bin_paths:
        logger.info("Importing binaries: %s", ", ".join(str(p) for p in bin_paths))
        logger.info("cli_positional_import_batch path_count=%s", len(bin_paths))

        async def _import_binaries() -> None:
            client = get_client(host="127.0.0.1", port=started_port)
            async with client:
                for path in bin_paths:
                    try:
                        await client.call_tool(Tool.OPEN.value, {"path": str(path.resolve()), "runAnalysis": True})
                        sys.stderr.write(f"Imported: {path}\n")
                    except Exception as e:
                        logger.warning(
                            "cli_positional_import_item_fail basename=%s exc_type=%s",
                            basename_hint(str(path)),
                            type(e).__name__,
                        )
                        sys.stderr.write(f"Import failed for {path}: {e}\n")

        run_async(_import_binaries())

    if wait_for_analysis:
        # Optional: wait a few seconds for analysis to progress (server is already up)
        time.sleep(5)

    return launcher, project_manager


def _env_port() -> int:
    """Default port from AGENT_DECOMPILE_PORT (1:1 Java applyHeadlessServerEnvOverrides)."""
    logger.debug("diag.enter %s", "launcher.py:_env_port")
    v = os.environ.get("AGENT_DECOMPILE_PORT")
    if not v:
        return 8080
    try:
        p = int(v)
        return p if p > 0 else 8080
    except ValueError:
        return 8080


def _env_host() -> str:
    """Default host from AGENT_DECOMPILE_HOST (1:1 Java applyHeadlessServerEnvOverrides)."""
    logger.debug("diag.enter %s", "launcher.py:_env_host")
    return (os.environ.get("AGENT_DECOMPILE_HOST") or "").strip() or "127.0.0.1"


def _resolve_proxy_backend_url(
    explicit_backend_url: str | None,
    explicit_mcp_server_url: str | None = None,
) -> str | None:
    """Resolve proxy backend URL from CLI/env and normalize to /mcp/message.

    Priority: --backend-url > --mcp-server-url > AGENT_DECOMPILE_* env
              > AGENTDECOMPILE_* env (compact form, e.g. AGENTDECOMPILE_MCP_SERVER_URL).
    """
    logger.debug("diag.enter %s", "launcher.py:_resolve_proxy_backend_url")
    raw = explicit_backend_url
    if not raw or not raw.strip():
        raw = explicit_mcp_server_url
    if not raw or not raw.strip():
        raw = os.environ.get("AGENT_DECOMPILE_BACKEND_URL") or os.environ.get("AGENT_DECOMPILE_MCP_SERVER_URL") or os.environ.get("AGENT_DECOMPILE_SERVER_URL")
    if not raw or not raw.strip():
        raw = os.environ.get("AGENTDECOMPILE_BACKEND_URL") or os.environ.get("AGENTDECOMPILE_MCP_SERVER_URL") or os.environ.get("AGENTDECOMPILE_SERVER_URL")
    if not raw or not raw.strip():
        return None
    return normalize_backend_url(raw.strip())


def main() -> None:
    """Parse server options and run init + transport."""
    logger.debug("diag.enter %s", "launcher.py:main")
    import argparse

    try:
        from agentdecompile_cli import __version__
    except ImportError:
        __version__ = "0.0.0.dev0"

    parser = argparse.ArgumentParser(
        description="AgentDecompile MCP server with project and transport options",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    # Server options (defaults from env to match Java headless launcher)
    g_server = parser.add_argument_group("Server options")
    g_server.add_argument(
        "-t",
        "--transport",
        choices=["stdio", "streamable-http", "sse", "http"],
        default="stdio",
        help="Transport: stdio (stdio bridge) or HTTP-based (server only)",
    )
    g_server.add_argument(
        "-p",
        "--port",
        "--mcp-port",
        "--mcp-listen-port",
        type=int,
        default=None,
        help="Port for HTTP transports (default: AGENT_DECOMPILE_PORT or 8080)",
    )
    g_server.add_argument(
        "-o",
        "--host",
        "--mcp-host",
        "--mcp-listen-ip",
        "--mcp-listen-host",
        type=str,
        default=None,
        help="Host for HTTP transports (default: AGENT_DECOMPILE_HOST or 127.0.0.1)",
    )
    g_server.add_argument(
        "--mcp-backend-url",
        "--backend-url",
        "--server-url",
        dest="backend_url",
        type=str,
        default=None,
        help=("Run in proxy mode and forward all MCP requests to an existing MCP server (http(s)://host:port[/mcp/message]); skips local PyGhidra/JVM startup"),
    )
    g_server.add_argument(
        "--mcp-server-url",
        dest="mcp_server_url",
        type=str,
        default=None,
        help=("Fallback backend URL if --backend-url is not provided (equivalent to AGENT_DECOMPILE_MCP_SERVER_URL)"),
    )
    g_server.add_argument(
        "--ghidra-server-host",
        type=str,
        default=None,
        help="Shared Ghidra server host (prefer AGENT_DECOMPILE_GHIDRA_SERVER_HOST in environment)",
    )
    g_server.add_argument(
        "--ghidra-server-port",
        type=int,
        default=None,
        help="Shared Ghidra server port (prefer AGENT_DECOMPILE_GHIDRA_SERVER_PORT in environment)",
    )
    g_server.add_argument(
        "--ghidra-server-username",
        type=str,
        default=None,
        help="Shared Ghidra server username (prefer AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME in environment)",
    )
    g_server.add_argument(
        "--ghidra-server-password",
        type=str,
        default=None,
        help="Shared Ghidra server password (prefer AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD in environment)",
    )
    g_server.add_argument(
        "--ghidra-server-repository",
        type=str,
        default=None,
        help="Shared Ghidra repository (prefer AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY in environment)",
    )
    g_server.add_argument(
        "--project-path",
        type=Path,
        default=Path("agentdecompile_projects"),
        help="Project directory or path to .gpr file",
    )
    g_server.add_argument(
        "--project-name",
        type=str,
        default="my_project",
        help="Project name (ignored when using .gpr)",
    )
    g_server.add_argument("--threaded", dest="threaded", action="store_true", help="Allow threaded analysis")
    g_server.add_argument("--no-threaded", dest="threaded", action="store_false", help="Disable threaded analysis")
    g_server.set_defaults(threaded=True)
    g_server.add_argument("--max-workers", type=int, default=0, help="Workers for analysis (0 = CPU count)")
    g_server.add_argument("--wait-for-analysis", dest="wait_for_analysis", action="store_true", help="Wait for initial analysis before serving")
    g_server.add_argument("--no-wait-for-analysis", dest="wait_for_analysis", action="store_false", help="Do not wait for initial analysis before serving")
    g_server.set_defaults(wait_for_analysis=False)

    # Project management
    g_proj = parser.add_argument_group("Project management")
    g_proj.add_argument("--list-project-binaries", action="store_true", help="List programs and exit")
    g_proj.add_argument("--delete-project-binary", type=str, metavar="NAME", help="Delete a program and exit")

    # Analysis options (passed through for future use; Java backend may use env)
    g_analysis = parser.add_argument_group("Analysis options")
    g_analysis.add_argument("--force-analysis", dest="force_analysis", action="store_true", help="Force re-analysis")
    g_analysis.add_argument("--no-force-analysis", dest="force_analysis", action="store_false", help="Disable forced re-analysis")
    g_analysis.set_defaults(force_analysis=False)
    g_analysis.add_argument("--verbose-analysis", dest="verbose_analysis", action="store_true", help="Verbose analysis log")
    g_analysis.add_argument("--no-verbose-analysis", dest="verbose_analysis", action="store_false", help="Disable verbose analysis log")
    g_analysis.set_defaults(verbose_analysis=False)
    g_analysis.add_argument("--no-symbols", action="store_true", help="Disable symbols for analysis")
    g_analysis.add_argument("--symbols-path", type=Path, default=None, help="Symbols directory")
    g_analysis.add_argument("--sym-file-path", type=Path, default=None, help="Single PDB symbol file")
    g_analysis.add_argument("--gdt", type=Path, action="append", default=[], help="GDT file (repeatable)")
    g_analysis.add_argument("--program-options", type=Path, default=None, help="JSON program options")
    g_analysis.add_argument("--gzfs-path", type=Path, default=None, help="GZF output path")

    parser.add_argument(
        "input_paths",
        nargs="*",
        type=Path,
        help="Binary paths to import before serving",
    )
    parser.add_argument("--config", type=Path, default=None, help="AgentDecompile config file")
    args = parser.parse_args()

    if args.ghidra_server_host:
        os.environ["AGENT_DECOMPILE_GHIDRA_SERVER_HOST"] = str(args.ghidra_server_host)
    if args.ghidra_server_port is not None:
        os.environ["AGENT_DECOMPILE_GHIDRA_SERVER_PORT"] = str(args.ghidra_server_port)
    if args.ghidra_server_username:
        os.environ["AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME"] = str(args.ghidra_server_username)
    if args.ghidra_server_password:
        os.environ["AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD"] = str(args.ghidra_server_password)
    if args.ghidra_server_repository:
        os.environ["AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY"] = str(args.ghidra_server_repository)

    # Apply env defaults for host/port (1:1 Java headless)
    port = args.port if args.port is not None else _env_port()
    host = args.host if args.host is not None else _env_host()
    backend_url = _resolve_proxy_backend_url(args.backend_url, getattr(args, "mcp_server_url", None))

    if backend_url:
        from agentdecompile_cli.bridge import _apply_mcp_session_fix

        _apply_mcp_session_fix()

        if args.list_project_binaries:
            parser.error("--list-project-binaries is not supported with --backend-url proxy mode")
        if args.delete_project_binary:
            parser.error("--delete-project-binary is not supported with --backend-url proxy mode")
        if args.input_paths:
            parser.error("input_paths import is not supported with --backend-url proxy mode")

        try:
            if args.transport == "stdio":
                from agentdecompile_cli.__main__ import AgentDecompileCLI

                cli = AgentDecompileCLI(
                    launcher=None,
                    project_manager=None,
                    backend=backend_url,
                )
                run_async(cli.run())
            elif args.transport in ["streamable-http", "http", "sse"]:
                from agentdecompile_cli.mcp_server.proxy_server import (
                    AgentDecompileMcpProxyServer,
                    ProxyServerConfig,
                )

                proxy_server = AgentDecompileMcpProxyServer(
                    ProxyServerConfig(
                        host=host,
                        port=port,
                        backend_url=backend_url,
                    ),
                )
                started_port = proxy_server.start()
                sys.stderr.write(
                    f"AgentDecompile proxy server running at http://{host}:{started_port}/mcp/message\n",
                )
                sys.stderr.write(f"Forwarding requests to backend {backend_url}\n")
                sys.stderr.write("Press Ctrl+C to stop.\n")
                while True:
                    time.sleep(3600)
            else:
                sys.stderr.write(f"Unknown transport: {args.transport}\n")
                sys.exit(1)
        except KeyboardInterrupt:
            sys.stderr.write("\nShutdown complete\n")
        finally:
            if args.transport in ["streamable-http", "http", "sse"] and "proxy_server" in locals():
                proxy_server.stop()
        return

    # Resolve project path (.gpr vs directory)
    project_path = args.project_path.resolve()
    if project_path.suffix.lower() == ".gpr":
        if args.project_name != "my_project":
            parser.error("Cannot use --project-name with a .gpr file")
        project_directory = str(project_path.parent)
        project_name = project_path.stem
        project_path_gpr = project_path
    else:
        project_directory = str(project_path)
        project_name = args.project_name
        project_path_gpr = None

    # PyGhidra and filters (same as __main__)
    from agentdecompile_cli.bridge import _apply_mcp_session_fix

    _apply_mcp_session_fix()

    original_stdout = sys.stdout
    original_stderr = sys.stderr
    try:
        from agentdecompile_cli.__main__ import StderrFilter, StdoutFilter, _redirect_java_outputs
    except ImportError:
        StderrFilter = None
        StdoutFilter = None
        _redirect_java_outputs = None

    if StderrFilter is not None and StdoutFilter is not None:
        sys.stderr = StderrFilter(original_stderr)
        sys.stdout = StdoutFilter(original_stdout)

    try:
        sys.stderr.write("Initializing PyGhidra...\n")
        try:
            import pyghidra
        except ImportError:
            sys.stderr.write(
                "PyGhidra is not installed. Install with: pip install 'agentdecompile[local]'\n",
            )
            sys.exit(1)
        pyghidra.start(verbose=args.verbose_analysis)
        if _redirect_java_outputs:
            _redirect_java_outputs()
        sys.stderr.write("PyGhidra initialized\n")

        launcher, project_manager = init_agentdecompile_context(
            input_paths=args.input_paths,
            project_name=project_name,
            project_directory=project_directory,
            project_path_gpr=project_path_gpr,
            force_analysis=args.force_analysis,
            verbose_analysis=args.verbose_analysis,
            no_symbols=args.no_symbols,
            gdts=[str(p) for p in args.gdt] if args.gdt else [],
            program_options_path=str(args.program_options) if args.program_options else None,
            gzfs_path=str(args.gzfs_path) if args.gzfs_path else None,
            threaded=args.threaded,
            max_workers=args.max_workers,
            wait_for_analysis=args.wait_for_analysis,
            list_project_binaries=args.list_project_binaries,
            delete_project_binary=args.delete_project_binary,
            symbols_path=str(args.symbols_path) if args.symbols_path else None,
            sym_file_path=str(args.sym_file_path) if args.sym_file_path else None,
            port=port if args.transport != "stdio" else None,
            host=host if args.transport != "stdio" else None,
            config_file=args.config,
        )
    except Exception as e:
        if sys.stdout != original_stdout:
            sys.stdout = original_stdout
        if sys.stderr != original_stderr:
            sys.stderr = original_stderr
        sys.stderr.write(f"Initialization error: {e}\n")
        raise
        # sys.exit(1)

    port = launcher.get_port()
    assert port is not None

    try:
        if args.transport == "stdio":
            from agentdecompile_cli.__main__ import AgentDecompileCLI

            cli = AgentDecompileCLI(
                launcher=launcher,
                project_manager=project_manager,
                backend=port,
            )
            run_async(cli.run())
        elif args.transport in ["streamable-http", "http", "sse"]:
            bind_host = host
            sys.stderr.write(f"AgentDecompile server running at http://{bind_host}:{port}/mcp/message\n")
            sys.stderr.write("Press Ctrl+C to stop.\n")
            while True:
                time.sleep(3600)
        else:
            sys.stderr.write(f"Unknown transport: {args.transport}\n")
            sys.exit(1)
    except KeyboardInterrupt:
        sys.stderr.write("\nShutdown complete\n")
    finally:
        if launcher:
            launcher.stop()
        if project_manager and hasattr(project_manager, "cleanup"):
            try:
                project_manager.cleanup()
            except Exception:
                pass


if __name__ == "__main__":
    main()
