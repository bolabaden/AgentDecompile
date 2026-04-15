"""Ghidra project context (ProgramInfo, PyGhidraContext).

``ProgramInfo`` is defined only in this module. ``launcher`` re-exports it for
call sites that import from the merged launcher entrypoint.

What lives here:
  - ProgramInfo: Dataclass holding a loaded program, its FlatProgramAPI, decompiler,
    metadata, and Chroma collections (code/strings) when available.
  - PyGhidraContext: Manages a Ghidra project (create/open), program import/analysis,
    symbol setup, GDT application, and Chroma semantic collections. Used by the
    headless analysis workflow; the MCP server uses ProjectManager + launcher instead.

A parallel ``PyGhidraContext`` implementation also exists in ``launcher.py`` for
the MCP/launcher stack; keep behavior aligned when changing either copy.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import logging
import multiprocessing
import time

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agentdecompile_cli.app_logger import basename_hint

try:
    import chromadb  # pyright: ignore[reportMissingImports, reportMissingModuleSource]

    from chromadb.api import ClientAPI  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
    from chromadb.config import Settings  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
    from chromadb.api.models.Collection import Collection  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
except Exception:
    if not TYPE_CHECKING:
        chromadb = None
        Settings = None

from agentdecompile_cli.tools.wrappers import GhidraTools

if TYPE_CHECKING:
    from ghidra.app.decompiler import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        DecompInterface as GhidraDecompInterface,
        DecompiledFunction as GhidraDecompiledFunction,
    )
    from ghidra.base.project import GhidraProject  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
    from ghidra.framework.model import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        DomainFile as GhidraDomainFile,
        DomainFolder as GhidraDomainFolder,
    )
    from ghidra.framework.options import ToolOptions as GhidraToolOptions  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
    from ghidra.framework.options import OptionType as GhidraOptionType  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
    from ghidra.program.flatapi import FlatProgramAPI as GhidraFlatProgramAPI  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
    from ghidra.program.model.listing import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        Function as GhidraFunction,
        Program as GhidraProgram,
    )

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ProgramInfo:
    """Information about a loaded program"""

    name: str
    program: GhidraProgram
    flat_api: GhidraFlatProgramAPI | None
    decompiler: GhidraDecompInterface | None
    metadata: dict[str, Any]  # Ghidra program metadata
    ghidra_analysis_complete: bool
    file_path: Path | None = None
    load_time: float | None = None
    code_collection: Collection | None = None
    strings_collection: Collection | None = None
    # Ghidra consumer passed to Program.release() for shared/versioned opens (see ProjectToolProvider).
    domain_object_consumer: Any | None = None
    # Resolved DomainFile for shared checkout / version-control flows (see ProjectToolProvider).
    domain_file: GhidraDomainFile | None = None

    def get_decompiler(self) -> GhidraDecompInterface | None:
        """Return the decompiler, lazily initializing it on first access if needed.

        When programs are eagerly opened at project-open time, the decompiler is
        stored as None to save ~15-30 MB of JVM memory per unused program.  The
        first call to ``get_decompiler()`` creates and caches the interface.
        """
        if self.decompiler is not None:
            return self.decompiler
        if self.program is None:
            return None
        try:
            from agentdecompile_cli.mcp_utils.decompiler_util import open_decompiler_for_program

            self.decompiler = open_decompiler_for_program(self.program)
            logger.info(
                "lazy_decompiler_init program=%s",
                self.name or "unknown",
            )
        except Exception as exc:
            logger.warning(
                "lazy_decompiler_init_failed program=%s exc_type=%s",
                self.name or "unknown",
                type(exc).__name__,
            )
            return None
        return self.decompiler

    @property
    def analysis_complete(self) -> bool:
        """Check if Ghidra analysis is complete."""
        logger.debug("diag.enter %s", "context.py:ProgramInfo.analysis_complete")
        return self.ghidra_analysis_complete

    @property
    def current_program(self) -> GhidraProgram | None:
        """Get the current program."""
        logger.debug("diag.enter %s", "context.py:ProgramInfo.current_program")
        return self.program

    @current_program.setter
    def current_program(self, program: GhidraProgram) -> None:
        """Set the current program."""
        logger.debug("diag.enter %s", "context.py:ProgramInfo.current_program")
        self.program = program


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
        logger.debug("diag.enter %s", "context.py:PyGhidraContext.__init__")
        self.project_name: str = project_name
        self.project_path: Path = Path(project_path)
        self.project: GhidraProject = self._get_or_create_project()

        self.programs: dict[str, ProgramInfo] = {}
        self._init_project_programs()

        self.agentdecompile_dir: Path = self.project_path / "agentdecompile" if agentdecompile_dir is None else Path(agentdecompile_dir)

        self.chroma_client: ClientAPI | None = None
        if chromadb is not None and Settings is not None:
            chromadb_path: Path = self.agentdecompile_dir / "chromadb"
            chromadb_path.mkdir(parents=True, exist_ok=True)
            self.chroma_client = chromadb.PersistentClient(
                path=str(chromadb_path),
                settings=Settings(anonymized_telemetry=False),
            )
        else:
            logger.warning("chromadb is unavailable; semantic collections are disabled")

        # From GhidraDiffEngine
        self.force_analysis: bool = force_analysis
        self.verbose_analysis: bool = verbose_analysis
        self.no_symbols: bool = no_symbols
        self.gdts: list[str] = [] if gdts is None else gdts

        # Symbol configuration
        self.symbols_path: Path = Path(symbols_path) if symbols_path else self.agentdecompile_dir / "symbols"
        self.sym_file_path: Path | None = None if sym_file_path is None else Path(sym_file_path)
        self.program_options: dict[str, Any] = {} if program_options is None else program_options
        self.gzfs_path: Path = self.agentdecompile_dir / "gzfs" if gzfs_path is None else Path(gzfs_path)
        self.gzfs_path.mkdir(exist_ok=True, parents=True)

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
        logger.debug("diag.enter %s", "context.py:PyGhidraContext.close")
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
        logger.debug("diag.enter %s", "context.py:PyGhidraContext._get_or_create_project")
        from ghidra.base.project import GhidraProject  # pyright: ignore[reportMissingModuleSource]
        from ghidra.framework.model import ProjectLocator  # pyright: ignore[reportMissingModuleSource]

        # For standard Ghidra projects, use directory containing .gpr file
        project_dir: Path = self.project_path
        project_dir.mkdir(exist_ok=True, parents=True)
        project_dir_str: str = str(project_dir.absolute())

        locator = ProjectLocator(project_dir_str, self.project_name)

        try:
            if locator.getProjectDir().exists() and locator.getMarkerFile().exists():
                logger.info(f"Opening existing project: {self.project_name}")
                from agentdecompile_cli.launcher import _patch_project_owner

                _patch_project_owner(project_dir_str, self.project_name)
                return GhidraProject.openProject(project_dir_str, self.project_name, False)
            logger.info(f"Creating new project: {self.project_name}")
            return GhidraProject.createProject(
                project_dir_str,
                self.project_name,
                False,
            )
        except Exception as e:
            logger.warning("pyghidra_project_create_open_exc exc_type=%s", type(e).__name__)
            raise

    def _init_project_programs(self):
        """Initializes the programs dictionary with existing programs in the project."""
        logger.debug("diag.enter %s", "context.py:PyGhidraContext._init_project_programs")
        all_binary_paths: list[str] = self.list_binaries()
        for binary_path_s in all_binary_paths:
            binary_path_str: str = str(binary_path_s)
            binary_path: Path = Path(binary_path_str)
            program: GhidraProgram | None = self.project.openProgram(
                str(binary_path.parent),
                binary_path.name,
                False,
            )
            if program is None:
                logger.warning(
                    "pyghidra_open_program_null basename=%s",
                    basename_hint(binary_path.name),
                )
                continue
            program_info: ProgramInfo | None = self._init_program_info(program)
            if program_info is None:
                logger.warning(
                    "pyghidra_program_info_init_failed basename=%s",
                    basename_hint(binary_path.name),
                )
                continue
            self.programs[str(binary_path)] = program_info

    def list_binaries(self) -> list[str]:
        """List all the binaries within the Ghidra project."""

        def list_folder_contents(folder: GhidraDomainFolder) -> list[str]:
            names: list[str] = []
            for subfolder in folder.getFolders():
                names.extend(list_folder_contents(subfolder))

            names.extend([f.getPathname() for f in folder.getFiles()])
            return names

        logger.debug("diag.enter %s", "context.py:PyGhidraContext.list_binaries")
        return list_folder_contents(self.project.getRootFolder())

    def list_binary_domain_files(self) -> list[GhidraDomainFile]:
        """Return a list of DomainFile objects for all binaries in the project.

        This mirrors `list_binaries` but returns the DomainFile objects themselves
        (filtered by content type == "Program").
        """

        def list_folder_domain_files(folder: GhidraDomainFolder) -> list[GhidraDomainFile]:
            files: list[GhidraDomainFile] = []
            for subfolder in folder.getFolders():
                files.extend(list_folder_domain_files(subfolder))

            files.extend(
                [f for f in folder.getFiles() if f.getContentType() == "Program"],
            )
            return files

        logger.debug("diag.enter %s", "context.py:PyGhidraContext.list_binary_domain_files")
        return list_folder_domain_files(self.project.getRootFolder())

    def delete_program(self, program_name: str) -> bool:
        """Deletes a program from the Ghidra project and saves the project.

        Args:
            program_name: The name of the program to delete.

        Returns:
            True if the program was deleted successfully, False otherwise.
        """
        logger.debug("diag.enter %s", "context.py:PyGhidraContext.delete_program")
        program_info: ProgramInfo | None = self.programs.get(program_name)
        if program_info is None:
            available_progs: list[str] = list(self.programs.keys())
            raise ValueError(f"Binary {program_name} not found. Available binaries: {available_progs}")
        logger.info("Deleting program: %s", program_name)
        try:
            assert isinstance(program_info, ProgramInfo), "Program info is not a ProgramInfo object"
            program_to_delete: GhidraProgram = program_info.program
            assert isinstance(program_to_delete, GhidraProgram), "Program is not a Program object"
            program_to_delete_df: GhidraDomainFile = program_to_delete.getDomainFile()
            assert isinstance(program_to_delete_df, GhidraDomainFile), "Domain file is not a DomainFile object"
            self.project.close(program_to_delete)
            program_to_delete_df.delete()
            # clean up program reference
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
        logger.debug("diag.enter %s", "context.py:PyGhidraContext.import_binary")
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
            assert isinstance(program, GhidraProgram), "Program is not a Program object"
            program.name = program_name
            if program:
                self.project.saveAs(program, ghidra_folder.pathname, program_name, True)

            program_info = self._init_program_info(program)
            assert isinstance(program_info, ProgramInfo), "Program info is not a ProgramInfo object"
            self.programs[program.getDomainFile().pathname] = program_info

        if program is None:
            raise ImportError(f"Failed to import binary: {binary_path}")

        if analyze:
            self.analyze_program(program_info.program)
            self._init_chroma_collections_for_program(program_info)

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
        logger.debug("diag.enter %s", "context.py:PyGhidraContext._create_folder_hierarchy")
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
        logger.debug("diag.enter %s", "context.py:PyGhidraContext.import_binaries")
        resolved_paths: list[Path] = [Path(p) for p in binary_paths]

        # Tuple of (full system path, relative path from provided path)
        files_to_import: list[tuple[Path, Path | None]] = []
        for p in resolved_paths:
            assert isinstance(p, Path), "Path is not a Path object"
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
                logger.error("Failed to import %s: %s", bin_path, e)
                # continue importing remaining files

    def _is_binary_file(self, path: Path) -> bool:
        # return self._detect_binary_format(path) is not None
        logger.debug("diag.enter %s", "context.py:PyGhidraContext._is_binary_file")
        return True

    def _detect_binary_format(self, path: Path) -> str | None:
        # loader = pyghidra.program_loader()

        # try:
        #     loader.source(str(path))
        #     if loader.load() is not None:
        #         return loader
        # except Exception:
        #     return None

        logger.debug("diag.enter %s", "context.py:PyGhidraContext._detect_binary_format")
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
        logger.debug("diag.enter %s", "context.py:PyGhidraContext._import_callback")
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
        logger.debug("diag.enter %s", "context.py:PyGhidraContext.import_binary_backgrounded")
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
        logger.debug("diag.enter %s", "context.py:PyGhidraContext.get_program_info")
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
        logger.debug("diag.enter %s", "context.py:PyGhidraContext._init_program_info")
        from ghidra.program.flatapi import FlatProgramAPI as GhidraFlatProgramAPI  # pyright: ignore[reportMissingImports, reportMissingModuleSource]

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
        logger.debug("diag.enter %s", "context.py:PyGhidraContext._gen_unique_bin_name")
        path = Path(path)

        def _sha1_file(local_bind_for_path: Path) -> str:
            sha1 = hashlib.sha1()

            with local_bind_for_path.open("rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha1.update(chunk)

            return sha1.hexdigest()

        return "-".join((path.name, _sha1_file(path.absolute())[:6]))

    def _init_chroma_code_collection_for_program(self, program_info: ProgramInfo):
        """Initialize Chroma code collection for a single program."""
        logger.debug("diag.enter %s", "context.py:PyGhidraContext._init_chroma_code_collection_for_program")
        if self.chroma_client is None:
            return

        logger.info(f"Initializing Chroma code collection for {program_info.name}")
        try:
            collection = self.chroma_client.get_collection(name=program_info.name)
            logger.info(f"Collection '{program_info.name}' exists; skipping code ingest.")
            program_info.code_collection = collection
        except Exception:
            logger.info(f"Creating new code collection '{program_info.name}'")
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
                    decompiled: GhidraDecompiledFunction = tools.decompile_function(func)  # pyright: ignore[reportAssignmentType]
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

            collection = self.chroma_client.create_collection(name=program_info.name)
            try:
                assert collection is not None, "Collection is None"
                collection.add(
                    documents=decompiles,
                    metadatas=metadatas,  # pyright: ignore[reportArgumentType]
                    ids=ids,
                )
            except Exception as e:
                logger.error(f"Failed add decompiles to collection: {e.__class__.__name__}: {e}")

            logger.info(f"Code analysis complete for collection '{program_info.name}'")
            program_info.code_collection = collection

    def _init_chroma_strings_collection_for_program(self, program_info: ProgramInfo):
        """Initialize Chroma strings collection for a single program."""
        logger.debug("diag.enter %s", "context.py:PyGhidraContext._init_chroma_strings_collection_for_program")
        if self.chroma_client is None:
            return

        collection_name: str = f"{program_info.name}_strings"
        logger.info(f"Initializing Chroma strings collection for {program_info.name}")
        strings_collection: Collection | None = None
        try:
            strings_collection = self.chroma_client.get_collection(name=collection_name)
            logger.info("Collection '%s' exists; skipping strings ingest.", collection_name)
            program_info.strings_collection = strings_collection
        except Exception:
            logger.info("Creating new strings collection '%s'", collection_name)
            tools = GhidraTools(program_info)

            strings: list[Any] = tools.get_all_strings()
            metadatas: list[dict[str, Any]] = [{"address": str(s.address)} for s in strings]
            ids: list[str] = [str(s.address) for s in strings]
            strings_values: list[str] = [s.value for s in strings]

            strings_collection = self.chroma_client.create_collection(name=collection_name)
            try:
                assert strings_collection is not None, "Strings collection is None"
                strings_collection.add(
                    documents=strings_values,
                    metadatas=metadatas,  # pyright: ignore[reportArgumentType]
                    ids=ids,
                )
            except Exception as e:
                logger.error(f"Failed to add strings to collection: {e.__class__.__name__}: {e}")

            logger.info("Strings analysis complete for collection '%s'", collection_name)
            program_info.strings_collection = strings_collection

    def _init_chroma_collections_for_program(self, program_info: ProgramInfo):
        """Initializes all Chroma collections (code and strings) for a single program."""
        logger.debug("diag.enter %s", "context.py:PyGhidraContext._init_chroma_collections_for_program")
        self._init_chroma_code_collection_for_program(program_info)
        self._init_chroma_strings_collection_for_program(program_info)

    def _init_all_chroma_collections(self):
        """Initializes Chroma collections for all programs in the project.

        If an executor is available, tasks are submitted asynchronously.
        Otherwise, initialization runs in the main thread.
        """
        logger.debug("diag.enter %s", "context.py:PyGhidraContext._init_all_chroma_collections")
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
        logger.debug("diag.enter %s", "context.py:PyGhidraContext._analysis_done_callback")
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
        logger.debug("diag.enter %s", "context.py:PyGhidraContext.analyze_project")
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
        logger.debug("diag.enter %s", "context.py:PyGhidraContext._analyze_project")
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

            from ghidra.framework.model import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
                DomainFile as GhidraDomainFile,
            )
            from ghidra.program.model.listing import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
                Program as GhidraProgram,
            )

            for future in concurrent.futures.as_completed(futures):
                result: GhidraDomainFile | GhidraProgram | None = future.result()
                if result is None:
                    logger.error("Analysis result is None, expected DomainFile or Program?")
                    continue
                if isinstance(result, GhidraDomainFile):
                    logger.info(f"Analysis complete for {result.getName()}")
                elif isinstance(result, GhidraProgram):
                    logger.info(f"Analysis complete for {result.name}")
                else:
                    logger.error(f"Analysis result is {type(result)}, expected DomainFile or Program?")
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
        logger.debug("diag.enter %s", "context.py:PyGhidraContext.analyze_program")
        from ghidra.app.script import GhidraScriptUtil  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
        from ghidra.framework.model import DomainFile as GhidraDomainFile  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
        from ghidra.program.flatapi import FlatProgramAPI as GhidraFlatProgramAPI  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
        from ghidra.program.model.listing import Program as GhidraProgram  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
        from ghidra.program.util import GhidraProgramUtilities as GhidraProgramUtilities  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
        from ghidra.util.task import ConsoleTaskMonitor as GhidraConsoleTaskMonitor  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
        from java.io import File as JavaFile  # pyright: ignore[reportMissingImports]

        # Import symbol utilities from ghidrecomp (disable_headless_unsafe_analyzers may be missing in some builds)
        from ghidrecomp.utility import (
            get_pdb,
            set_pdb,
            set_remote_pdbs,
            setup_symbol_server,
        )

        try:
            if not TYPE_CHECKING:
                from ghidrecomp.utility import disable_headless_unsafe_analyzers
        except (ImportError, AttributeError):

            def disable_headless_unsafe_analyzers(program: GhidraProgram) -> None:
                """No-op when ghidrecomp does not export this (e.g. older or different build)."""

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
            self.programs[df_or_prog.getName() if df is None else df.pathname] = self._init_program_info(program)  # pyright: ignore[reportArgumentType]

        logger.info("Analyzing program: %s", program)

        assert isinstance(program, GhidraProgram), "Program is not a Program object"

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
                analyzers_options = program_options.get("Analyzers", {})
                decompiler_parameter_id = analyzers_options.get("Decompiler Parameter ID")
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
                pdb: JavaFile | None = get_pdb(program)
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

            pathname: str = df.pathname.replace("/", "_")
            gzf_file: Path = self.gzfs_path / f"{pathname}.gzf"
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
        logger.debug("diag.enter %s", "context.py:PyGhidraContext.set_analysis_option")
        from ghidra.program.model.listing import Program as GhidraProgram  # pyright: ignore[reportMissingImports, reportMissingModuleSource]

        prog_options: GhidraToolOptions = prog.getOptions(GhidraProgram.ANALYSIS_PROPERTIES)
        option_type: GhidraOptionType = prog_options.getType(option_name)

        option_type_str: str = str(option_type)
        if option_type_str == "INT_TYPE":
            logger.debug("Setting type: INT")
            prog_options.setInt(option_name, int(value))
        elif option_type_str == "LONG_TYPE":
            logger.debug("Setting type: LONG")
            prog_options.setLong(option_name, int(value))
        elif option_type_str == "STRING_TYPE":
            logger.debug("Setting type: STRING")
            prog_options.setString(option_name, value)
        elif option_type_str == "DOUBLE_TYPE":
            logger.debug("Setting type: DOUBLE")
            prog_options.setDouble(option_name, float(value))
        elif option_type_str == "FLOAT_TYPE":
            logger.debug("Setting type: FLOAT")
            prog_options.setFloat(option_name, float(value))
        elif option_type_str == "BOOLEAN_TYPE":
            logger.debug("Setting type: BOOLEAN")
            if isinstance(value, str):
                temp_bool = value.lower()
                if temp_bool in {"true", "false"}:
                    prog_options.setBoolean(option_name, temp_bool == "true")
            elif isinstance(value, bool):
                prog_options.setBoolean(option_name, value)
            else:
                raise ValueError(
                    f"Failed to setBoolean on {option_name} {option_type}",
                )
        elif option_type_str == "ENUM_TYPE":
            logger.debug("Setting type: ENUM")
            from java.lang import Enum as JavaEnum  # pyright: ignore[reportMissingImports]

            enum_for_option = prog_options.getEnum(option_name, None)
            if enum_for_option is None:
                raise ValueError(
                    f"Attempted to set an Enum option {option_name} without an existing enum value alreday set.",
                )
            new_enum = None
            try:
                new_enum = JavaEnum.valueOf(enum_for_option.getClass(), value)
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
        else:
            logger.warning("option %s set not supported, ignoring", option_type)

    def configure_symbols(
        self,
        symbols_path: str | Path,
        symbol_urls: list[str] | None = None,
        allow_remote: bool = True,
    ):
        """Configures symbol servers and attempts to load PDBs for programs."""
        logger.debug("diag.enter %s", "context.py:PyGhidraContext.configure_symbols")
        from ghidra.app.plugin.core.analysis import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
            PdbAnalyzer,  # pyright: ignore[reportAttributeAccessIssue]
            PdbUniversalAnalyzer,  # pyright: ignore[reportAttributeAccessIssue]
        )
        from ghidra.app.util.pdb import PdbProgramAttributes  # pyright: ignore[reportMissingImports, reportMissingModuleSource]

        logger.info("Configuring symbol search paths...")
        # This is a simplification. A real implementation would need to configure the symbol server
        # which is more involved. For now, we'll focus on enabling the analyzers.

        for program_name, program in self.programs.items():
            logger.info("Configuring symbols for %s", program_name)
            try:
                if hasattr(
                    PdbUniversalAnalyzer,
                    "setAllowUntrustedOption",
                ):  # Ghidra 11.2+
                    PdbUniversalAnalyzer.setAllowUntrustedOption(program, allow_remote)
                    PdbAnalyzer.setAllowUntrustedOption(program, allow_remote)
                else:  # Ghidra < 11.2
                    PdbUniversalAnalyzer.setAllowRemoteOption(program, allow_remote)
                    PdbAnalyzer.setAllowRemoteOption(program, allow_remote)

                # The following is a placeholder for actual symbol loading logic
                pdb_attr = PdbProgramAttributes(program)
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
        logger.debug("diag.enter %s", "context.py:PyGhidraContext.apply_gdt")
        from ghidra.app.cmd.function import ApplyFunctionDataTypesCmd as GhidraApplyFunctionDataTypesCmd  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
        from ghidra.program.model.address import AddressSetView as GhidraAddressSetView  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
        from ghidra.program.model.data import FileDataTypeManager as GhidraFileDataTypeManager  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
        from ghidra.program.model.symbol import SourceType as GhidraSourceType  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
        from ghidra.util.task import ConsoleTaskMonitor as GhidraConsoleTaskMonitor  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
        from java.io import File as JavaFile  # pyright: ignore[reportMissingImports]
        from java.util import List as JavaList  # pyright: ignore[reportMissingImports]

        gdt_path = Path(gdt_path)

        if verbose:
            monitor = GhidraConsoleTaskMonitor()
        else:
            monitor = GhidraConsoleTaskMonitor().DUMMY_MONITOR

        archive_gdt = JavaFile(str(gdt_path))
        archive_dtm: GhidraFileDataTypeManager | None = GhidraFileDataTypeManager.openFileArchive(archive_gdt, False)
        if archive_dtm is None:
            raise ValueError(f"Failed to open file archive {gdt_path}")
        always_replace = True
        create_bookmarks_enabled = True
        cmd = GhidraApplyFunctionDataTypesCmd(
            JavaList.of(archive_dtm),
            GhidraAddressSetView.EMPTY_SET,
            GhidraSourceType.USER_DEFINED,
            always_replace,
            create_bookmarks_enabled,
        )
        cmd.applyTo(program, monitor)

    def get_metadata(self, prog: GhidraProgram) -> dict[str, Any]:
        """Generate dict from program metadata"""
        logger.debug("diag.enter %s", "context.py:PyGhidraContext.get_metadata")
        meta: dict[str, Any] = prog.getMetadata()
        return dict(meta)

    def setup_decompiler(self, program: GhidraProgram) -> GhidraDecompInterface | None:
        logger.debug("diag.enter %s", "context.py:PyGhidraContext.setup_decompiler")
        from agentdecompile_cli.mcp_utils.decompiler_util import open_decompiler_for_program

        try:
            return open_decompiler_for_program(program)
        except Exception as exc:
            logger.warning(
                "setup_decompiler_failed program=%s exc_type=%s",
                getattr(program, "name", "unknown"),
                exc.__class__.__name__,
            )
            return None
