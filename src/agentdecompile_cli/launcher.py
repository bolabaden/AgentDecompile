"""Merged module: launcher, context, project_manager, and server entry point.

Merged from:
  - context.py         (ProgramInfo dataclass, PyGhidraContext)
  - project_manager.py (ProjectManager)
  - launcher.py        (AgentDecompileLauncher, _log_config_block)
  - server.py          (init_agentdecompile_context, _env_port, _env_host, main)

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
import sys
import tempfile
import time

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import chromadb

from chromadb.config import Settings

from agentdecompile_cli.executor import get_client, run_async
from agentdecompile_cli.tools.wrappers import GhidraTools

if TYPE_CHECKING:
    from ghidra.app.decompiler import (
        DecompInterface,  # pyright: ignore[reportMissingImports]
        DecompiledFunction,  # pyright: ignore[reportMissingImports]
    )
    from ghidra.base.project import GhidraProject  # pyright: ignore[reportMissingImports]
    from ghidra.framework.model import (  # pyright: ignore[reportMissingImports]
        DomainFile,
        DomainFolder,
    )
    from ghidra.framework.options import ToolOptions  # pyright: ignore[reportMissingImports]
    from ghidra.program.flatapi import FlatProgramAPI  # pyright: ignore[reportMissingImports]
    from ghidra.program.model.listing import (
        Program,  # pyright: ignore[reportMissingImports]
        Program as GhidraProgram,  # pyright: ignore[reportMissingImports]
    )

    from agentdecompile_cli.mcp_server import PythonMcpServer, ServerConfig  # noqa: F401

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ProgramInfo + PyGhidraContext  (formerly context.py)
# ---------------------------------------------------------------------------


@dataclass
class ProgramInfo:
    """Information about a loaded program"""

    name: str
    program: Program
    flat_api: FlatProgramAPI | None
    decompiler: DecompInterface
    metadata: dict[str, Any]  # Ghidra program metadata
    ghidra_analysis_complete: bool
    file_path: Path | None = None
    load_time: float | None = None
    code_collection: chromadb.Collection | None = None
    strings_collection: chromadb.Collection | None = None

    @property
    def analysis_complete(self) -> bool:
        """Check if Ghidra analysis is complete."""
        return self.ghidra_analysis_complete

    @property
    def current_program(self) -> Program | None:
        """Get the current program."""
        return self.program

    @current_program.setter
    def current_program(self, program: Program) -> None:
        """Set the current program."""
        self.program = program


class PyGhidraContext:
    """Manages a Ghidra project, including its creation, program imports, and cleanup."""

    def __init__(
        self,
        project_name: str,
        project_path: str | Path,
        pyghidra_mcp_dir: Path | None = None,
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
        self.project_name: str = project_name
        self.project_path: Path = Path(project_path)
        self.project: GhidraProject = self._get_or_create_project()

        self.programs: dict[str, ProgramInfo] = {}
        self._init_project_programs()

        self.pyghidra_mcp_dir = (
            self.project_path / "pyghidra-mcp" if pyghidra_mcp_dir is None else Path(pyghidra_mcp_dir)  # Use provided pyghidra-mcp directory or create default
        )

        chromadb_path: Path = self.pyghidra_mcp_dir / "chromadb"
        chromadb_path.mkdir(parents=True, exist_ok=True)
        self.chroma_client: chromadb.PersistentClient = chromadb.PersistentClient(
            path=str(chromadb_path),
            settings=Settings(anonymized_telemetry=False),
        )

        # From GhidraDiffEngine
        self.force_analysis: bool = force_analysis
        self.verbose_analysis: bool = verbose_analysis
        self.no_symbols: bool = no_symbols
        self.gdts: list[str] = [] if gdts is None else gdts

        # Symbol configuration
        self.symbols_path: Path = Path(symbols_path) if symbols_path else self.pyghidra_mcp_dir / "symbols"
        self.sym_file_path: Path | None = None if sym_file_path is None else Path(sym_file_path)
        self.program_options: dict[str, Any] = {} if program_options is None else program_options
        self.gzfs_path: Path = self.pyghidra_mcp_dir / "gzfs" if gzfs_path is None else Path(gzfs_path)
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
        for _program_name, program_info in self.programs.items():
            program: Program = program_info.program
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
        from ghidra.base.project import GhidraProject
        from ghidra.framework.model import ProjectLocator

        # For standard Ghidra projects, use directory containing .gpr file
        project_dir: Path = self.project_path
        project_dir.mkdir(exist_ok=True, parents=True)
        project_dir_str: str = str(project_dir.absolute())

        locator = ProjectLocator(project_dir_str, self.project_name)

        # TODO: determine if it should be:
        # if locator.getMarkerFile().exists() and locator.getProjectDir().exists():
        if locator.exists():
            logger.info(f"Opening existing project: {self.project_name}")
            return GhidraProject.openProject(project_dir_str, self.project_name, True)
        logger.info(f"Creating new project: {self.project_name}")
        return GhidraProject.createProject(
            project_dir_str,
            self.project_name,
            False,
        )

    def _init_project_programs(self):
        """Initializes the programs dictionary with existing programs in the project."""
        all_binary_paths: list[str] = self.list_binaries()
        for binary_path_s in all_binary_paths:
            binary_path_str: str = str(binary_path_s)
            binary_path: Path = Path(binary_path_str)
            program: Program | None = self.project.openProgram(
                str(binary_path.parent),
                binary_path.name,
                False,
            )
            if program is None:
                logger.error(f"Failed to init program: {binary_path_s} during the open process")
                continue
            program_info: ProgramInfo = self._init_program_info(program)
            self.programs[str(binary_path)] = program_info

    def list_binaries(self) -> list[str]:
        """List all the binaries within the Ghidra project."""

        def list_folder_contents(folder: DomainFolder) -> list[str]:
            names: list[str] = []
            for subfolder in folder.getFolders():
                names.extend(list_folder_contents(subfolder))

            names.extend([f.getPathname() for f in folder.getFiles()])
            return names

        return list_folder_contents(self.project.getRootFolder())

    def list_binary_domain_files(self) -> list[DomainFile]:
        """Return a list of DomainFile objects for all binaries in the project.

        This mirrors `list_binaries` but returns the DomainFile objects themselves
        (filtered by content type == "Program").
        """

        def list_folder_domain_files(folder: DomainFolder) -> list[DomainFile]:
            files: list[DomainFile] = []
            for subfolder in folder.getFolders():
                files.extend(list_folder_domain_files(subfolder))

            files.extend(
                [f for f in folder.getFiles() if f.getContentType() == "Program"],
            )
            return files

        return list_folder_domain_files(self.project.getRootFolder())

    def delete_program(self, program_name: str) -> bool:
        """Deletes a program from the Ghidra project and saves the project.

        Args:
            program_name: The name of the program to delete.

        Returns:
            True if the program was deleted successfully, False otherwise.
        """
        program_info: ProgramInfo | None = self.programs.get(program_name)
        if program_info is None:
            available_progs: list[str] = list(self.programs.keys())
            raise ValueError(f"Binary {program_name} not found. Available binaries: {available_progs}")
        logger.info(f"Deleting program: {program_name}")
        try:
            assert isinstance(program_info, ProgramInfo), "Program info is not a ProgramInfo object"
            program_to_delete: Program = program_info.program
            assert isinstance(program_to_delete, Program), "Program is not a Program object"
            program_to_delete_df: DomainFile = program_to_delete.getDomainFile()
            assert isinstance(program_to_delete_df, DomainFile), "Domain file is not a DomainFile object"
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
        binary_path = Path(binary_path)
        if binary_path.is_dir():
            return self.import_binaries([binary_path], analyze=analyze)

        program_name = PyGhidraContext._gen_unique_bin_name(binary_path)

        program: Program | None = None
        root_folder = self.project.getRootFolder()

        # Create folder hierarchy if relative_path is provided
        if relative_path is not None:
            ghidra_folder = self._create_folder_hierarchy(root_folder, relative_path)
        else:
            ghidra_folder = root_folder

        # Check if program already exists at this location
        full_path: str = str(Path(ghidra_folder.pathname) / program_name)
        if self.programs.get(full_path) is not None:
            logger.info(f"Opening existing program: {program_name}")
            program = self.programs[full_path].program
            program_info = self.programs[full_path]
        else:
            logger.info(f"Importing new program: {program_name}")
            program = self.project.importProgram(binary_path)
            assert isinstance(program, Program), "Program is not a Program object"
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

        logger.info(f"Program {program_name} is ready for use.")

    @staticmethod
    def _create_folder_hierarchy(root_folder: DomainFolder, relative_path: Path) -> DomainFolder:
        """Recursively creates folder hierarchy in Ghidra project.

        Args:
            root_folder: The root folder of the Ghidra project.
            relative_path: The path hierarchy to create (e.g., Path("bin/subfolder")).

        Returns:
            The folder object at the end of the hierarchy.
        """
        current_folder: DomainFolder = root_folder

        # Split the path into parts and iterate through them
        for part in relative_path.parts:
            existing_folder: DomainFolder | None = current_folder.getFolder(part)
            if existing_folder is not None:
                current_folder = existing_folder
                logger.debug(f"Using existing folder: {part}")
            else:
                current_folder = current_folder.createFolder(part)
                logger.debug(f"Created folder: {part}")

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
        resolved_paths: list[Path] = [Path(p) for p in binary_paths]

        # Tuple of (full system path, relative path from provided path)
        files_to_import: list[tuple[Path, Path | None]] = []
        for p in resolved_paths:
            assert isinstance(p, Path), "Path is not a Path object"
            if p.exists() and p.is_dir():
                logger.info(f"Discovering files in directory: {p}")
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
                logger.error(f"Failed to import {bin_path}: {e}")
                # continue importing remaining files

    def _is_binary_file(self, path: Path) -> bool:
        # return self._detect_binary_format(path) is not None
        return True

    def _detect_binary_format(self, path: Path) -> str | None:
        # loader = pyghidra.program_loader()

        # try:
        #     loader.source(str(path))
        #     if loader.load() is not None:
        #         return loader
        # except Exception:
        #     return None

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
        try:
            result: concurrent.futures.Future | None = future.result()
            if result is not None:
                logger.info(f"Background import task completed successfully. Result: {result}")
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

    def _init_program_info(self, program: Program | None) -> ProgramInfo | None:
        from ghidra.program.flatapi import FlatProgramAPI  # pyright: ignore[reportMissingImports]

        if program is None:
            logger.error("Program is None")
            return None

        metadata: dict[str, Any] = self.get_metadata(program)

        program_info: ProgramInfo = ProgramInfo(
            name=program.name,
            program=program,
            flat_api=FlatProgramAPI(program),
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
        from ghidra.program.model.listing import Function  # pyright: ignore[reportMissingImports]

        logger.info(f"Initializing Chroma code collection for {program_info.name}")
        try:
            collection: chromadb.Collection | None = self.chroma_client.get_collection(name=program_info.name)
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
                func: Function
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
        collection_name: str = f"{program_info.name}_strings"
        logger.info(f"Initializing Chroma strings collection for {program_info.name}")
        try:
            strings_collection: chromadb.Collection | None = self.chroma_client.get_collection(name=collection_name)
            logger.info(f"Collection '{collection_name}' exists; skipping strings ingest.")
            program_info.strings_collection = strings_collection
        except Exception:
            logger.info(f"Creating new strings collection '{collection_name}'")
            tools = GhidraTools(program_info)

            strings: list[String] = tools.get_all_strings()
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

            logger.info(f"Strings analysis complete for collection '{collection_name}'")
            program_info.strings_collection = strings_collection

    def _init_chroma_collections_for_program(self, program_info: ProgramInfo):
        """Initializes all Chroma collections (code and strings) for a single program."""
        self._init_chroma_code_collection_for_program(program_info)
        self._init_chroma_strings_collection_for_program(program_info)

    def _init_all_chroma_collections(self):
        """Initializes Chroma collections for all programs in the project.

        If an executor is available, tasks are submitted asynchronously.
        Otherwise, initialization runs in the main thread.
        """
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
        try:
            future.result()
            logging.info("Asynchronous analysis finished successfully.")
        except Exception as e:
            logging.exception(f"Asynchronous analysis failed with exception: {e}")
            raise e

    def analyze_project(
        self,
        require_symbols: bool = True,
        force_analysis: bool = False,
        verbose_analysis: bool = False,
    ) -> concurrent.futures.Future | None:
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
                    logger.error(f"Analysis completed with an exception: {e}")
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
        domain_files: list[DomainFile] = self.list_binary_domain_files()

        logger.info(f"Starting analysis for {len(domain_files)} binaries")

        prog_count: int = len(domain_files)
        completed_count: int = 0

        if self.executor is not None:
            futures: list[concurrent.futures.Future[DomainFile | Program | None]] = [
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
                result: DomainFile | Program | None = future.result()
                if result is None:
                    logger.error("Analysis result is None, expected DomainFile or Program?")
                    continue
                if isinstance(result, DomainFile):
                    logger.info(f"Analysis complete for {result.getName()}")
                elif isinstance(result, Program):
                    logger.info(f"Analysis complete for {result.name}")
                else:
                    logger.error(f"Analysis result is {type(result)}, expected DomainFile or Program?")
                    continue
                completed_count += 1
                logger.info(f"Completed {completed_count}/{prog_count} programs")
        else:
            for domain_file in domain_files:
                self.analyze_program(
                    domain_file,
                    require_symbols,
                    force_analysis,
                    verbose_analysis,
                )
                completed_count += 1
                logger.info(f"Completed {completed_count}/{prog_count} programs")

        logger.info("All programs analyzed.")
        # The chroma collections need to be initialized after analysis is complete
        # At this point, threaded or not, all analysis is done
        self._init_all_chroma_collections()  # DO NOT MOVE

    def analyze_program(  # noqa C901
        self,
        df_or_prog: DomainFile | Program,
        require_symbols: bool = True,
        force_analysis: bool = False,
        verbose_analysis: bool = False,
    ):
        from ghidra.app.script import GhidraScriptUtil  # pyright: ignore[reportMissingImports]
        from ghidra.framework.model import DomainFile  # pyright: ignore[reportMissingImports]
        from ghidra.program.flatapi import FlatProgramAPI  # pyright: ignore[reportMissingImports]
        from ghidra.program.model.listing import Program  # pyright: ignore[reportMissingImports]
        from ghidra.program.util import GhidraProgramUtilities  # pyright: ignore[reportMissingImports]
        from ghidra.util.task import ConsoleTaskMonitor  # pyright: ignore[reportMissingImports]

        # Import symbol utilities from ghidrecomp
        from agentdecompile_cli.ghidrecomp.utility import (
            get_pdb,
            set_pdb,
            set_remote_pdbs,
            setup_symbol_server,
        )

        df: DomainFile | None = None
        if isinstance(df_or_prog, DomainFile):
            df = df_or_prog
        elif isinstance(df_or_prog, Program):
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
            self.programs[df_or_prog.getName() if df is None else df.pathname] = self._init_program_info(program)

        logger.info(f"Analyzing program: {program}")

        assert isinstance(program, Program), "Program is not a Program object"

        for gdt in self.gdts:
            logger.info(f"Loading GDT: {gdt}")
            if not Path(gdt).exists():
                raise FileNotFoundError(f"GDT Path not found {gdt}")
            self.apply_gdt(program, gdt)

        gdt_names: list[str] = [name for name in program.getDataTypeManager().getSourceArchives()]
        if len(gdt_names) > 0:
            logger.debug(f"Using file gdts: {gdt_names}")

        if verbose_analysis or self.verbose_analysis:
            monitor = ConsoleTaskMonitor()
            flat_api = FlatProgramAPI(program, monitor)
        else:
            flat_api = FlatProgramAPI(program)

        if GhidraProgramUtilities.shouldAskToAnalyze(program) or force_analysis or self.force_analysis:
            GhidraScriptUtil.acquireBundleHostReference()

            program_options = self.program_options.get("program_options", {})
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
                    logger.info(f"Setting prog option:{k} with value:{v}")
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

            logger.info(f"Starting Ghidra analysis of {program}...")
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
            logger.info(f"Analysis already complete.. skipping {program}!")

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
        prog: Program,
        option_name: str,
        value: Any,
    ) -> None:
        """Set boolean program analysis options.

        Inspired by: Ghidra/Features/Base/src/main/java/ghidra/app/script/GhidraScript.java#L1272
        """
        from ghidra.program.model.listing import Program  # pyright: ignore[reportMissingImports]

        prog_options: ToolOptions = prog.getOptions(Program.ANALYSIS_PROPERTIES)
        option_type = prog_options.getType(option_name)

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
                    temp_bool = value.lower()
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
                logger.warning(f"option {option_type} set not supported, ignoring")

    def configure_symbols(
        self,
        symbols_path: str | Path,
        symbol_urls: list[str] | None = None,
        allow_remote: bool = True,
    ):
        """Configures symbol servers and attempts to load PDBs for programs."""
        from ghidra.app.plugin.core.analysis import (  # pyright: ignore[reportMissingImports]
            PdbAnalyzer,
            PdbUniversalAnalyzer,
        )
        from ghidra.app.util.pdb import PdbProgramAttributes  # pyright: ignore[reportMissingImports]

        logger.info("Configuring symbol search paths...")
        # This is a simplification. A real implementation would need to configure the symbol server
        # which is more involved. For now, we'll focus on enabling the analyzers.

        for program_name, program in self.programs.items():
            logger.info(f"Configuring symbols for {program_name}")
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
                    logger.warning(f"PDB not loaded for {program_name}. Manual loading might be required.")

            except Exception as e:
                logger.error(f"Failed to configure symbols for {program_name}: {e}")

    def apply_gdt(
        self,
        program: Program,
        gdt_path: str | Path,
        verbose: bool = False,
    ):
        """Apply GDT to program"""
        from ghidra.app.cmd.function import ApplyFunctionDataTypesCmd  # pyright: ignore[reportMissingImports]
        from ghidra.program.model.data import FileDataTypeManager  # pyright: ignore[reportMissingImports]
        from ghidra.program.model.symbol import SourceType  # pyright: ignore[reportMissingImports]
        from ghidra.util.task import ConsoleTaskMonitor  # pyright: ignore[reportMissingImports]
        from java.io import File  # pyright: ignore[reportMissingImports]
        from java.util import List  # pyright: ignore[reportMissingImports]

        gdt_path = Path(gdt_path)

        if verbose:
            monitor = ConsoleTaskMonitor()
        else:
            monitor = ConsoleTaskMonitor().DUMMY_MONITOR

        archive_gdt = File(str(gdt_path))
        archive_dtm: FileDataTypeManager | None = FileDataTypeManager.openFileArchive(archive_gdt, False)
        if archive_dtm is None:
            raise ValueError(f"Failed to open file archive {gdt_path}")
        always_replace = True
        create_bookmarks_enabled = True
        cmd: ApplyFunctionDataTypesCmd = ApplyFunctionDataTypesCmd(
            List.of(archive_dtm),
            None,
            SourceType.USER_DEFINED,
            always_replace,
            create_bookmarks_enabled,
        )
        cmd.applyTo(program, monitor)

    def get_metadata(self, prog: Program) -> dict[str, Any]:
        """Generate dict from program metadata"""
        meta: dict[str, Any] = prog.getMetadata()
        return dict(meta)

    def setup_decompiler(self, program: Program) -> DecompInterface:
        from ghidra.app.decompiler import DecompInterface, DecompileOptions  # pyright: ignore[reportMissingImports]

        prog_options = DecompileOptions()

        decomp = DecompInterface()

        # grab default options from program
        prog_options.grabFromProgram(program)

        # increase maxpayload size to 100MB (default 50MB)
        prog_options.setMaxPayloadMBytes(100)

        decomp.setOptions(prog_options)
        decomp.openProgram(program)

        return decomp


# ---------------------------------------------------------------------------
# ProjectManager  (formerly project_manager.py)
# ---------------------------------------------------------------------------


class ProjectManager:
    """Manages Ghidra project creation and lifecycle for AgentDecompile CLI."""

    def __init__(
        self,
        projects_dir: Path | None = None,
    ):
        """Initialize project manager.

        Args:
            projects_dir: Custom projects directory, defaults to .agentdecompile/projects/ in current directory
        """
        if projects_dir is None:
            self.projects_dir = Path.cwd() / ".agentdecompile" / "projects"
        else:
            self.projects_dir = Path(projects_dir)

        # Don't create directory here - defer until first tool use (lazy initialization)
        self.project: GhidraProject | None = None
        self._opened_programs: list[GhidraProgram] = []
        self._initialized: bool = False

    def _ensure_initialized(self):
        """Ensure the project directory exists and project is opened.

        This implements lazy initialization - the .agentdecompile directory and Ghidra project
        are only created when first needed (e.g., when importing a binary).
        """
        if self._initialized:
            return

        # Create projects directory
        self.projects_dir.mkdir(parents=True, exist_ok=True)

        # Open/create the Ghidra project
        self.open_project()

        self._initialized = True

    def get_project_name(self) -> str:
        """Get project name based on current working directory.

        Returns:
            Project name derived from current directory name
        """
        cwd: Path = Path.cwd()
        # Use current directory name as project name
        project_name: str = cwd.name.strip()

        # Sanitize project name for Ghidra
        # Remove invalid characters and replace with underscores
        sanitized: str = "".join(c if c.isalnum() or c in "._-" else "_" for c in project_name)

        # Ensure name is not empty
        if not sanitized or sanitized.startswith("."):
            sanitized = "default_project"

        return sanitized

    def get_or_create_project(self) -> tuple[str, Path]:
        """Get or create Ghidra project for current working directory.

        Returns:
            Tuple of (project_name, project_directory_path)
        """
        project_name: str = self.get_project_name()
        project_path: Path = self.projects_dir / project_name

        # Create project directory if it doesn't exist
        project_path.mkdir(parents=True, exist_ok=True)

        return project_name, project_path

    def open_project(self) -> GhidraProject:
        """Open or create Ghidra project using PyGhidra.

        Returns:
        -------
            Ghidra Project instance (GhidraProject wrapper)

        Raises:
        ------
            ImportError: If Ghidra/PyGhidra not available
        """
        from ghidra.base.project import GhidraProject
        from ghidra.framework.model import ProjectLocator

        project_name, project_path = self.get_or_create_project()

        # Check if we should force ignore lock files
        # HACK: dumb idea, may keep for another time.
        # force_ignore_lock: bool = os.getenv(
        #    "AGENT_DECOMPILE_FORCE_IGNORE_LOCK",
        #    "",
        # ).lower().strip() in (
        #    "true",
        #    "1",
        #    "yes",
        #    "y",
        # )
        # if force_ignore_lock:
        #    self._delete_lock_files(project_path, project_name)

        # Use GhidraProject (PyGhidra's approach) - handles protected constructor properly
        project_locator = ProjectLocator(str(project_path), project_name)

        # Try to open existing project or create new one
        if project_locator.getProjectDir().exists() and project_locator.getMarkerFile().exists():
            sys.stderr.write(f"Opening existing project: {project_name}\n")
            self.project = GhidraProject.openProject(
                str(project_path),
                project_name,
                True,
            )
        else:
            sys.stderr.write(f"Creating new project: {project_name} at {project_path}\n")
            project_path.mkdir(parents=True, exist_ok=True)
            self.project = GhidraProject.createProject(
                str(project_path),
                project_name,
                False,
            )

        return self.project

    def _delete_lock_files(
        self,
        project_path: Path,
        project_name: str,
    ) -> None:
        """Delete lock files for a project, using rename trick if file handle is in use.

        Deletes both <projectName>.lock and <projectName>.lock~ files.
        If direct deletion fails (file handle in use), attempts to rename the file
        first, then delete it.

        Args:
        ----
            project_path: Path to the Ghidra project directory
            project_name: Name of the Ghidra project
        """
        lock_file: Path = project_path / f"{project_name}.lock"
        lock_file_backup: Path = project_path / f"{project_name}.lock~"

        # Delete main lock file
        if lock_file.exists() and lock_file.is_file():
            try:
                lock_file.unlink(missing_ok=True)
                sys.stderr.write(f"Deleted lock file: {lock_file.name}\n")
            except (OSError, PermissionError):
                # Try rename trick if direct delete fails (file handle in use)
                try:
                    temp_file = project_path / f"{project_name}.lock.tmp.{int(time.time() * 1000)}"
                    os.rename(str(lock_file), str(temp_file))
                    temp_file.unlink()
                    sys.stderr.write(f"Deleted lock file using rename trick: {lock_file.name}\n")
                except Exception as rename_error:
                    sys.stderr.write(f"Warning: Could not delete lock file (may be in use): {lock_file.name} - {rename_error}\n")

        # Delete backup lock file
        if lock_file_backup.exists() and lock_file_backup.is_file():
            try:
                lock_file_backup.unlink(missing_ok=True)
                sys.stderr.write(f"Deleted backup lock file: '{lock_file_backup.name}'\n")
            except (OSError, PermissionError):
                # Try rename trick if direct delete fails
                try:
                    temp_file = project_path / f"{project_name}.lock~.tmp.{int(time.time() * 1000)}"
                    os.rename(str(lock_file_backup), str(temp_file))
                    temp_file.unlink(missing_ok=True)
                    sys.stderr.write(f"Deleted backup lock file using rename trick: '{lock_file_backup.name}'\n")
                except Exception as rename_error:
                    sys.stderr.write(f"Warning: Could not delete backup lock file (may be in use): '{lock_file_backup.name}' - {rename_error}\n")

    def import_binary(
        self,
        binary_path: Path,
        program_name: str | None = None,
    ) -> GhidraProgram | None:
        """Import a binary file into the opened project.

        Args:
        ----
            binary_path: Path to binary file to import
            program_name: Optional custom program name, defaults to binary filename

        Returns:
        -------
            Imported GhidraProgram instance, or None if import fails
        """
        # Ensure project is initialized (lazy initialization on first use)
        self._ensure_initialized()

        if not binary_path.exists() or not binary_path.is_file():
            sys.stderr.write(f"Warning: Binary not found: {binary_path}\n")
            return None

        if program_name is None or not program_name.strip():
            program_name = binary_path.name

        try:
            sys.stderr.write(f"Importing binary: '{binary_path}' as '{program_name}'\n")
            from java.io import File  # pyright: ignore[reportMissingImports]

            # Use GhidraProject's importProgram method (auto-detects language/loader)
            program: GhidraProgram = self.project.importProgram(File(str(binary_path)))  # pyright: ignore[reportOptionalMemberAccess, reportArgumentType, reportUnknownLambdaType]

            # Save with custom name if specified
            if program_name.lower().strip() != binary_path.name.lower().strip():
                self.project.saveAs(program, "/", program_name, True)  # pyright: ignore[reportOptionalMemberAccess]

            self._opened_programs.append(program)

        except Exception as e:
            sys.stderr.write(f"Error importing binary '{binary_path}': {e.__class__.__name__}: {e}\n")
            import traceback

            traceback.print_exc(file=sys.stderr)
            return None

        else:
            sys.stderr.write(f"Successfully imported: '{program_name}'\n")
            return program

    def cleanup(self):
        """Clean up opened programs and close project."""
        # Release opened programs
        for program in self._opened_programs:
            try:
                if program is not None and not program.isClosed():
                    program.release(None)
            except Exception as e:
                sys.stderr.write(f"Error releasing program: {e.__class__.__name__}: {e}\n")

        self._opened_programs.clear()

        # Close project
        if self.project is not None:
            try:
                self.project.close()
            except Exception as e:
                sys.stderr.write(f"Error closing project: {e.__class__.__name__}: {e}\n")
            finally:
                self.project = None


# ---------------------------------------------------------------------------
# AgentDecompileLauncher helpers + class  (formerly launcher.py)
# ---------------------------------------------------------------------------


def _log_config_block(projects_dir: Path, project_name: str) -> None:
    """Write a single readable configuration block to stderr (no password value)."""
    lines = [
        "AgentDecompile configuration:",
        f"  project: {projects_dir / project_name}",
    ]
    project_path = os.getenv("AGENT_DECOMPILE_PROJECT_PATH")
    if project_path:
        lines.append(f"  AGENT_DECOMPILE_PROJECT_PATH: {project_path}")
    if os.getenv("AGENT_DECOMPILE_FORCE_IGNORE_LOCK"):
        lines.append("  AGENT_DECOMPILE_FORCE_IGNORE_LOCK: (set, project lock files may be ignored)")
    host = os.getenv("AGENT_DECOMPILE_SERVER_HOST")
    port = os.getenv("AGENT_DECOMPILE_SERVER_PORT")
    repo = os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY")
    if host or port or repo:
        lines.append(f"  server: host={host or '(not set)'}, port={port or '(not set)'}, repository={repo or '(not set)'}")
    if os.getenv("AGENT_DECOMPILE_SERVER_USERNAME"):
        lines.append("  AGENT_DECOMPILE_SERVER_USERNAME: (set)")
    if os.getenv("AGENT_DECOMPILE_SERVER_PASSWORD"):
        lines.append("  AGENT_DECOMPILE_SERVER_PASSWORD: (set)")
    ghidra_dir = os.getenv("GHIDRA_INSTALL_DIR")
    if ghidra_dir:
        lines.append(f"  GHIDRA_INSTALL_DIR: {ghidra_dir}")
    sys.stderr.write("\n".join(lines) + "\n")


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
    ) -> int:
        """Start Python MCP server.

        Args:
            port: Fixed port to bind (default: random). Set env AGENT_DECOMPILE_PORT.
            host: Host to bind (default: 127.0.0.1). Set env AGENT_DECOMPILE_HOST.
            project_directory: Optional project directory (used when AGENT_DECOMPILE_PROJECT_PATH not set).
            project_name: Optional project name (used with project_directory).

        Returns:
        -------
            Server port number

        Raises:
        ------
            RuntimeError: If server fails to start
        """
        try:
            use_random = port is None
            if port is not None:
                os.environ["AGENT_DECOMPILE_PORT"] = str(port)
            if host is not None:
                os.environ["AGENT_DECOMPILE_HOST"] = host
            self.use_random_port = use_random

            # Check for AGENT_DECOMPILE_PROJECT_PATH environment variable
            project_gpr_path = os.getenv("AGENT_DECOMPILE_PROJECT_PATH")

            if project_gpr_path:
                # Use user-specified project from environment variable
                project_gpr = Path(project_gpr_path)

                # Validate it's a .gpr file
                if not project_gpr.suffix.lower() == ".gpr":
                    raise ValueError(f"AGENT_DECOMPILE_PROJECT_PATH must point to a .gpr file, got: {project_gpr_path}")

                # Validate the file exists
                if not project_gpr.exists():
                    raise FileNotFoundError(f"Project file specified in AGENT_DECOMPILE_PROJECT_PATH does not exist: {project_gpr_path}")

                # Extract project directory and name (same logic as open tool for projects)
                project_dir = project_gpr.parent
                project_name = project_gpr.stem  # Gets filename without extension

                if not project_name:
                    raise ValueError(f"Invalid project name extracted from path: {project_gpr_path}")

                # Store the user project path (so we don't clean it up)
                self.user_project_path = project_gpr

                # Use the project directory
                projects_dir = project_dir
            elif project_directory is not None and project_name:
                # Explicit project directory and name (e.g. from server --project-path/--project-name)
                projects_dir = Path(project_directory)
                projects_dir.mkdir(parents=True, exist_ok=True)
            else:
                # Stdio mode: ephemeral projects in temp directory (session-scoped, auto-cleanup)
                # Keeps working directory clean - no .agentdecompile creation in cwd
                self.temp_project_dir = Path(tempfile.mkdtemp(prefix="agentdecompile_project_"))
                self.project_manager = ProjectManager()
                project_name = self.project_manager.get_project_name()

                # Use temp directory for the project (not .agentdecompile/projects)
                projects_dir = self.temp_project_dir

            # Log configuration once in a readable block (no password value)
            _log_config_block(projects_dir, project_name)

            # Create PyGhidra context for proper Ghidra integration
            self.pyghidra_context = PyGhidraContext(
                project_name=project_name,
                project_path=str(projects_dir),
                force_analysis=False,
                verbose_analysis=False,
                no_symbols=False,
            )

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
            if host:
                server_config.host = host
            if port:
                server_config.port = port

            # Create and start MCP server
            self.mcp_server = PythonMcpServer(server_config)
            self.mcp_server.set_program_info(self.program_info)

            # Pass the GhidraProject so providers can checkout from shared repos
            if self.pyghidra_context is not None:
                self.mcp_server.set_ghidra_project(self.pyghidra_context.project)

            # Start the server
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
        return self.port

    def is_running(self) -> bool:
        """Check if server is running.

        Returns:
        --------
            True if server is running
        """
        return self.mcp_server is not None and self.mcp_server.is_running()

    def stop(self):
        """Stop the Python MCP server and cleanup PyGhidra context."""
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
    if not os.getenv("AGENT_DECOMPILE_PROJECT_PATH"):
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

        async def _import_binaries() -> None:
            client = get_client(host="127.0.0.1", port=started_port)
            async with client:
                for path in bin_paths:
                    try:
                        await client.call_tool("open", {"path": str(path.resolve()), "runAnalysis": True})
                        sys.stderr.write(f"Imported: {path}\n")
                    except Exception as e:
                        sys.stderr.write(f"Import failed for {path}: {e}\n")

        run_async(_import_binaries())

    if wait_for_analysis:
        # Optional: wait a few seconds for analysis to progress (server is already up)
        time.sleep(5)

    return launcher, project_manager


def _env_port() -> int:
    """Default port from AGENT_DECOMPILE_PORT (1:1 Java applyHeadlessServerEnvOverrides)."""
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
    return (os.environ.get("AGENT_DECOMPILE_HOST") or "").strip() or "127.0.0.1"


def main() -> None:
    """Parse server options and run init + transport."""
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
        type=int,
        default=None,
        help="Port for HTTP transports (default: AGENT_DECOMPILE_PORT or 8080)",
    )
    g_server.add_argument(
        "-o",
        "--host",
        type=str,
        default=None,
        help="Host for HTTP transports (default: AGENT_DECOMPILE_HOST or 127.0.0.1)",
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

    # Apply env defaults for host/port (1:1 Java headless)
    port = args.port if args.port is not None else _env_port()
    host = args.host if args.host is not None else _env_host()

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
